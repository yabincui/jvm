#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vector>

#include "java_class.h"
#include "java_class_namemap.h"

constexpr uint32_t CLASS_MAGIC = 0xCAFEBABE;

#define CHECK(expr) \
  if (!(expr)) abort()

#define Abort(fmt,...) \
  do { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    abort(); \
  } while (0)

template <typename T>
void Read(const char*& p, const char* end, T& value) {
  static_assert(std::is_standard_layout<T>::value, "...");
  if (p + sizeof(T) > end) {
    Abort("data not enough for Read()\n");
  }
  value = 0;
  for (size_t i = 0; i < sizeof(T); ++i) {
    value = (value << 8) | *(const uint8_t*)p;
    p++;
  }
}

static void PrintIndented(int indent, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  printf("%*s", indent * 2, "");
  vprintf(fmt, ap);
  va_end(ap);
}

static std::string StringPrintf(const char* fmt, ...) {
  va_list backup_ap;
  va_start(backup_ap, fmt);
  va_list ap;
  va_copy(ap, backup_ap);
  char buf[40];
  int result = vsnprintf(buf, sizeof(buf), fmt, ap);
  if (result < sizeof(buf)) {
    va_end(ap);
    va_end(backup_ap);
    return buf;
  }
  va_copy(ap, backup_ap);
  std::string s(result, '\0');
  vsnprintf(&s[0], result + 1, fmt, ap);
  va_end(ap);
  va_end(backup_ap);
  return s;
}

class JavaClass {
 public:
  JavaClass(const char* filename, const char* data, size_t size)
      : filename_(filename), data_(data), size_(size), end_(data_ + size_) {
  }

  bool ParseHead() {
    p_ = data_;
    uint32_t magic;
    Read(p_, end_, magic);
    printf("magic = 0x%x\n", magic);
    if (magic != CLASS_MAGIC) {
      fprintf(stderr, "%s is not a class file\n", filename_);
      return false;
    }
    uint16_t major_version;
    uint16_t minor_version;
    Read(p_, end_, minor_version);
    Read(p_, end_, major_version);
    printf("version %u.%u\n", major_version, minor_version);
    return true;
  }

  bool ParseConstantPool() {
    Read(p_, end_, constant_pool_count_);
    printf("constant_pool_count: %u\n", constant_pool_count_);
    printf("constant pool:\n");
    constant_pool_.resize(constant_pool_count_ + 1, nullptr);
    for (uint16_t i = 1; i < constant_pool_count_; ++i) {
      constant_pool_[i] = p_;
      CHECK(p_ + 1 < end_);
      uint8_t tag = *p_;
      switch (tag) {
      case CONSTANT_Class:
      case CONSTANT_String:
      case CONSTANT_MethodType:
        p_ += 3; break;
      case CONSTANT_MethodHandle:
        p_ += 4; break;
      case CONSTANT_Fieldref:
      case CONSTANT_Methodref:
      case CONSTANT_InterfaceMethodref:
      case CONSTANT_Integer:
      case CONSTANT_Float:
      case CONSTANT_NameAndType:
        p_ += 5; break;
      case CONSTANT_Long:
      case CONSTANT_Double:
        p_ += 9; ++i; break;
      case CONSTANT_Utf8: {
          const char* p = p_ + 1;
          uint16_t length;
          Read(p, end_, length);
          p_ += 3 + length;
          break;
        }
      default:
        fprintf(stderr, "unknown tag %u\n", tag);
        return false;
      }
    }
    for (uint16_t i = 1; i < constant_pool_count_; ++i) {
      if (constant_pool_[i] != nullptr) {
        PrintConstantPoolEntry(0, i);
      }
    }
    return true;
  }

  bool ParseAccessFlags() {
    uint16_t access_flags;
    Read(p_, end_, access_flags);
    printf("access_flags: 0x%x, %s\n", access_flags,
           FindMaskVector(CLASS_ACCESS_FLAGS_NAME_VECTOR, access_flags).c_str());
    uint16_t this_class;
    Read(p_, end_, this_class);
    printf("this_class: %u\n", this_class);
    PrintConstantPoolEntry(0, this_class);
    uint16_t super_class;
    Read(p_, end_, super_class);
    printf("super_class: %u\n", super_class);
    PrintConstantPoolEntry(0, super_class);
    uint16_t interface_count;
    Read(p_, end_, interface_count);
    printf("interface_count: %u\n", interface_count);
    for (int i = 0; i < interface_count; ++i) {
      uint16_t interface_idx;
      Read(p_, end_, interface_idx);
      printf("interface #%d: index %u\n", i, interface_idx);
      PrintConstantPoolEntry(0, interface_idx);
    }
    return true;
  }

  bool ParseFields() {
    Read(p_, end_, field_count_);
    printf("field_count: %u\n", field_count_);
    printf("fields:\n");
    for (int i = 0; i < field_count_; ++i) {
      uint16_t access_flags;
      uint16_t name_index;
      uint16_t descriptor_index;
      uint16_t attribute_count;
      Read(p_, end_, access_flags);
      Read(p_, end_, name_index);
      Read(p_, end_, descriptor_index);
      printf("#%d: %s [Type:%s]\n", i, GetConstantPoolEntryString(name_index).c_str(),
             GetConstantPoolEntryString(descriptor_index).c_str());
      PrintIndented(1, "access_flags: 0x%x %s\n", access_flags,
                    FindMaskVector(FIELD_ACCESS_FLAGS_NAME_VECTOR, access_flags).c_str());
      Read(p_, end_, attribute_count);
      p_ = PrintAttributeArray(1, p_, attribute_count);
    }
  }

  bool ParseMethods() {
    Read(p_, end_, method_count_);
    printf("method_count: %u\n", method_count_);
    printf("methods:\n");
    for (int i = 0; i < method_count_; ++i) {
      uint16_t access_flags;
      uint16_t name_index;
      uint16_t descriptor_index;
      uint16_t attribute_count;
      Read(p_, end_, access_flags);
      Read(p_, end_, name_index);
      Read(p_, end_, descriptor_index);
      printf("#%d: %s [Type:%s]\n", i, GetConstantPoolEntryString(name_index).c_str(),
             GetConstantPoolEntryString(descriptor_index).c_str());
      PrintIndented(1, "access_flags: 0x%x %s\n", access_flags,
                    FindMaskVector(METHOD_ACCESS_FLAGS_NAME_VECTOR, access_flags).c_str());
      Read(p_, end_, attribute_count);
      p_ = PrintAttributeArray(1, p_, attribute_count);
    }
  }

  bool ParseAttributes() {
    uint16_t attribute_count;
    Read(p_, end_, attribute_count);
    p_ = PrintAttributeArray(0, p_, attribute_count);
    return true;
  }

 private:
  bool PrintConstantPoolEntry(int indent, int constIndex) {
    const char* p = constant_pool_[constIndex];
    uint8_t tag = *p++;
    if (indent == 0) {
      printf("#%d ", constIndex);
    }
    PrintIndented(indent, "tag %s(%u)\n",
        FindMap(CONSTANT_POOL_TAGS_NAME_MAP, tag), tag);
    indent++;
    switch (tag) {
    case CONSTANT_Utf8:
    {
      uint16_t length;
      Read(p, end_, length);
      char buf[length + 1];
      memcpy(buf, p, length);
      buf[length] = '\0';
      PrintIndented(indent, "bytes: %s\n", buf);
      break;
    }
    case CONSTANT_String:
    {
      uint16_t string_index;
      Read(p, end_, string_index);
      PrintIndented(indent, "string_index: %u\n", string_index);
      PrintConstantPoolEntry(indent, string_index);
      break;
    }
    case CONSTANT_Integer:
    {
      int32_t value;
      Read(p, end_, value);
      PrintIndented(indent, "vaue: %d\n", value);
      break;
    }
    case CONSTANT_Float:
    {
      int32_t value;
      Read(p, end_, value);
      PrintIndented(indent, "value: %f\n", *(float*)&value);
      break;
    }
    case CONSTANT_Long:
    {
      int64_t value;
      Read(p, end_, value);
      PrintIndented(indent, "value: %lld\n", (long long)value);
      break;
    }
    case CONSTANT_Double:
    {
      int64_t value;
      Read(p, end_, value);
      PrintIndented(indent, "value: %f\n", *(double*)&value);
      break;
    }
    case CONSTANT_Class:
    {
      uint16_t name_index;
      Read(p, end_, name_index);
      PrintIndented(indent, "name_index: %u\n", name_index);
      PrintConstantPoolEntry(indent, name_index);
      break;
    }
    case CONSTANT_NameAndType:
    {
      uint16_t name_index;
      uint16_t descriptor_index;
      Read(p, end_, name_index);
      Read(p, end_, descriptor_index);
      PrintIndented(indent, "name_index: %u\n", name_index);
      PrintIndented(indent, "descriptor_index: %u\n", descriptor_index);
      PrintConstantPoolEntry(indent, name_index);
      PrintConstantPoolEntry(indent, descriptor_index);
      break;
    }
    case CONSTANT_Fieldref:
    case CONSTANT_Methodref:
    case CONSTANT_InterfaceMethodref:
    {
      uint16_t class_index;
      uint16_t name_and_type_index;
      Read(p, end_, class_index);
      Read(p, end_, name_and_type_index);
      PrintIndented(indent, "class_index: %u\n", class_index);
      PrintIndented(indent, "name_and_type_index: %u\n", name_and_type_index);
      PrintConstantPoolEntry(indent, class_index);
      PrintConstantPoolEntry(indent, name_and_type_index);
      break;
    }

    default:
      fprintf(stderr, "unhandled tag %u\n", tag);
      return false;
    }
    return true;
  }

  std::string GetConstantPoolEntryString(int constIndex) {
    const char* p = constant_pool_[constIndex];
    uint8_t tag = *p++;
    switch (tag) {
    case CONSTANT_Utf8:
    {
      uint16_t length;
      Read(p, end_, length);
      std::string result(length, '\0');
      memcpy(&result[0], p, length);
      return result;
    }
    case CONSTANT_String:
    {
      uint16_t string_index;
      Read(p, end_, string_index);
      return GetConstantPoolEntryString(string_index);
    }
    case CONSTANT_Integer:
    {
      int32_t value;
      Read(p, end_, value);
      return StringPrintf("%d", value);
    }
    case CONSTANT_Float:
    {
      int32_t value;
      Read(p, end_, value);
      return StringPrintf("%f", *(float*)&value);
    }
    case CONSTANT_Long:
    {
      int64_t value;
      Read(p, end_, value);
      return StringPrintf("%lld", (long long)value);
    }
    case CONSTANT_Double:
    {
      int64_t value;
      Read(p, end_, value);
      return StringPrintf("%f", *(double*)&value);
      break;
    }
    case CONSTANT_Class:
    {
      uint16_t name_index;
      Read(p, end_, name_index);
      return GetConstantPoolEntryString(name_index);
      break;
    }
    case CONSTANT_NameAndType:
    {
      uint16_t name_index;
      uint16_t descriptor_index;
      Read(p, end_, name_index);
      Read(p, end_, descriptor_index);
      std::string name = GetConstantPoolEntryString(name_index);
      std::string descriptor = GetConstantPoolEntryString(descriptor_index);
      return StringPrintf("%s [Type:%s]", name.c_str(), descriptor.c_str());
    }
    case CONSTANT_Fieldref:
    case CONSTANT_Methodref:
    case CONSTANT_InterfaceMethodref:
    {
      uint16_t class_index;
      uint16_t name_and_type_index;
      Read(p, end_, class_index);
      Read(p, end_, name_and_type_index);
      std::string class_name = GetConstantPoolEntryString(class_index);
      std::string name_and_type = GetConstantPoolEntryString(name_and_type_index);
      return StringPrintf("%s [Class:%s]", name_and_type.c_str(), class_name.c_str());
    }

    default:
      fprintf(stderr, "unhandled tag %u\n", tag);
      return "";
    }
  }

  const char* PrintAttributeArray(int indent, const char* p, int attribute_count) {
    PrintIndented(indent, "attribute_count: %u\n", attribute_count);
    for (int i = 0; i < attribute_count; ++i) {
      PrintIndented(indent, "attribute #%d\n", i);
      uint16_t attribute_name_index;
      uint32_t attribute_length;
      Read(p, end_, attribute_name_index);
      Read(p, end_, attribute_length);
      std::string name = GetConstantPoolEntryString(attribute_name_index);
      PrintIndented(indent + 1, "attribute %s\n", name.c_str());
      PrintIndented(indent + 1, "attribute_length: %u\n", attribute_length);
      const char* next_p = p + attribute_length;
      if (name == "Code") {
        uint16_t max_stack;
        Read(p, next_p, max_stack);
        PrintIndented(indent + 1, "max_stack: %u\n", max_stack);
        uint16_t max_locals;
        Read(p, next_p, max_locals);
        PrintIndented(indent + 1, "max_locals: %u\n", max_locals);
        uint32_t code_length;
        Read(p, next_p, code_length);
        PrintIndented(indent + 1, "code_length: %u\n", code_length);
        PrintCodeArray(indent + 2, p, p + code_length);
        p += code_length;
        uint16_t exception_table_length;
        Read(p, next_p, exception_table_length);
        PrintIndented(indent + 1, "exception_table_length: %u\n", exception_table_length);
        for (int j = 0; j < exception_table_length; ++j) {
          uint16_t start_pc;
          uint16_t end_pc;
          uint16_t handler_pc;
          uint16_t catch_type;
          Read(p, next_p, start_pc);
          Read(p, next_p, end_pc);
          Read(p, next_p, handler_pc);
          Read(p, next_p, catch_type);
          PrintIndented(indent + 1, "start_pc %u, end_pc %u, handler_pc %u, catch_type %u\n",
                        start_pc, end_pc, handler_pc, catch_type);
        }
        uint16_t code_attribute_count;
        Read(p, next_p, code_attribute_count);
        p = PrintAttributeArray(indent + 1, p, code_attribute_count);
      } else if (name == "LineNumberTable") {
        uint16_t line_number_table_length;
        Read(p, next_p, line_number_table_length);
        PrintIndented(indent + 1, "line number table length: %u\n", line_number_table_length);
        for (int i = 0; i < line_number_table_length; ++i) {
          uint16_t start_pc;
          uint16_t line_number;
          Read(p, next_p, start_pc);
          Read(p, next_p, line_number);
          PrintIndented(indent + 2, "start_pc 0x%x, line_number %u\n", start_pc, line_number);
        }
      } else if (name == "SourceFile") {
        uint16_t sourcefile_index;
        Read(p, next_p, sourcefile_index);
        PrintIndented(indent + 1, "sourcefile: %s\n", GetConstantPoolEntryString(sourcefile_index).c_str());
      } else if (name == "StackMapTable") {
        uint16_t num_of_entries;
        Read(p, next_p, num_of_entries);
        PrintIndented(indent + 1, "num_of_entries: %u\n", num_of_entries);
        uint16_t prev_offset = -1;
        for (int i = 0; i < num_of_entries; ++i) {
          uint8_t frame_type = *p++;
          if (frame_type <= 63) {
            uint16_t offset_delta = frame_type;
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> same_frame\n", prev_offset);
          } else if (frame_type <= 127) {
            uint16_t offset_delta = frame_type - 64;
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> same_locals_1_stack_item_frame\n", prev_offset);
            p = PrintVerificationTypeInfo(indent + 3, p, next_p);
          } else if (frame_type <= 246) {
            Abort("reserved frame_type %d\n", frame_type);
          } else if (frame_type == 247) {
            uint16_t offset_delta;
            Read(p, next_p, offset_delta);
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> same_locals_1_stack_item_frame_extended\n", prev_offset);
            p = PrintVerificationTypeInfo(indent + 3, p, next_p);
          } else if (frame_type <= 250) {
            int chop = 251 - frame_type;
            uint16_t offset_delta;
            Read(p, next_p, offset_delta);
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> chop_frame %d\n", prev_offset, chop);
          } else if (frame_type == 251) {
            uint16_t offset_delta;
            Read(p, next_p, offset_delta);
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> same_frame_extended\n", prev_offset);
          } else if (frame_type <= 254) {
            int append = frame_type - 251;
            uint16_t offset_delta;
            Read(p, next_p, offset_delta);
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> append_frame %d\n", prev_offset, append);
            for (int i = 0; i < append; ++i) {
              p = PrintVerificationTypeInfo(indent + 3, p, next_p);
            }
          } else if (frame_type == 255) {
            uint16_t offset_delta;
            uint16_t number_of_locals;
            uint16_t number_of_stack_items;
            Read(p, next_p, offset_delta);
            prev_offset += offset_delta + 1;
            PrintIndented(indent + 2, "<0x%x> full_frame\n", prev_offset);
            Read(p, next_p, number_of_locals);
            PrintIndented(indent + 3, "number_of_locals: %u\n", number_of_locals);
            for (int i = 0; i < number_of_locals; ++i) {
              p = PrintVerificationTypeInfo(indent + 3, p, next_p);
            }
            Read(p, next_p, number_of_stack_items);
            PrintIndented(indent + 3, "number_of_stack_items: %u\n", number_of_stack_items);
            for (int i = 0; i < number_of_stack_items; ++i) {
              p = PrintVerificationTypeInfo(indent + 3, p, next_p);
            }
          }
        }
      } else if (name == "Exceptions") {
        uint16_t number_of_exceptions;
        Read(p, next_p, number_of_exceptions);
        PrintIndented(indent + 1, "number_of_exceptions: %u\n", number_of_exceptions);
        for (int i = 0; i < number_of_exceptions; ++i) {
          uint16_t index;
          Read(p, next_p, index);
          PrintIndented(indent + 1, "%s\n", GetConstantPoolEntryString(index).c_str());
        }
      } else if (name == "InnerClasses") {
        uint16_t number_of_classes;
        Read(p, next_p, number_of_classes);
        PrintIndented(indent + 1, "number_of_classes: %u\n", number_of_classes);
        for (int i = 0; i < number_of_classes; ++i) {
          uint16_t inner_class_info_index;
          uint16_t outer_class_info_index;
          uint16_t inner_name_index;
          uint16_t inner_class_access_flags;
          Read(p, next_p, inner_class_info_index);
          Read(p, next_p, outer_class_info_index);
          Read(p, next_p, inner_name_index);
          Read(p, next_p, inner_class_access_flags);
          PrintIndented(indent + 1, "class #%d\n", i);
          PrintIndented(indent + 2, "inner_class %s\n",
                        GetConstantPoolEntryString(inner_class_info_index).c_str());
          if (outer_class_info_index != 0) {
            PrintIndented(indent + 2, "outer_class %s\n",
                          GetConstantPoolEntryString(outer_class_info_index).c_str());
          }
          if (inner_name_index != 0) {
            PrintIndented(indent + 2, "inner_name %s\n",
                          GetConstantPoolEntryString(inner_name_index).c_str());
          }
          PrintIndented(indent + 2, "access_flags: %s\n",
                        FindMaskVector(INNER_CLASS_ACCESS_FLAGS_NAME_VECTOR,
                                       inner_class_access_flags).c_str());

        }
      } else {
        Abort("unsupported attribute %s\n", name.c_str());
      }
      p = next_p;
    }
    return p;
  }

  const char* PrintVerificationTypeInfo(int indent, const char* p, const char* end) {
    uint8_t tag = *p++;
    PrintIndented(indent, "verification info: %s", FindMap(VERIFICATION_TYPE_NAME_MAP, tag));
    if (tag == ITEM_Object) {
      uint16_t cpool_index;
      Read(p, end, cpool_index);
      printf(" %u  #%s\n", cpool_index, GetConstantPoolEntryString(cpool_index).c_str());
    } else if (tag == ITEM_Uninitialized) {
      uint16_t offset;
      Read(p, end, offset);
      printf(" 0x%x\n", offset);
    }
    printf("\n");
    return p;
  }

  bool PrintCodeArray(int indent, const char* start, const char* end) {
    const char* p = start;
    while (p < end) {
      uint8_t inst = *p++;
      PrintIndented(indent, "#0x%x %s ", (uint32_t)(p - start - 1),
                    FindMap(CLASS_INST_OP_NAME_MAP, inst));
      switch (inst) {
        case INST_ALOAD:
        case INST_ASTORE:
        case INST_DLOAD:
        case INST_DSTORE:
        case INST_FLOAD:
        case INST_FSTORE:
        case INST_ILOAD:
        case INST_ISTORE:
        case INST_LLOAD:
        case INST_LSTORE:
        case INST_RET:
        {
          uint8_t index = *p++;
          printf("%u\n", index);
          break;
        }
        case INST_LDC:
        {
          uint8_t index = *p++;
          printf("%u   #%s\n", index, GetConstantPoolEntryString(index).c_str());
          break;
        }
        case INST_ANEWARRAY:
        case INST_CHECKCAST:
        case INST_GETFIELD:
        case INST_GETSTATIC:
        case INST_INSTANCEOF:
        case INST_INVOKESPECIAL:
        case INST_INVOKESTATIC:
        case INST_INVOKEVIRTUAL:
        case INST_LDC_W:
        case INST_LDC2_W:
        case INST_NEW:
        case INST_PUTFIELD:
        case INST_PUTSTATIC:
        {
          uint16_t index;
          Read(p, end, index);
          printf("%u   #%s\n", index, GetConstantPoolEntryString(index).c_str());
          break;
        }
        case INST_BIPUSH:
        {
          int8_t byte = *p++;
          printf("%d\n", byte);
          break;
        }
        case INST_SIPUSH:
        {
          int16_t value;
          Read(p, end, value);
          printf("%d\n", value);
          break;
        }
        case INST_GOTO:
        case INST_IF_ACMPEQ:
        case INST_IF_ACMPNE:
        case INST_IF_ICMPEQ:
        case INST_IF_ICMPNE:
        case INST_IF_ICMPLT:
        case INST_IF_ICMPGE:
        case INST_IF_ICMPGT:
        case INST_IF_ICMPLE:
        case INST_IFEQ:
        case INST_IFNE:
        case INST_IFLT:
        case INST_IFGE:
        case INST_IFGT:
        case INST_IFLE:
        case INST_IFNONNULL:
        case INST_IFNULL:
        case INST_JSR:
        {
          int16_t branch;
          uint16_t offset = p - start - 1;
          Read(p, end, branch);
          offset += branch;
          printf("0x%x\n", offset);
          break;
        }
        case INST_GOTO_W:
        case INST_JSR_W:
        {
          int32_t branch;
          uint16_t offset = p - start - 1;
          Read(p, end, branch);
          offset += branch;
          printf("0x%x\n", offset);
          break;
        }
        case INST_IINC:
        {
          uint8_t index = *p++;
          int8_t const_value = *p++;
          printf("index %u, const %d\n", index, const_value);
          break;
        }
        case INST_INVOKEDYNAMIC:
        {
          uint16_t index;
          Read(p, end, index);
          uint16_t zero;
          Read(p, end, zero);
          CHECK(zero == 0);
          printf("%u\n", index);
          break;
        }
        case INST_INVOKEINTERFACE:
        {
          uint16_t index;
          Read(p, end, index);
          uint8_t count = *p++;
          CHECK(*p == 0);
          p++;
          printf("index %u, count %u\n", index, count);
          break;
        }
        case INST_LOOKUPSWITCH:
        {
          uint32_t offset = p - start - 1;
          // pad
          while ((p - start) % 4 != 0) {
            p++;
          }
          int32_t default_branch;
          Read(p, end, default_branch);
          int32_t npairs;
          Read(p, end, npairs);
          printf("npairs %d\n", npairs);
          for (int i = 0; i < npairs; ++i) {
            int32_t value;
            int32_t branch;
            Read(p, end, value);
            Read(p, end, branch);
            uint32_t target = offset + branch;
            PrintIndented(indent + 1, "%d : 0x%x\n", value, target);
          }
          uint32_t target = offset + default_branch;
          PrintIndented(indent + 1, "default: 0x%x\n", target);
          break;
        }
        case INST_TABLESWITCH:
        {
          uint32_t offset = p - start - 1;
          // pad
          while ((p - start) % 4 != 0) {
            p++;
          }
          int32_t default_branch;
          Read(p, end, default_branch);
          int32_t low;
          int32_t high;
          Read(p, end, low);
          Read(p, end, high);
          printf("low = %d, high = %d\n", low, high);
          for (int i = low; i <= high; ++i) {
            int32_t branch;
            Read(p, end, branch);
            uint32_t target = offset + branch;
            PrintIndented(indent + 1, "%d: 0x%x\n", i, target);
          }
          uint32_t target = offset + default_branch;
          PrintIndented(indent + 1, "default: 0x%x\n", target);
          break;
        }
        case INST_MULTIANEWARRAY:
        {
          uint16_t index;
          Read(p, end, index);
          uint8_t dimensions = *p++;
          printf("index %u, dimensions %u\n", index, dimensions);
          break;
        }
        case INST_NEWARRAY:
        {
          uint8_t atype = *p++;
          printf("atype %s(%u)\n", FindMap(CLASS_INST_ARRAY_TYPE_NAME_MAP, atype), atype);
          break;
        }
        case INST_WIDE:
        {
          uint8_t opcode = *p++;
          printf("%s(0x%x) ", FindMap(CLASS_INST_OP_NAME_MAP, opcode), opcode);
          if (opcode == INST_IINC) {
            uint16_t index;
            int16_t const_value;
            Read(p, end, index);
            Read(p, end, const_value);
            printf("index %u, const %d\n", index, const_value);
          } else {
            uint16_t index;
            Read(p, end, index);
            printf("%u\n", index);
          }
          break;
        }
        default:
        {
          printf("\n");
          break;
        }
      }
    }
    return true;
  }

  const char* filename_;
  const char* data_;
  size_t size_;
  const char* end_;
  const char* p_;

  std::vector<const char*> constant_pool_;
  uint16_t constant_pool_count_;

  uint16_t field_count_;
  uint16_t method_count_;
};

bool ReadClass(const char* filename) {
  FILE* fp = fopen(filename, "rb");
  if (fp == nullptr) {
    fprintf(stderr, "failed to open %s\n", filename);
    return false;
  }
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  printf("size of %s is %ld\n", filename, size);
  fseek(fp, 0, SEEK_SET);
  std::vector<char> buf(size);
  if (fread(buf.data(), size, 1, fp) != 1) {
    fprintf(stderr, "failed to read %s\n", filename);
    fclose(fp);
  }
  fclose(fp);
  JavaClass cls(filename, buf.data(), buf.size());
  cls.ParseHead();
  cls.ParseConstantPool();
  cls.ParseAccessFlags();
  cls.ParseFields();
  cls.ParseMethods();
  cls.ParseAttributes();
  return true;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "read_class <class_file>\n");
    return 1;
  }
  const char* filename = argv[1];
  ReadClass(filename);
}

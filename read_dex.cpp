#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <vector>

#include "dex.h"
#include "dex_namemap.h"
#include "utils.h"

template <typename T>
void Read(const char*& p, const char* end, T& value) {
  static_assert(std::is_standard_layout<T>::value, "...");
  if (p + sizeof(T) > end) {
    Abort("data not enough for Read()\n");
  }
  memcpy(&value, p, sizeof(T));
  p += sizeof(T);
}

template <typename T>
void ReadEncodedValue(const char*& p, int size, T& value, bool sign_extend) {
  value = 0;
  char* t = (char*)&value;
  memcpy(t, p, size + 1);
  p += size + 1;
  t += size + 1;
  if (sign_extend && (*(t - 1) & 0x80)) {
    memset(t, 0xff, sizeof(T) - size - 1);
  }
}

template <typename T>
void ReadEncodedFloatValue(const char*& p, int size, T& value) {
  char* t = (char*)&value;
  char* end = t + sizeof(value);
  memset(t, '\0', sizeof(value));
  for (int i = 0; i <= size; ++i) {
    --end;
    *end = *p++;
  }
}

class JavaDex {
 public:
  JavaDex(const char* filename, const char* data, size_t size)
      : filename_(filename), data_(data), size_(size), end_(data + size) {
  }

  bool ParseHead() {
    p_ = data_;
    const char* magic = p_;
    p_ += 8;
    printf("magic: %s\n", magic);
    if (strncmp(magic, "dex\n", 4) != 0) {
      fprintf(stderr, "%s is not a dex file\n", filename_);
      return false;
    }
    uint32_t checksum;
    Read(p_, end_, checksum);
    printf("checksum = 0x%x\n", checksum);
    const char* signature = p_;
    p_ += 20;
    printf("signature: %s\n", GetHexString(signature, 20).c_str());
    uint32_t file_size;
    Read(p_, end_, file_size);
    printf("file_size: 0x%x\n", file_size);
    uint32_t header_size;
    Read(p_, end_, header_size);
    printf("header_size: 0x%x\n", header_size);
    uint32_t endian_tag;
    Read(p_, end_, endian_tag);
    printf("endian_tag: 0x%x\n", endian_tag);
    uint32_t link_size;
    uint32_t link_off;
    Read(p_, end_, link_size);
    Read(p_, end_, link_off);
    printf("link_size: 0x%x, link_off: 0x%x\n", link_size, link_off);
    uint32_t map_off;
    Read(p_, end_, map_off);
    printf("map_off: 0x%x\n", map_off);
    Read(p_, end_, string_ids_size_);
    Read(p_, end_, string_ids_off_);
    string_ids_ = (const string_id_item*)(data_ + string_ids_off_);
    printf("string_ids: [0x%x-0x%x] string_ids_size %u\n", string_ids_off_,
        (uint32_t)(string_ids_off_ + string_ids_size_ * sizeof(string_id_item)), string_ids_size_);

    Read(p_, end_, type_ids_size_);
    Read(p_, end_, type_ids_off_);
    type_ids_ = (const type_id_item*)(data_ + type_ids_off_);
    printf("type_ids: [0x%x-0x%x] type_ids_size %u\n", type_ids_off_,
        (uint32_t)(type_ids_off_ + type_ids_size_ * sizeof(type_id_item)), type_ids_size_);

    Read(p_, end_, proto_ids_size_);
    Read(p_, end_, proto_ids_off_);
    proto_ids_ = (const proto_id_item*)(data_ + proto_ids_off_);
    printf("proto_ids: [0x%x-0x%x] proto_ids_size %u\n", proto_ids_off_,
        (uint32_t)(proto_ids_off_ + proto_ids_size_ * sizeof(proto_id_item)), proto_ids_size_);

    Read(p_, end_, field_ids_size_);
    Read(p_, end_, field_ids_off_);
    field_ids_ = (const field_id_item*)(data_ + field_ids_off_);
    printf("field_ids: [0x%x-0x%x] field_ids_size %u\n", field_ids_off_,
        (uint32_t)(field_ids_off_ + field_ids_size_ * sizeof(field_id_item)), field_ids_size_);

    Read(p_, end_, method_ids_size_);
    Read(p_, end_, method_ids_off_);
    method_ids_ = (const method_id_item*)(data_ + method_ids_off_);
    printf("method_ids: [0x%x-0x%x] method_ids_size %u\n", method_ids_off_,
        (uint32_t)(method_ids_off_ + method_ids_size_ * sizeof(method_id_item)), method_ids_size_);

    Read(p_, end_, class_defs_size_);
    Read(p_, end_, class_defs_off_);
    class_defs_ = (const class_def_item*)(data_ + class_defs_off_);
    printf("class_defs: [0x%x-0x%x] class_defs_size %u\n", class_defs_off_,
        (uint32_t)(class_defs_off_ + class_defs_size_ * sizeof(class_def_item)), class_defs_size_);

    Read(p_, end_, data_sec_size_);
    Read(p_, end_, data_sec_off_);
    printf("data: [0x%x-0x%x]\n", data_sec_off_, data_sec_off_ + data_sec_size_);
    return true;
  }

  bool PrintStringIds() {
    for (uint32_t i = 0; i < string_ids_size_; ++i) {
      const string_id_item& id = string_ids_[i];
      PrintIndented(1, "string #%u: [0x%x]: ", i, id.string_data_off);
      const char* data_p = data_ + id.string_data_off;
      uint32_t utf16_size = ReadULEB128(data_p, end_);
      printf("utf16_size %u, string %s\n", utf16_size, data_p);
    }
    return true;
  }

  bool PrintTypeIds() {
    for (uint32_t i = 0; i < type_ids_size_; ++i) {
      PrintIndented(1, "type #%d: %s\n", i, GetType(i));
    }
    return true;
  }

  bool PrintProtoIds() {
    for (uint32_t i = 0; i < proto_ids_size_; ++i) {
      const proto_id_item& id = proto_ids_[i];
      PrintIndented(1, "proto #%d: short_desc: %s, desc %s\n", i,
          GetString(id.shorty_idx), GetProto(i).c_str());
    }
    return true;
  }

  bool PrintFieldIds() {
    for (uint32_t i = 0; i < field_ids_size_; ++i) {
      PrintIndented(1, "field #%d: %s\n", i, GetField(i).c_str());
    }
    return true;
  }

  bool PrintMethodIds() {
    for (uint32_t i = 0; i < method_ids_size_; ++i) {
      PrintIndented(1, "method #%d: %s\n", i, GetMethod(i).c_str());
    }
    return true;
  }

  bool PrintClassDefs() {
    for (uint32_t i = 0; i < class_defs_size_; ++i) {
      const class_def_item& cls = class_defs_[i];
      PrintIndented(1, "class #%d:\n", i);
      PrintIndented(2, "name: %s\n", GetType(cls.class_idx));
      PrintIndented(2, "access_flags: %s\n",
          FindMaskVector(CLASS_ACCESS_FLAGS_NAMEVECTOR, cls.access_flags).c_str());
      PrintIndented(2, "superclass: %s\n",
          cls.superclass_idx == NO_INDEX ? "None" : GetType(cls.superclass_idx));
      PrintIndented(2, "interfaces: %s\n",
          cls.interfaces_off == 0 ? "None" : GetTypeList(cls.interfaces_off).c_str());
      PrintIndented(2, "source_file: %s\n",
          cls.source_file_idx == NO_INDEX ? "None" : GetString(cls.source_file_idx));
      PrintIndented(2, "annotations_off: 0x%x\n", cls.annotations_off);
      if (cls.annotations_off != 0) {
        PrintAnnotationsDirectoryItem(3, cls.annotations_off);
      }
      PrintIndented(2, "class_data_off: 0x%x\n", cls.class_data_off);
      if (cls.class_data_off != 0) {
        PrintClassDataItem(3, cls.class_data_off);
      }
      PrintIndented(2, "static_values_off: 0x%x\n", cls.static_values_off);
      if (cls.static_values_off != 0) {
        const char* p = data_ + cls.static_values_off;
        PrintEncodedArray(3, p);
      }
    }
    return true;
  }

 private:
  const char* GetString(uint32_t string_id) {
    CHECK(string_id < string_ids_size_);
    uint32_t string_off = string_ids_[string_id].string_data_off;
    const char* p = data_ + string_off;
    uint32_t utf16_size = ReadULEB128(p, end_);
    return p;
  }

  const char* GetType(uint32_t type_id) {
    CHECK(type_id < type_ids_size_);
    return GetString(type_ids_[type_id].descriptor_idx);
  }

  std::string GetProto(uint32_t proto_id) {
    CHECK(proto_id < proto_ids_size_);
    const proto_id_item& id = proto_ids_[proto_id];
    std::string result = GetType(id.return_type_idx);
    result += " (";
    if (id.parameters_off != 0) {
      result += GetTypeList(id.parameters_off);
    }
    result.push_back(')');
    return result;
  }

  std::string GetTypeList(uint32_t data_off) {
    std::string result;
    const char* p = data_ + data_off;
    uint32_t size;
    Read(p, end_, size);
    for (uint32_t i = 0; i < size; ++i) {
      uint16_t type_idx;
      Read(p, end_, type_idx);
      if (i > 0) {
        result += ", ";
      }
      result += GetType(type_idx);
    }
    return result;
  }

  std::string GetField(uint32_t field_id) {
    CHECK(field_id < field_ids_size_);
    const field_id_item& field = field_ids_[field_id];
    return StringPrintf("(class %s, type %s, name %s)",
        GetType(field.class_idx), GetType(field.type_idx), GetString(field.name_idx));
  }

  std::string GetMethod(uint32_t method_id) {
    CHECK(method_id < method_ids_size_);
    const method_id_item& method = method_ids_[method_id];
    return StringPrintf("(class %s, proto %s, name %s)",
        GetType(method.class_idx),
        GetProto(method.proto_idx).c_str(),
        GetString(method.name_idx));
  }

  bool PrintAnnotationsDirectoryItem(int indent, uint32_t directory_off) {
    const char* p = data_ + directory_off;
    uint32_t class_annotations_off;
    Read(p, end_, class_annotations_off);
    PrintIndented(indent, "class_annotations: off 0x%x\n", class_annotations_off);
    if (class_annotations_off != 0) {
      PrintAnnotationSetItem(indent + 1, class_annotations_off);
    }
    uint32_t fields_size;
    uint32_t annotated_methods_size;
    uint32_t annotated_parameters_size;
    Read(p, end_, fields_size);
    Read(p, end_, annotated_methods_size);
    Read(p, end_, annotated_parameters_size);
    PrintIndented(indent, "annotated_fields_size: %u\n", fields_size);
    for (uint32_t i = 0; i < fields_size; ++i) {
      uint32_t field_idx;
      Read(p, end_, field_idx);
      PrintIndented(indent + 1, "field #%u: %s\n", i, GetField(field_idx).c_str());
      uint32_t annotations_off;
      Read(p, end_, annotations_off);
      PrintAnnotationSetItem(indent + 2, annotations_off);
    }
    PrintIndented(indent, "annotated_methods_size: %u\n", annotated_methods_size);
    for (uint32_t i = 0; i < annotated_methods_size; ++i) {
      uint32_t method_idx;
      Read(p, end_, method_idx);
      PrintIndented(indent + 1, "method #%u: %s\n", i, GetMethod(method_idx).c_str());
      uint32_t annotations_off;
      Read(p, end_, annotations_off);
      PrintAnnotationSetItem(indent + 2, annotations_off);
    }
    PrintIndented(indent, "annoated_paramters_size: %u\n", annotated_parameters_size);
    for (uint32_t i = 0; i < annotated_parameters_size; ++i) {
      uint32_t method_idx;
      Read(p, end_, method_idx);
      PrintIndented(indent + 1, "method #%u: %s\n", i, GetMethod(method_idx).c_str());
      uint32_t annotations_off;
      Read(p, end_, annotations_off);
      PrintAnnotationSetRefList(indent + 2, annotations_off);
    }
    return true;
  }

  void PrintAnnotationSetRefList(int indent, uint32_t off) {
    const char* p = data_ + off;
    uint32_t size;
    Read(p, end_, size);
    for (uint32_t i = 0; i < size; ++i) {
      uint32_t annotations_off;
      Read(p, end_, annotations_off);
      PrintIndented(indent, "annotation_ref #%u: off 0x%x\n", i, annotations_off);
      PrintAnnotationSetItem(indent + 1, annotations_off);
    }
  }

  bool PrintAnnotationSetItem(int indent, uint32_t off) {
    const char* p = data_ + off;
    uint32_t size;
    Read(p, end_, size);
    for (uint32_t i = 0; i < size; ++i) {
      uint32_t annotation_off;
      Read(p, end_, annotation_off);
      PrintIndented(indent, "annotate #%u\n", i);
      PrintAnnotationItem(indent, annotation_off);
    }
    return true;
  }

  void PrintAnnotationItem(int indent, uint32_t off) {
    const char* p = data_ + off;
    uint8_t visibility;
    Read(p, end_, visibility);
    PrintIndented(indent, "annotation: %s\n", FindMap(ANNOTATION_VISIBILITY_NAMEMAP, visibility));
    PrintEncodedAnnotation(indent + 1, p);
  }

  void PrintEncodedAnnotation(int indent, const char*& p) {
    uint32_t type_idx = ReadULEB128(p, end_);
    PrintIndented(indent, "annotation type %s\n", GetType(type_idx));
    uint32_t size = ReadULEB128(p, end_);
    PrintIndented(indent, "annotation size %u\n", size);
    for (uint32_t i = 0; i < size; ++i) {
      uint32_t name_idx = ReadULEB128(p, end_);
      PrintIndented(indent + 1, "name %s\n", GetString(name_idx));
      PrintEncodedValue(indent + 1, p);
    }
  }

  void PrintEncodedArray(int indent, const char*& p) {
    uint32_t size = ReadULEB128(p, end_);
    for (uint32_t i = 0; i < size; ++i) {
      PrintEncodedValue(indent, p);
    }
  }

  void PrintEncodedValue(int indent, const char*& p) {
    uint8_t value_arg = (*p & 0xff) >> 5;
    uint8_t value_type = *p & 0x1f;
    p++;
    switch (value_type) {
      case ENCODED_VALUE_BYTE:
      {
        PrintIndented(indent, "(byte) %d\n", *p++);
        break;
      }
      case ENCODED_VALUE_SHORT:
      {
        CHECK(value_arg <= 1);
        int16_t value;
        ReadEncodedValue(p, value_arg, value, true);
        PrintIndented(indent, "(short) %d\n", value);
        break;
      }
      case ENCODED_VALUE_CHAR:
      {
        CHECK(value_arg <= 1);
        uint16_t value;
        ReadEncodedValue(p, value_arg, value, false);
        PrintIndented(indent, "(char) %d\n", value);
        break;
      }
      case ENCODED_VALUE_INT:
      {
        CHECK(value_arg <= 3);
        int32_t value;
        ReadEncodedValue(p, value_arg, value, true);
        PrintIndented(indent, "(int) %d\n", value);
        break;
      }
      case ENCODED_VALUE_LONG:
      {
        CHECK(value_arg <= 7);
        int64_t value;
        ReadEncodedValue(p, value_arg, value, true);
        PrintIndented(indent, "(long) %" PRId64 "\n", value);
        break;
      }
      case ENCODED_VALUE_FLOAT:
      {
        CHECK(value_arg <= 3);
        float value;
        ReadEncodedFloatValue(p, value_arg, value);
        PrintIndented(indent, "(float) %f\n", value);
        break;
      }
      case ENCODED_VALUE_DOUBLE:
      {
        CHECK(value_arg <= 7);
        double value;
        ReadEncodedFloatValue(p, value_arg, value);
        PrintIndented(indent, "(double) %f\n", value);
        break;
      }
      case ENCODED_VALUE_STRING:
      {
        CHECK(value_arg <= 3);
        uint32_t value;
        ReadEncodedValue(p, value_arg, value, false);
        PrintIndented(indent, "(string) %s\n", GetString(value));
        break;
      }
      case ENCODED_VALUE_TYPE:
      {
        CHECK(value_arg <= 3);
        uint32_t value;
        ReadEncodedValue(p, value_arg, value, false);
        PrintIndented(indent, "(type) %s\n", GetType(value));
        break;
      }
      case ENCODED_VALUE_FIELD:
      {
        CHECK(value_arg <= 3);
        uint32_t value;
        ReadEncodedValue(p, value_arg, value, false);
        PrintIndented(indent, "(field) %s\n", GetField(value).c_str());
        break;
      }
      case ENCODED_VALUE_METHOD:
      {
        CHECK(value_arg <= 3);
        uint32_t value;
        ReadEncodedValue(p, value_arg, value, false);
        PrintIndented(indent, "(method) %s\n", GetMethod(value).c_str());
        break;
      }
      case ENCODED_VALUE_ENUM:
      {
        CHECK(value_arg <= 3);
        uint32_t value;
        ReadEncodedValue(p, value_arg, value, false);
        PrintIndented(indent, "(enum) %s\n", GetField(value).c_str());
        break;
      }
      case ENCODED_VALUE_ARRAY:
      {
        CHECK(value_arg == 0);
        PrintIndented(indent, "(array):\n");
        PrintEncodedArray(indent + 1, p);
        break;
      }
      case ENCODED_VALUE_ANNOTATION:
      {
        CHECK(value_arg == 0);
        PrintIndented(indent, "(annotation):\n");
        PrintEncodedAnnotation(indent + 1, p);
        break;
      }
      case ENCODED_VALUE_NULL:
      {
        CHECK(value_arg == 0);
        PrintIndented(indent, "(null)\n");
        break;
      }
      case ENCODED_VALUE_BOOLEAN:
      {
        CHECK(value_arg <= 1);
        PrintIndented(indent, "(%s)\n", value_arg == 0 ? "false" : "true");
        break;
      }
      default:
      {
        Abort("unknown encoded value type %u\n", value_type);
      }
    }
  }

  void PrintClassDataItem(int indent, uint32_t off) {
    const char* p = data_ + off;
    uint32_t static_fields_size = ReadULEB128(p, end_);
    uint32_t instance_fields_size = ReadULEB128(p, end_);
    uint32_t direct_methods_size = ReadULEB128(p, end_);
    uint32_t virtual_methods_size = ReadULEB128(p, end_);
    PrintIndented(indent, "static_fields: size %u\n", static_fields_size);
    PrintEncodedFields(indent + 1, p, static_fields_size);
    PrintIndented(indent, "instanc_fields: size %u\n", instance_fields_size);
    PrintEncodedFields(indent + 1, p, instance_fields_size);
    PrintIndented(indent, "direct_methods: size %u\n", direct_methods_size);
    PrintEncodedMethods(indent + 1, p, direct_methods_size);
    PrintIndented(indent, "virtual_methods: size %u\n", virtual_methods_size);
    PrintEncodedMethods(indent + 1, p, virtual_methods_size);
  }

  void PrintEncodedFields(int indent, const char*& p, uint32_t field_size) {
    uint32_t field_idx = 0;
    for (uint32_t i = 0; i < field_size; ++i) {
      uint32_t field_idx_diff = ReadULEB128(p, end_);
      field_idx += field_idx_diff;
      uint32_t access_flags = ReadULEB128(p, end_);
      PrintIndented(indent, "field %s, access_flags %s\n", GetField(field_idx).c_str(),
          FindMaskVector(FIELD_ACCESS_FLAGS_NAMEVECTOR, access_flags).c_str());
    }
  }

  void PrintEncodedMethods(int indent, const char*& p, uint32_t method_size) {
    uint32_t method_idx = 0;
    for (uint32_t i = 0; i < method_size; ++i) {
      uint32_t method_idx_diff = ReadULEB128(p, end_);
      method_idx += method_idx_diff;
      uint32_t access_flags = ReadULEB128(p, end_);
      uint32_t code_off = ReadULEB128(p, end_);
      PrintIndented(indent, "method %s, access_flags %s, code_off 0x%x\n",
          GetMethod(method_idx).c_str(),
          FindMaskVector(METHOD_ACCESS_FLAGS_NAMEVECTOR, access_flags).c_str(),
          code_off);
      if (code_off != 0) {
        PrintCodeItem(indent + 1, code_off);
      }
    }
  }

  void PrintCodeItem(int indent, uint32_t off) {
    const char* p = data_ + off;
    uint16_t registers_size;
    uint16_t ins_size;
    uint16_t outs_size;
    uint16_t tries_size;
    Read(p, end_, registers_size);
    Read(p, end_, ins_size);
    Read(p, end_, outs_size);
    Read(p, end_, tries_size);
    PrintIndented(indent, "registers_size %u, ins_size %u, outs_size %u, tries_size %u\n",
                  registers_size, ins_size, outs_size, tries_size);
    uint32_t debug_info_off;
    Read(p, end_, debug_info_off);
    PrintIndented(indent, "debug_info_off 0x%x\n", debug_info_off);
    uint32_t insns_size;
    Read(p, end_, insns_size);
    PrintIndented(indent, "insns_size %u\n", insns_size);
    PrintInstructions(indent + 1, p, p + insns_size * 2);
    p += insns_size * 2;
    if (tries_size != 0u && (insns_size & 1)) {
      p += 2;
    }
    if (tries_size > 0u) {
      PrintIndented(indent, "try_items size %u\n", tries_size);
      for (uint32_t i = 0; i < tries_size; ++i) {
        uint32_t start_addr;
        uint16_t insn_count;
        uint16_t handler_off;
        Read(p, end_, start_addr);
        Read(p, end_, insn_count);
        Read(p, end_, handler_off);
        PrintIndented(indent + 1, "try[%u] range [0x%x-0x%x], handler_off 0x%x\n",
                      i, start_addr * 2, (start_addr + insn_count) * 2, handler_off);
      }
      uint32_t handlers_size = ReadULEB128(p, end_);
      PrintIndented(indent, "catch handler size %u\n", handlers_size);
      for (uint32_t i = 0; i < handlers_size; ++i) {
        int32_t size = ReadLEB128(p, end_);
        bool has_catch_all = (size <= 0);
        size = abs(size);
        PrintIndented(indent + 1, "handler[%u] catch_type_size %u %s\n", i, size,
                      has_catch_all ? "has catch all" : "");
        for (int j = 0; j < size; ++j) {
          uint32_t type_idx = ReadULEB128(p, end_);
          uint32_t addr = ReadULEB128(p, end_);
          PrintIndented(indent + 2, "type %s, addr 0x%x\n", GetType(type_idx), addr);
        }
        if (has_catch_all) {
          uint32_t addr = ReadULEB128(p, end_);
          PrintIndented(indent + 2, "catch_all_addr: 0x%x\n", addr);
        }
      }
    }
    if (debug_info_off != 0u) {
      PrintIndented(indent, "debug_info: offset 0x%x\n", debug_info_off);
      PrintDebugInfoItem(indent + 1, debug_info_off);
    }
  }

  void PrintInstructions(int indent, const char* start, const char* end) {
    const char* p = start;
    while (p < end) {
      uint32_t offset = p - start;
      PrintIndented(indent, "<0x%x> ", offset);
      uint8_t op = *p++;
      if (op == 0x00) {
        if (*p == 0x01) {
          // packed-switch-payload format
          p++;
          uint16_t size;
          Read(p, end, size);
          printf("packed_switch_payload, size = %u\n", size);
          uint32_t first_key;
          Read(p, end, first_key);
          uint32_t key = first_key;
          uint32_t target;
          for (uint16_t i = 0; i < size; ++i) {
            Read(p, end, target);
            PrintIndented(indent + 1, "key %u, target %u\n", key, target);
            key++;
          }
          continue;
        } else if (*p == 0x02) {
          // sparse-switch-payload format
          p++;
          uint16_t size;
          Read(p, end, size);
          printf("sparse_switch_payload, size = %u\n", size);
          uint32_t keys[size];
          uint32_t targets[size];
          for (uint16_t i = 0; i < size; ++i) {
            Read(p, end, keys[i]);
          }
          for (uint16_t i = 0; i < size; ++i) {
            Read(p, end, targets[i]);
          }
          for (uint16_t i = 0; i < size; ++i) {
            PrintIndented(indent + 1, "key %u, target %u\n", keys[i], targets[i]);
          }
          continue;
        } else if (*p == 0x03) {
          // fill-array-data-payload format
          p++;
          uint16_t element_width;
          uint32_t size;
          Read(p, end, element_width);
          Read(p, end, size);
          printf("fill-array-data-payload, element_width = %u, size = %u\n", element_width, size);
          p += element_width * size;
          continue;
        }
      }
      std::string opstr = FindMap(DEX_OP_NAMEMAP, op);
      std::transform(opstr.begin(), opstr.end(), opstr.begin(), tolower);
      printf("%s ", opstr.c_str());
      uint16_t vA;
      uint16_t vB;
      uint16_t B;
      uint32_t BB;
      uint16_t vC;
      uint16_t C;
      if (op == 0x00) {
        p++;
      } else if (op == 0x01 || op == 0x04 || op == 0x07) {
        GetAB_4(p, vA, vB);
        printf("v%u, v%u", vA, vB);
      } else if (op == 0x02 || op == 0x05 || op == 0x08) {
        GetAB_8_16(p, vA, vB);
        printf("v%u, v%u", vA, vB);
      } else if (op == 0x03 || op == 0x06 || op == 0x09) {
        p++;
        GetAB_16_16(p, vA, vB);
        printf("v%u, v%u", vA, vB);
      } else if (op == 0x0a || op == 0x0b || op == 0x0c || op == 0x0d) {
        uint8_t vA = *p++;
        printf("v%u", vA);
      } else if (op == 0x0e) {
        p++;
      } else if (op == 0x0f || op == 0x10 || op == 0x11) {
        uint8_t vA = *p++;
        printf("v%u", vA);
      } else if (op == 0x12) {
        GetAB_4(p, vA, B);
        int8_t sB = B;
        if (sB & 0x08) {
          sB |= 0xf0;
        }
        printf("v%u, #%d", vA, sB);
      } else if (op == 0x13) {
        uint8_t vA = *p++;
        int16_t B;
        Read(p, end, B);
        printf("v%u, #%d", vA, B);
      } else if (op == 0x14) {
        GetAB_8_32(p, vA, BB);
        printf("v%u, #%d", vA, BB);
      } else if (op == 0x15) {
        GetAB_8_16(p, vA, B);
        BB = ((int16_t)B) << 16;
        printf("v%u, #%d", vA, BB);
      } else if (op == 0x16) {
        GetAB_8_16(p, vA, B);
        printf("v%u, #%d", vA, (int16_t)B);
      } else if (op == 0x17) {
        GetAB_8_32(p, vA, BB);
        printf("v%u, #%d", vA, BB);
      } else if (op == 0x18) {
        uint8_t vA = *p++;
        int64_t B;
        Read(p, end, B);
        printf("v%u, #%" PRId64, vA, B);
      } else if (op == 0x19) {
        uint8_t vA = *p++;
        int16_t tB;
        Read(p, end, tB);
        int64_t B = ((int64_t)tB) << 48;
        printf("v%u, #%" PRId64, vA, B);
      } else if (op == 0x1a) {
        GetAB_8_16(p, vA, B);
        printf("v%u, string@%u", vA, B);
      } else if (op == 0x1b) {
        GetAB_8_32(p, vA, BB);
        printf("v%u, string@%u", vA, BB);
      } else if (op == 0x1c) {
        GetAB_8_16(p, vA, B);
        printf("v%u, type@%u", vA, B);
      } else if (op == 0x1d) {
        uint8_t vA = *p++;
        printf("v%u", vA);
      } else if (op == 0x1e) {
        uint8_t vA = *p++;
        printf("v%u", vA);
      } else if (op == 0x1f) {
        GetAB_8_16(p, vA, B);
        printf("v%u, type@%u", vA, B);
      } else if (op == 0x20) {
        GetAB_4(p, vA, vB);
        Read(p, end, C);
        printf("v%u, v%u, type@%u", vA, vB, C);
      } else if (op == 0x21) {
        GetAB_4(p, vA, vB);
        printf("v%u, v%u", vA, vB);
      } else if (op == 0x22) {
        GetAB_8_16(p, vA, B);
        printf("v%u, type@%u", vA, B);
      } else if (op == 0x23) {
        GetAB_4(p, vA, vB);
        Read(p, end, C);
        printf("v%u, v%u, type@%u  #%s", vA, vB, C, GetType(C));
      } else if (op == 0x24) {
        uint16_t vG;
        GetAB_4(p, vA, vG);
        Read(p, end, B);
        uint8_t regs[5];
        GetCDEF(p, regs);
        regs[4] = vG;
        printf("{");
        for (int i = 0; i < vA; ++i) {
          printf("v%u, ", regs[i]);
        }
        printf("} type@%u  #%s", B, GetType(B));
      } else if (op == 0x25) {
        GetAB_8_16(p, vA, B);
        Read(p, end, C);
        printf("{v%u .. v%u}, type@%u  #%s", C, C + vA - 1, B, GetType(B));
      } else if (op == 0x26) {
        GetAB_8_32(p, vA, BB);
        printf("v%u, %u  # payload 0x%x", vA, BB, offset + BB * 2);
      } else if (op == 0x27) {
        vA = *p++;
        printf("v%u", vA);
      } else if (op == 0x28) {
        int8_t t = *p++;
        printf("%d", t);
      } else if (op == 0x29) {
        p++;
        int16_t t;
        Read(p, end, t);
        printf("%d", t);
      } else if (op == 0x2a) {
        p++;
        int32_t t;
        Read(p, end, t);
        printf("%d", t);
      } else if (op == 0x2b) {
        GetAB_8_32(p, vA, BB);
        printf("v%u, %d", vA, BB);
      } else if (op == 0x2c) {
        GetAB_8_32(p, vA, BB);
        printf("v%u, %d", vA, BB);
      } else if (op >= 0x2d && op <= 0x31) {
        GetABC_8(p, vA, vB, vC);
        printf("v%u, v%u, v%u", vA, vB, vC);
      } else if (op >= 0x32 && op <= 0x37) {
        GetAB_4(p, vA, vB);
        Read(p, end, C);
        printf("v%u, v%u, %d", vA, vB, (int16_t)C);
      } else if (op >= 0x38 && op <= 0x3d) {
        GetAB_8_16(p, vA, B);
        printf("v%u, %d", vA, (int16_t)B);
      } else if (op >= 0x44 && op <= 0x51) {
        GetABC_8(p, vA, vB, vC);
        printf("v%u, v%u, v%u", vA, vB, vC);
      } else if (op >= 0x52 && op <= 0x5f) {
        GetAB_8_16(p, vA, B);
        printf("v%u, field@%u   #%s", vA, B, GetField(B).c_str());
      } else if (op >= 0x60 && op <= 0x6d) {
        GetAB_8_16(p, vA, B);
        printf("v%u, field@%u   #%s", vA, B, GetField(B).c_str());
      } else if (op >= 0x6e && op <= 0x72) {
        uint16_t vG;
        GetAB_4(p, vA, vG);
        Read(p, end, B);
        uint8_t regs[5];
        GetCDEF(p, regs);
        regs[4] = vG;
        printf("{");
        for (int i = 0; i < vA; ++i) {
          printf("v%u, ", regs[i]);
        }
        printf("} meth@%u   #%s", B, GetMethod(B).c_str());
      } else if (op >= 0x74 && op <= 0x78) {
        GetAB_8_16(p, vA, B);
        Read(p, end, C);
        printf("{v%u .. v%u}, meth@%u   #%s", C, C + vA - 1, B, GetMethod(B).c_str());
      } else if (op >= 0x7b && op <= 0x8f) {
        GetAB_4(p, vA, vB);
        printf("v%u, v%u", vA, vB);
      } else if (op >= 0x90 && op <= 0xaf) {
        GetABC_8(p, vA, vB, vC);
        printf("v%u, v%u, v%u", vA, vB, vC);
      } else if (op >= 0xb0 && op <= 0xcf) {
        GetAB_4(p, vA, vB);
        printf("v%u, v%u", vA, vB);
      } else if (op >= 0xd0 && op <= 0xd7) {
        GetAB_4(p, vA, vB);
        Read(p, end, C);
        printf("v%u, v%u, %d", vA, vB, (int16_t)C);
      } else if (op >= 0xd8 && op <= 0xe2) {
        GetABC_8(p, vA, vB, C);
        printf("v%u, v%u, %d", vA, vB, (int8_t)C);
      } else {
        Abort("unknown dex op 0x%x\n", op);
      }
      printf("\n");
    }
    CHECK(p == end);
  }

  void GetAB_4(const char*& p, uint16_t& vA, uint16_t& vB) {
    vA = *p & 0x0f;
    vB = (*p >> 4) & 0x0f;
    p++;
  }

  void GetAB_8_16(const char*& p, uint16_t& vA, uint16_t& vB) {
    vA = (uint8_t)*p++;
    Read(p, end_, vB);
  }

  void GetAB_8_32(const char*& p, uint16_t& vA, uint32_t& vB) {
    vA = (uint8_t)*p++;
    Read(p, end_, vB);
  }

  void GetAB_16_16(const char*& p, uint16_t& vA, uint16_t& vB) {
    Read(p, end_, vA);
    Read(p, end_, vB);
  }

  void GetABC_8(const char*& p, uint16_t& vA, uint16_t& vB, uint16_t& vC) {
    vA = (uint8_t)*p++;
    vB = (uint8_t)*p++;
    vC = (uint8_t)*p++;
  }

  void GetCDEF(const char*& p, uint8_t* regs) {
    regs[0] = *p & 0x0f;
    regs[1] = (*p >> 4) & 0x0f;
    p++;
    regs[2] = *p & 0x0f;
    regs[3] = (*p >> 4) & 0x0f;
    p++;
  }

  void PrintDebugInfoItem(int indent, uint32_t off) {
    const char* p = data_ + off;
    uint32_t line_start = ReadULEB128(p, end_);
    uint32_t parameters_size = ReadULEB128(p, end_);
    PrintIndented(indent, "line_start: %u\n", line_start);
    PrintIndented(indent, "parametrs_size: %u\n", parameters_size);
    for (uint32_t i = 0; i < parameters_size; ++i) {
      uint32_t name_idx = ReadULEB128P1(p, end_);
      PrintIndented(indent + 1, "parameters[%u] = %s\n", i,
                    (name_idx == NO_INDEX) ? "" : GetString(name_idx));
    }
    PrintIndented(indent, "debug code:\n");
    while (true) {
      uint8_t op = *p++;
      if (op == DBG_END_SEQUENCE) {
        PrintIndented(indent + 1, "end_sequence\n");
        break;
      } else if (op == DBG_ADVANCE_PC) {
        uint32_t addr_diff = ReadULEB128(p, end_);
        PrintIndented(indent + 1, "advance_pc 0x%x\n", addr_diff);
      } else if (op == DBG_ADVANCE_LINE) {
        int32_t line_diff = ReadLEB128(p, end_);
        PrintIndented(indent + 1, "advance_line %d\n", line_diff);
      } else if (op == DBG_START_LOCAL) {
        uint32_t register_num = ReadULEB128(p, end_);
        int32_t name_idx = ReadULEB128P1(p, end_);
        int32_t type_idx = ReadULEB128P1(p, end_);
        PrintIndented(indent + 1, "start_local r%u, name %s, type %s\n",
               register_num, (name_idx == NO_INDEX) ? "" : GetString(name_idx),
               (type_idx == NO_INDEX) ? "" : GetType(type_idx));
      } else if (op == DBG_START_LOCAL_EXTENDED) {
        uint32_t register_num = ReadULEB128(p, end_);
        int32_t name_idx = ReadULEB128P1(p, end_);
        int32_t type_idx = ReadULEB128P1(p, end_);
        int32_t sig_idx = ReadULEB128P1(p, end_);
        PrintIndented(indent + 1, "start_local_extended r%u, name %s, type %s, sig %s\n",
               register_num, (name_idx == NO_INDEX ? "" : GetString(name_idx)),
               (type_idx == NO_INDEX ? "" : GetType(type_idx)),
               (sig_idx == NO_INDEX ? "" : GetString(sig_idx)));
      } else if (op == DBG_END_LOCAL) {
        uint32_t register_num = ReadULEB128(p, end_);
        PrintIndented(indent + 1, "end_local r%u\n", register_num);
      } else if (op == DBG_RESTART_LOCAL) {
        uint32_t register_num = ReadULEB128(p, end_);
        PrintIndented(indent + 1, "restart_local r%u\n", register_num);
      } else if (op == DBG_SET_PROLOGUE_END) {
        PrintIndented(indent + 1, "set_prologue_end\n");
      } else if (op == DBG_SET_EPILOGUE_BEGIN) {
        PrintIndented(indent + 1, "set_epilogue_begin\n");
      } else if (op == DBG_SET_FILE) {
        int32_t name_idx = ReadULEB128P1(p, end_);
        PrintIndented(indent + 1, "set_file %s\n", name_idx == NO_INDEX ? "" : GetString(name_idx));
      } else {
        uint8_t adjusted_opcode = op - 0x0a;
        int32_t line_diff = -4 + (adjusted_opcode % 15);
        uint32_t addr_diff = (adjusted_opcode / 15);
        PrintIndented(indent + 1, "advance pc %u, line %d\n", addr_diff, line_diff);
      }
    }
  }

  const char* filename_;
  const char* data_;
  size_t size_;
  const char* end_;
  const char* p_;

  uint32_t string_ids_off_;
  uint32_t string_ids_size_;
  const string_id_item* string_ids_;

  uint32_t type_ids_off_;
  uint32_t type_ids_size_;
  const type_id_item* type_ids_;

  uint32_t proto_ids_off_;
  uint32_t proto_ids_size_;
  const proto_id_item* proto_ids_;

  uint32_t field_ids_off_;
  uint32_t field_ids_size_;
  const field_id_item* field_ids_;

  uint32_t method_ids_off_;
  uint32_t method_ids_size_;
  const method_id_item* method_ids_;

  uint32_t class_defs_off_;
  uint32_t class_defs_size_;
  const class_def_item* class_defs_;

  uint32_t data_sec_off_;
  uint32_t data_sec_size_;
};

bool ReadDex(const char* filename) {
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
  JavaDex dex(filename, buf.data(), buf.size());
  dex.ParseHead();
  dex.PrintStringIds();
  dex.PrintTypeIds();
  dex.PrintProtoIds();
  dex.PrintFieldIds();
  dex.PrintMethodIds();
  dex.PrintClassDefs();
  return true;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "read_dex <dex_file>\n");
    return 1;
  }
  const char* filename = argv[1];
  ReadDex(filename);
}

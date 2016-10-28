#include <stdio.h>
#include <string.h>

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

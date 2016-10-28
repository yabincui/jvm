#ifndef DEX_H_
#define DEX_H_

#include <inttypes.h>

struct string_id_item {
  uint32_t string_data_off;
};

// A data type
struct type_id_item {
  uint32_t descriptor_idx;
};

// A method type
struct proto_id_item {
  uint32_t shorty_idx;
  uint32_t return_type_idx;
  uint32_t parameters_off;
};

// A field
struct field_id_item {
  uint16_t class_idx;
  uint16_t type_idx;
  uint32_t name_idx;
};

// A method
struct method_id_item {
  uint16_t class_idx;
  uint16_t proto_idx;
  uint32_t name_idx;
};

// A class
struct class_def_item {
  uint32_t class_idx;
  uint32_t access_flags;
  uint32_t superclass_idx;
  uint32_t interfaces_off;
  uint32_t source_file_idx;
  uint32_t annotations_off;
  uint32_t class_data_off;
  uint32_t static_values_off;
};

static constexpr uint32_t NO_INDEX = 0xffffffff;

enum CLASS_ACCESS_FLAGS {
  CLASS_ACC_PUBLIC = 0x1,
  CLASS_ACC_PRIVATE = 0x2,
  CLASS_ACC_PROTECTED = 0x4,
  CLASS_ACC_STATIC = 0x8,
  CLASS_ACC_FINAL = 0x10,
  CLASS_ACC_INTERFACE = 0x200,
  CLASS_ACC_ABSTRACT = 0x400,
  CLASS_ACC_SYNTHETIC = 0x1000,
  CLASS_ACC_ANNOTATION = 0x2000,
  CLASS_ACC_ENUM = 0x4000,
};

enum FIELD_ACCESS_FLAGS {
  FIELD_ACC_PUBLIC = 0x1,
  FIELD_ACC_PRIVATE = 0x2,
  FIELD_ACC_PROTECTED = 0x4,
  FIELD_ACC_STATIC = 0x8,
  FIELD_ACC_FINAL = 0x10,
  FIELD_ACC_VOLATILE = 0x40,
  FIELD_ACC_TRANSIENT = 0x80,
  FIELD_ACC_SYNTHETIC = 0x1000,
  FIELD_ACC_ENUM = 0x4000,
};

enum METHOD_ACCESS_FLAGS {
  METHOD_ACC_PUBLIC = 0x1,
  METHOD_ACC_PRIVATE = 0x2,
  METHOD_ACC_PROTECTED = 0x4,
  METHOD_ACC_STATIC = 0x8,
  METHOD_ACC_FINAL = 0x10,
  METHOD_ACC_SYNCHRONIZED = 0x20,
  METHOD_ACC_BRIDGE = 0x40,
  METHOD_ACC_VARARGS = 0x80,
  METHOD_ACC_NATIVE = 0x100,
  METHOD_ACC_ABSTRACT = 0x400,
  METHOD_ACC_STRICT = 0x800,
  METHOD_ACC_SYNTHETIC = 0x1000,
  METHOD_ACC_CONSTRUCTOR = 0x10000,
  METHOD_ACC_DECLARED_SYNCHRONIZED = 0x20000,
};

enum ANNOTATION_VISIBILITY {
  VISIBILITY_BUILD = 0x0,
  VISIBILITY_RUNTIME = 0x1,
  VISIBILITY_SYSTEM = 0x2,
};

enum ENCODED_VALUE_FORMATS {
  ENCODED_VALUE_BYTE = 0x00,
  ENCODED_VALUE_SHORT = 0x02,
  ENCODED_VALUE_CHAR = 0x03,
  ENCODED_VALUE_INT = 0x04,
  ENCODED_VALUE_LONG = 0x06,
  ENCODED_VALUE_FLOAT = 0x10,
  ENCODED_VALUE_DOUBLE = 0x11,
  ENCODED_VALUE_STRING = 0x17,
  ENCODED_VALUE_TYPE = 0x18,
  ENCODED_VALUE_FIELD = 0x19,
  ENCODED_VALUE_METHOD = 0x1a,
  ENCODED_VALUE_ENUM = 0x1b,
  ENCODED_VALUE_ARRAY = 0x1c,
  ENCODED_VALUE_ANNOTATION = 0x1d,
  ENCODED_VALUE_NULL = 0x1e,
  ENCODED_VALUE_BOOLEAN = 0x1f,
};

#endif  // DEX_H_

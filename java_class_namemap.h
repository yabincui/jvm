#ifndef JAVA_CLASS_NAMEMAP_H_
#define JAVA_CLASS_NAMEMAP_H_

#include <unordered_map>

#include "java_class.h"

static const std::unordered_map<int, const char*> CONSTANT_POOL_TAGS_NAME_MAP = {
  {CONSTANT_Class, "CONSTANT_Class"},
  {CONSTANT_Fieldref, "CONSTANT_Fieldref"},
  {CONSTANT_Methodref, "CONSTANT_Methodref"},
  {CONSTANT_InterfaceMethodref, "CONSTANT_InterfaceMethodref"},
  {CONSTANT_String, "CONSTANT_String"},
  {CONSTANT_Integer, "CONSTANT_Integer"},
  {CONSTANT_Float, "CONSTANT_Float"},
  {CONSTANT_Long, "CONSTANT_Long"},
  {CONSTANT_Double, "CONSTANT_Double"},
  {CONSTANT_NameAndType, "CONSTANT_NameAndType"},
  {CONSTANT_Utf8, "CONSTANT_Utf8"},
  {CONSTANT_MethodHandle, "CONSTANT_MethodHandle"},
  {CONSTANT_MethodType, "CONSTANT_MethodType"},
  {CONSTANT_InvokeDynamic, "CONSTANT_InvokeDynamic"},
};

static const char* FindMap(const std::unordered_map<int, const char*>& map, int value) {
  auto it = map.find(value);
  if (it != map.end()) {
    return it->second;
  }
  return "";
}

#endif  // JAVA_CASS_NAMEMAP_H_

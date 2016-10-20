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

template <typename T>
void Read(const char*& p, const char* end, T& value) {
  if (p + sizeof(T) > end) {
    fprintf(stderr, "data not enough for Read()\n");
    exit(1);
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
    Read(p_, end_, constant_pool_count_);
    printf("constant_pool_count: %u\n", constant_pool_count_);
    return true;
  }

  bool ParseConstantPool() {
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

    default:
      fprintf(stderr, "unhandled tag %u\n", tag);
      return false;
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

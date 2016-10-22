#include <stdio.h>
#include <string.h>

#include <vector>

#include "utils.h"

template <typename T>
void Read(const char*& p, const char* end, T& value) {
  static_assert(std::is_standard_layout<T>::value, "...");
  if (p + sizeof(T) > end) {
    Abort("data not enough for Read()\n");
  }
  value = 0;
  int shift = 0;
  for (size_t i = 0; i < sizeof(T); ++i) {
    uint8_t a = *(const uint8_t*)p++;
    value |= (a << shift);
    shift += 8;
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
    uint32_t string_ids_size;
    uint32_t string_ids_off;
    Read(p_, end_, string_ids_size);
    Read(p_, end_, string_ids_off);
    printf("string_ids: [0x%x-0x%x]\n", string_ids_off, string_ids_off + string_ids_size * 4);
    uint32_t type_ids_size;
    uint32_t type_ids_off;
    Read(p_, end_, type_ids_size);
    Read(p_, end_, type_ids_off);
    printf("type_ids: [0x%x-0x%x]\n", type_ids_off, type_ids_off + type_ids_size);
    uint32_t proto_ids_size;
    uint32_t proto_ids_off;
    Read(p_, end_, proto_ids_size);
    Read(p_, end_, proto_ids_off);
    printf("proto_ids: [0x%x-0x%x]\n", proto_ids_off, proto_ids_off + proto_ids_size);
    uint32_t field_ids_size;
    uint32_t field_ids_off;
    Read(p_, end_, field_ids_size);
    Read(p_, end_, field_ids_off);
    printf("field_ids: [0x%x-0x%x]\n", field_ids_off, field_ids_off + field_ids_size);
    uint32_t method_ids_size;
    uint32_t method_ids_off;
    Read(p_, end_, method_ids_size);
    Read(p_, end_, method_ids_off);
    printf("method_ids: [0x%x-0x%x]\n", method_ids_off, method_ids_off + method_ids_size);
    uint32_t class_defs_size;
    uint32_t class_defs_off;
    Read(p_, end_, class_defs_size);
    Read(p_, end_, class_defs_off);
    printf("class_defs: [0x%x-0x%x]\n", class_defs_off, class_defs_off + class_defs_size);
    uint32_t data_size;
    uint32_t data_off;
    Read(p_, end_, data_size);
    Read(p_, end_, data_off);
    printf("data: [0x%x-0x%x]\n", data_off, data_off + data_size);
    return true;
  }

 private:
  const char* filename_;
  const char* data_;
  size_t size_;
  const char* end_;
  const char* p_;
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

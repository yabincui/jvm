#ifndef UTILS_H_
#define UTILS_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <unordered_map>
#include <vector>

#define CHECK(expr) \
  if (!(expr)) abort()

#define Abort(fmt,...) \
  do { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    abort(); \
  } while (0)

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

static std::string GetHexString(const char* p, size_t size) {
  std::string result(size * 2, '\0');
  for (size_t i = 0; i < size; ++i) {
    sprintf(&result[2*i], "%02x", (unsigned char)p[i]);
  }
  return result;
}

static uint64_t ReadULEB128(const char*& p, const char* end) {
  uint64_t result = 0;
  int shift = 0;
  while ((*p & 0x80) && p < end) {
    result |= (*p & 0x7f) << shift;
    shift += 7;
    p++;
  }
  if (p >= end) {
    Abort("data not enough to read\n");
  }
  result |= *p << shift;
  p++;
  return result;
}

static int64_t ReadLEB128(const char*& p, const char* end) {
  int64_t result = 0;
  int shift = 0;
  while ((*p & 0x80) && p < end) {
    result |= (*p & 0x7f) << shift;
    shift += 7;
    p++;
  }
  if (p >= end) {
    Abort("data not enough to read\n");
  }
  result |= *p << shift;
  if (*p & 0x40) {
    result |= (-1LL << (shift + 7));
  }
  p++;
  return result;
}

static int64_t ReadULEB128P1(const char*& p, const char* end) {
  uint64_t value = ReadULEB128(p, end);
  int64_t result = (int64_t)value;
  return result - 1;
}

static const char* FindMap(const std::unordered_map<int, const char*>& map, int value) {
  auto it = map.find(value);
  if (it != map.end()) {
    return it->second;
  }
  return "";
}

static std::string FindMaskVector(const std::vector<std::pair<int, const char*>>& v, int value) {
  std::string result;
  for (auto& p : v) {
    if (value & p.first) {
      if (!result.empty()) {
        result.push_back(' ');
      }
      result += p.second;
    }
  }
  return result;
}


#endif  // UTILS_H_

#ifndef UTILS_H_
#define UTILS_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>

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

#endif  // UTILS_H_

// Shared helpers for the trunk-recorder fuzz harnesses.
#pragma once
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <cstddef>
#include <cstdint>
#include <string>

// Silence boost::log once at startup (process-global, never changed per input).
static inline void fuzz_quiet_logs() {
  boost::log::core::get()->set_filter(boost::log::trivial::severity > boost::log::trivial::fatal);
}

struct FuzzReader {
  const uint8_t *p;
  size_t n;
  bool empty() const { return n == 0; }
  uint8_t u8() {
    if (!n) return 0;
    uint8_t v = *p++;
    n--;
    return v;
  }
  std::string bytes(size_t want) {
    if (want > n) want = n;
    std::string s(reinterpret_cast<const char *>(p), want);
    p += want;
    n -= want;
    return s;
  }
};

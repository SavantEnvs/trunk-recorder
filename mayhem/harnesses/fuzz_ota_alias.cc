// Over-the-air radio alias decoding (Motorola / Harris, P25 phase 1 and 2):
// p25_parser hands the alias fragments it collects from MBT/LCW messages to
// these UnitTagsOTA decoders. Byte 0 picks the decoder and message count; the
// rest is split into up to 10 fragments {len, bytes}.
#include "fuzz_common.h"
#include "../../trunk-recorder/unit_tags_ota.h"
#include <array>
#include <vector>

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fuzz_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzReader r{data, size};
  uint8_t sel = r.u8();
  int messages = r.u8() % 11;
  std::array<std::vector<uint8_t>, 10> buf;
  for (int i = 0; i < 10 && !r.empty(); i++) {
    std::string s = r.bytes(r.u8() & 0x1f);
    buf[i].assign(s.begin(), s.end());
  }
  switch (sel & 3) {
    case 0: UnitTagsOTA::decode_motorola_alias(buf, messages); break;
    case 1: UnitTagsOTA::decode_motorola_alias_p2(buf, messages); break;
    case 2: UnitTagsOTA::decode_harris_alias(buf, 1234567, 101, "BEE00", "3A1"); break;
    default: UnitTagsOTA::decode_harris_alias_p2(buf, 1234567, 101, "BEE00", "3A1"); break;
  }
  return 0;
}

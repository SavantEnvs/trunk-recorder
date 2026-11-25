// DMR Tier III / Capacity+ parser: DmrParser::parse_message() receives the
// CACH SLC, CSBK, MBC and voice LC blocks the OP25 DMR framer decodes.
// Input = records {m_type, arg1 (rxid<<1|slot), len, payload}.
#include "fuzz_common.h"
#include "../../trunk-recorder/systems/dmr_parser.h"
#include "../../trunk-recorder/systems/system_impl.h"
#include <gnuradio/message.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fuzz_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzReader r{data, size};
  System_impl sys(0);
  sys.set_short_name("fuzz");
  DmrParser parser;
  int count = 0;
  while (!r.empty() && count++ < 64) {
    int16_t m_type = (int16_t)(r.u8() % 11) - 1;  // M_DMR_TIMEOUT(-1) .. M_DMR_SLOT_ESB(9)
    long arg1 = r.u8() & 3;
    std::string body = r.bytes(r.u8() & 0x3f);
    long type = (1L << 16) | (uint16_t)m_type;    // PROTOCOL_DMR
    gr::message::sptr msg = gr::message::make_from_string(body, type, arg1, 0);
    parser.parse_message(msg, &sys);
  }
  return 0;
}

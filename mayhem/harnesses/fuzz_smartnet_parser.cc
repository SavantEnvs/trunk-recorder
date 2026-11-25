// Motorola SmartNet/SmartZone OSW parser: SmartnetParser::parse_message() is fed
// every 5-byte outbound signalling word the OP25 rx_smartnet framer decodes.
// Input: byte 0 picks the bandplan; then records {kind, 5 OSW bytes}.
#include "fuzz_common.h"
#include "../../trunk-recorder/systems/smartnet_parser.h"
#include "../../trunk-recorder/systems/system_impl.h"
#include <gnuradio/message.h>

static const char *kBandplans[] = {"800_standard", "800_reband", "800_splinter", "900", "400_custom"};

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fuzz_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzReader r{data, size};
  System_impl sys(0);
  sys.set_short_name("fuzz");
  sys.set_system_type("smartnet");
  sys.set_bandplan(kBandplans[r.u8() % 5]);
  sys.set_bandplan_base(851.0125);
  sys.set_bandplan_high(869.9875);
  sys.set_bandplan_spacing(0.025);
  sys.set_bandplan_offset(380);
  SmartnetParser parser(&sys);
  double ts = 1000.0;
  int count = 0;
  while (!r.empty() && count++ < 256) {
    uint8_t kind = r.u8();
    int16_t m_type = 0;  // M_SMARTNET_OSW
    if ((kind & 0x1f) == 0x1f) m_type = -2;       // BAD_OSW
    else if ((kind & 0x1f) == 0x1e) m_type = -1;  // TIMEOUT
    std::string body = m_type == 0 ? r.bytes(5) : std::string();
    ts += 0.01 + (kind >> 5);
    long type = (2L << 16) | (uint16_t)m_type;
    gr::message::sptr msg = gr::message::make_from_string(body, type, 0, ts);
    parser.parse_message(msg, &sys);
  }
  return 0;
}

// P25 control-channel message parser: P25Parser::parse_message() is what
// p25_trunking hands every TSBK/MBT/TDULC message the OP25 frame assembler
// decodes off the air. Input = sequence of records {type, len, body}; the body
// is the message string (first two bytes = NAC), exactly as OP25 queues it.
#include "fuzz_common.h"
#include "../../trunk-recorder/systems/p25_parser.h"
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
  P25Parser parser;  // fresh per input: its channel tables come only from this input
  int count = 0;
  while (!r.empty() && count++ < 64) {
    uint8_t sel = r.u8();
    long type;
    switch (sel & 3) {
      case 0: type = 7; break;   // TSBK
      case 1: type = 12; break;  // MBT
      case 2: type = 15; break;  // TDULC
      default: type = (int8_t)r.u8(); break;
    }
    std::string body = r.bytes(r.u8());
    // OP25 queues an MBT (type 12) only after the PDU's CRCs pass, as the NAC
    // plus ((blks + 1) * 12) - 4 bytes with blks >= 1, i.e. at least 2 + 20
    // bytes (lib/op25_repeater/lib/p25p1_fdma.cc, process_duid call in the
    // PDU path). parse_message relies on that (s.substr(10) on the MBT body),
    // so a shorter MBT is not a message the real frame assembler can emit.
    if (type == 12 && body.size() < 2 + 20) return -1;
    gr::message::sptr msg = gr::message::make_from_string(body, type, 0, 0);
    parser.parse_message(msg, &sys);
  }
  return 0;
}

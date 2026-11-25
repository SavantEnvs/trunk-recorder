// OP25 symbol-stream decoders: the blocks trunk-recorder puts right after the
// FSK4/CQPSK demodulator, fed the received dibit stream. Byte 0 picks the
// decoder exactly as trunk-recorder builds it:
//   0: p25_frame_assembler, phase 1 FDMA (p25_trunking.cc / p25_recorder_decode.cc)
//   1: p25_frame_assembler, phase 2 TDMA (slot from bit 2 of byte 0)
//   2: frame_assembler ""        - rx_sync, DMR (dmr_recorder_impl.cc)
//   3: frame_assembler "smartnet" - rx_smartnet (smartnet_fsk2_demod.cc)
// The rest of the input is the symbol stream (one dibit per byte, low 2 bits).
// A fresh flowgraph is built per input, run to completion, and its message queue drained.
#include "fuzz_common.h"
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/msg_queue.h>
#include <gnuradio/top_block.h>
#include <op25_repeater/frame_assembler.h>
#include <op25_repeater/p25_frame_assembler.h>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fuzz_quiet_logs();
  // GNU Radio's buffer allocator records its chosen vmcircbuf factory under
  // the user config dir ($HOME/.config/gnuradio/prefs) and throws if it cannot
  // create it, which aborts every input when $HOME is read-only (Mayhem's
  // read-only image mount, the rlenv sandbox user). Point GR_PREFS_PATH, which
  // GNU Radio reads for that dir, at a scratch dir under $TMPDIR instead. Set
  // once at startup; the file only caches an allocator choice, not input data.
  if (!getenv("GR_PREFS_PATH")) {
    const char *tmp = getenv("TMPDIR");
    std::string dir = std::string(tmp && *tmp ? tmp : "/tmp") + "/gr-prefs-XXXXXX";
    if (mkdtemp(&dir[0])) setenv("GR_PREFS_PATH", dir.c_str(), 1);
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  uint8_t sel = data[0];
  std::vector<unsigned char> syms(data + 1, data + size);
  for (auto &s : syms) s &= 3;
  if (syms.size() > 32768) syms.resize(32768);

  gr::top_block_sptr tb = gr::make_top_block("fuzz");
  gr::msg_queue::sptr q = gr::msg_queue::make(0);
  auto src = gr::blocks::vector_source_b::make(syms, false);
  switch (sel & 3) {
    case 0:
    case 1: {
      bool tdma = sel & 1;
      auto fa = gr::op25_repeater::p25_frame_assembler::make(0, true, "", 0, 0, true, true, true, q, true, tdma, false);
      if (tdma) {
        fa->set_phase2_tdma(true);
        fa->set_slotid((sel >> 2) & 1);
      }
      auto sink = gr::blocks::null_sink::make(sizeof(int16_t));
      tb->connect(src, 0, fa, 0);
      tb->connect(fa, 0, sink, 0);
      break;
    }
    default: {
      // op25_audio's ctor memcmp()s 7 bytes of the options string against "file://"/"udp://"
      // regardless of its length (op25_audio.cc:112), so the plain "" literal trunk-recorder
      // passes is overread on every construction. Pass the same empty string from a padded buffer
      // so that constant, input-independent overread does not mask the decoder itself.
      static const char kEmpty[16] = "";
      const char *opt = (sel & 3) == 2 ? kEmpty : "smartnet";
      auto fa = gr::op25_repeater::frame_assembler::make(opt, 0, 1, q, (sel & 3) == 2);
      auto s0 = gr::blocks::null_sink::make(sizeof(int16_t));
      auto s1 = gr::blocks::null_sink::make(sizeof(int16_t));
      tb->connect(src, 0, fa, 0);
      tb->connect(fa, 0, s0, 0);
      tb->connect(fa, 1, s1, 0);
      break;
    }
  }
  tb->run();
  while (q->count() > 0) {
    gr::message::sptr m = q->delete_head_nowait();
    if (!m) break;
    volatile size_t n = m->to_string().size();
    (void)n;
  }
  return 0;
}

/* Analog in-band signalling decoders (MDC-1200, FleetSync) that
 * signal_decoder_sink runs over every analog call's audio. Byte 0 picks the
 * decoder; the rest is 8-bit PCM converted to float samples, fed in chunks.
 * The Star decoder is not driven: star_decode.cc _process_sample_per() indexes
 * _sintable[256] with ofs up to ~307 on every input longer than a few samples
 * (theta is checked for wrap only after the lookup), so it would abort on every
 * input and hide the other two decoders. */
#include "../../trunk-recorder/gr_blocks/decoders/fsync_decode.h"
#include "../../trunk-recorder/gr_blocks/decoders/mdc_decode.h"
#include <stdint.h>
#include <stdlib.h>

static void mdc_cb(int fc, unsigned char op, unsigned char arg, unsigned short uid,
                   unsigned char e0, unsigned char e1, unsigned char e2, unsigned char e3, void *ctx) {
  (void)fc; (void)op; (void)arg; (void)uid; (void)e0; (void)e1; (void)e2; (void)e3;
  (*(int *)ctx)++;
}
static void fs_cb(int cmd, int subcmd, int ff, int fu, int tf, int tu, int all, unsigned char *payload,
                  int plen, unsigned char *raw, int rlen, void *ctx, int f2, int b2400) {
  (void)cmd; (void)subcmd; (void)ff; (void)fu; (void)tf; (void)tu; (void)all; (void)f2; (void)b2400;
  volatile unsigned s = 0;
  for (int i = 0; i < plen; i++) s += payload[i];
  for (int i = 0; i < rlen; i++) s += raw[i];
  (*(int *)ctx)++;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  int which = data[0] & 1;
  int rate = (data[0] & 4) ? 16000 : 8000;
  data++; size--;
  float *buf = (float *)malloc((size ? size : 1) * sizeof(float));
  for (size_t i = 0; i < size; i++) buf[i] = ((int)data[i] - 128) / 128.0f;
  int hits = 0;
  const int chunk = 160;
  if (which == 0) {
    mdc_decoder_t *d = mdc_decoder_new(rate);
    mdc_decoder_set_callback(d, mdc_cb, &hits);
    for (size_t off = 0; off < size; off += chunk) {
      int n = (int)(size - off < (size_t)chunk ? size - off : chunk);
      mdc_decoder_process_samples(d, buf + off, n);
    }
    free(d);
  } else if (which == 1) {
    fsync_decoder_t *d = fsync_decoder_new(rate);
    fsync_decoder_set_callback(d, fs_cb, &hits);
    for (size_t off = 0; off < size; off += chunk) {
      int n = (int)(size - off < (size_t)chunk ? size - off : chunk);
      fsync_decoder_process_samples(d, buf + off, n);
    }
    fsync_decoder_end_samples(d);
    free(d);
  }
  free(buf);
  return 0;
}

// Known-answer functional test for trunk-recorder's input parsers (upstream ships no unit
// tests). Built with the project's normal flags by build.sh; run by test.sh.
// Each check prints "PASS <name>" or "FAIL <name>"; exit status = number of failures.
#include "../../trunk-recorder/talkgroup.h"
#include "../../trunk-recorder/talkgroups.h"
#include "../../trunk-recorder/gr_blocks/decoders/mdc_decode.h"
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <cmath>
#include <cstdio>
#include <string>

static int failures = 0;
static void check(bool ok, const char *name) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) failures++;
}

int main(int argc, char **argv) {
  boost::log::core::get()->set_filter(boost::log::trivial::severity > boost::log::trivial::fatal);
  std::string ex = argc > 1 ? argv[1] : "examples";
  std::string fx = argc > 2 ? argv[2] : "mayhem/selftest";

  Talkgroups tgs;
  tgs.load_talkgroups(0, ex + "/talkgroups.csv");
  Talkgroup *t = tgs.find_talkgroup(0, 101);
  check(t && t->alpha_tag == "DCFD 01 Disp", "talkgroup_101_alpha_tag");
  check(t && t->description == "Fire Dispatch", "talkgroup_101_description");
  check(t && t->group == "Fire" && t->priority == 1, "talkgroup_101_group_priority");
  Talkgroup *t2 = tgs.find_talkgroup(0, 142);
  check(t2 && t2->tag == "Hospital" && t2->priority == 2, "talkgroup_142_tag_priority");
  check(tgs.find_talkgroup(0, 999999) == nullptr, "talkgroup_unknown_is_null");
  check(tgs.find_talkgroup(1, 101) == nullptr, "talkgroup_other_system_is_null");

  Talkgroups chans;
  chans.load_channels(0, fx + "/channels.csv");
  Talkgroup *c = chans.find_talkgroup_by_freq(0, 462562500);
  check(c && c->number == 1 && c->alpha_tag == "FRS 01", "channel_by_freq_frs01");
  Talkgroup *c2 = chans.find_talkgroup(0, 2);
  check(c2 && std::fabs(c2->freq - 462587500) < 1, "channel_2_freq_mhz_converted");

  // MDC-1200 decoder on silence must report no packet.
  mdc_decoder_t *d = mdc_decoder_new(8000);
  float zeros[800] = {0};
  int r = mdc_decoder_process_samples(d, zeros, 800);
  unsigned char op = 0xff, arg = 0xff;
  unsigned short uid = 0xffff;
  check(d != nullptr && r == 0 && mdc_decoder_get_packet(d, &op, &arg, &uid) == -1, "mdc_silence_no_packet");

  printf("SELFTEST failures=%d\n", failures);
  return failures;
}

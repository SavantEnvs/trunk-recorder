// Local CSV inputs named in config.json: the unit-tags file (regex patterns ->
// tags) and the over-the-air alias cache file. Byte 0 picks which; the rest is
// written to a scratch file under $TMPDIR and loaded through the same public
// entry points trunk-recorder uses.
//
// The P25 custom frequency table (P25Parser::load_freq_table) is deliberately
// NOT fuzzed here: it lets csv-parser exceptions escape (no try/catch in it or
// in parse_message), so an empty or one-line file aborts trunk-recorder via
// std::terminate. That shallow bug fired on nearly every mutated input and
// kept this target from fuzzing at all; its reproducer is in
// mayhem/csv-files/known-findings/freq-table-uncaught-exception/.
#include "fuzz_common.h"
#include "../../trunk-recorder/unit_tags.h"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  fuzz_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const char *tmp = getenv("TMPDIR");
  std::string path = std::string(tmp && *tmp ? tmp : "/tmp") + "/trfuzz-XXXXXX";
  int fd = mkstemp(&path[0]);
  if (fd < 0) return 0;
  size_t off = 1;
  while (off < size) {
    ssize_t w = write(fd, data + off, size - off);
    if (w <= 0) break;
    off += (size_t)w;
  }
  close(fd);

  switch (data[0] % 2) {
    case 0: {
      UnitTags tags;
      tags.load_unit_tags(path);
      for (long id : {0L, 1L, 101L, 1234567L, 16777215L}) tags.find_unit_tag(id);
      break;
    }
    default: {
      UnitTags tags;
      tags.load_unit_tags_ota(path);
      for (long id : {0L, 1L, 101L, 1234567L}) tags.find_unit_tag_ota(id);
      break;
    }
  }
  unlink(path.c_str());
  return 0;
}

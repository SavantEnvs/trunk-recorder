# P25 custom frequency table: uncaught csv-parser exception

`P25Parser::load_freq_table` (`trunk-recorder/systems/p25_parser.cc`) builds a
`csv::CSVReader` on the file named by a system's `customFrequencyTable` without
a try/catch, and `P25Parser::parse_message` does not catch either. An empty file
makes `csv::internals::get_csv_head` throw `std::runtime_error`, which reaches
`std::terminate` and aborts trunk-recorder on the first P25 control message.
A file with fewer than five header columns also reads `headers[0..4]` out of
bounds.

`crash-empty-table` is the input from the attempt-1 `csv-files` harness, where
byte 0 (`&`, 38 % 3 == 2) selected the frequency-table branch and the remaining
(empty) bytes became the table file. That branch was removed from the harness
because this bug fired on almost every input.

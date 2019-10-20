# parse_quote
Small Haskell Code Sample that parses market UDP packet dumps for quotes.

Optionally re-orders packets according to quote accept time with flag.

To use:

```
make
./parse_quote [-r] <pcap_file>
```

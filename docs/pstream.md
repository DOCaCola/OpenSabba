# PStream control values

Multibyte lengths/integers are big endian. One message has one typed value without an extra object-length prefix.

| Hex tag | Value | Payload |
| --- | --- | --- |
| 00 | Null | One zero byte |
| 01 | Unsigned integer | Width 1, 2, 4 or 8, then bytes |
| 10 | String | 16-bit byte length, bytes |
| 20 | Buffer | 32-bit byte length, bytes |
| 30 | File transfer | Unsupported by value codec |
| 40 | Container end | None |
| 41 | Array | Values until tag 40 |
| 42 | Map | String-key/value pairs until tag 40 |
| 43 | Extended file transfer | Unsupported by value codec |

The encoder selects the smallest integer width; zero uses one byte. There is no boolean tag. Maps sort keys. Delimiters in length-prefixed payloads are ordinary bytes.

```text
null:          00 00
integer 256:   01 02 01 00
string "abc":  10 00 03 61 62 63
empty array:   41 40
empty map:     42 40
```

The decoder rejects unknown/file tags, duplicate/nonstring keys, invalid widths, truncation and misplaced ends. Buffer decode requires exactly one root. Defaults are 16 MiB, 100,000 nodes including keys, depth 64. Strings over 65,535 bytes are rejected before encoding.

Exact-read checks allocation lengths before requesting data and stops precisely at value end. Transport handles partial reads/cancellation/deadlines. Multiple-value upload streams have separate completion rules; see [image transfer](image-transfer.md).

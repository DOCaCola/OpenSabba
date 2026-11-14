# Transport and discovery

TCP defaults to 5510. Send plaintext PStream `encrypt_channel`, read a complete response skipping `type=keep_alive`, reject any `error` member, then upgrade the same socket to TLS. Send `query_server_info` over TLS. No credentials enter the plaintext request.

Requests carry `agent.version` with integer `major=3`, `minor=2`, `mini=1` and string `build="5059"`. This selects a wire dialect; OpenSabba reports its own version separately. Authenticated requests add device UUID, token and `ds_id` as needed. Codec keys directly represent wire keys.

OpenSSL 3 uses TLS 1.2+, DNS SNI and DNS/IP certificate identity checks. Specified CA files replace default roots; approval/renewal follows [authentication](authentication.md). TLS failure does not trigger plaintext retry.

Nonblocking connection establishment tries DNS results in order. A monotonic deadline covers control operations; socket waits support cancellation, OS DNS is synchronous. Bulk transfer uses per-block deadlines.

The bounded exact-read [parser](pstream.md) stops at each value without consuming the next message/TLS bytes. At most 256 consecutive keep-alives are allowed alongside byte/node/depth/time bounds. Errors report codes without arbitrary payloads.

Long polling stays open, pulling events after notification. Authentication repeats every 60 seconds and timezone checks align to 180-second boundaries. The one-second local tick makes no network requests. See [service](service.md).

NAS-side deduplication needs no separate fingerprint exchange. [Proxies](proxy.md) preserve NAS TLS.

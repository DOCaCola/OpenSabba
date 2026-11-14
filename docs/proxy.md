# HTTP CONNECT proxy

```sh
opensabba --connect --address nas.example --username USER \
  --proxy-address proxy.example --proxy-port 3128 \
  --proxy-username PROXY_USER --proxy-password-fd 3 3< /private/proxy-password
```

Basic authorization goes only to the configured proxy. The proxy leg is plaintext: Base64 does not encrypt credentials. NAS TLS remains end to end inside the tunnel. HTTPS transport to the proxy is not implemented.

For NTLM add `--proxy-auth ntlm --proxy-domain DOMAIN --proxy-workstation CLIENT`. NTLMv2 is default; v1 requires explicit `--proxy-ntlm-version 1`, without downgrade. `DOMAIN\USER` supplies an omitted domain. UTF-8 credentials become UTF-16LE; v2 uses Unicode simple uppercase for its response key.

Negotiate, challenge and proof remain on one connection. Only initial bare-407 negotiation may reconnect; closing after the challenge is rejected. NTLMv2 handles proof, target info, timestamp, keys and MIC. Explicit v1 handles extended-session/plain challenges. Non-ASCII or passwords longer than 14 bytes omit plain-mode LM response while retaining NT response.

A shared descriptor supplies NAS password, optional OTP then proxy password. Credentials exclude controls and are bounded to 4096 bytes; Basic usernames exclude colons. Basic non-ASCII charset negotiation is not implemented.

The proxy password is saved unencrypted in the private 0600 session for unattended use. Status/errors/exports omit it. Logout removes the session; later login without proxy authentication does not retain old secrets. Failure preserves prior settings and never bypasses the proxy directly.

CONNECT parsing bounds headers/responses, validates framing and preserves tunnel bytes. All later connections use saved policy and [transport](transport.md) cancellation/deadline rules.

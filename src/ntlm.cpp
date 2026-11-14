#include "opensabba/ntlm.hpp"
#include "opensabba/client.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/rand.h>

namespace opensabba::ntlm {
namespace {
// MS-NLMP 2.2.2.5. HTTP CONNECT does not use post-authentication sealing,
// but SIGN and KEY_EXCH allow the proxy to request an encrypted session key.
constexpr std::uint32_t unicode = 0x00000001, request_target = 0x00000004, sign = 0x00000010,
                        ntlm = 0x00000200, always_sign = 0x00008000, extended = 0x00080000,
                        target_info = 0x00800000, key_exchange = 0x40000000, bits128 = 0x20000000,
                        bits56 = 0x80000000;
constexpr std::uint32_t offered = unicode | request_target | sign | ntlm | always_sign | extended |
                                  target_info | key_exchange | bits128 | bits56;
#include "ntlm_uppercase.inc"
struct Cleanse {
    Bytes& bytes;
    ~Cleanse() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
void put16(Bytes& b, std::size_t p, std::uint16_t n) {
    b[p] = static_cast<std::uint8_t>(n);
    b[p + 1] = static_cast<std::uint8_t>(n >> 8);
}
void put32(Bytes& b, std::size_t p, std::uint32_t n) {
    for (std::size_t i = 0; i < 4; ++i)
        b[p + i] = static_cast<std::uint8_t>(n >> (8 * i));
}
void put64(Bytes& b, std::size_t p, std::uint64_t n) {
    for (std::size_t i = 0; i < 8; ++i)
        b[p + i] = static_cast<std::uint8_t>(n >> (8 * i));
}
std::uint16_t get16(std::span<const std::uint8_t> b, std::size_t p) {
    if (p + 2 > b.size())
        throw pstream::Error("invalid NTLM challenge");
    return static_cast<std::uint16_t>(b[p] | (b[p + 1] << 8));
}
std::uint32_t get32(std::span<const std::uint8_t> b, std::size_t p) {
    if (p + 4 > b.size())
        throw pstream::Error("invalid NTLM challenge");
    return std::uint32_t(b[p]) | (std::uint32_t(b[p + 1]) << 8) | (std::uint32_t(b[p + 2]) << 16) |
           (std::uint32_t(b[p + 3]) << 24);
}
void append(Bytes& b, std::span<const std::uint8_t> tail) {
    b.insert(b.end(), tail.begin(), tail.end());
}
void append(Bytes& b, const Bytes& tail) { append(b, std::span<const std::uint8_t>(tail)); }
Bytes field(std::span<const std::uint8_t> b, std::size_t p) {
    auto n = get16(b, p), m = get16(b, p + 2);
    auto off = get32(b, p + 4);
    if (n > m || off > b.size() || n > b.size() - off)
        throw pstream::Error("invalid NTLM challenge field");
    return Bytes(b.begin() + off, b.begin() + off + n);
}
Bytes utf16(std::string_view input, bool upper = false) {
    Bytes out;
    out.reserve(input.size() * 2);
    for (std::size_t i = 0; i < input.size();) {
        auto c = static_cast<unsigned char>(input[i++]);
        std::uint32_t cp = c;
        int more = 0;
        if (c >= 0xF0 && c <= 0xF4) {
            cp = c & 7;
            more = 3;
        } else if (c >= 0xE0 && c <= 0xEF) {
            cp = c & 15;
            more = 2;
        } else if (c >= 0xC2 && c <= 0xDF) {
            cp = c & 31;
            more = 1;
        } else if (c >= 0x80)
            throw pstream::Error("invalid UTF-8 NTLM credential");
        for (int k = 0; k < more; ++k) {
            if (i == input.size() || (static_cast<unsigned char>(input[i]) & 0xC0) != 0x80)
                throw pstream::Error("invalid UTF-8 NTLM credential");
            cp = (cp << 6) | (static_cast<unsigned char>(input[i++]) & 63);
        }
        if ((more == 1 && cp < 0x80) || (more == 2 && cp < 0x800) || (more == 3 && cp < 0x10000) ||
            cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            throw pstream::Error("invalid UTF-8 NTLM credential");
        if (upper) {
            const auto* found = std::lower_bound(
                std::begin(uppercase_map), std::end(uppercase_map), cp,
                [](const auto& pair, std::uint32_t value) { return pair.first < value; });
            if (found != std::end(uppercase_map) && found->first == cp)
                cp = found->second;
        }
        if (cp < 0x10000) {
            out.push_back(static_cast<std::uint8_t>(cp));
            out.push_back(static_cast<std::uint8_t>(cp >> 8));
        } else {
            cp -= 0x10000;
            auto hi = 0xD800 + (cp >> 10), lo = 0xDC00 + (cp & 1023);
            out.push_back(static_cast<std::uint8_t>(hi));
            out.push_back(static_cast<std::uint8_t>(hi >> 8));
            out.push_back(static_cast<std::uint8_t>(lo));
            out.push_back(static_cast<std::uint8_t>(lo >> 8));
        }
    }
    return out;
}
Bytes hmac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    Bytes out(16);
    unsigned int size = 0;
    if (!HMAC(EVP_md5(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
              out.data(), &size) ||
        size != 16)
        throw pstream::Error("NTLM HMAC failed");
    return out;
}
Bytes md4(std::span<const std::uint8_t> data) {
    Bytes out(16);
    if (!MD4(data.data(), data.size(), out.data()))
        throw pstream::Error("NTLM MD4 failed");
    return out;
}
Bytes random_bytes(std::size_t size) {
    Bytes b(size);
    if (RAND_bytes(b.data(), static_cast<int>(size)) != 1)
        throw pstream::Error("NTLM random generation failed");
    return b;
}
Bytes rc4(std::span<const std::uint8_t> key, std::span<const std::uint8_t> input) {
    std::array<std::uint8_t, 256> s{};
    for (std::size_t i = 0; i < 256; ++i)
        s[i] = static_cast<std::uint8_t>(i);
    std::uint8_t j = 0;
    for (std::size_t i = 0; i < 256; ++i) {
        j = static_cast<std::uint8_t>(j + s[i] + key[i % key.size()]);
        std::swap(s[i], s[static_cast<std::size_t>(j)]);
    }
    Bytes out(input.size());
    std::uint8_t i = 0;
    j = 0;
    for (std::size_t k = 0; k < input.size(); ++k) {
        ++i;
        j = static_cast<std::uint8_t>(j + s[static_cast<std::size_t>(i)]);
        std::swap(s[static_cast<std::size_t>(i)], s[static_cast<std::size_t>(j)]);
        const auto index = static_cast<std::uint8_t>(s[static_cast<std::size_t>(i)] +
                                                     s[static_cast<std::size_t>(j)]);
        out[k] = input[k] ^ s[static_cast<std::size_t>(index)];
    }
    OPENSSL_cleanse(s.data(), s.size());
    return out;
}
Bytes des_response(std::span<const std::uint8_t> hash, std::span<const std::uint8_t> challenge) {
    std::array<std::uint8_t, 21> padded{};
    std::copy(hash.begin(), hash.end(), padded.begin());
    Bytes out(24);
    for (int block = 0; block < 3; ++block) {
        DES_cblock key{};
        const auto* p = padded.data() + block * 7;
        key[0] = p[0] & 0xfe;
        key[1] = static_cast<unsigned char>((p[0] << 7) | (p[1] >> 1)) & 0xfe;
        key[2] = static_cast<unsigned char>((p[1] << 6) | (p[2] >> 2)) & 0xfe;
        key[3] = static_cast<unsigned char>((p[2] << 5) | (p[3] >> 3)) & 0xfe;
        key[4] = static_cast<unsigned char>((p[3] << 4) | (p[4] >> 4)) & 0xfe;
        key[5] = static_cast<unsigned char>((p[4] << 3) | (p[5] >> 5)) & 0xfe;
        key[6] = static_cast<unsigned char>((p[5] << 2) | (p[6] >> 6)) & 0xfe;
        key[7] = static_cast<unsigned char>(p[6] << 1) & 0xfe;
        DES_key_schedule schedule;
        DES_set_odd_parity(&key);
        DES_set_key_unchecked(&key, &schedule);
        DES_cblock in{}, result{};
        std::copy(challenge.begin(), challenge.end(), in);
        DES_ecb_encrypt(&in, &result, &schedule, DES_ENCRYPT);
        std::copy(result, result + 8, out.begin() + block * 8);
        OPENSSL_cleanse(&schedule, sizeof(schedule));
    }
    OPENSSL_cleanse(padded.data(), padded.size());
    return out;
}
void setfield(Bytes& message, std::size_t header, const Bytes& data) {
    if (data.size() > 65535)
        throw pstream::Error("NTLM field too long");
    put16(message, header, static_cast<std::uint16_t>(data.size()));
    put16(message, header + 2, static_cast<std::uint16_t>(data.size()));
    put32(message, header + 4, static_cast<std::uint32_t>(message.size()));
    append(message, data);
}
struct Challenge {
    std::uint32_t flags;
    Bytes server, target, info;
    bool timestamp = false;
    std::array<std::uint8_t, 8> time{};
    bool mic = false;
};
Challenge parse(std::span<const std::uint8_t> b) {
    // Type 2: signature/type (0..11), target buffer (12..19), flags (20..23),
    // nonce (24..31), reserved (32..39), and target-info buffer (40..47).
    if (b.size() < 48 || std::memcmp(b.data(), "NTLMSSP\0", 8) || get32(b, 8) != 2)
        throw pstream::Error("invalid NTLM challenge");
    Challenge c;
    c.flags = get32(b, 20);
    if (!(c.flags & unicode) || !(c.flags & ntlm))
        throw pstream::Error("proxy NTLM challenge lacks Unicode or NTLM support");
    c.server = Bytes(b.begin() + 24, b.begin() + 32);
    if (c.flags & request_target)
        c.target = field(b, 12);
    if (c.flags & target_info)
        c.info = field(b, 40);
    if (c.flags & target_info) {
        if (c.info.empty())
            throw pstream::Error("NTLM target info missing");
        std::size_t p = 0;
        bool ended = false, seen_flags = false;
        while (p < c.info.size()) {
            auto id = get16(c.info, p), len = get16(c.info, p + 2);
            p += 4;
            if (len > c.info.size() - p)
                throw pstream::Error("invalid NTLM target info");
            if (id == 0) {
                if (len || p != c.info.size())
                    throw pstream::Error("invalid NTLM target info terminator");
                ended = true;
                break;
            }
            if (id == 7) {
                if (len != 8 || c.timestamp)
                    throw pstream::Error("invalid NTLM timestamp");
                c.timestamp = true;
                std::copy_n(c.info.data() + p, 8, c.time.begin());
            }
            if (id == 6) {
                if (len != 4 || seen_flags)
                    throw pstream::Error("invalid NTLM AV flags");
                seen_flags = true;
                c.mic = (get32(c.info, p) & 2) != 0;
            }
            p += len;
        }
        if (!ended)
            throw pstream::Error("unterminated NTLM target info");
    }
    return c;
}
} // namespace
Bytes negotiate() {
    Bytes b(32);
    std::copy_n("NTLMSSP\0", 8, b.begin());
    put32(b, 8, 1);
    put32(b, 12, offered);
    put32(b, 20, 32);
    put32(b, 28, 32);
    return b;
}
Bytes authenticate(std::span<const std::uint8_t> type1, std::span<const std::uint8_t> type2,
                   const ProxyCredentials& credentials) {
    auto c = parse(type2);
    if (credentials.username.empty() || credentials.username.size() > 4096 ||
        credentials.password.size() > 4096 || credentials.domain.size() > 4096 ||
        credentials.workstation.size() > 4096)
        throw pstream::Error("invalid NTLM proxy credentials");
    auto user = utf16(credentials.username), domain = utf16(credentials.domain),
         workstation = utf16(credentials.workstation), password = utf16(credentials.password);
    Cleanse wipe_password{password};
    auto nt_hash = md4(password);
    Cleanse wipe_hash{nt_hash};
    Bytes lm, nt, session_key;
    Cleanse wipe_lm{lm}, wipe_nt{nt}, wipe_session{session_key};
    bool mic = false;
    auto flags = c.flags & offered;
    if (credentials.ntlm_version == 2) {
        Bytes identity = utf16(credentials.username, true);
        Cleanse wipe_identity{identity};
        append(identity, domain);
        auto response_key = hmac(nt_hash, identity);
        Cleanse wipe_response{response_key};
        auto nonce = random_bytes(8);
        Cleanse wipe_nonce{nonce};
        Bytes blob(28);
        Cleanse wipe_blob{blob};
        blob[0] = 1;
        blob[1] = 1;
        if (c.timestamp)
            std::copy(c.time.begin(), c.time.end(), blob.begin() + 8);
        else {
            const auto now = std::chrono::system_clock::now().time_since_epoch();
            const auto ticks = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100 +
                116444736000000000LL);
            put64(blob, 8, ticks);
        }
        std::copy(nonce.begin(), nonce.end(), blob.begin() + 16);
        if (!c.info.empty()) {
            Bytes info = c.info;
            if (c.timestamp || c.mic) {
                bool found = false;
                for (std::size_t p = 0; p + 4 <= info.size();) {
                    auto id = get16(info, p), len = get16(info, p + 2);
                    if (id == 0)
                        break;
                    if (id == 6) {
                        put32(info, p + 4, get32(info, p + 4) | 2);
                        found = true;
                        break;
                    }
                    p += 4 + len;
                }
                if (!found) {
                    info.resize(info.size() - 4);
                    info.insert(info.end(), {6, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0});
                }
                mic = true;
            }
            append(blob, info);
        } else
            blob.insert(blob.end(), {0, 0, 0, 0});
        blob.insert(blob.end(), {0, 0, 0, 0});
        Bytes proof_input = c.server;
        append(proof_input, blob);
        auto proof = hmac(response_key, proof_input);
        Cleanse wipe_proof{proof};
        nt = proof;
        append(nt, blob);
        if (!c.timestamp) {
            Bytes lm_input = c.server;
            append(lm_input, nonce);
            lm = hmac(response_key, lm_input);
            append(lm, nonce);
        } else
            lm.resize(24);
        session_key = hmac(response_key, proof);
    } else if (credentials.ntlm_version == 1) {
        if (flags & extended) {
            auto nonce = random_bytes(8);
            lm = nonce;
            lm.resize(24);
            Bytes mix = c.server;
            append(mix, nonce);
            unsigned char digest[16];
            EVP_Digest(mix.data(), mix.size(), digest, nullptr, EVP_md5(), nullptr);
            nt = des_response(nt_hash, std::span<const std::uint8_t>(digest, 8));
            OPENSSL_cleanse(digest, sizeof(digest));
            auto session_base_key = md4(nt_hash);
            session_key = hmac(session_base_key, mix);
            OPENSSL_cleanse(session_base_key.data(), session_base_key.size());
        } else {
            nt = des_response(nt_hash, c.server);
            const bool oem_password =
                credentials.password.size() <= 14 &&
                std::all_of(credentials.password.begin(), credentials.password.end(),
                            [](unsigned char ch) { return ch < 128; });
            if (oem_password) {
                Bytes oem(21);
                for (std::size_t p = 0; p < credentials.password.size(); ++p) {
                    auto ch = static_cast<unsigned char>(credentials.password[p]);
                    oem[p] = static_cast<std::uint8_t>(ch >= 'a' && ch <= 'z' ? ch - 32 : ch);
                }
                constexpr std::uint8_t magic[8] = {'K', 'G', 'S', '!', '@', '#', '$', '%'};
                auto lm_hash = des_response(oem, magic);
                lm_hash.resize(16);
                lm = des_response(lm_hash, c.server);
                OPENSSL_cleanse(lm_hash.data(), lm_hash.size());
                OPENSSL_cleanse(oem.data(), oem.size());
            } else
                lm.resize(24);
            session_key = md4(nt_hash);
        }
    } else
        throw pstream::Error("unsupported NTLM version");
    bool exchange = (flags & key_exchange) && (flags & sign);
    Bytes encrypted_key, exported = session_key;
    Cleanse wipe_encrypted{encrypted_key}, wipe_exported{exported};
    if (exchange) {
        exported = random_bytes(16);
        encrypted_key = rc4(session_key, exported);
    } else
        flags &= ~key_exchange;
    // Type 3 has six security buffers in bytes 12..59 and flags in 60..63.
    // MIC occupies bytes 72..87 after the all-zero version slot at 64..71.
    Bytes message(mic ? 88 : 64);
    std::copy_n("NTLMSSP\0", 8, message.begin());
    put32(message, 8, 3);
    put32(message, 60, flags);
    setfield(message, 12, lm);
    setfield(message, 20, nt);
    setfield(message, 28, domain);
    setfield(message, 36, user);
    setfield(message, 44, workstation);
    setfield(message, 52, encrypted_key);
    if (mic) {
        Bytes signed_messages(type1.begin(), type1.end());
        append(signed_messages, type2);
        append(signed_messages, message);
        auto signature = hmac(exported, signed_messages);
        std::copy(signature.begin(), signature.end(), message.begin() + 72);
    }
    return message;
}
std::string encode(std::span<const std::uint8_t> message) {
    std::string result(4 * ((message.size() + 2) / 3), '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()), message.data(),
                    static_cast<int>(message.size()));
    return result;
}
Bytes decode(std::string_view text) {
    if (text.empty() || text.size() % 4 || text.size() > 16384)
        throw pstream::Error("invalid NTLM proxy challenge encoding");
    Bytes out(text.size() / 4 * 3);
    int size = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(text.data()),
                               static_cast<int>(text.size()));
    if (size < 0)
        throw pstream::Error("invalid NTLM proxy challenge encoding");
    std::size_t pad = 0;
    if (text.back() == '=')
        ++pad;
    if (text.size() > 1 && text[text.size() - 2] == '=')
        ++pad;
    out.resize(static_cast<std::size_t>(size) - pad);
    return out;
}
} // namespace opensabba::ntlm

#include "opensabba/client.hpp"
#include "opensabba/ntlm.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace {
using opensabba::ntlm::Bytes;
constexpr std::array<std::uint8_t, 8> client_nonce{
    0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44};
constexpr std::array<std::uint8_t, 16> exported_session_key{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
int random_calls = 0;

void put32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i)
        bytes[offset+i] = static_cast<std::uint8_t>(value >> (i*8));
}
std::uint16_t get16(const Bytes& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset] | (bytes[offset+1] << 8));
}
std::uint32_t get32(const Bytes& bytes, std::size_t offset) {
    return std::uint32_t(bytes[offset]) | (std::uint32_t(bytes[offset+1]) << 8) |
           (std::uint32_t(bytes[offset+2]) << 16) | (std::uint32_t(bytes[offset+3]) << 24);
}
Bytes field(const Bytes& bytes, std::size_t offset) {
    const auto size = get16(bytes, offset);
    const auto start = get32(bytes, offset+4);
    if (start > bytes.size() || size > bytes.size()-start)
        throw std::runtime_error("Type 3 field out of bounds");
    return Bytes(bytes.begin()+start, bytes.begin()+start+size);
}
}

// The test executable wraps only its own RAND_bytes calls. Production continues
// to use OpenSSL randomness; fixed bytes make the key-exchange result observable.
extern "C" int __wrap_RAND_bytes(unsigned char* output, int size) {
    if (size == 8) std::copy(client_nonce.begin(), client_nonce.end(), output);
    else if (size == 16)
        std::copy(exported_session_key.begin(), exported_session_key.end(), output);
    else throw std::runtime_error("unexpected NTLM random request");
    ++random_calls;
    return 1;
}

int main() {
    const auto type1 = opensabba::ntlm::negotiate();
    Bytes type2(48);
    std::copy_n("NTLMSSP\0", 8, type2.begin());
    put32(type2, 8, 2);
    put32(type2, 20, 0x00000001 | 0x00000010 | 0x00000200 |
                       0x00080000 | 0x20000000 | 0x40000000);
    constexpr std::array<std::uint8_t, 8> server_challenge{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    std::copy(server_challenge.begin(), server_challenge.end(), type2.begin()+24);
    put32(type2, 16, 48); // Empty target name.
    put32(type2, 44, 48); // Empty target info.
    opensabba::ProxyCredentials credentials{"User", "Password"};
    credentials.scheme = "ntlm";
    credentials.domain = "Domain";
    credentials.workstation = "PI";
    credentials.ntlm_version = 1;
    const auto type3 = opensabba::ntlm::authenticate(type1, type2, credentials);
    if (random_calls != 2 || type3.size() < 64 || get32(type3, 8) != 3)
        throw std::runtime_error("unexpected NTLMv1 exchange layout");
    const auto lm = field(type3, 12);
    if (lm.size() != 24 || !std::equal(client_nonce.begin(), client_nonce.end(), lm.begin()) ||
        !std::all_of(lm.begin()+8, lm.end(), [](std::uint8_t byte){return byte == 0;}))
        throw std::runtime_error("wrong NTLMv1 extended LM response");
    // Independent Python HMAC-MD5 and RC4 over published NT hash
    // a4f49c406510bdcab6824ee7c30fd852 (Password):
    // SessionBaseKey=d87262b0cde4b1cb7499becccdf10784;
    // KXKEY=HMAC-MD5(SessionBaseKey, ServerChallenge || ClientNonce)
    // =649d52cdb865a50bf7f524f548122e40.
    constexpr std::array<std::uint8_t, 16> expected_encrypted_key{
        0x1b, 0x91, 0xd3, 0xee, 0x70, 0xdf, 0x03, 0x66,
        0xfd, 0xdf, 0xa1, 0x48, 0xfa, 0x19, 0x0e, 0x8d};
    const auto encrypted_key = field(type3, 52);
    if (!std::equal(encrypted_key.begin(), encrypted_key.end(),
                    expected_encrypted_key.begin(), expected_encrypted_key.end()))
        throw std::runtime_error("wrong NTLMv1 extended key exchange");
}

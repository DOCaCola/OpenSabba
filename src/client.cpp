#include "opensabba/client.hpp"
#include "opensabba/image.hpp"
#include "opensabba/backup_resume.hpp"
#include "opensabba/file_restore_job.hpp"
#include "opensabba/task_policy.hpp"
#include "opensabba/backup_scripts.hpp"
#include "opensabba/bandwidth.hpp"
#include "opensabba/volume_nodes.hpp"
#include "opensabba/ntlm.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <ctime>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <set>
#include <sstream>
#include <utility>

namespace opensabba {
namespace { class Channel; }
class ConnectionPool {
public:
    struct Addresses {
        BIO_ADDRINFO* value = nullptr;
        ~Addresses() { BIO_ADDRINFO_free(value); }
    };
    struct Entry {
        std::string key;
        std::unique_ptr<Channel> channel;
        std::time_t expires;
    };
    std::mutex mutex, identity_mutex;
    std::condition_variable available;
    std::size_t channels = 0;
    std::map<std::string,std::shared_ptr<Addresses>> addresses;
    std::map<std::string,std::string> identities;
    std::vector<Entry> idle;
    ~ConnectionPool();
};
namespace {
using pstream::Value;
using pstream::Error;
using Clock = std::chrono::steady_clock;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using Tls = std::unique_ptr<SSL, decltype(&SSL_free)>;

[[noreturn]] void ssl_error(const std::string& operation) {
    std::string message = operation;
    unsigned long code;
    while ((code = ERR_get_error()) != 0) {
        char text[256];
        ERR_error_string_n(code, text, sizeof(text));
        message += ": ";
        message += text;
    }
    throw Error(message);
}

void wait_socket(int fd, bool for_read, Clock::time_point deadline,
                 const std::function<bool()>& cancelled) {
    for (;;) {
        if (cancelled && cancelled()) throw Cancelled();
        auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now());
        if (remaining.count() <= 0) throw TransportError("operation timed out");
        const auto milliseconds = static_cast<int>(std::min<std::int64_t>(
            remaining.count(), cancelled ? 100 : 300'000));
#ifdef _WIN32
        fd_set ready, errors;
        FD_ZERO(&ready);
        FD_ZERO(&errors);
        FD_SET(static_cast<SOCKET>(fd), &ready);
        FD_SET(static_cast<SOCKET>(fd), &errors);
        timeval timeout{milliseconds / 1000, (milliseconds % 1000) * 1000};
        const auto result = select(0, for_read ? &ready : nullptr,
                                   for_read ? nullptr : &ready, &errors, &timeout);
        if (result == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) continue;
#else
        pollfd event{fd, static_cast<short>(for_read ? POLLIN : POLLOUT), 0};
        const auto result = poll(&event, 1, milliseconds);
        if (result < 0 && errno == EINTR) continue;
#endif
        if (result < 0) throw TransportError("socket readiness wait failed");
        if (result > 0) return; // Includes connection errors: the caller checks SO_ERROR.
    }
}

Bio connect_socket(const Endpoint& endpoint, Clock::time_point deadline) {
    if (BIO_sock_init() != 1) ssl_error("cannot initialize sockets");
    const auto key = endpoint.host+":"+std::to_string(endpoint.port);
    std::shared_ptr<ConnectionPool::Addresses> resolved;
    {
        std::lock_guard lock(endpoint.connections->mutex);
        auto& saved = endpoint.connections->addresses[key];
        if (!saved) {
            auto fresh = std::make_shared<ConnectionPool::Addresses>();
            const auto port = std::to_string(endpoint.port);
            if (BIO_lookup_ex(endpoint.host.c_str(), port.c_str(), BIO_LOOKUP_CLIENT,
                              AF_UNSPEC, SOCK_STREAM, 0, &fresh->value) != 1)
                throw TransportError("hostname lookup failed");
            saved = std::move(fresh);
        }
        resolved = saved;
    }
    const auto* addresses = resolved->value;
    int last_error = 0;
    for (const auto* address = addresses; address; address = BIO_ADDRINFO_next(address)) {
        if (endpoint.cancelled && endpoint.cancelled()) throw Cancelled();
        if (Clock::now() >= deadline) throw TransportError("operation timed out");
        ERR_clear_error();
        const auto fd = BIO_socket(BIO_ADDRINFO_family(address), BIO_ADDRINFO_socktype(address),
                                   BIO_ADDRINFO_protocol(address), BIO_SOCK_NONBLOCK);
        if (fd < 0) continue;
        Bio socket(BIO_new_socket(fd, BIO_CLOSE), BIO_free_all);
        if (!socket) {
            BIO_closesocket(fd);
            ssl_error("cannot allocate socket BIO");
        }
        if (BIO_connect(fd, BIO_ADDRINFO_address(address), BIO_SOCK_NONBLOCK) == 1)
            return socket;
        if (!BIO_sock_should_retry(0)) continue;
        wait_socket(fd, false, deadline, endpoint.cancelled);
        last_error = BIO_sock_error(fd);
        if (last_error == 0) {
            ERR_clear_error();
            return socket;
        }
    }
    throw TransportError("TCP connection failed (socket error " + std::to_string(last_error) + ")");
}

// OpenSSL owns each socket after connection; no architecture-dependent wire layouts.
class Channel {
public:
    explicit Channel(const Endpoint& endpoint)
        : socket_(nullptr, BIO_free_all),
          context_(SSL_CTX_new(TLS_client_method()), SSL_CTX_free),
          tls_(nullptr, SSL_free), host_(endpoint.host),
          deadline_(Clock::now() + endpoint.timeout), cancelled_(endpoint.cancelled),
          operation_timeout_(endpoint.timeout), trust_certificate_(endpoint.trust_certificate),
          custom_ca_(!endpoint.ca_file.empty()) {
        if (cancelled_ && cancelled_()) throw Cancelled();
        if (host_.empty() || host_.find('\0') != std::string::npos ||
            host_.find_first_of("[]/ \t\r\n") != std::string::npos)
            throw Error("host must be a DNS name or an unbracketed IP address");
        if (endpoint.port == 0 || endpoint.timeout.count() < 1 || endpoint.timeout.count() > 600)
            throw Error("port must be 1..65535 and timeout must be 1..600 seconds");
        if (!context_) ssl_error("cannot allocate TLS transport");
        if (SSL_CTX_set_min_proto_version(context_.get(), TLS1_2_VERSION) != 1)
            ssl_error("cannot configure TLS version");
        SSL_CTX_set_verify(context_.get(), SSL_VERIFY_PEER,
            trust_certificate_ && !custom_ca_ ? +[](int, X509_STORE_CTX*) { return 1; } : nullptr);
        const auto trusted = endpoint.ca_file.empty()
            ? SSL_CTX_set_default_verify_paths(context_.get())
            : SSL_CTX_load_verify_locations(context_.get(), endpoint.ca_file.c_str(), nullptr);
        if (trusted != 1) ssl_error("cannot load trust store");
        if (endpoint.proxy_host.empty() != (endpoint.proxy_port == 0))
            throw Error("proxy host and port must be supplied together");
        if (endpoint.proxy_credentials && endpoint.proxy_host.empty())
            throw Error("proxy credentials require a proxy endpoint");
        if (endpoint.proxy_host.empty()) {
            socket_ = connect_socket(endpoint, deadline_);
        } else {
            if (endpoint.proxy_host.find_first_of("[]/ \t\r\n") != std::string::npos ||
                endpoint.proxy_host.find('\0') != std::string::npos)
                throw Error("proxy host must be a DNS name or an unbracketed IP address");
            Endpoint proxy;
            proxy.host = endpoint.proxy_host;
            proxy.port = endpoint.proxy_port;
            proxy.cancelled = endpoint.cancelled;
            proxy.connections = endpoint.connections;
            const auto authority = (host_.find(':') == std::string::npos ? host_ : "["+host_+"]") +
                                   ":" + std::to_string(endpoint.port);
            const auto request_start = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
            auto request = request_start;
            struct WipeText {
                std::string& text;
                ~WipeText() { OPENSSL_cleanse(text.data(), text.size()); }
            } wipe_request{request};
            if (endpoint.proxy_credentials) {
                const auto& credentials = *endpoint.proxy_credentials;
                const auto invalid = [](const std::string& value) {
                    return value.size() > 4096 || std::any_of(value.begin(),value.end(),
                        [](unsigned char ch) { return ch < 32 || ch == 127; });
                };
                if (credentials.username.empty() ||
                    invalid(credentials.username) || invalid(credentials.password) ||
                    invalid(credentials.domain) || invalid(credentials.workstation))
                    throw Error("invalid proxy credentials: values must be nonempty where required, free of control characters, and at most 4096 bytes");
                if (credentials.scheme == "basic") {
                    if (credentials.username.find(':') != std::string::npos)
                        throw Error("invalid Basic proxy username: colon is forbidden");
                    auto clear = credentials.username + ":" + credentials.password;
                    WipeText wipe_clear{clear};
                    std::string encoded(4*((clear.size()+2)/3)+1, '\0');
                    WipeText wipe_encoded{encoded};
                    const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()),
                        reinterpret_cast<const unsigned char*>(clear.data()), static_cast<int>(clear.size()));
                    encoded.resize(static_cast<std::size_t>(length));
                    request.reserve(request.size()+encoded.size()+32);
                    request += "Proxy-Authorization: Basic ";
                    request += encoded;
                    request += "\r\n";
                } else if (credentials.scheme == "ntlm") {
                    if (credentials.ntlm_version != 1 && credentials.ntlm_version != 2)
                        throw Error("NTLM proxy version must be 1 or 2");
                } else throw Error("proxy authentication scheme must be basic or ntlm");
            }
            const bool use_ntlm = endpoint.proxy_credentials &&
                                  endpoint.proxy_credentials->scheme == "ntlm";
            ntlm::Bytes type1;
            if (use_ntlm) {
                type1 = ntlm::negotiate();
                request += "Proxy-Authorization: NTLM " + ntlm::encode(type1) + "\r\n";
            }
            request += "\r\n";
            socket_ = connect_socket(proxy, deadline_);
            write_all(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(request.data()), request.size()));
            std::size_t total = 0;
            bool sent_type3 = false;
            bool repeated_type1 = false;
            for (;;) {
                std::string header;
                while (!header.ends_with("\r\n\r\n")) {
                    if (++total > 16384) throw Error("proxy response headers exceed size limit");
                    std::uint8_t byte;
                    read_exact({&byte, 1});
                    header += static_cast<char>(byte);
                }
                const auto end = header.find("\r\n");
                const auto line = std::string_view(header).substr(0,end);
                if (line.size() < 13 || (!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 ")) ||
                    line[12] != ' ' || line[9] < '1' || line[9] > '5' ||
                    line[10] < '0' || line[10] > '9' || line[11] < '0' || line[11] > '9')
                    throw Error("invalid HTTP proxy response");
                const auto code = (line[9]-'0')*100 + (line[10]-'0')*10 + line[11]-'0';
                if (code >= 100 && code < 200 && code != 101) continue;
                if (code >= 200 && code < 300) break;
                if (code == 407 && use_ntlm && !sent_type3) {
                    auto lower = [](std::string_view value) {
                        std::string result(value);
                        std::transform(result.begin(), result.end(), result.begin(),
                            [](unsigned char ch){ return static_cast<char>(std::tolower(ch)); });
                        return result;
                    };
                    std::string challenge;
                    std::optional<std::size_t> content_length;
                    bool chunked = false, close = line.starts_with("HTTP/1.0 ");
                    bool ntlm_offered = false;
                    const auto scan_authenticate = [&](std::string_view value) {
                        const auto trim = [](std::string_view part) {
                            while (!part.empty() && (part.front() == ' ' || part.front() == '\t'))
                                part.remove_prefix(1);
                            while (!part.empty() && (part.back() == ' ' || part.back() == '\t'))
                                part.remove_suffix(1);
                            return part;
                        };
                        const auto challenge_part = [&](std::string_view part) {
                            part = trim(part);
                            const auto name_end = part.find_first_of(" \t");
                            const auto scheme = part.substr(0, name_end);
                            if (lower(scheme) != "ntlm") return;
                            ntlm_offered = true;
                            auto token = name_end == std::string_view::npos ?
                                std::string_view{} : trim(part.substr(name_end+1));
                            if (!token.empty()) {
                                if (token.find_first_of(" \t\"") != std::string_view::npos)
                                    throw Error("invalid NTLM proxy challenge");
                                if (!challenge.empty() && challenge != token)
                                    throw Error("conflicting NTLM proxy challenges");
                                challenge = token;
                            }
                        };
                        bool quoted = false, escaped = false;
                        std::size_t start = 0;
                        for (std::size_t i = 0; i <= value.size(); ++i) {
                            if (i == value.size()) {
                                if (quoted) throw Error("invalid proxy authentication header");
                                challenge_part(value.substr(start, i-start));
                                break;
                            }
                            const char ch = value[i];
                            if (escaped) { escaped = false; continue; }
                            if (quoted && ch == '\\') { escaped = true; continue; }
                            if (ch == '"') { quoted = !quoted; continue; }
                            if (ch == ',' && !quoted) {
                                challenge_part(value.substr(start, i-start));
                                start = i+1;
                            }
                        }
                    };
                    for (std::size_t p = end + 2; p < header.size() - 2;) {
                        const auto next = header.find("\r\n", p);
                        if (next == std::string::npos || next == p) break;
                        const auto colon = header.find(':', p);
                        if (colon == std::string::npos || colon >= next)
                            throw Error("invalid HTTP proxy response header");
                        const auto name = lower(std::string_view(header).substr(p, colon-p));
                        auto value = std::string_view(header).substr(colon+1, next-colon-1);
                        while (!value.empty() && (value.front()==' ' || value.front()=='\t')) value.remove_prefix(1);
                        while (!value.empty() && (value.back()==' ' || value.back()=='\t')) value.remove_suffix(1);
                        if (name == "proxy-authenticate") {
                            scan_authenticate(value);
                        } else if (name == "content-length") {
                            std::size_t length = 0;
                            const auto [last,error] = std::from_chars(value.data(),value.data()+value.size(),length);
                            if (error != std::errc{} || last != value.data()+value.size() ||
                                length > 65536 || (content_length && *content_length != length))
                                throw Error("invalid proxy authentication response length");
                            content_length = length;
                        } else if (name == "transfer-encoding") {
                            if (lower(value) != "chunked") throw Error("unsupported proxy authentication response framing");
                            chunked = true;
                        } else if (name == "connection" || name == "proxy-connection") {
                            const auto directive = lower(value);
                            if (directive.find("keep-alive") != std::string::npos) close = false;
                            if (directive.find("close") != std::string::npos) close = true;
                        }
                        p = next+2;
                    }
                    if (!ntlm_offered) throw Error("proxy did not offer NTLM authentication");
                    if (challenge.empty() && repeated_type1)
                        throw Error("proxy did not provide an NTLM challenge");
                    if (close && !challenge.empty())
                        throw Error("proxy closed NTLM challenge connection");
                    if (chunked && content_length) throw Error("ambiguous proxy authentication response framing");
                    auto discard = [&](std::size_t count) {
                        if (count > 65536) throw Error("proxy authentication response body exceeds size limit");
                        std::array<std::uint8_t,1024> buffer{};
                        while (count) {
                            const auto size = std::min(count,buffer.size());
                            read_exact({buffer.data(),size});
                            count -= size;
                        }
                    };
                    if (content_length && !close) discard(*content_length);
                    if (chunked && !close) {
                        std::size_t body = 0;
                        for (;;) {
                            std::string length_line;
                            do {
                                if (length_line.size() > 32) throw Error("invalid chunked proxy authentication response");
                                std::uint8_t byte;
                                read_exact({&byte,1});
                                length_line += static_cast<char>(byte);
                            } while (!length_line.ends_with("\r\n"));
                            length_line.resize(length_line.size()-2);
                            const auto semi = length_line.find(';');
                            if (semi != std::string::npos) length_line.resize(semi);
                            std::size_t count = 0;
                            const auto [last,error] = std::from_chars(length_line.data(),
                                length_line.data()+length_line.size(),count,16);
                            if (error != std::errc{} || last != length_line.data()+length_line.size() ||
                                count > 65536-body) throw Error("invalid chunked proxy authentication response");
                            body += count;
                            if (!count) {
                                std::size_t trailers = 0;
                                for (;;) {
                                    std::string trailer;
                                    do {
                                        if (++trailers > 16384)
                                            throw Error("proxy authentication trailers exceed size limit");
                                        std::uint8_t byte;
                                        read_exact({&byte,1});
                                        trailer += static_cast<char>(byte);
                                    } while (!trailer.ends_with("\r\n"));
                                    if (trailer == "\r\n") break;
                                    if (trailer.find(':') == std::string::npos)
                                        throw Error("invalid chunked proxy authentication response");
                                }
                                break;
                            }
                            discard(count);
                            std::uint8_t suffix[2];
                            read_exact(suffix);
                            if (suffix[0]!='\r' || suffix[1]!='\n')
                                throw Error("invalid chunked proxy authentication response");
                        }
                    }
                    if (challenge.empty()) {
                        // Some proxies insist on an initial challenge before Type 1.
                        // A bare 407 may close its socket; Type 2 must stay on the
                        // Type 1 socket, so only this first stage may reconnect.
                        if (close) socket_ = connect_socket(proxy, deadline_);
                        write_all(std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(request.data()), request.size()));
                        repeated_type1 = true;
                        continue;
                    }
                    const auto decoded = ntlm::decode(challenge);
                    auto type3 = ntlm::authenticate(type1,decoded,*endpoint.proxy_credentials);
                    struct WipeBytes {
                        ntlm::Bytes& bytes;
                        ~WipeBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
                    } wipe_type3{type3};
                    auto encoded = ntlm::encode(type3);
                    WipeText wipe_encoded{encoded};
                    auto authenticated = request_start + "Proxy-Authorization: NTLM " +
                                         encoded + "\r\n\r\n";
                    WipeText wipe_authenticated{authenticated};
                    write_all(std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(authenticated.data()), authenticated.size()));
                    sent_type3 = true;
                    continue;
                }
                if (code == 407) throw Error(endpoint.proxy_credentials ?
                    (use_ntlm ? "proxy rejected NTLM authentication (status 407)" :
                                "proxy rejected Basic authentication (status 407); check credentials and supported authentication scheme") :
                    "proxy authentication is required (status 407); configure proxy credentials");
                throw Error("HTTP proxy CONNECT rejected (status " + std::to_string(code) + ")");
            }
        }
    }
    void start_tls() {
        if (tls_) return;
        tls_.reset(SSL_new(context_.get()));
        if (!tls_) ssl_error("cannot create TLS session");
        SSL_set_hostflags(tls_.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> ip(
            a2i_IPADDRESS(host_.c_str()), ASN1_OCTET_STRING_free);
        if (ip) {
            if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(tls_.get()), host_.c_str()) != 1)
                ssl_error("cannot set certificate IP identity");
        } else {
            ERR_clear_error(); // a2i_IPADDRESS's expected failure for DNS names
            if (SSL_set1_host(tls_.get(), host_.c_str()) != 1 ||
                SSL_set_tlsext_host_name(tls_.get(), host_.c_str()) != 1)
                ssl_error("cannot set certificate hostname");
        }
        if (BIO_up_ref(socket_.get()) != 1) ssl_error("cannot reference TCP transport");
        SSL_set_bio(tls_.get(), socket_.get(), socket_.get());
        for (;;) {
            check_deadline();
            ERR_clear_error();
            const auto result = SSL_connect(tls_.get());
            if (result == 1) break;
            if (custom_ca_ && SSL_get_verify_result(tls_.get()) != X509_V_OK)
                throw CertificateError(false);
            retry_tls(result, "TLS handshake or certificate verification failed");
        }
        if (trust_certificate_) {
            std::unique_ptr<X509, decltype(&X509_free)> certificate(
                SSL_get1_peer_certificate(tls_.get()), X509_free);
            if (!certificate) throw TransportError("server did not present a TLS certificate");
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned size = 0;
            if (X509_digest(certificate.get(), EVP_sha256(), digest, &size) != 1)
                ssl_error("cannot fingerprint server certificate");
            constexpr char hex[] = "0123456789abcdef";
            ServerCertificate details;
            for (unsigned i = 0; i < size; ++i) {
                details.sha256 += hex[digest[i] >> 4];
                details.sha256 += hex[digest[i] & 15];
            }
            auto name = [](X509_NAME* value) {
                std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
                if (!output || X509_NAME_print_ex(output.get(), value, 0, XN_FLAG_RFC2253) < 0)
                    ssl_error("cannot read certificate name");
                char* data = nullptr;
                const auto count = BIO_get_mem_data(output.get(), &data);
                return std::string(data, static_cast<std::size_t>(count));
            };
            details.subject = name(X509_get_subject_name(certificate.get()));
            details.issuer = name(X509_get_issuer_name(certificate.get()));
            const auto verification = SSL_get_verify_result(tls_.get());
            details.verified = verification == X509_V_OK;
            details.verification_error = X509_verify_cert_error_string(verification);
            if (!trust_certificate_(details)) throw CertificateError(false);
        }
    }
    bool encrypted() const { return bool(tls_); }
    void configure(const Endpoint& endpoint) {
        cancelled_ = endpoint.cancelled;
        operation_timeout_ = endpoint.timeout;
        begin_operation();
    }
    void begin_operation() { deadline_ = Clock::now() + operation_timeout_; }
    void write_all(std::span<const std::uint8_t> bytes) {
        while (!bytes.empty()) {
            check_deadline();
            ERR_clear_error();
            std::size_t written = 0;
            const auto result = tls_
                ? SSL_write_ex(tls_.get(), bytes.data(), bytes.size(), &written)
                : BIO_write_ex(socket_.get(), bytes.data(), bytes.size(), &written);
            if (result == 1) bytes = bytes.subspan(written);
            else if (tls_) retry_tls(result, "TLS write failed");
            else retry_plain("TCP write failed");
        }
    }
    void read_exact(std::span<std::uint8_t> bytes) {
        while (!bytes.empty()) {
            check_deadline();
            ERR_clear_error();
            std::size_t received = 0;
            const auto result = tls_
                ? SSL_read_ex(tls_.get(), bytes.data(), bytes.size(), &received)
                : BIO_read_ex(socket_.get(), bytes.data(), bytes.size(), &received);
            if (result == 1) bytes = bytes.subspan(received);
            else if (tls_) retry_tls(result, "TLS read failed or peer closed the connection");
            else retry_plain("TCP read failed or peer closed the connection");
        }
    }
private:
    Bio socket_;
    Context context_;
    Tls tls_; // Frees its BIO reference before socket_ is destroyed.
    std::string host_;
    Clock::time_point deadline_;
    std::function<bool()> cancelled_;
    std::chrono::seconds operation_timeout_;
    std::function<bool(const ServerCertificate&)> trust_certificate_;
    bool custom_ca_;
    void check_deadline() const {
        if (cancelled_ && cancelled_()) throw Cancelled();
        if (Clock::now() >= deadline_) throw TransportError("operation timed out");
    }
    void wait(bool for_read) {
        check_deadline();
        int fd = -1;
        if (BIO_get_fd(socket_.get(), &fd) < 0) ssl_error("transport has no socket");
        wait_socket(fd, for_read, deadline_, cancelled_);
        check_deadline();
    }
    void retry_plain(const char* operation) {
        if (!BIO_should_retry(socket_.get())) throw TransportError(operation);
        wait(BIO_should_read(socket_.get()) != 0);
    }
    void retry_tls(int result, const char* operation) {
        const auto error = SSL_get_error(tls_.get(), result);
        if (error == SSL_ERROR_WANT_READ) wait(true);
        else if (error == SSL_ERROR_WANT_WRITE) wait(false);
        else if (error == SSL_ERROR_SYSCALL || error == SSL_ERROR_ZERO_RETURN)
            throw TransportError(operation);
        else if (error == SSL_ERROR_SSL &&
                 ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            throw TransportError(operation);
        else ssl_error(operation);
    }
};

// One exclusive lease per request/stream; long-poll never occupies a control
// channel needed by heartbeats. Only a complete NAS reply can return a lease.
class Stream {
    std::shared_ptr<ConnectionPool> pool_;
    std::unique_ptr<Channel> channel_;
    std::string key_;
    std::time_t expires_ = 0;
public:
    explicit Stream(const Endpoint& endpoint) : pool_(endpoint.connections) {
        key_ = endpoint.host+":"+std::to_string(endpoint.port)+"\n"+endpoint.ca_file+
            "\n"+endpoint.proxy_host+":"+std::to_string(endpoint.proxy_port);
        if (endpoint.proxy_credentials) {
            const auto& p = *endpoint.proxy_credentials;
            key_ += "\n"+p.scheme+"\n"+p.username+"\n"+p.password+"\n"+p.domain+
                    "\n"+p.workstation+"\n"+std::to_string(p.ntlm_version);
        }
        {
            std::unique_lock lock(pool_->mutex);
            for (;;) {
                if (endpoint.cancelled && endpoint.cancelled()) throw Cancelled();
                const auto expired = std::erase_if(pool_->idle,[](const auto& entry) {
                    return entry.expires < std::time(nullptr);
                });
                pool_->channels -= expired;
                const auto found = std::find_if(pool_->idle.begin(),pool_->idle.end(),
                    [&](const auto& entry) { return entry.key == key_; });
                if (found != pool_->idle.end()) {
                    channel_ = std::move(found->channel);
                    pool_->idle.erase(found);
                    break;
                }
                // Connection setup gives the
                // encrypted protocol pool ten exclusive channel slots.
                if (pool_->channels < 10) { ++pool_->channels; break; }
                pool_->available.wait_for(lock,std::chrono::milliseconds{100});
            }
        }
        if (!channel_) {
            try { channel_ = std::make_unique<Channel>(endpoint); }
            catch (...) {
                std::lock_guard lock(pool_->mutex);
                --pool_->channels;
                pool_->available.notify_one();
                throw;
            }
        }
        channel_->configure(endpoint);
    }
    ~Stream() {
        std::lock_guard lock(pool_->mutex);
        if (expires_ && channel_->encrypted())
            pool_->idle.push_back({std::move(key_),std::move(channel_),expires_});
        else --pool_->channels;
        pool_->available.notify_one();
    }
    bool encrypted() const { return channel_->encrypted(); }
    void start_tls() { channel_->start_tls(); }
    void begin_operation() { channel_->begin_operation(); }
    void write_all(std::span<const std::uint8_t> bytes) {
        expires_ = 0;
        channel_->write_all(bytes);
    }
    void read_exact(std::span<std::uint8_t> bytes) { channel_->read_exact(bytes); }
    void response(const Value::Object& response) {
        const auto found = response.find("alive");
        const auto* seconds = found == response.end() ? nullptr : std::get_if<std::uint64_t>(&found->second.data);
        // the official agent unsigned decoding consumes the low 32 bits. Missing/zero closes the channel.
        const auto alive = seconds ? static_cast<std::uint32_t>(*seconds) : 0;
        expires_ = alive ? std::time(nullptr)+alive : 0;
    }
};

const Value::Object& object(const Value& value) {
    const auto* result = std::get_if<Value::Object>(&value.data);
    if (!result) throw Error("server response must be a map");
    return *result;
}

std::string_view server_error_description(std::uint64_t code) {
    // Confirmed by server 3.2.1 handlers; codes can cover multiple conditions.
    // Do not turn 4096 into "wrong password" or guess at unmapped codes.
    switch (code) {
    case 4096: return "Authentication denied: invalid account, missing credentials, or insufficient privileges";
    case 4100: return "The user account has expired";
    case 4101: return "A one-time password (OTP) is required";
    case 4102: return "The one-time password (OTP) is invalid";
    case 4103: return "OTP is enforced by the administrator";
    case 4106: return "User token or temporary device registration not found";
    case 4118: return "Active Backup for Business is managed by AEM";
    case 8193: return "Running backup task not found or task database lookup failed";
    case 28676: return "The server has not completed the backup";
    case 16385: return "The server requires a newer client version";
    case 53250: return "The server identity (ds_id) has changed";
    default: return {};
    }
}

Value read_response(Stream& stream, std::string_view action, pstream::Limits limits = {}) {
    // The official agent receiver ignores keep_alive messages before the actual reply.
    for (std::size_t i = 0; i < 256; ++i) {
        auto response = pstream::read([&](std::span<std::uint8_t> bytes) {
            stream.read_exact(bytes);
        }, limits);
        const auto& fields = object(response);
        auto type = fields.find("type");
        if (type != fields.end()) {
            auto* name = std::get_if<std::string>(&type->second.data);
            if (name && *name == "keep_alive") continue;
        }
        stream.response(fields);
        auto error = fields.find("error");
        if (error != fields.end()) {
            std::string message = "server rejected " + std::string(action);
            std::string server_message;
            std::optional<std::uint64_t> error_code;
            if (const auto* details = std::get_if<Value::Object>(&error->second.data)) {
                auto code = details->find("code");
                if (code != details->end())
                    if (const auto* number = std::get_if<std::uint64_t>(&code->second.data)) {
                        error_code = *number;
                        message += " (code " + std::to_string(*number) + ")";
                        const auto description = server_error_description(*number);
                        if (!description.empty()) message += ": " + std::string(description);
                    }
                // Raw NAS text stays out of user-facing messages; only the
                // official agent-format server-time log consumes it.
                if (const auto detail = details->find("message"); detail != details->end())
                    if (const auto* text = std::get_if<std::string>(&detail->second.data))
                        server_message = *text;
            }
            throw ServerError(message, error_code, server_message);
        }
        return response;
    }
    throw Error("too many keep_alive messages");
}

Value exchange(Stream& stream, std::string_view action, const Value& request) {
    if (action == "encrypt_channel" && stream.encrypted()) return Value{Value::Object{}};
    auto bytes = pstream::encode(request);
    // Auth requests contain passwords. Wipe the temporary serialized copy even
    // when a socket write fails.
    struct Wipe {
        pstream::Bytes& bytes;
        ~Wipe() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
    } wipe{bytes};
    stream.write_all(bytes);
    return read_response(stream, action);
}

Value exchange(Stream& stream, std::string_view action) {
    return exchange(stream, action, make_request(action));
}

std::string required_text(const Value::Object& fields, const char* key) {
    auto entry = fields.find(key);
    if (entry == fields.end()) throw Error(std::string("server response missing ") + key);
    auto* text = std::get_if<std::string>(&entry->second.data);
    if (!text || text->empty()) throw Error(std::string("invalid server response field: ") + key);
    return *text;
}

std::uint64_t required_number(const Value::Object& fields, const char* key) {
    auto entry = fields.find(key);
    if (entry == fields.end() || !std::holds_alternative<std::uint64_t>(entry->second.data))
        throw Error(std::string("server response missing or invalid ") + key);
    return std::get<std::uint64_t>(entry->second.data);
}

void verify_identity(const Endpoint& endpoint, const SavedAuth& auth) {
    if (auth.token.empty() || auth.ds_id.empty() || auth.device_uuid.empty() || auth.username.empty())
        throw Error("saved authentication identity is incomplete; log in again");
    std::lock_guard lock(endpoint.connections->identity_mutex);
    const auto key = endpoint.host+":"+std::to_string(endpoint.port);
    const auto known = endpoint.connections->identities.find(key);
    if (known != endpoint.connections->identities.end() && known->second == auth.ds_id) return;
    const auto info = probe(endpoint);
    if (required_text(object(info), "ds_id") != auth.ds_id)
        throw Error("server identity (ds_id) differs from the saved session; token was not sent");
    endpoint.connections->identities[key] = auth.ds_id;
}

Value authenticated_request(std::string_view action, const SavedAuth& auth) {
    auto request = make_request(action);
    auto& fields = std::get<Value::Object>(request.data);
    fields["token"] = Value{auth.token_value ? auth.token_value() : auth.token};
    fields["ds_id"] = Value{auth.ds_id};
    return request;
}

Value backup_control(const Endpoint& endpoint, const SavedAuth& auth, const Value& request,
                     std::string_view operation, const std::function<void()>& before_send) {
    if (!before_send) throw Error("backup operation requires a durable before-send callback");
    // Validate local request bounds before acquiring a server-side resource.
    pstream::encode(request);
    verify_identity(endpoint, auth);
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    before_send();
    stream.begin_operation();
    return exchange(stream, operation, request);
}

void validate_run(const BackupRun& run) {
    if (!run.running_task_id || !run.version_id || !run.result_id)
        throw Error("backup operation requires running task, version, and result IDs");
}

std::string_view outcome_text(BackupOutcome outcome) {
    switch (outcome) {
    case BackupOutcome::complete: return "complete";
    case BackupOutcome::partial: return "partial";
    case BackupOutcome::cancelled: return "cancel";
    case BackupOutcome::error: return "error";
    }
    throw Error("invalid backup outcome");
}
} // namespace

ConnectionPool::~ConnectionPool() = default;
std::shared_ptr<ConnectionPool> make_connection_pool() { return std::make_shared<ConnectionPool>(); }

pstream::Value make_request(std::string_view action) {
    return Value{Value::Object{
        // Request metadata uses "_agent" internally, but map serialization
        // strips one leading underscore from keys. Values here model wire keys.
        {"agent", Value{Value::Object{
            {"version", Value{Value::Object{
                {"major", Value{std::uint64_t{3}}},
                {"minor", Value{std::uint64_t{2}}},
                {"mini", Value{std::uint64_t{1}}},
                {"build", Value{std::string("5059")}},
            }}},
        }}},
        {"action", Value{std::string(action)}},
    }};
}

pstream::Value probe(const Endpoint& endpoint) {
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    return exchange(stream, "query_server_info");
}

LoginResult login(const Endpoint& endpoint, const LoginCredentials& credentials) {
    if (credentials.username.empty() || credentials.password.empty() ||
        credentials.device_uuid.empty())
        throw Error("username, password, and device identity are required");
    const auto info = probe(endpoint);
    const auto ds_id = required_text(object(info), "ds_id");
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    auto request = make_request("auth");
    auto& fields = std::get<Value::Object>(request.data);
    fields["username"] = Value{credentials.username};
    fields["password"] = Value{credentials.password};
    fields["otp"] = Value{credentials.otp};
    fields["device_uuid"] = Value{credentials.device_uuid};
    fields["host_name"] = Value{credentials.host_name};
    fields["os_name"] = Value{credentials.os_name};
    // OpenSabba has no active snapshot provider. The official Linux agent hardcodes "enable";
    // advertising that would incorrectly claim driver availability.
    fields["driver_status"] = Value{std::string("disable")};
    struct Wipe {
        Value::Object& fields;
        ~Wipe() {
            for (auto key : {"password", "otp"}) {
                auto& text = std::get<std::string>(fields.at(key).data);
                OPENSSL_cleanse(text.data(), text.size());
            }
        }
    } wipe{fields};
    const auto response = exchange(stream, "auth", request);
    const auto& result = object(response);
    LoginResult login_result{required_text(result, "token"), ds_id,
                             required_number(result, "auth_type"), {}, {}, {}};
    if (login_result.auth_type != 5) {
        auto device = result.find("temp_device");
        if (device == result.end()) throw Error("pending authentication response missing temp_device");
        login_result.backup_type = required_number(object(device->second), "backup_type");
        Value::Object display;
        // Daemon copies the saved server name (the connect address).
        display.emplace("server_name",Value{endpoint.host});
        Value::Object display_device{{"backup_type",Value{*login_result.backup_type}}};
        const auto& device_fields = object(device->second);
        if (device_fields.contains("user_name")) display_device.emplace("user_name",device_fields.at("user_name"));
        display.emplace("temp_device",Value{std::move(display_device)});
        for (const auto key : {"cms_managed","scope"})
            if (result.contains(key)) display.emplace(key,result.at(key));
        login_result.confirmation_display = Value{std::move(display)};
        auto task = result.find("task_template");
        if (task != result.end() && !std::holds_alternative<std::monostate>(task->second.data)) {
            const auto& template_fields = object(task->second);
            Value::Object selected;
            // Only preserve/display known template fields, never arbitrary auth data.
            for (auto key : {"id", "template_name", "source_type", "share_name", "custom_volume",
                             "sched_content", "retention_policy", "bandwidth_content",
                             "enable_compress_transfer", "enable_encrypt_transfer",
                             "storage_compress", "storage_encrypt", "enable_verification",
                             "pre_post_script_setting", "users_permissioned_by_name",
                             "groups_permissioned_by_name"}) {
                auto item = template_fields.find(key);
                if (item != template_fields.end()) selected.emplace(key, item->second);
            }
            required_number(template_fields, "id");
            login_result.task_template = Value{std::move(selected)};
            pstream::encode(login_result.task_template, {65536, 4096, 16});
        }
        std::get<Value::Object>(login_result.confirmation_display.data).emplace("task_template",login_result.task_template);
    }
    return login_result;
}

void confirm_registration(const Endpoint& endpoint, const SavedAuth& auth,
                          const DeviceMetadata& device, const Registration& registration,
                          const std::function<void()>& before_send) {
    if (registration.connect_type != "backup" && registration.connect_type != "restore")
        throw Error("connection type must be backup or restore");
    verify_identity(endpoint, auth);
    auto request = authenticated_request("confirm_auth", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["backup_type"] = Value{registration.backup_type};
    fields["template_id"] = Value{registration.template_id};
    fields["connect_type"] = Value{registration.connect_type};
    fields["driver_status"] = Value{std::string("disable")};
    fields["time_zone"] = Value{static_cast<std::uint64_t>(static_cast<std::int64_t>(device.time_zone))};
    fields["kernel_version"] = Value{device.kernel_version};
    fields["dsm_model"] = Value{std::string{}};
    fields["dsm_unique"] = Value{std::string{}};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    before_send();
    exchange(stream, "confirm_auth", request);
}

TokenResult reconnect(const Endpoint& endpoint, const SavedAuth& auth, const DeviceMetadata& device,
                      DriverStatus driver, bool initialize) {
    verify_identity(endpoint, auth);
    auto request = authenticated_request("auth", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["username"] = Value{auth.username};
    fields["device_uuid"] = Value{auth.device_uuid};
    fields["host_name"] = Value{device.host_name};
    fields["os_name"] = Value{device.os_name};
    fields["kernel_version"] = Value{device.kernel_version};
    // First token authentication identifies a new agent process to the NAS.
    fields["init"] = Value{std::uint64_t{initialize}};
    fields["driver_status"] = Value{std::string(driver == DriverStatus::enabled ? "enable" : "disable")};
    fields["time_zone"] = Value{static_cast<std::uint64_t>(static_cast<std::int64_t>(device.time_zone))};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "auth", request);
    const auto& result = object(response);
    // auth_type == 5 is a password-login shortcut, not the success criterion
    // for token authentication. The official agent token authentication accepts a successful
    // response and consumes its token and ds_id without testing auth_type.
    const auto ds_id = required_text(result, "ds_id");
    if (ds_id != auth.ds_id) throw Error("token authentication returned a different server identity");
    return {required_text(result, "token"), ds_id};
}

void unlink_connection(const Endpoint& endpoint, const SavedAuth& auth) {
    verify_identity(endpoint, auth);
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    exchange(stream, "unlink_connection", authenticated_request("unlink_connection", auth));
}

void authorize_logout(const Endpoint& endpoint, const SavedAuth& auth, const LoginCredentials& credentials) {
    verify_identity(endpoint, auth);
    auto request = authenticated_request("auth_admin", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["username"] = Value{credentials.username};
    fields["password"] = Value{credentials.password};
    fields["otp"] = Value{credentials.otp};
    struct Wipe {
        Value::Object& fields;
        ~Wipe() {
            for (const auto key : {"password", "otp"}) {
                auto& value = std::get<std::string>(fields.at(key).data);
                OPENSSL_cleanse(value.data(), value.size());
            }
        }
    } wipe{fields};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    exchange(stream, "auth_admin", request);
}

ServerTime get_server_time(const Endpoint& endpoint, const SavedAuth& auth) {
    auto timed = endpoint;
    timed.timeout = std::chrono::seconds{10};
    verify_identity(timed, auth);
    Stream stream(timed);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto before = std::time(nullptr);
    const auto reply = exchange(stream, "get_timezone", authenticated_request("get_timezone", auth));
    const auto after = std::time(nullptr);
    return server_time_reply(reply,before,after);
}

void heartbeat(const Endpoint& endpoint, const SavedAuth& auth, DriverStatus driver) {
    verify_identity(endpoint, auth);
    auto request = authenticated_request("heart_beat", auth);
    std::get<Value::Object>(request.data)["driver_status"] = Value{std::string(driver == DriverStatus::enabled ? "enable" : "disable")};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    exchange(stream, "heart_beat", request);
}

namespace {
// Keep credentials, script contents, and restore payloads out of CLI output.
Value::Object select_fields(const Value& source,
                            std::initializer_list<const char*> numbers,
                            std::initializer_list<const char*> strings) {
    const auto& fields = object(source);
    Value::Object selected;
    for (auto key : numbers) {
        auto item = fields.find(key);
        if (item == fields.end()) continue;
        if (!std::holds_alternative<std::uint64_t>(item->second.data))
            throw Error(std::string("invalid numeric task field: ") + key);
        selected.emplace(key, item->second);
    }
    for (auto key : strings) {
        auto item = fields.find(key);
        if (item == fields.end()) continue;
        if (!std::holds_alternative<std::string>(item->second.data))
            throw Error(std::string("invalid text task field: ") + key);
        selected.emplace(key, item->second);
    }
    return selected;
}

Value::Array task_list(const Endpoint& endpoint, const SavedAuth& auth, bool running, bool scripts = false) {
    verify_identity(endpoint, auth);
    const auto action = running ? "get_running_task" : "get_task";
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, action, authenticated_request(action, auth));
    const auto& fields = object(response);
    auto entry = fields.find(running ? "running_task_list" : "task_list");
    // Server get-task handler creates task_list only inside its per-task loop.
    if (!running && entry == fields.end()) return {};
    if (entry == fields.end() || !std::holds_alternative<Value::Array>(entry->second.data))
        throw Error("server response missing a valid task list");
    Value::Array result;
    for (const auto& item : std::get<Value::Array>(entry->second.data)) {
        const auto& source = object(item);
        required_number(source, "id");
        Value::Object selected;
        if (running) {
            required_number(source, "task_id");
            selected = select_fields(item,
                {"id", "type", "task_id", "device_id", "version_id", "job_id", "result_id",
                 "bandwidth", "create_time", "start_time", "trigger_uid", "status", "detail_status"}, {});
            if (required_number(source, "type") == 1)
                selected.emplace("file_restore_task", file_restore_task(item));
            auto backup = source.find("backup_task");
            if (backup != source.end()) {
                selected.emplace("backup_task", Value{select_fields(backup->second,
                    {"total_size", "current_size", "error_code", "trigger_type", "trigger_event"},
                    {"task_name", "task_uuid"})});
            }
        } else {
            required_text(source, "name");
            selected = select_fields(item,
                {"id", "backup_type", "source_type", "backup_external", "encryption",
                 "compression", "app_aware_bkp", "last_backup_success_time", "is_paused", "cached_enabled",
                 "cached_volume_space_lower_bound_unit", "cached_volume_space_lower_bound_value"},
                {"name", "task_uuid", "sched_content", "cached_mount_path", "cached_volume_name"});
            selected.merge(task_script_policy(item));
            if (scripts) selected.merge(task_script_execution_policy(item));
            for (auto key : {"custom_volume", "custom_volume_alias"}) {
                auto volumes = source.find(key);
                if (volumes == source.end()) continue;
                // Server initializes these as null and allocates an array on
                // the first selected volume, so null means an empty selection.
                if (std::holds_alternative<std::monostate>(volumes->second.data)) {
                    selected.emplace(key, Value{Value::Array{}});
                    continue;
                }
                const auto* array = std::get_if<Value::Array>(&volumes->second.data);
                if (!array) throw Error(std::string("invalid volume list: ") + key);
                for (const auto& volume : *array)
                    if (!std::holds_alternative<std::string>(volume.data))
                        throw Error(std::string("invalid volume name: ") + key);
                selected.emplace(key, volumes->second);
            }
        }
        result.push_back(Value{std::move(selected)});
    }
    return result;
}
} // namespace

Value::Array tasks(const Endpoint& endpoint, const SavedAuth& auth) {
    return task_list(endpoint, auth, false);
}
Value::Array execution_tasks(const Endpoint& endpoint, const SavedAuth& auth) {
    return task_list(endpoint,auth,false,true);
}
void update_backup_cache_policy(const Endpoint& endpoint, const SavedAuth& auth, const Value& task) {
    verify_identity(endpoint,auth);
    auto request = authenticated_request("update_cached_setting",auth);
    auto& fields = std::get<Value::Object>(request.data);
    const auto& source = object(task);
    fields["task_id"] = Value{required_number(source,"id")};
    for (const auto key : {"cached_enabled","cached_mount_path","cached_volume_name",
            "cached_volume_space_lower_bound_unit","cached_volume_space_lower_bound_value","is_paused"})
        fields[key] = source.at(key);
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel");
    stream.start_tls();
    (void)exchange(stream,"backup cache setting translation",request);
}
void report_script_activity(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
    std::uint64_t log_type, std::uint64_t log_time, const std::string& parameters) {
    verify_identity(endpoint,auth);
    auto request = authenticated_request("log_report",auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("result_detail")};
    fields["logs"] = Value{Value::Array{Value{Value::Object{
        {"running_task_id",Value{run}},{"log_type",Value{log_type}},
        {"log_time",Value{log_time}},{"other_params",Value{parameters}}}}}};
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel"); stream.start_tls();
    exchange(stream,"script result detail",request);
}
void upload_script_output(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t task,
    std::uint64_t version, bool pre, std::span<const std::uint8_t> output) {
    verify_identity(endpoint,auth);
    auto request = authenticated_request("log_report",auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("script_log")};
    fields["logs"] = Value{Value::Array{Value{Value::Object{
        {"task_id",Value{task}},{"version_id",Value{version}},
        {"output_source",Value{std::string(pre ? "pre" : "post")}},
        {"output",Value{pstream::Bytes(output.begin(),output.end())}}}}}};
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel"); stream.start_tls();
    exchange(stream,"script output",request);
}
void report_script_upload_error(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t log_time) {
    verify_identity(endpoint,auth);
    auto request = authenticated_request("log_report",auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("activity_log")};
    fields["logs"] = Value{Value::Array{Value{Value::Object{
        {"task_id",Value{std::uint64_t{0}}},{"log_type",Value{std::uint64_t{7067}}},
        {"log_time",Value{log_time}},{"other_params",Value{std::string("null")}}}}}};
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel"); stream.start_tls();
    exchange(stream,"script output failure activity",request);
}
Value::Array running_tasks(const Endpoint& endpoint, const SavedAuth& auth) {
    return task_list(endpoint, auth, true);
}
std::optional<BackupEventState> backup_event_state(const Endpoint& endpoint, const SavedAuth& auth,
                                                  std::uint64_t task, std::uint64_t run) {
    verify_identity(endpoint,auth);
    auto request = authenticated_request("get_running_task",auth);
    std::get<Value::Object>(request.data)["check_backup_exist"] = Value{std::uint64_t{1}};
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel"); stream.start_tls();
    const auto response = exchange(stream,"backup event recovery",request);
    const auto& list = std::get<Value::Array>(object(response).at("running_task_list").data);
    std::optional<BackupEventState> result;
    for (const auto& entry : list) {
        const auto& job = object(entry);
        if (required_number(job,"id") != run) continue;
        if (result || required_number(job,"type") != 0 || required_number(job,"task_id") != task)
            throw Error("NAS recovery event differs from the saved backup");
        const auto& backup = object(job.at("backup_task"));
        result = BackupEventState{
            {run,required_number(job,"version_id"),required_number(job,"result_id"),
             required_number(backup,"data_format")},
            required_number(job,"status"),required_number(backup,"error_code"),
            job.contains("is_backing_up") && required_number(job,"is_backing_up") != 0,
            std::get<std::string>(backup.at("resume_info").data)};
    }
    return result;
}
bool events_pending(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t last_event_id) {
    verify_identity(endpoint, auth);
    auto request = authenticated_request("long_poll", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["timeout"] = Value{std::uint64_t{400}};
    // A delivered cursor suppresses repeated wakeups; held IDs still prevent redelivery.
    fields["last_event_id"] = Value{last_event_id};
    auto polling = endpoint;
    // Long polling sends timeout=400 with request handling's
    // independent 600-second transport deadline. CLI timeout remains bounded
    // separately; this internal subscription outlives a backup queue tick.
    polling.timeout = std::chrono::seconds{600};
    Stream stream(polling);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "long_poll", request);
    const auto& result = object(response);
    const auto value = required_number(result, "has_event");
    if (value > 1) throw Error("invalid long_poll has_event flag");
    return value == 1;
}

namespace {
Value event_request(const Endpoint& endpoint, const SavedAuth& auth,
                    const char* action, const char* key, const Value::Array& ids) {
    verify_identity(endpoint, auth);
    auto request = authenticated_request(action, auth);
    std::get<Value::Object>(request.data)[key] = Value{ids};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    return exchange(stream, action, request);
}
}
Value::Array pull_events(const Endpoint& endpoint, const SavedAuth& auth, const Value::Array& held_ids) {
    const auto response = event_request(endpoint, auth, "pull_event", "event_list", held_ids);
    const auto& fields = object(response);
    const auto found = fields.find("event_list");
    if (found == fields.end()) throw Error("pull_event response missing event_list");
    // Server initializes a null value, converting it to an array on first append.
    if (std::holds_alternative<std::monostate>(found->second.data)) return {};
    const auto* list = std::get_if<Value::Array>(&found->second.data);
    if (!list) throw Error("pull_event response has invalid event_list");
    return *list;
}
void done_events(const Endpoint& endpoint, const SavedAuth& auth, const Value::Array& ids) {
    if (ids.empty()) return;
    event_request(endpoint, auth, "done_event", "done_events", ids);
}
void report_client_nodes(const Endpoint& endpoint, const SavedAuth& auth, const Value& result) {
    verify_identity(endpoint,auth);
    validate_client_node_result(result);
    const auto& fields = object(result);
    auto request = authenticated_request("act_client_result",auth);
    auto& output = std::get<Value::Object>(request.data);
    for (const auto* key : {"event_id","error_code"})
        output.emplace(key,fields.at(key));
    if (fields.contains("node_list")) output.emplace("node_list",fields.at("node_list"));
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel");
    stream.start_tls();
    exchange(stream,"act_client_result",request);
}
std::optional<std::uint64_t> backup_bandwidth(const Endpoint& endpoint, const SavedAuth& auth) {
    verify_identity(endpoint,auth);
    Stream control(endpoint);
    exchange(control,"encrypt_channel");
    control.start_tls();
    const auto response = exchange(control,"get_backup_bandwidth",
        authenticated_request("get_backup_bandwidth",auth));
    const auto& policy = object(response);
    if (!policy.contains("backup_bandwidth")) return {};
    return required_number(policy,"backup_bandwidth");
}
std::uint64_t backup_base_version(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t task_id) {
    if (!task_id) throw Error("base selection requires an assigned task ID");
    verify_identity(endpoint, auth);
    auto request = authenticated_request("client_trigger", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("get_base_version")};
    fields["task_id"] = Value{task_id};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "incremental base selection", request);
    // Base selection / uses signed 32-bit decoding:
    // absent, null and non-integer members have the value zero.
    const auto& values = object(response);
    const auto selected = values.find("base_version_id");
    const auto* integer = selected == values.end() ? nullptr : std::get_if<std::uint64_t>(&selected->second.data);
    return integer ? static_cast<std::uint32_t>(*integer) : 0;
}

static BackupRun create_backup(const Endpoint& endpoint, const SavedAuth& auth,
                             std::uint64_t task_id, std::uint64_t base_version,
                             const std::function<void()>& before_send) {
    if (!task_id) throw Error("an assigned backup task ID is required");
    auto request = authenticated_request("client_trigger", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("add_backup_task")};
    fields["task_id"] = Value{task_id};
    fields["trigger_type"] = Value{endpoint.backup_trigger_type};
    fields["base_version_id"] = Value{base_version};
    fields["is_cbt"] = Value{std::uint64_t{base_version != 0}};
    fields["is_cache"] = Value{std::uint64_t{endpoint.cached_backup}};
    fields["check_point_backup"] = Value{std::uint64_t{0}};
    const auto response = backup_control(endpoint, auth, request, "backup creation", before_send);
    const auto& result = object(response);
    BackupRun run{required_number(result, "running_task_id"), required_number(result, "version_id"),
                  required_number(result, "result_id"), required_number(result, "data_format")};
    validate_run(run);
    return run;
}
BackupRun create_full_backup(const Endpoint& endpoint, const SavedAuth& auth,
                             std::uint64_t task, const std::function<void()>& before) {
    return create_backup(endpoint, auth, task, 0, before);
}
BackupRun create_incremental_backup(const Endpoint& endpoint, const SavedAuth& auth,
                                    std::uint64_t task, std::uint64_t base,
                                    const std::function<void()>& before) {
    if (!base || base > INT32_MAX) throw Error("invalid incremental base version");
    if (!endpoint.cached_backup && backup_base_version(endpoint, auth, task) != base)
        throw Error("NAS-selected base changed before incremental backup creation");
    return create_backup(endpoint, auth, task, base, before);
}

static BackupRun prepare_backup(const Endpoint& endpoint, const SavedAuth& auth,
                              std::uint64_t running_task_id, std::uint64_t base,
                              const std::function<void()>& before_send) {
    if (!running_task_id) throw Error("a NAS-created running task ID is required");
    auto request = authenticated_request("client_trigger", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("update_backup_task")};
    fields["running_task_id"] = Value{running_task_id};
    fields["base_version_id"] = Value{base};
    fields["is_cbt"] = Value{std::uint64_t{base != 0}};
    fields["is_cache"] = Value{std::uint64_t{endpoint.cached_backup}};
    fields["check_point_backup"] = Value{std::uint64_t{0}};
    const auto response = backup_control(endpoint, auth, request, "backup preparation", before_send);
    const auto& result = object(response);
    BackupRun run{required_number(result, "running_task_id"), required_number(result, "version_id"),
                  required_number(result, "result_id"), required_number(result, "data_format")};
    validate_run(run);
    if (run.running_task_id != running_task_id)
        throw Error("server returned a different running task ID");
    return run;
}

BackupRun prepare_full_backup(const Endpoint& endpoint, const SavedAuth& auth,
                              std::uint64_t run, const std::function<void()>& before) {
    return prepare_backup(endpoint, auth, run, 0, before);
}
BackupRun prepare_incremental_backup(const Endpoint& endpoint, const SavedAuth& auth,
                                     std::uint64_t task, std::uint64_t run, std::uint64_t base,
                                     const std::function<void()>& before) {
    if (!base || base > INT32_MAX) throw Error("invalid incremental base version");
    if (!endpoint.cached_backup && backup_base_version(endpoint, auth, task) != base)
        throw Error("NAS-selected base changed before incremental backup preparation");
    return prepare_backup(endpoint, auth, run, base, before);
}

void upload_backup_spec(const Endpoint& endpoint, const SavedAuth& auth, const BackupRun& run,
                        std::span<const std::uint8_t> snapshot_json,
                        const std::function<void()>& before_send, bool resume) {
    validate_run(run);
    if (snapshot_json.empty() || snapshot_json.size() > 8 * 1024 * 1024 ||
        std::find(snapshot_json.begin(), snapshot_json.end(), 0) != snapshot_json.end())
        throw Error("snapshot JSON must be nonempty, NUL-free and at most 8 MiB");
    auto request = authenticated_request("backup", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("update_device_spec")};
    fields["running_task_id"] = Value{run.running_task_id};
    fields["resume"] = Value{std::uint64_t{resume}};
    fields["enable_app_aware"] = Value{std::uint64_t{endpoint.backup_app_aware && run.data_format != 2}};
    fields["snapshot_info"] = Value{pstream::Bytes(snapshot_json.begin(), snapshot_json.end())};
    // The official agent server returns an empty map here. There is no success flag.
    backup_control(endpoint, auth, request, "backup metadata upload", before_send);
}

BackupOutcome finish_backup(const Endpoint& endpoint, const SavedAuth& auth, const BackupRun& run,
                            BackupOutcome requested, const std::function<void()>& before_send, bool incremental) {
    validate_run(run);
    auto request = authenticated_request("backup", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("check_complete")};
    fields["running_task_id"] = Value{run.running_task_id};
    fields["result_id"] = Value{run.result_id};
    fields["is_cbt"] = Value{std::uint64_t{incremental}};
    fields["status"] = Value{std::string(outcome_text(requested))};
    const auto response = backup_control(endpoint, auth, request, "backup completion", before_send);
    const auto status = required_text(object(response), "status");
    for (auto outcome : {BackupOutcome::complete, BackupOutcome::partial,
                         BackupOutcome::cancelled, BackupOutcome::error})
        if (status == outcome_text(outcome)) return outcome;
    throw Error("server returned an unknown backup completion status");
}

void upload_prepared_image(const Endpoint& endpoint, const SavedAuth& auth,
                           std::uint64_t running_task_id, const std::filesystem::path& path,
                           std::string_view name, std::size_t block_size) {
    ImageSource source(path);
    upload_prepared_image(endpoint, auth, running_task_id, source, name, block_size);
}
void upload_prepared_image(const Endpoint& endpoint, const SavedAuth& auth,
                           std::uint64_t running_task_id, ImageSource& source,
                           std::string_view name, std::size_t block_size,
                           std::optional<std::uint64_t> resume_offset,
                           const std::function<void(std::uint64_t)>& sent,
                           TransferCompression compression, const DeltaPlan* delta,
                           std::span<const ChangedExtent> unused_ranges,
                           std::span<const ChangedExtent> reread_ranges,
                           std::uint64_t resume_transferred) {
    const UploadImage image{&source,std::string(name),resume_offset,sent,compression,delta,
        {unused_ranges.begin(),unused_ranges.end()},{reread_ranges.begin(),reread_ranges.end()},resume_transferred};
    upload_prepared_images(endpoint,auth,running_task_id,std::span(&image,1),block_size);
}
void upload_prepared_images(const Endpoint& endpoint, const SavedAuth& auth,
                            std::uint64_t running_task_id, std::span<const UploadImage> images,
                            std::size_t block_size) {
    if (!running_task_id) throw Error("a prepared running task ID is required");
    if (images.empty()) throw Error("upload requires at least one prepared image");
    std::set<std::string> names;
    bool resuming = false;
    for (const auto& image : images) {
        validate_image_options(image.name,block_size);
        if (!names.insert(image.name).second) throw Error("duplicate upload image name");
        if (image.delta) {
            validate_delta_plan(*image.delta,image.source->size());
            validate_reread_ranges(image.reread_ranges,*image.delta);
        }
        verify_unused_source(*image.source,image.unused_ranges);
        image.source->verify_unchanged();
        resuming |= image.resume_offset.has_value();
    }
    verify_identity(endpoint, auth);
    auto init = authenticated_request("backup", auth);
    auto& fields = std::get<Value::Object>(init.data);
    fields["subaction"] = Value{std::string("upload_block")};
    fields["running_task_id"] = Value{running_task_id};
    fields["is_cache"] = Value{std::uint64_t{endpoint.cached_backup}};
    fields["resume"] = Value{std::uint64_t{resuming}};
    Stream stream(endpoint);
    if (endpoint.backup_encryption) {
        exchange(stream, "encrypt_channel");
        stream.start_tls();
    }
    const auto response = exchange(stream, "backup upload initialization", init);
    if (required_number(object(response), "success") != 1)
        throw Error("server did not accept image upload initialization");
    const auto& reply = object(response);
    auto& bandwidth = *endpoint.backup_bandwidth_policy;
    if (reply.contains("backup_bandwidth"))
        bandwidth.update(required_number(reply,"backup_bandwidth"));
    auto& statistics = *endpoint.backup_performance;
    if (statistics.running_task_id && statistics.running_task_id != running_task_id) {
        statistics.pending.clear();
        statistics.snapshot_nanoseconds = 0;
    }
    statistics.running_task_id = running_task_id;
    auto& performance = statistics.pending;
    const auto add_performance = [&](const char* type, std::uint64_t time, std::uint64_t size) {
        auto entry = performance.try_emplace(type,Value{Value::Object{
            {"size",Value{std::uint64_t{0}}},{"time",Value{std::uint64_t{0}}}}}).first;
        auto& counters = std::get<Value::Object>(entry->second.data);
        std::get<std::uint64_t>(counters.at("time").data) += time;
        std::get<std::uint64_t>(counters.at("size").data) += size;
    };
    if (statistics.snapshot_nanoseconds) {
        add_performance("snapshot",statistics.snapshot_nanoseconds,0);
        statistics.snapshot_nanoseconds = 0;
    }
    const auto send_performance = [&] {
        if (performance.empty()) return;
        auto pending = std::move(performance);
        performance.clear();
        stream.begin_operation();
        stream.write_all(pstream::encode(Value{Value::Object{
            {"performance",Value{std::move(pending)}}}}));
    };
    // The backup context sums every image transfer_length and counts prepared,
    // uncompressed payload bytes. These counters are independent of durable
    // logical offsets, compression and the journal save cadence.
    std::uint64_t current = 0, total = 0;
    for (const auto& image : images) {
        total += image.delta ? image.delta->transfer_bytes : image.source->size();
        current += image.resume_transferred;
    }
    current = std::min(current,total);
    endpoint.service_status->backup_transfer(current,total);
    std::time_t performance_sent_at = 0;
    for (const auto& image : images) {
    auto delta = image.delta;
    const auto& unused = image.unused_ranges;
    stream_image(*image.source, image.name, block_size, [&](const Value& block) {
        const auto& fields = object(block);
        if (fields.contains("buffer"))
            current += std::min(required_number(fields,"length"),total-current);
        endpoint.service_status->backup_transfer(current,total);
        const auto started = std::chrono::system_clock::now();
        const auto rate = bandwidth.rate();
        UploadPacing pacing;
        pacing.started = UploadPacing::Clock::now();
        const auto bytes = pstream::encode(block);
        paced_upload(bytes,rate,[&](auto part) {
            // Intentional pacing must not consume the socket's I/O deadline.
            stream.begin_operation();
            stream.write_all(part);
        },endpoint.cancelled,std::move(pacing));
        if (fields.contains("buffer")) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now()-started).count();
            add_performance("send",static_cast<std::uint64_t>(elapsed),required_number(fields,"length"));
        }
        const auto now = std::time(nullptr);
        if (performance_sent_at+5 <= now) {
            performance_sent_at = now;
            send_performance();
        }
        if (image.sent) {
            image.sent(required_number(fields, "offset") + required_number(fields, "length"));
        }
    }, endpoint.cancelled, image.resume_offset.value_or(0), image.compression, delta,
        unused, image.reread_ranges,
        [&](auto elapsed, auto size) { add_performance("read_disk",elapsed,size); },endpoint.source_read_activity);
    image.source->verify_unchanged();
    }
    send_performance();
    stream.begin_operation();
    const auto closed = exchange(stream, "backup upload close",
        Value{Value::Object{{"close", Value{std::uint64_t{1}}}}});
    if (required_number(object(closed), "close") != 1)
        throw Error("server did not confirm upload channel closure");
}
std::uint64_t restore_device(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t task_id) {
    if (!task_id) throw Error("restore requires a backup task ID");
    verify_identity(endpoint, auth);
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "restore task discovery", authenticated_request("list_device_task", auth));
    const auto& fields = object(response);
    const auto entry = fields.find("tasks");
    if (entry == fields.end() || !std::holds_alternative<Value::Array>(entry->second.data))
        throw Error("server response missing restore tasks");
    std::uint64_t device_id = 0;
    for (const auto& item : std::get<Value::Array>(entry->second.data)) {
        const auto& task = object(item);
        if (required_number(task, "task_id") != task_id) continue;
        const auto device = task.find("device_info");
        if (device == task.end()) throw Error("restore task missing device identity");
        const auto& info = object(device->second);
        if (required_text(info, "device_uuid") != auth.device_uuid)
            throw Error("restore task belongs to a different device");
        if (device_id) throw Error("server returned an ambiguous restore task");
        device_id = required_number(info, "device_id");
        if (!device_id) throw Error("server returned an invalid restore device ID");
    }
    if (!device_id) throw Error("saved backup task is not available for restore");
    return device_id;
}

pstream::Value restore_versions(const Endpoint& endpoint, const SavedAuth& auth,
                                std::uint64_t task_id, std::uint64_t offset,
                                std::uint64_t limit) {
    if (!task_id || task_id > INT32_MAX || offset > INT32_MAX ||
        !limit || limit > 50 || offset > INT32_MAX - limit)
        throw Error("restore catalog requires a task ID, offset and page size within supported bounds");
    const auto device_id = restore_device(endpoint, auth, task_id);
    auto request = authenticated_request("list_task_version", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["task_id"] = Value{task_id};
    fields["device_id"] = Value{device_id};
    fields["filter"] = Value{Value::Object{
        {"offset",Value{offset}}, {"limit",Value{limit}},
        // Recovery wizard initial and subsequent pages use newest start time first.
        {"order_by",Value{std::string("time_start")}},
        {"direction",Value{std::string("DESC")}},
        {"version_status",Value{Value::Array{Value{std::uint64_t{3}}}}}}};
    verify_identity(endpoint, auth);
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "restore version catalog", request);
    const auto& reply = object(response);
    const auto total = required_number(reply, "total");
    if (total > INT32_MAX)
        throw Error("NAS returned invalid restore catalog pagination");
    const auto entry = reply.find("versions");
    if (entry == reply.end() || !std::holds_alternative<Value::Array>(entry->second.data))
        throw Error("NAS response missing a valid restore version list");
    const auto& source = std::get<Value::Array>(entry->second.data);
    if (source.size() > limit) throw Error("NAS returned more versions than requested");
    Value::Array versions;
    std::set<std::uint64_t> seen;
    for (const auto& item : source) {
        const auto& record = object(item);
        const auto id = required_number(record, "version_id");
        if (!id || id > INT32_MAX || !seen.insert(id).second)
            throw Error("invalid or duplicate NAS version identifier");
        Value::Object selected{{"version_id",Value{id}}};
        for (auto key : {"status", "time_start", "time_end", "used_size", "full_backup"})
            selected.emplace(key,Value{required_number(record,key)});
        versions.push_back(Value{std::move(selected)});
    }
    if (versions.size() > total || (offset < total && versions.empty()) ||
        (offset >= total && !versions.empty()) ||
        (offset < total && versions.size() > total-offset))
        throw Error("NAS returned inconsistent restore catalog totals");
    return Value{Value::Object{
        {"task_id",Value{task_id}}, {"device_id",Value{device_id}},
        {"offset",Value{offset}}, {"limit",Value{limit}},
        {"total",Value{total}}, {"versions",Value{versions}}}};
}

std::uint64_t create_image_restore(const Endpoint& endpoint, const SavedAuth& auth,
                                  std::uint64_t task_id, std::uint64_t device_id,
                                  std::uint64_t version_id, const std::function<void()>& before_send) {
    if (!task_id || !device_id || !version_id) throw Error("restore requires task, device and version IDs");
    auto request = authenticated_request("image_restore", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["task_id"] = Value{task_id};
    fields["device_id"] = Value{device_id};
    fields["version_id"] = Value{version_id};
    fields["device_uuid"] = Value{auth.device_uuid};
    fields["restore_mode"] = Value{std::uint64_t{1}}; // Server maps to FULL (restore_type 1).
    const auto response = backup_control(endpoint, auth, request, "restore creation", before_send);
    const auto run = required_number(object(response), "running_task_id");
    if (!run) throw Error("server returned an invalid restore running task ID");
    return run;
}

void download_restore_image(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
                            std::string_view name, std::uint64_t size,
                            const std::function<void(std::span<const std::uint8_t>)>& receive,
                            const std::function<void()>& before_close, std::uint64_t start_offset,
                            const std::function<void()>& validate_offline_resume) {
    constexpr std::size_t block_size = 1024 * 1024;
    validate_image_options(name, block_size);
    if (!run || !size || size % 512 || !receive || !before_close || start_offset > size || start_offset % 512)
        throw Error("invalid restore image transfer parameters");
    verify_identity(endpoint, auth);
    auto request = authenticated_request("image_restore", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("read_image_requests")};
    fields["running_task_id"] = Value{run};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "restore download initialization", request);
    if (required_number(object(response), "success") != 1)
        throw Error("server did not accept restore download initialization");
    for (std::uint64_t offset = start_offset; offset < size;) {
        const auto length = std::min<std::uint64_t>(block_size, size - offset);
        stream.begin_operation();
        const auto reply = exchange(stream, "restore image range", Value{Value::Object{
            {"image_name", Value{std::string(name)}}, {"offset", Value{offset}}, {"length", Value{length}}}});
        const auto& part = object(reply);
        const auto status = part.find("running_task_status");
        if (status != part.end()) {
            const auto state = required_number(part, "running_task_status");
            // Running-task status: WAITING=0, RUNNING=1, PAUSING=2, CANCELING=3.
            if (state == 2 && validate_offline_resume) validate_offline_resume();
            else if (state > 1) throw Error("NAS paused, cancelled or lost the restore task");
        }
        const auto buffer = part.find("buffer");
        if (part.contains("close") || buffer == part.end() ||
            !std::holds_alternative<pstream::Bytes>(buffer->second.data))
            throw Error("restore range reply missing image bytes");
        const auto& bytes = std::get<pstream::Bytes>(buffer->second.data);
        if (bytes.size() != length) throw Error("restore range reply has an incorrect length");
        receive(bytes);
        offset += length;
    }
    before_close();
    stream.begin_operation();
    // Progress messages have no reply; the subsequent close does.
    stream.write_all(pstream::encode(Value{Value::Object{{"progress", Value{Value::Object{
        {"current_size", Value{size}}, {"total_size", Value{size}}}}}}}));
    const auto closed = exchange(stream, "restore download close",
        Value{Value::Object{{"close", Value{std::uint64_t{1}}}}});
    const auto& result = object(closed);
    if (required_number(result, "close") != 1)
        throw Error("server did not confirm restore channel closure");
    const auto status = required_text(result, "status");
    if (status != "running" && status != "complete")
        throw Error("NAS did not close the restore channel successfully");
}

std::uint64_t file_restore_device(const Endpoint& endpoint, const SavedAuth& auth) {
    verify_identity(endpoint,auth);
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream,"file restore device discovery",
                                  authenticated_request("list_device_task",auth));
    const auto& fields = object(response);
    const auto entry = fields.find("tasks");
    if (entry == fields.end() || !std::get_if<Value::Array>(&entry->second.data))
        throw Error("file restore device discovery is missing tasks");
    std::uint64_t device = 0;
    for (const auto& task : std::get<Value::Array>(entry->second.data)) {
        const auto& info = object(object(task).at("device_info"));
        if (required_text(info,"device_uuid") != auth.device_uuid) continue;
        const auto id = required_number(info,"device_id");
        if (!id || (device && device != id)) throw Error("ambiguous saved file restore destination device");
        device = id;
    }
    if (!device) throw Error("saved device is not available in the NAS restore catalog");
    return device;
}

void download_restore_files(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
    const std::optional<Value>& resume, const std::function<void(const Value&)>& receive,
    const std::function<Value::Array(const Value&, const std::function<void()>&)>& precheck) {
    if (!run || !receive || !precheck) throw Error("invalid file restore transfer parameters");
    verify_identity(endpoint, auth);
    auto request = authenticated_request("restore", auth);
    auto& fields = std::get<Value::Object>(request.data);
    std::get<Value::Object>(fields.at("agent").data)["device_uuid"] = Value{auth.device_uuid};
    fields["subaction"] = Value{std::string("get_file")};
    fields["running_task_id"] = Value{run};
    if (resume) fields["resume"] = *resume;
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    stream.write_all(pstream::encode(request));
    for (;;) {
        stream.begin_operation();
        auto response = read_response(stream, "file restore download", file_restore_limits);
        const auto& part = object(response);
        if (part.contains("precheck") && required_number(part, "precheck") != 0) {
            const auto paths = precheck(response, [&] {
                stream.begin_operation();
                stream.write_all(pstream::encode(Value{Value::Object{{"alive", Value{std::uint64_t{1}}}}}));
            });
            stream.begin_operation();
            stream.write_all(pstream::encode(Value{Value::Object{{"paths", Value{paths}}}}));
            continue;
        }
        const auto more = required_number(part, "has_more");
        if (more > 1) throw Error("invalid file restore stream continuation");
        if (part.contains("file")) receive(part.at("file"));
        else if (more) throw Error("file restore stream is missing its file record");
        if (!more) break;
    }
}

void acknowledge_restore_files(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
                               const Value::Array& done) {
    if (!run || done.empty()) throw Error("file restore acknowledgement requires records");
    auto request = authenticated_request("restore", auth);
    auto& fields = std::get<Value::Object>(request.data);
    std::get<Value::Object>(fields.at("agent").data)["device_uuid"] = Value{auth.device_uuid};
    fields["subaction"] = Value{std::string("update_done_ids")};
    fields["running_task_id"] = Value{run};
    fields["done_ids"] = Value{done};
    verify_identity(endpoint,auth);
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel");
    stream.start_tls();
    stream.begin_operation();
    // Completion-ID update checks transport status only, unlike restore-completion checking.
    // Only an actual ACK reply retires the snapshot, not a preflight rejection.
    try { exchange(stream,"file restore acknowledgement",request); }
    catch (const ServerError&) {}
}

std::string finish_file_restore(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
                               std::string_view status, const std::function<void()>& before_send) {
    if (!run || (status != "complete" && status != "error"))
        throw Error("invalid file restore completion request");
    auto request = authenticated_request("restore", auth);
    auto& fields = std::get<Value::Object>(request.data);
    std::get<Value::Object>(fields.at("agent").data)["device_uuid"] = Value{auth.device_uuid};
    fields["subaction"] = Value{std::string("check_complete")};
    fields["running_task_id"] = Value{run};
    fields["status"] = Value{std::string(status)};
    const auto response = backup_control(endpoint, auth, request, "file restore completion", before_send);
    const auto outcome = required_text(object(response), "status");
    if (outcome != "complete" && outcome != "partial" && outcome != "error" && outcome != "cancel")
        throw Error("unknown file restore completion status");
    return outcome;
}

std::string finish_image_restore(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
                                 const std::function<void()>& before_send, BackupOutcome requested) {
    if (!run) throw Error("restore completion requires a running task ID");
    if (requested != BackupOutcome::complete && requested != BackupOutcome::cancelled)
        throw Error("unsupported restore completion request");
    auto request = authenticated_request("image_restore", auth);
    auto& fields = std::get<Value::Object>(request.data);
    fields["subaction"] = Value{std::string("check_complete")};
    fields["running_task_id"] = Value{run};
    fields["status"] = Value{std::string(outcome_text(requested))};
    const auto response = backup_control(endpoint, auth, request, "restore completion", before_send);
    const auto status = required_text(object(response), "status");
    if (status != "complete" && status != "cancel" && status != "error")
        throw Error("server returned an unknown restore completion status");
    return status;
}
Value running_task_result(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t result_id) {
    verify_identity(endpoint, auth);
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    auto request = authenticated_request("get_running_task_result", auth);
    if (result_id) std::get<Value::Object>(request.data)["result_id"] = Value{result_id};
    const auto response = exchange(stream, "activity result lookup", request);
    Value::Object selected;
    for (auto key : {"backup_result","running_task_result"}) {
        const auto entry = object(response).find(key);
        if (entry == object(response).end()) continue;
        selected.emplace(key,Value{std::string_view(key) == "backup_result" ?
            select_fields(entry->second,{"last_success_time"},{"last_backup_status"}) :
            select_fields(entry->second,{"task_id","version_id","result_id","time_start"},{"job_action","status"})});
    }
    return Value{std::move(selected)};
}
std::optional<std::string> portal_link(const Endpoint& endpoint, const SavedAuth& auth) {
    auto address = endpoint.host;
    if (address.starts_with('[')) address = address.substr(1,address.find(']')-1);
    in6_addr ipv6{};
    if (inet_pton(AF_INET6,address.c_str(),&ipv6) == 1) {
        std::ostringstream formatted;
        formatted << '[' << std::hex;
        for (unsigned i = 0; i < 8; ++i) {
            if (i) formatted << ':';
            formatted << ((static_cast<unsigned>(ipv6.s6_addr[i*2])<<8)|ipv6.s6_addr[i*2+1]);
        }
        formatted << ']';
        address = formatted.str();
    } else if (const auto colon = address.rfind(':'); colon != address.npos) address.resize(colon);
    auto request = authenticated_request("get_portal_link",auth);
    std::get<Value::Object>(request.data)["address"] = Value{address};
    Stream stream(endpoint);
    exchange(stream,"encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream,"recovery portal",request);
    const auto& reply = object(response);
    if (!reply.contains("url")) return {};
    return std::get<std::string>(reply.at("url").data);
}
static std::string activity_result(const Endpoint& endpoint, const SavedAuth& auth,
                                   std::uint64_t task_id, std::uint64_t result_id, std::string_view action) {
    if (!task_id || !result_id) throw Error("activity result requires task and result IDs");
    const auto response = running_task_result(endpoint,auth,result_id);
    const auto& fields = object(response);
    const auto entry = fields.find("running_task_result");
    if (entry == fields.end()) throw Error("NAS did not return the requested activity result");
    const auto& result = object(entry->second);
    if (required_number(result, "task_id") != task_id ||
        required_number(result, "result_id") != result_id || required_text(result, "job_action") != action)
        throw Error("NAS returned a result for a different task, result ID or operation");
    const auto status = required_text(result, "status");
    if (status == "partial_success") return "partial";
    if (status == "failure") return "error";
    if (status == "complete" || status == "cancel" || status == "incomplete") return status;
    throw Error("NAS returned an unknown activity result status");
}
std::string backup_result(const Endpoint& endpoint, const SavedAuth& auth,
                          std::uint64_t task_id, std::uint64_t result_id) {
    return activity_result(endpoint, auth, task_id, result_id, "backup");
}
std::string restore_result(const Endpoint& endpoint, const SavedAuth& auth,
                           std::uint64_t task_id, std::uint64_t result_id) {
    return activity_result(endpoint, auth, task_id, result_id, "restore");
}
std::map<std::string,std::uint64_t> backup_checkpoint_images(
    const Endpoint& endpoint, const SavedAuth& auth, const BackupRun& run,
    std::uint64_t task, const std::map<std::string,std::uint64_t>& sizes,
    std::uint64_t base_version, std::map<std::string,std::uint64_t>* transferred) {
    validate_run(run);
    if (!task) throw Error("backup checkpoint requires a saved task ID");
    verify_identity(endpoint, auth);
    auto request = authenticated_request("get_running_task", auth);
    std::get<Value::Object>(request.data)["check_backup_exist"] = Value{std::uint64_t{1}};
    Stream stream(endpoint);
    exchange(stream, "encrypt_channel");
    stream.start_tls();
    const auto response = exchange(stream, "backup checkpoint lookup", request);
    const auto& fields = object(response);
    const auto list = fields.find("running_task_list");
    if (list == fields.end() || !std::holds_alternative<Value::Array>(list->second.data))
        throw Error("NAS checkpoint lookup is missing the running task list");
    std::optional<std::map<std::string,std::uint64_t>> offsets;
    for (const auto& item : std::get<Value::Array>(list->second.data)) {
        const auto& job = object(item);
        if (required_number(job, "id") != run.running_task_id) continue;
        if (offsets || required_number(job, "type") != 0 || required_number(job, "task_id") != task ||
            required_number(job, "result_id") != run.result_id ||
            required_number(job, "version_id") != run.version_id)
            throw Error("NAS running task does not match the saved backup");
        if (required_number(job, "is_backing_up") != 0)
            throw BackupRetry("previous NAS backup worker is still active");
        const auto status = required_number(job, "status");
        if (status > 2 || (status == 2 && required_number(job, "detail_status") != 6))
            throw Error("NAS backup is cancelled or paused for a reason other than disconnection");
        const auto backup = job.find("backup_task");
        if (backup == job.end()) throw Error("NAS backup checkpoint is missing task details");
        const auto& details = object(backup->second);
        if (base_version && (required_number(details, "is_cbt") != 1 ||
                             required_number(details, "base_version_id") != base_version))
            throw Error("NAS running backup has a different incremental base");
        if (required_number(details, "error_code") != 0)
            throw Error("NAS backup has an error; reconcile its result before continuing");
        const auto resume = details.find("resume_info");
        if (resume == details.end() || !std::holds_alternative<std::string>(resume->second.data))
            throw Error("NAS backup is missing resume information");
        offsets = backup_resume_offsets(std::get<std::string>(resume->second.data),sizes,transferred);
    }
    if (!offsets) throw Error("saved backup is no longer running; use backup reconcile");
    return *offsets;
}
std::uint64_t backup_checkpoint(const Endpoint& endpoint, const SavedAuth& auth, const BackupRun& run,
                                std::uint64_t task, std::string_view name, std::uint64_t size,
                                std::uint64_t base_version, std::uint64_t* transferred) {
    std::map<std::string,std::uint64_t> progress;
    const auto offsets = backup_checkpoint_images(endpoint,auth,run,task,
        {{std::string(name),size}},base_version,&progress);
    if (transferred) *transferred = progress.at(std::string(name));
    return offsets.at(std::string(name));
}
std::uint64_t restore_result_id(const Endpoint& endpoint, const SavedAuth& auth, std::uint64_t run,
                                std::uint64_t task, std::uint64_t device, std::uint64_t version, bool require_resumable) {
    if (!run || !task || !device || !version) throw Error("restore result discovery requires complete job identifiers");
    std::uint64_t result = 0;
    for (const auto& item : running_tasks(endpoint, auth)) {
        const auto& job = object(item);
        if (required_number(job, "id") != run) continue;
        if (result || required_number(job, "task_id") != task ||
            required_number(job, "device_id") != device || required_number(job, "version_id") != version ||
            required_number(job, "type") != 2)
            throw Error("NAS running task does not match the saved image restore");
        if (require_resumable) {
            const auto status = required_number(job, "status");
            // The Mac range handler leaves PAUSING_OFFLINE in the running-task observer
            // after reconnect. Unlike get_content, it does not reset that marker.
            if (status > 2 || (status == 2 && required_number(job, "detail_status") != 6))
                throw Error("NAS restore is cancelled or paused for a reason other than disconnection");
        }
        result = required_number(job, "result_id");
        if (!result) throw Error("NAS restore does not yet have a valid activity result ID");
    }
    if (!result) throw Error("restore result ID is unknown and the saved run is no longer available; no result was guessed");
    return result;
}
} // namespace opensabba

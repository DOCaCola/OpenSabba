#include "opensabba/certificate_trust.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    auto check = [](bool value) { if (!value) throw std::runtime_error("certificate trust failed"); };
    std::optional<std::string> saved;
    unsigned writes = 0, prompts = 0;
    auto read = [&] { return saved; };
    auto write = [&](const std::string& pin) { saved = pin; ++writes; };
    const opensabba::ServerCertificate first{"first","","","self signed",false};
    const opensabba::ServerCertificate changed{"second","","","self signed",false};
    auto service = opensabba::certificate_verifier(read, write);
    check(!service(first) && !saved && writes == 0);
    auto quiet = opensabba::certificate_verifier(read, write, {}, true);
    check(quiet(first) && saved == "first" && writes == 1);
    check(service(first) && writes == 1);
    check(!quiet(changed) && !service(changed) && saved == "first" && writes == 1);
    auto interactive = opensabba::certificate_verifier(read, write,
        [&](const opensabba::ServerCertificate& certificate, bool was_changed) {
            ++prompts; check(was_changed && certificate.sha256 == "second"); return true;
        });
    check(interactive(changed) && prompts == 1 && saved == "second");
    auto renewed = first;
    renewed.verified = true;
    check(service(renewed) && saved == "first" && writes == 3);
    check(quiet(renewed) && writes == 3);
    auto reject = opensabba::certificate_verifier(read, write,
        [&](const opensabba::ServerCertificate&, bool) { ++prompts; return false; });
    check(!reject(changed) && saved == "first" && writes == 3);
    auto broken = opensabba::certificate_verifier(read,
        [](const std::string&) { throw std::runtime_error("cannot persist trust"); });
    try { broken(changed); } catch (...) { check(false); }
    bool failed = false;
    try {
        broken(opensabba::ServerCertificate{"third","","","",true});
    } catch (const std::runtime_error&) { failed = true; }
    check(failed);
    std::cout << "persistent trust decisions passed\n";
}

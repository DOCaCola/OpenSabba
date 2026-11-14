#include "opensabba/bandwidth.hpp"
#include "opensabba/client.hpp"
#include <iostream>
#include <limits>
#include <vector>

using namespace opensabba;
void check(bool value) { if (!value) throw pstream::Error("bandwidth invariant failed"); }
int main() {
    try {
        using Clock = UploadPacing::Clock;
        using namespace std::chrono_literals;
        BackupBandwidthPolicy policy;
        check(policy.rate() == 0);
        policy.update(1);
        check(policy.rate() == 1);
        policy.update({}); // Omitted fields leave the limit unchanged.
        check(policy.rate() == 1);
        policy.update(0);
        check(policy.rate() == 0);
        policy.update(12); // Later setters win, irrespective of query start time.
        check(policy.rate() == 12);
        for (auto rate : {std::uint64_t{0},std::uint64_t{1},std::uint64_t{1000},
                          std::uint64_t{1024*1024},std::numeric_limits<std::uint64_t>::max()}) {
            const pstream::Bytes input(10003,0xa5);
            pstream::Bytes sent;
            auto now = Clock::time_point{};
            UploadPacing timing{[&] { return now; },[&](auto duration) {
                check(duration > Clock::duration::zero() && duration <= 1s);
                now += duration;
            }};
            paced_upload(input,rate,[&](auto bytes) {
                check(bytes.size() == (rate ? std::min<std::uint64_t>(input.size()-sent.size(),rate) : input.size()));
                if (sent.empty()) check(now == Clock::time_point{}); // Write before sleeping.
                sent.insert(sent.end(),bytes.begin(),bytes.end());
            },{},timing);
            check(sent == input);
            check(now.time_since_epoch() == (rate ? std::chrono::microseconds(input.size()*1000000/rate) : 0us));
        }
        // the official agent subtracts elapsed encoding and write time, starting its timer
        // at Policy publication before serialization.
        auto now = Clock::time_point{};
        UploadPacing timing{[&] { return now; },[&](auto duration) { now += duration; },now};
        now += 250ms; // Serialization after the configured timer start.
        paced_upload(pstream::Bytes(512),512,[&](auto bytes) {
            check(bytes.size() == 512 && now.time_since_epoch() == 250ms);
            now += 250ms; // Socket write time.
        },{},timing);
        check(now.time_since_epoch() == 1s);
        // Socket/scheduler delays do not accumulate on top of the rate's
        // time allowance. Full-rate writes replace the invented rate/10 quanta.
        now = Clock::time_point{};
        timing.started.reset();
        std::size_t writes = 0;
        paced_upload(pstream::Bytes(4096),512,[&](auto bytes) {
            check(bytes.size() == 512 && now.time_since_epoch() == std::chrono::seconds(writes));
            ++writes; now += 200ms;
        },{},timing);
        check(writes == 8 && now.time_since_epoch() == 8s);
        // After an overrun the timer restarts, without carrying idle credit
        // into the following write (Post-write pacing ).
        now = Clock::time_point{}; writes = 0;
        paced_upload(pstream::Bytes(1024),512,[&](auto) {
            if (++writes == 1) now += 1500ms;
        },{},timing);
        check(writes == 2 && now.time_since_epoch() == 2500ms);
        // Cancellation is observed between writes. the official agent sleeps once after a
        // completed write, rather than delaying that write with a polling loop.
        now = Clock::time_point{};
        bool cancelled = false;
        writes = 0;
        timing.sleep = [&](auto duration) { check(duration == 1s); now += duration; cancelled = true; };
        try {
            paced_upload(pstream::Bytes(100,1),1,[&](auto bytes) { check(bytes.size() == 1); ++writes; },
                         [&] { return cancelled; },timing);
            throw pstream::Error("cancellation ignored");
        } catch (const Cancelled&) {}
        check(writes == 1 && now.time_since_epoch() == 1s);
        // The upload worker samples policy once per encoded record, then
        // The channel keeps it fixed until the next record.
        now = Clock::time_point{}; writes = 0;
        timing.sleep = [&](auto duration) { now += duration; };
        policy.update(512);
        paced_upload(pstream::Bytes(1024),policy.rate(),[&](auto bytes) {
            check(bytes.size() == 512); ++writes; policy.update(0);
        },{},timing);
        check(writes == 2 && now.time_since_epoch() == 2s);
        policy.update({}); // A missing handshake field preserves that zero.
        paced_upload(pstream::Bytes(32768),policy.rate(),[&](auto bytes) {
            check(bytes.size() == 32768); ++writes; policy.update(1024);
        },{},timing);
        check(writes == 3 && now.time_since_epoch() == 2s);
        paced_upload(pstream::Bytes(2048),policy.rate(),[&](auto bytes) {
            check(bytes.size() == 1024); ++writes;
        },{},timing);
        check(writes == 5 && now.time_since_epoch() == 4s);
        std::cout << "Upload pacing tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

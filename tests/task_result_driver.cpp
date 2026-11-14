#include "opensabba/events.hpp"
#include <fstream>
#include <iostream>
using namespace opensabba;
using pstream::Value;
int main(int argc, char** argv) {
    try {
        if (argc != 5) throw pstream::Error("task result driver arguments");
        Endpoint endpoint{"127.0.0.1",static_cast<std::uint16_t>(std::stoul(argv[1])),argv[2]};
        const SavedAuth auth{"test-user","test-device","test-token","test-nas"};
        EventInbox inbox(auth);
        const auto save = [&] {
            const auto bytes = pstream::encode(inbox.serialize());
            std::ofstream output(argv[3],std::ios::binary|std::ios::trunc);
            output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
            if (!output) throw pstream::Error("task result driver write failed");
        };
        inbox.merge(pull_events(endpoint,auth,inbox.held_ids()));
        save();
        const auto result = running_task_result(endpoint,auth,std::stoull(argv[4]));
        inbox.prepare_task_result(42,std::stoull(argv[4]),result);
        save();
        inbox.finish_task_result(42,result);
        save();
        EventInbox replay(auth,pstream::decode(pstream::encode(inbox.serialize())));
        done_events(endpoint,auth,replay.ready_ids());
        replay.acknowledged(replay.ready_ids());
        inbox = std::move(replay);
        save();
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

#include "opensabba/machine_capture.hpp"
#include "opensabba/snapshot.hpp"
#include <iostream>

using namespace opensabba;
using namespace opensabba::pstream;
namespace {
const Value& field(const Value& value, const char* key) {
    return std::get<Value::Object>(value.data).at(key);
}
std::uint64_t number(const Value& value, const char* key) {
    return std::get<std::uint64_t>(field(value,key).data);
}
std::string text(const Value& value, const char* key) {
    return std::get<std::string>(field(value,key).data);
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw Error("usage: lvm_capture_probe CAPTURE_DIRECTORY");
        ReadyMachineCapture capture(argv[1]);
        const auto& journal = capture.journal();
        const auto& disks = std::get<Value::Array>(field(journal.plan,"additional_disks").data);
        const auto& artifact = std::get<Value::Array>(field(journal.artifact,"additional_images").data);
        std::vector<const Value*> logical;
        if (std::get<Value::Object>(field(journal.plan,"root").data).contains("lv_uuid"))
            logical.push_back(&field(journal.plan,"root"));
        for (const auto& entry : std::get<Value::Array>(field(journal.plan,"selected_extra").data))
            if (std::get<Value::Object>(entry.data).contains("lv_uuid")) logical.push_back(&entry);
        if (artifact.size() != disks.size()+logical.size() ||
            capture.disk_count() != artifact.size()+1 || logical.empty())
            throw Error("LVM capture image inventory differs from its plan");
        std::vector<MetadataDisk> inputs;
        inputs.push_back({&capture.source(),static_cast<std::uint32_t>(
            number(journal.artifact,"sector_size")),"lab-root.img",&journal.plan});
        for (std::size_t i = 0; i < disks.size(); ++i)
            inputs.push_back({&capture.source(i+1),
                static_cast<std::uint32_t>(number(artifact[i],"sector_size")),
                "lab-disk-"+std::to_string(i+1)+".img",&disks[i]});
        for (std::size_t i = 0; i < logical.size(); ++i)
            inputs.push_back({&capture.source(disks.size()+i+1),512,
                text(*logical[i],"image_name"),logical[i]});
        const auto bytes = fixed_machine_metadata(inputs,number(journal.reservation,"snapshot_time"));
        std::cout.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}

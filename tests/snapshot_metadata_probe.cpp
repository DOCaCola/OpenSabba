#include "opensabba/machine_capture.hpp"
#include "opensabba/snapshot.hpp"
#include "opensabba/snapshot_driver.hpp"
#include "opensabba/filesystem.hpp"
#include <iostream>

int main(int argc,char** argv) {
    try {
        if (argc != 2) throw opensabba::pstream::Error("expected capture directory");
        using namespace opensabba;
        ReadyMachineCapture capture(argv[1]);
        const auto& plan = capture.journal().plan;
        const auto& fields = std::get<pstream::Value::Object>(plan.data);
        const auto& root = std::get<pstream::Value::Object>(fields.at("root").data);
        const auto root_at = std::get<std::uint64_t>(root.at("offset").data);
        if (fixed_image_metadata(capture.source(),512,"physical.img",123,nullptr,&plan).empty())
            throw pstream::Error("missing physical metadata");
        if (capture.source().read(root_at+2*1024*1024,4096).size() != 4096)
            throw pstream::Error("short physical snapshot payload");
        // A standalone typed reader uses the same buffered metadata descriptor;
        // there is no synthetic single-volume MBR image mode in the product.
        SnapshotReader volume(capture.journal().snapshot,true);
        const auto& identity = std::get<pstream::Value::Object>(capture.journal().snapshot.data);
        (void)snapshot_used_context(std::get<std::string>(identity.at("origin_path").data),volume.size(),
            [&](auto at,auto length) { return volume.read_metadata(at,length); });
        if (volume.read_metadata(0,512).size() != 512 || volume.read_metadata(1024,1024).size() != 1024)
            throw pstream::Error("short standalone filesystem identity metadata");
        if (volume.read(2*1024*1024,4096).size() != 4096)
            throw pstream::Error("short standalone snapshot payload");
        std::cout << "physical and standalone reader metadata/payload routing passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

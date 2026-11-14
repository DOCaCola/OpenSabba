#pragma once
#include "opensabba/machine.hpp"

namespace opensabba {
struct VolumeNode {
    std::string path, filesystem, uuid;
    std::uint64_t total_size = 0, used_size = 0, free_size = 0;
};
// The official Linux agent root list_nodes representation for mounted block volumes.
pstream::Value::Array volume_node_values(const std::vector<VolumeNode>&);
// Observe only mounted block filesystems; no activation, mount or filesystem write.
pstream::Value::Array mounted_volume_nodes();

struct DirectoryNode {
    std::string name;
    bool directory = false, symlink = false;
};
struct DirectoryNodes {
    pstream::Value::Array nodes;
    std::uint64_t error_code = 0;
};
// Directory listing uses the directory-entry type, including every symlink as
// a directory, and preserves the requested path and native enumeration order.
pstream::Value::Array directory_node_values(const std::string& path, bool dir_only,
                                           const std::vector<DirectoryNode>&);
DirectoryNodes directory_nodes(const std::string& path, bool dir_only);
// Shared wire/storage validation, including official agent's signed-int error encoding.
void validate_client_node_result(const pstream::Value&);
}

#pragma once
#include "opensabba/image.hpp"
namespace opensabba {
// Public discovery decodes policy flags; never expose script contents or paths.
pstream::Value::Object task_script_policy(const pstream::Value& wire_task);
bool task_app_aware(const pstream::Value& task);
bool task_transfer_encrypted(const pstream::Value& task);
// Explicit image/snapshot commands select their source locally.
TransferCompression validate_task_policy(const pstream::Value& task, bool script_boundary = false);
// A usable captured set keeps its selected images and completed script boundary;
// only transfer policy is refreshed from the current assigned task.
TransferCompression validate_machine_transfer_policy(const pstream::Value& task);
// Validate a newly discovered capture plan against its acquisition-time task.
TransferCompression validate_machine_task_policy(const pstream::Value& task, const pstream::Value& plan,
                                                  bool script_boundary = false);
// Missing custom paths produce official agent warning 7096; they do not pin topology.
std::vector<std::string> machine_task_missing_mounts(const pstream::Value& task,
                                                    const pstream::Value& capture_plan);
std::vector<std::string> machine_task_extra_mounts(const pstream::Value& task,
                                                    const pstream::Value& discovered_plan,
                                                    bool script_boundary = false);
}

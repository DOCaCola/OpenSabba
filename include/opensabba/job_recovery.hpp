#pragma once
#include "opensabba/client.hpp"

namespace opensabba {
// Original transfer phases remain intact. Recovery records separately capture
// cancellation intent or an authoritative NAS result.
void apply_job_resolution(const pstream::Value& record, pstream::Value& summary);
struct JobRecoveryPolicy {
    std::uint64_t task_type;
    std::optional<std::uint64_t> device_id;
    std::function<pstream::Value(const pstream::Value&)> status;
    std::function<std::uint64_t(const pstream::Value&)> result_id;
    std::function<std::string(std::uint64_t)> outcome;
    std::function<void(const pstream::Value&,const std::function<void()>&)> cancel;
};
void recover_job(const Endpoint&,const SavedAuth&,const pstream::Value&,
    bool cancel,const JobRecoveryPolicy&,const std::function<void(const pstream::Value&)>& save);
void recover_backup_job(const Endpoint&,const SavedAuth&,const pstream::Value&,
    bool cancel,const std::function<void(const pstream::Value&)>& save);
}

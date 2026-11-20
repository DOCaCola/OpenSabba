#pragma once

#include "opensabba/pstream.hpp"
#include "opensabba/server_time.hpp"
#include "opensabba/image.hpp"
#include "opensabba/bandwidth.hpp"
#include "opensabba/service_status.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <filesystem>
#include <optional>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace opensabba {
struct ProxyCredentials {
    std::string username, password;
    std::string scheme = "basic";
    std::string domain, workstation;
    unsigned ntlm_version = 2;
};
struct ServerCertificate {
    std::string sha256, subject, issuer, verification_error;
    bool verified = false;
};
// Ordinary official agent jobs retain pending counters only in process memory. Endpoint
// copies share the same job's counters across reconnects; draining clears them
// before the unacknowledged performance message is sent.
struct BackupPerformance {
    std::uint64_t running_task_id = 0;
    std::uint64_t snapshot_nanoseconds = 0;
    pstream::Value::Object pending;
};
struct BackupRun {
    std::uint64_t running_task_id, version_id, result_id, data_format;
};
struct PreparedBackup {
    BackupRun run;
    std::uint64_t base_version_id;
};
class ConnectionPool;
std::shared_ptr<ConnectionPool> make_connection_pool();

struct Endpoint {
    std::string host;
    std::uint16_t port = 5510;
    std::string ca_file;
    std::chrono::seconds timeout{30};
    // Optional cooperative cancellation, also checked during socket waits.
    std::function<bool()> cancelled;
    std::string proxy_host;
    std::uint16_t proxy_port = 0;
    std::optional<ProxyCredentials> proxy_credentials;
    // Called after TLS handshake, before any application data or credentials.
    // A custom CA remains authoritative: invalid chains cannot be overridden.
    std::function<bool(const ServerCertificate&)> trust_certificate;
    std::shared_ptr<BackupPerformance> backup_performance = std::make_shared<BackupPerformance>();
    // Only durable cache replay uses the official agent cache upload/handshake flag.
    bool cached_backup = false;
    std::shared_ptr<BackupBandwidthPolicy> backup_bandwidth_policy = std::make_shared<BackupBandwidthPolicy>();
    std::shared_ptr<ServiceStatus> service_status = std::make_shared<ServiceStatus>();
    std::uint64_t backup_trigger_type = 1;
    // The official Linux agent reports the task's shared flag; its snapshot hooks are inert.
    bool backup_app_aware = false;
    // Copies share official agent connection discovery and NAS-granted channel leases.
    std::shared_ptr<ConnectionPool> connections = make_connection_pool();
    // Applies only to the upload_block data connection; control remains TLS.
    // Automatic dispatch sets this from the current assigned NAS task.
    bool backup_encryption = true;
    // Identity and result-detail sink owned by the service backup worker.
    std::string backup_task_uuid;
    SourceReadActivity source_read_activity;
    // Automatic capture handshakes before rotation/preparation as official agent does.
    std::optional<PreparedBackup> prepared_backup;
};
// Service workers observe the task manager's event-refreshed state. Standalone
// protocol fixtures explicitly supply their own observation source.
struct TaskView {
    std::function<pstream::Value::Array(const Endpoint&)> tasks, running;
};
class TransportError : public pstream::Error { public: using Error::Error; };
class CertificateError : public TransportError {
public:
    bool changed;
    explicit CertificateError(bool was_changed)
        : TransportError("server certificate rejected; run opensabba --connect interactively to review it"),
          changed(was_changed) {}
};
class Cancelled : public pstream::Error { public: Cancelled() : Error("operation cancelled") {} };

// Version fields describe the supported wire dialect, not OpenSabba's version.
pstream::Value make_request(std::string_view action);

// Performs TCP -> encrypt_channel acknowledgment -> verified TLS -> server info.
// No account credentials, device registration, or snapshot driver are involved.
pstream::Value probe(const Endpoint& endpoint);

struct LoginCredentials {
    std::string username, password, otp, device_uuid, host_name, os_name;
};
struct LoginResult {
    std::string token, ds_id;
    std::uint64_t auth_type;
    // Server-selected Linux backup type and template; absent for auth_type 5.
    std::optional<std::uint64_t> backup_type;
    pstream::Value task_template;
    pstream::Value confirmation_display;
};
// Password authentication only; does not send confirm_auth or start backups.
LoginResult login(const Endpoint& endpoint, const LoginCredentials& credentials);

class ServerError : public pstream::Error {
public:
    std::optional<std::uint64_t> code;
    std::string server_message;
    ServerError(std::string message, std::optional<std::uint64_t> number, std::string detail = {})
        : Error(std::move(message)), code(number), server_message(std::move(detail)) {}
};
struct SavedAuth {
    std::string username, device_uuid, token, ds_id;
    // Service requests consume the current factory token across routine auth.
    std::function<std::string()> token_value;
};
struct DeviceMetadata {
    std::string host_name, os_name, kernel_version;
    std::int32_t time_zone = 0;
};
struct Registration {
    std::uint64_t backup_type, template_id;
    std::string connect_type = "backup";
};
// before_send runs only after verifying the server identity and establishing TLS.
void confirm_registration(const Endpoint&, const SavedAuth&, const DeviceMetadata&,
                          const Registration&, const std::function<void()>& before_send);
struct TokenResult {
    std::string token, ds_id;
};
// Wire capability advertisement. The caller must validate its backup provider
// before enabling it; merely loading a kernel module is not sufficient.
enum class DriverStatus { disabled, enabled };
TokenResult reconnect(const Endpoint&, const SavedAuth&, const DeviceMetadata&,
                      DriverStatus = DriverStatus::disabled, bool initialize = true);
ServerTime get_server_time(const Endpoint&, const SavedAuth&);
void heartbeat(const Endpoint&, const SavedAuth&, DriverStatus = DriverStatus::disabled);
// Notify the NAS that this device is offline. This is not token revocation.
void unlink_connection(const Endpoint&, const SavedAuth&);
// NAS administrator authorization for logout. This does not rotate the device
// session or return the daemon's local, one-use authorization token.
void authorize_logout(const Endpoint&, const SavedAuth&, const LoginCredentials&);
// Read-only discovery. Results contain validated, selected display fields only.
pstream::Value::Array tasks(const Endpoint&, const SavedAuth&);
// Private execution discovery includes script buffers. Never display/store raw
// results in the public task/event cache.
pstream::Value::Array execution_tasks(const Endpoint&, const SavedAuth&);
void update_backup_cache_policy(const Endpoint&, const SavedAuth&, const pstream::Value& task);
void report_script_activity(const Endpoint&, const SavedAuth&, std::uint64_t run,
    std::uint64_t log_type, std::uint64_t log_time, const std::string& other_params);
void upload_script_output(const Endpoint&, const SavedAuth&, std::uint64_t task,
    std::uint64_t version, bool pre, std::span<const std::uint8_t> output);
void report_script_upload_error(const Endpoint&, const SavedAuth&, std::uint64_t log_time);
pstream::Value::Array running_tasks(const Endpoint&, const SavedAuth&);
bool events_pending(const Endpoint&, const SavedAuth&, std::uint64_t last_event_id = 0);
pstream::Value::Array pull_events(const Endpoint&, const SavedAuth&,
                                 const pstream::Value::Array& held_ids);
void done_events(const Endpoint&, const SavedAuth&, const pstream::Value::Array& ids);
void finish_agent_update(const Endpoint&, const SavedAuth&);
void report_client_nodes(const Endpoint&, const SavedAuth&, const pstream::Value&);
// An absent field means the NAS supplies no change to the current policy.
std::optional<std::uint64_t> backup_bandwidth(const Endpoint&, const SavedAuth&);
// A job can be deferred while its previous NAS worker disconnects. The service
// keeps its event and retries; this is not an agent initialization failure.
class BackupRetry : public pstream::Error {
public: using Error::Error;
};
struct BackupEventState {
    BackupRun run;
    std::uint64_t status, error_code;
    bool worker_active;
    std::string resume_info;
};
// Private recovery lookup, including the official agent check_backup_exist handshake.
std::optional<BackupEventState> backup_event_state(const Endpoint&, const SavedAuth&,
                                                  std::uint64_t task, std::uint64_t run);
// Creates a manual full-backup run on an existing assigned task.
// A lost response must not be retried: the run ID may already exist on the NAS.
BackupRun create_full_backup(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                             const std::function<void()>& before_send);
BackupRun create_incremental_backup(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                    std::uint64_t base_version,
                                    const std::function<void()>& before_send);
// Backup handshakes for a NAS-created running task. This does not create a
// task or infer the official agent trigger-type enum. No automatic retries on lost replies.
// before_send must durably record an uncertain operation before request bytes
// leave the client; throwing prevents the request.
BackupRun prepare_full_backup(const Endpoint&, const SavedAuth&,
                              std::uint64_t running_task_id,
                              const std::function<void()>& before_send);
BackupRun prepare_incremental_backup(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                     std::uint64_t running_task_id, std::uint64_t base_version,
                                     const std::function<void()>& before_send);
// the official agent snapshot metadata JSON bytes (not PStream text). The snapshot provider owns
// schema construction and must keep image names/extents consistent with upload.
// Reports the shared task flag except for NAS data format 2, as the official Linux agent does.
void upload_backup_spec(const Endpoint&, const SavedAuth&, const BackupRun&,
                        std::span<const std::uint8_t> snapshot_json,
                        const std::function<void()>& before_send, bool resume = false);
enum class BackupOutcome { complete, partial, cancelled, error };
// A request to finish is not a successful result: returns the NAS's terminal
// outcome. Missing/unknown status is a protocol error, never assumed complete.
BackupOutcome finish_backup(const Endpoint&, const SavedAuth&, const BackupRun&,
                            BackupOutcome requested,
                            const std::function<void()>& before_send, bool incremental = false);
// Data-channel primitive for an ALREADY prepared disposable running task.
// Caller must have registered matching image metadata. Does not create a task,
// upload device specifications, finalize a backup, or prove recoverability.
void upload_prepared_image(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                           const std::filesystem::path&, std::string_view image_name,
                           std::size_t block_size = 1024 * 1024);
// Preserve the same open file from planning through metadata and transfer.
void upload_prepared_image(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                           ImageSource&, std::string_view image_name,
                           std::size_t block_size = 1024 * 1024,
                           std::optional<std::uint64_t> resume_offset = {},
                           TransferCompression compression = TransferCompression::none,
                           const DeltaPlan* delta = nullptr,
                           std::span<const ChangedExtent> unused_ranges = {},
                           std::span<const ChangedExtent> reread_ranges = {},
                           std::uint64_t resume_transferred = 0);
struct UploadImage {
    ImageSource* source;
    std::string name;
    std::optional<std::uint64_t> resume_offset;
    TransferCompression compression = TransferCompression::none;
    const DeltaPlan* delta = nullptr;
    std::vector<ChangedExtent> unused_ranges;
    std::vector<ChangedExtent> reread_ranges;
    std::uint64_t resume_transferred = 0;
};
// One official agent upload_block channel for every image in the registered disk spec.
void upload_prepared_images(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                            std::span<const UploadImage>, std::size_t block_size = 1024*1024);
// NAS persisted position, only after matching the exact unfinished backup and
// verifying that the previous writer has stopped. No mutations or local offsets.
std::uint64_t backup_checkpoint(const Endpoint&, const SavedAuth&, const BackupRun&,
                                std::uint64_t task_id, std::string_view image_name,
                                std::uint64_t image_size, std::uint64_t base_version = 0,
                                std::uint64_t* transferred = nullptr);
std::map<std::string,std::uint64_t> backup_checkpoint_images(
    const Endpoint&, const SavedAuth&, const BackupRun&, std::uint64_t task_id,
    const std::map<std::string,std::uint64_t>& image_sizes,
    std::uint64_t base_version = 0,
    std::map<std::string,std::uint64_t>* transferred = nullptr);
// Resolve only this authenticated device's task. Never expose the server's
// connection-settings record, which also contains credentials.
std::uint64_t restore_device(const Endpoint&, const SavedAuth&, std::uint64_t task_id);
// Read-only, page-bounded NAS restore catalog for this authenticated device.
// Returned fields are allowlisted; the server's device specs and raw version
// records must never be displayed or persisted.
pstream::Value restore_versions(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                std::uint64_t offset, std::uint64_t limit);
std::uint64_t create_image_restore(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                                  std::uint64_t device_id, std::uint64_t version_id,
                                  const std::function<void()>& before_send);
// Sequential range channel. before_close must persist and verify the received
// file before progress is reported. A lost reply is never retried here.
// Explicit resume may supply a callback that verifies the exact job is still
// resumable when the channel reports PAUSING; otherwise PAUSING is rejected.
void download_restore_image(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                            std::string_view image_name, std::uint64_t size,
                            const std::function<void(std::span<const std::uint8_t>)>& receive,
                            const std::function<void()>& before_close,
                            std::uint64_t start_offset = 0,
                            const std::function<void()>& validate_offline_resume = {});
std::string finish_image_restore(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                                 const std::function<void()>& before_send,
                                 BackupOutcome requested = BackupOutcome::complete);
// Read one specific activity result; never substitutes the latest task result.
// Returns complete, partial, error, cancel or incomplete after matching IDs/action.
// Event handler lookup: official agent omits result_id when there is no matching history.
pstream::Value running_task_result(const Endpoint&, const SavedAuth&, std::uint64_t result_id = 0);
std::optional<std::string> portal_link(const Endpoint&, const SavedAuth&);
std::string backup_result(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                          std::uint64_t result_id);
// Read-only official agent base selection. Zero means no usable NAS base.
std::uint64_t backup_base_version(const Endpoint&, const SavedAuth&, std::uint64_t task_id);
std::string restore_result(const Endpoint&, const SavedAuth&, std::uint64_t task_id,
                           std::uint64_t result_id);
// Bind a restore run to its activity result while it still exists. All source
// identifiers must match; no latest-result or completed-task inference.
// require_resumable also rejects cancellation and pauses other than offline.
std::uint64_t restore_result_id(const Endpoint&, const SavedAuth&, std::uint64_t running_task_id,
                                std::uint64_t task_id, std::uint64_t device_id, std::uint64_t version_id,
                                bool require_resumable = false);
} // namespace opensabba

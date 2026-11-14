#include "lab.hpp"
#include "opensabba/display.hpp"
#include "../src/session_runtime.hpp"
#include "opensabba/restore_job.hpp"
#include "opensabba/job_recovery.hpp"
#include "opensabba/task_policy.hpp"
#include "opensabba/device_info.hpp"
#include "opensabba/machine.hpp"
#include <openssl/crypto.h>
#include <charconv>
#include <chrono>
#include <future>
#include <fstream>
#include <iostream>
#include <thread>
namespace opensabba {
using namespace pstream;
using namespace session_detail;
#ifndef _WIN32
namespace {
void lab_recover_job(const Endpoint& endpoint,const SavedAuth& auth,const Value& record,
    bool restore,bool cancel,const std::function<void(const Value&)>& save) {
    if (!restore) { recover_backup_job(endpoint,auth,record,cancel,save); return; }
    const auto summary = restore_job_status(record,auth);
    const JobRecoveryPolicy policy{2,number(summary,"device_id"),
        [&](const Value& saved) { return restore_job_status(saved,auth); },
        [&](const Value& saved) {
            if (fields(saved).contains("result_id")) return number(saved,"result_id");
            return restore_result_id(endpoint,auth,number(summary,"running_task_id"),number(summary,"task_id"),
                number(summary,"device_id"),number(summary,"version_id"));
        },
        [&](std::uint64_t result) { return restore_result(endpoint,auth,number(summary,"task_id"),result); },
        [&](const Value&,const std::function<void()>& intent) {
            if (finish_image_restore(endpoint,auth,number(summary,"running_task_id"),intent,BackupOutcome::cancelled) != "cancel")
                throw Error("NAS did not confirm restore cancellation");
        }};
    recover_job(endpoint,auth,record,cancel,policy,save);
}
int restore_command(int argc, char** argv) {
    if (argc >= 3 && std::string_view(argv[2]) == "versions") {
        std::optional<std::uint64_t> task;
        std::uint64_t offset = 0, limit = 20;
        bool json = false, have_offset = false, have_limit = false;
        for (int index = 3; index < argc; ++index) {
            const std::string_view option(argv[index]);
            if (option == "--json" && !json) { json = true; continue; }
            if ((option == "--task" && !task) ||
                (option == "--offset" && !have_offset) ||
                (option == "--limit" && !have_limit)) {
                if (++index == argc) throw Error("missing restore catalog option value");
                const std::string_view input(argv[index]);
                std::uint64_t value = 0;
                const auto [last, error] = std::from_chars(input.data(), input.data()+input.size(), value);
                if (input.empty() || error != std::errc{} || last != input.data()+input.size() ||
                    value > INT32_MAX || (option != "--offset" && !value))
                    throw Error("invalid restore catalog numeric option");
                if (option == "--task") task = value;
                else if (option == "--offset") { offset = value; have_offset = true; }
                else { limit = value; have_limit = true; }
                continue;
            }
            throw Error("usage: restore versions --task ID [--offset N] [--limit 1..50] [--json]");
        }
        if (!task || limit > 50 || offset > INT32_MAX-limit)
            throw Error("usage: restore versions --task ID [--offset N] [--limit 1..50] [--json]");
        Store store(false);
        const auto session = store.read("session.pstream");
        if (!session) throw Error("no saved session; log in first");
        if (text(*session, "registration_state") != "confirmed")
            throw Error("confirm registration or reconnect before browsing restore versions");
        const auto endpoint = endpoint_from(*session);
        const auto catalog = restore_versions(endpoint, auth_from(*session), *task, offset, limit);
        if (json) {
            print_json(std::cout, catalog);
            std::cout << '\n';
        } else {
            std::cout << "Task " << *task << ", device " << number(catalog,"device_id")
                      << ": " << number(catalog,"total") << " NAS version(s)\n";
            const auto& versions = std::get<Value::Array>(field(catalog,"versions").data);
            for (const auto& version : versions)
                std::cout << "  Version " << number(version,"version_id")
                          << "  start " << number(version,"time_start")
                          << "  end " << number(version,"time_end")
                          << "  " << number(version,"used_size") << " bytes"
                          << "  status " << number(version,"status")
                          << "  backup type " << number(version,"full_backup") << '\n';
            if (number(catalog,"offset")+versions.size() < number(catalog,"total"))
                std::cout << "More versions: use --offset "
                          << number(catalog,"offset")+versions.size() << '\n';
        }
        return 0;
    }
    const bool status = argc >= 3 && std::string_view(argv[2]) == "status";
    const bool resume = argc >= 3 && std::string_view(argv[2]) == "resume";
    const bool json = status && argc == 4 && std::string_view(argv[3]) == "--json";
    const bool image = argc >= 3 && std::string_view(argv[2]) == "image";
    const bool named_image = image && argc == 6 && std::string_view(argv[4]) == "--image-name";
    if (status ? (argc != 3 && !json) : resume ? argc != 3 :
        (!image || (argc != 4 && !named_image)))
        throw Error("usage: restore versions --task ID [--offset N] [--limit 1..50] [--json] | restore image NEW_FILE [--image-name NAME] | restore resume | restore status [--json]");
    std::optional<std::string_view> image_name;
    if (named_image) {
        image_name = argv[5];
        validate_image_options(*image_name, 1024*1024);
    }
    Store store(!status);
    const auto session = store.read("session.pstream");
    if (!session) throw Error("no saved session; log in first");
    const auto auth = auth_from(*session);
    const auto previous = store.read("restore-job.pstream");
    if (status) {
        if (!previous) {
            std::cout << (json ? "null\n" : "No saved restore job.\n");
            return 0;
        }
        const auto summary = restore_job_status(*previous, auth);
        if (json) print_json(std::cout, summary);
        else {
            std::cout << "Restore job " << number(summary, "running_task_id") << ": "
                      << text(summary, "phase") << "\nDestination: " << text(summary, "destination")
                      << "\nSHA-256 verification: " << (number(summary, "verified") ? "passed" : "pending") << '\n';
            if (!number(summary, "terminal"))
                std::cout << "Outcome unresolved; no request has been replayed.\n";
        }
        std::cout << '\n';
        return 0;
    }
    if (text(*session, "registration_state") != "confirmed")
        throw Error("confirm registration or reconnect before restore");
    auto save = [&](const Value& record) {
        store.write("restore-job.pstream", record);
        std::cout << "Restore: " << text(record, "phase");
        if (text(record, "phase") == "download" && fields(record).contains("checkpoint"))
            std::cout << " (" << number(field(record, "checkpoint"), "offset") << "/"
                      << number(record, "image_size") << " bytes saved)";
        std::cout << '\n' << std::flush;
    };
    if (resume) {
        if (!previous) throw Error("no saved restore to resume");
        Signals signals;
        auto endpoint = endpoint_from(*session);
        endpoint.cancelled = [] { return service_stop || service_reload; };
        resume_saved_image(endpoint, auth, *previous, save);
        std::cout << "Restore resumed and verified; NAS confirmed completion.\n";
        return 0;
    }
    if (previous) {
        const auto summary = restore_job_status(*previous, auth);
        if (!number(summary, "terminal"))
            throw Error("previous restore outcome is unresolved; inspect restore status before another restore");
        const auto archive = "restore-job-" + std::to_string(number(summary, "running_task_id")) + ".pstream";
        store.write(archive.c_str(), *previous);
    }
    const auto backup = store.read("backup-job.pstream", backup_limits);
    if (!backup) throw Error("no saved image backup to restore");
    Signals signals;
    auto endpoint = endpoint_from(*session);
    endpoint.cancelled = [] { return service_stop || service_reload; };
    try {
        restore_saved_image(endpoint, auth, *backup, argv[3], image_name, save);
    } catch (...) {
        std::cerr << "Restore stopped; any new output file is retained. Inspect restore status before retrying.\n";
        throw;
    }
    std::cout << "Image restored to a new file; SHA-256 matches the saved backup. NAS confirmed completion.\n";
    return 0;
}

int recovery_command(int argc, char** argv) {
    if (argc != 3) throw Error("usage: backup reconcile | backup cancel | restore reconcile | restore cancel");
    const bool restore = std::string_view(argv[1]) == "restore";
    const bool cancel = std::string_view(argv[2]) == "cancel";
    Store store;
    const auto session = store.read("session.pstream");
    if (!session) throw Error("no saved session; log in first");
    if (text(*session, "registration_state") != "confirmed")
        throw Error("confirm registration or reconnect before job recovery");
    const auto filename = restore ? "restore-job.pstream" : "backup-job.pstream";
    const auto limits = restore ? session_limits : backup_limits;
    const auto record = store.read(filename, limits);
    if (!record) throw Error("no saved job to recover");
    Signals signals;
    auto endpoint = endpoint_from(*session);
    endpoint.cancelled = [] { return service_stop || service_reload; };
    const auto auth = auth_from(*session);
    lab_recover_job(endpoint, auth, *record, restore, cancel, [&](const Value& saved) {
        store.write(filename, saved, limits);
        const auto summary = restore ? restore_job_status(saved, auth) : backup_job_status(saved, auth);
        std::cout << (restore ? "Restore: " : "Backup: ") << text(summary, "phase") << '\n' << std::flush;
    });
    std::cout << "NAS outcome recorded. Retained image files were not changed.\n";
    return 0;
}

BackupOutcome with_backup_heartbeat(Endpoint endpoint, const SavedAuth& auth,
                                    const std::function<BackupOutcome(const Endpoint&)>& operation) {
    std::atomic_bool stop{false};
    endpoint.cancelled = [&] { return service_stop || service_reload || stop.load(); };
    heartbeat(endpoint, auth);
    auto beats = std::async(std::launch::async, [&] {
        try {
            while (!endpoint.cancelled()) {
                const auto next = std::chrono::steady_clock::now() + std::chrono::seconds{5};
                while (!endpoint.cancelled() && std::chrono::steady_clock::now() < next)
                    std::this_thread::sleep_for(std::chrono::milliseconds{100});
                if (!endpoint.cancelled()) heartbeat(endpoint, auth);
            }
        } catch (...) { stop = true; throw; }
    });
    std::exception_ptr error;
    std::optional<BackupOutcome> outcome;
    try { outcome = operation(endpoint); }
    catch (...) { error = std::current_exception(); }
    stop = true;
    try { beats.get(); }
    catch (const Cancelled&) {}
    // Preserve heartbeat failures instead of masking them as cancellation.
    catch (...) { error = std::current_exception(); }
    if (error) {
        std::cerr << "Backup stopped; inspect backup status. Uncertain operations are not automatically retried.\n";
        std::rethrow_exception(error);
    }
    return *outcome;
}

int backup_command(int argc, char** argv) {
    const bool status = argc >= 3 && std::string_view(argv[2]) == "status";
    if (status) {
        const bool json = argc == 4 && std::string_view(argv[3]) == "--json";
        if (argc != 3 && !json) throw Error("usage: backup status [--json]");
        Store store(false);
        auto session = store.read("session.pstream");
        if (!session) throw Error("no saved session; log in first");
        auto record = store.read("backup-job.pstream", backup_limits);
        if (!record) {
            if (json) std::cout << "null\n";
            else std::cout << "No saved backup job.\n";
            return 0;
        }
        const auto summary = backup_job_status(*record, auth_from(*session));
        if (json) print_json(std::cout, summary);
        else {
            if (number(summary, "running_task_id"))
                std::cout << "Backup job " << number(summary, "running_task_id");
            else
                std::cout << "Backup creation for task " << number(summary, "create_task_id")
                          << " (running job ID not yet known)";
            std::cout << ": " << text(summary, "phase") << '\n'
                      << "Image: " << text(summary, "image_name") << " ("
                      << number(summary, "image_size") << " bytes)\n"
                      << "SHA-256: " << text(summary, "image_sha256",true) << '\n';
            if (!number(summary, "terminal"))
                std::cout << "Outcome unresolved; no request has been replayed.\n";
        }
        std::cout << '\n';
        return 0;
    }
    if (argc >= 3 && std::string_view(argv[2]) == "resume") {
        if (argc != 4) throw Error("usage: backup resume IMAGE");
        Store store;
        const auto session = store.read("session.pstream");
        if (!session) throw Error("no saved session; log in first");
        if (text(*session, "registration_state") != "confirmed")
            throw Error("confirm registration or reconnect before backup");
        const auto record = store.read("backup-job.pstream", backup_limits);
        if (!record) throw Error("no saved backup to resume");
        const auto auth = auth_from(*session);
        const auto summary = backup_job_status(*record, auth);
        const auto phase = text(summary, "phase");
        if (phase != "metadata-accepted" && phase != "upload" && phase != "uploaded")
            throw Error("backup is not in a resumable upload phase; reconcile uncertain outcomes first");
        Signals signals;
        if (fields(*record).contains("source_capture"))
            throw Error("this backup requires its bound machine capture; resume it with service run");
        ImageSource source{std::filesystem::path(argv[3])};
        auto transfer_endpoint = endpoint_from(*session);
        bool assigned = false;
        for (const auto& task : tasks(transfer_endpoint,auth))
            if (number(task,"id") == number(summary,"task_id")) {
                transfer_endpoint.backup_encryption = task_transfer_encrypted(task);
                assigned = true;
            }
        if (!assigned) throw Error("saved backup task is no longer assigned to this device");
        const auto outcome = with_backup_heartbeat(transfer_endpoint, auth, [&](const Endpoint& endpoint) {
            return resume_image_job(endpoint, auth, source, *record, [&](const Value& saved) {
                store.write("backup-job.pstream", saved, backup_limits);
                print_backup_progress(saved);
            });
        });
        if (outcome != BackupOutcome::complete)
            throw Error("NAS reported a non-complete backup outcome; see backup status");
        std::cout << "Backup resumed; NAS reported completion. Restore verification is still required.\n";
        return 0;
    }
    constexpr auto usage = "usage: backup image IMAGE --task ID [--running-task ID] --sector-size 512|4096 --image-name NAME | backup resume IMAGE";
    if ((argc != 10 && argc != 12) || std::string_view(argv[2]) != "image") throw Error(usage);
    std::map<std::string_view,std::string_view> options;
    for (int i = 4; i < argc; i += 2)
        if (!options.emplace(argv[i],argv[i+1]).second) throw Error("duplicate backup option");
    for (const auto& [key,value] : options)
        if (key != "--task" && key != "--running-task" && key != "--image-name" && key != "--sector-size")
            throw Error(usage);
    for (const auto key : {"--task","--image-name","--sector-size"})
        if (!options.contains(key)) throw Error(usage);
    auto id = [&](const char* key) {
        const auto input = options.at(key);
        std::uint64_t value{};
        auto [end, error] = std::from_chars(input.data(), input.data()+input.size(), value);
        if (error != std::errc{} || end != input.data()+input.size() || !value)
            throw Error("invalid backup numeric option");
        return value;
    };
    const auto task_id = id("--task"), sector = id("--sector-size");
    const auto run_id = options.contains("--running-task") ? id("--running-task") : 0;
    if (sector != 512 && sector != 4096) throw Error("sector size must be 512 or 4096");
    const auto name = options.at("--image-name");
    Store store; // Token changes, service and other backup writers are excluded.
    const auto session = store.read("session.pstream");
    if (!session) throw Error("no saved session; log in first");
    if (text(*session, "registration_state") != "confirmed")
        throw Error("confirm registration or reconnect before backup");
    const auto auth = auth_from(*session);
    if (const auto previous = store.read("backup-job.pstream", backup_limits)) {
        const auto summary = backup_job_status(*previous, auth);
        if (!number(summary, "terminal"))
            throw Error("previous backup outcome is unresolved; inspect backup status before another backup");
        if (number(summary, "running_task_id") == run_id)
            throw Error("this running task already has a recorded outcome");
        const auto archive = "backup-job-" + std::to_string(number(summary, "running_task_id")) +
                             "-" + std::to_string(number(summary, "result_id")) + ".pstream";
        store.write(archive.c_str(), *previous, backup_limits);
    }
    Signals signals;
    auto endpoint = endpoint_from(*session);
    endpoint.cancelled = [] { return service_stop || service_reload; };
    ImageSource source{std::filesystem::path(argv[3])};
    const auto metadata = fixed_image_metadata(source,static_cast<std::uint32_t>(sector),name,server_time_now());
    bool assigned = false, current = false;
    auto compression = TransferCompression::none;
    for (const auto& task : tasks(endpoint, auth))
        if (number(task, "id") == task_id) {
            assigned = true;
            compression = validate_task_policy(task);
            endpoint.backup_app_aware = task_app_aware(task);
            endpoint.backup_encryption = task_transfer_encrypted(task);
        }
    if (!assigned) throw Error("selected backup task is not assigned to this device");
    for (const auto& job : running_tasks(endpoint, auth)) {
        if (!run_id && number(job, "task_id") == task_id)
            throw Error("selected task already has a running job; inspect --status --online");
        if (number(job, "id") == run_id && number(job, "task_id") == task_id) current = true;
    }
    if (run_id && !current) throw Error("selected running task does not belong to the assigned backup task");
    auto save = [&](const Value& record) {
        auto saved = record;
        set(saved, "task_id", Value{task_id});
        store.write("backup-job.pstream", saved, backup_limits);
        print_backup_progress(saved);
    };
    const auto outcome = with_backup_heartbeat(endpoint, auth, [&](const Endpoint& active) {
        return run_id ? run_full_image_job(active, auth, run_id, source, name, metadata, save,
                                           BackupOutcome::complete, compression)
                      : create_full_image_job(active, auth, task_id, source, name, metadata, save, compression);
    });
    if (outcome != BackupOutcome::complete)
        throw Error("NAS reported a non-complete backup outcome; see backup status");
    std::cout << "NAS reported completion. Restore verification is still required.\n";
    return 0;
}

int service_machine_command(int argc, char** argv) {
    if (argc != 8 || std::string_view(argv[4]) != "--task" || std::string_view(argv[6]) != "--image-name")
        throw Error("usage: service bind-machine DIRECTORY --task ID --image-name NAME");
    Store store;
    const auto session = store.read("session.pstream");
    if (!session || text(*session, "registration_state") != "confirmed")
        throw Error("service source requires a confirmed saved session");
    const auto auth = auth_from(*session);
    if (const auto job = store.read("backup-job.pstream", backup_limits);
        job && !number(backup_job_status(*job, auth), "terminal"))
        throw Error("resolve the current backup before rebinding the service source");
    std::uint64_t task{};
    const std::string_view input(argv[5]);
    const auto [end, error] = std::from_chars(input.data(), input.data()+input.size(), task);
    if (error != std::errc{} || end != input.data()+input.size() || !task) throw Error("invalid service task ID");
    validate_image_options(argv[7], 1024*1024);
    ReadyMachineCapture capture(argv[3]);
    const auto& journal = capture.journal();
    if (const auto previous = store.read("service-source.pstream")) {
        validate_service_source(*previous, auth);
        if (text(*previous, "capture_id") == journal.id && number(*previous, "claimed_run"))
            throw Error("this machine capture is already consumed; bind a fresh capture");
    }
    verify_machine_images(capture);
    if (capture.disk_count() > 1)
        (void)fixed_machine_metadata(machine_metadata_disks(capture,argv[7]),
            number(journal.reservation,"snapshot_time"));
    else
        (void)fixed_image_metadata(capture.source(),
            static_cast<std::uint32_t>(number(journal.artifact,"sector_size")),
            argv[7],number(journal.reservation,"snapshot_time"),nullptr,&journal.plan);
    bool assigned = false;
    std::string task_uuid;
    for (const auto& entry : tasks(endpoint_from(*session), auth))
        if (number(entry, "id") == task) { (void)validate_machine_task_policy(entry,journal.plan); assigned = true; task_uuid = text(entry,"task_uuid"); }
    if (!assigned) throw Error("service task is not assigned to this device");
    const auto queued = queued_machine_run(running_tasks(endpoint_from(*session),auth),task);
    if (!queued) throw Error("explicit capture injection requires a queued NAS backup");
    Value binding{Value::Object{{"format", Value{std::uint64_t{3}}},
        {"ds_id", Value{auth.ds_id}}, {"device_uuid", Value{auth.device_uuid}}, {"username", Value{auth.username}},
        {"task_id", Value{task}}, {"task_uuid",Value{task_uuid}}, {"queued_run",Value{*queued}},
        {"base_version_id",Value{std::uint64_t{0}}}, {"image_name", Value{std::string(argv[7])}},
        {"capture_id", Value{journal.id}}, {"capture_directory", field(journal.reservation, "directory")},
        {"capture", capture_journal_value(journal)}, {"claimed_run", Value{std::uint64_t{0}}}}};
    store.write("service-source.pstream", binding);
    std::cout << "Completed machine capture bound to service task " << task << "; one queued full backup may run.\n";
    return 0;
}

int service_source_command(int argc,char**) {
    if (argc != 3) throw Error("usage: service source");
    Store store(false);
    const auto session = store.read("session.pstream");
    if (!session) throw Error("no saved session; log in first");
    const auto source = store.read("service-source.pstream");
    if (source) validate_service_source(*source,auth_from(*session));
    print_json(std::cout,source ? *source : Value{});
    std::cout << '\n';
    return 0;
}

}
#endif
int lab_session_command(int argc,char** argv) {
#ifdef _WIN32
    return session_command(argc,argv);
#else
    load_saved_server_time();
    const std::string_view command(argv[1]);
    if (command == "service" && argc >= 3) {
        if (std::string_view(argv[2]) == "bind-machine") return service_machine_command(argc,argv);
        if (std::string_view(argv[2]) == "source") return service_source_command(argc,argv);
    }
    if (argc >= 3 && ((command == "backup" || command == "restore") &&
        (std::string_view(argv[2]) == "cancel" || std::string_view(argv[2]) == "reconcile")))
        return recovery_command(argc,argv);
    if (command == "backup") return backup_command(argc,argv);
    if (command == "restore") return restore_command(argc,argv);
    if (command == "events") {
        const bool json = argc == 3 && std::string_view(argv[2]) == "--json";
        if (argc != 2 && !json) throw Error("usage: opensabba events [--json]");
        Store store(false);
        auto session = store.read("session.pstream");
        if (!session) throw Error("no saved session; log in first");
        const auto summary = load_inbox(store, auth_from(*session)).summary();
        if (json) print_json(std::cout, summary);
        else {
            const auto& events = std::get<Value::Array>(field(summary, "events").data);
            std::cout << "Retained events: " << events.size() << '\n';
            for (const auto& event : events)
                std::cout << "  " << number(event, "id") << ": "
                          << safe_display(text(event, "action")) << " ("
                          << safe_display(text(event, "state")) << ")\n";
        }
        std::cout << '\n';
        return 0;
    }
    if (command == "tasks" || (command == "status" && argc > 2 &&
        std::any_of(argv+2,argv+argc,[](const char* arg) {
            return std::string_view(arg) == "--online" || std::string_view(arg) == "--json";
        }))) {
        bool online = command == "tasks", json = false;
        for (int index = 2; index < argc; ++index) {
            const std::string_view option(argv[index]);
            if (option == "--online" && command == "status" && !online) online = true;
            else if (option == "--json" && !json) json = true;
            else throw Error("usage: tasks [--json] or status --online [--json]");
        }
        if (!online) throw Error("status --json requires --online");
        Store store(false);
        auto session = store.read("session.pstream");
        if (!session) throw Error("no saved session; log in first");
        if (text(*session, "registration_state") != "confirmed")
            throw Error("confirm registration or reconnect before querying tasks");
        const auto endpoint = endpoint_from(*session);
        const auto auth = auth_from(*session);
        auto assigned = tasks(endpoint, auth);
        Value::Array running;
        if (command == "status") running = running_tasks(endpoint, auth);
        for (auto& task : assigned) client_display_times(task);
        if (json) {
            Value::Object output{{"task_list", Value{std::move(assigned)}}};
            if (command == "status")
                output.emplace("running_task_list", Value{std::move(running)});
            print_json(std::cout, Value{std::move(output)});
            std::cout << '\n';
            return 0;
        }
        std::cout << "NAS: " << safe_display(endpoint.host) << ':' << endpoint.port
                  << "\nAssigned tasks: " << assigned.size() << '\n';
        auto show = [](const Value::Array& list, bool jobs) {
            const std::map<std::string, std::string> labels{
                {"backup_type", "Backup type (NAS code)"}, {"source_type", "Source type (NAS code)"},
                {"custom_volume", "Selected volumes"}, {"custom_volume_alias", "Volume aliases"},
                {"sched_content", "Schedule (NAS JSON)"}, {"is_paused", "Paused"},
                {"compression", "Transfer compression"}, {"encryption", "Transfer encryption"},
                {"last_backup_success_time", "Last successful backup (Unix seconds)"},
                {"status", "Status (NAS code)"}, {"detail_status", "Detail status (NAS code)"},
                {"type", "Job type (NAS code)"}, {"backup_task", "Backup progress (bytes)"}};
            for (const auto& item : list) {
                std::cout << (jobs ? "\nJob " : "\nTask ") << number(item, "id");
                if (!jobs) std::cout << ": " << safe_display(text(item, "name"));
                std::cout << '\n';
                for (const auto& [key, value] : fields(item)) {
                    if (key == "id" || key == "name") continue;
                    const auto label = labels.find(key);
                    std::cout << "  " << (label == labels.end() ? key : label->second) << ": ";
                    if (key == "is_paused" || key == "compression" || key == "encryption")
                        std::cout << (std::get<std::uint64_t>(value.data) ? "yes" : "no");
                    else print_json(std::cout, value);
                    std::cout << '\n';
                }
            }
        };
        show(assigned, false);
        if (command == "status") {
            std::cout << "\nNAS-reported current jobs: " << running.size() << '\n';
            show(running, true);
            std::cout << "Automatic backup requires a configured service source and supported task settings.\n";
        }
        std::cout << "Destination: not supplied by the task-discovery response.\n";
        return 0;
    }
    if (command == "reconnect" || command == "heartbeat") {
        Store store;
        auto session = store.read("session.pstream");
        if (!session) throw Error("no saved session; log in first");
        const auto endpoint = endpoint_from(*session);
        if (argc != 2) throw Error("reconnect and heartbeat take no options");
        const auto state = text(*session, "registration_state");
        if (command == "heartbeat") {
            if (state != "confirmed") throw Error("confirm registration before sending a heartbeat");
            heartbeat(endpoint, auth_from(*session));
            std::cout << "Heartbeat accepted.\n";
            return 0;
        }
        const auto result = reconnect(endpoint, auth_from(*session), device_metadata());
        set(*session, "token", Value{result.token});
        set(*session, "ds_id", Value{result.ds_id});
        set(*session, "registration_state", Value{std::string("confirmed")});
        store.write("session.pstream", *session);
        refresh_server_time(store,endpoint,auth_from(*session));
        std::cout << "Saved-token authentication accepted; session updated.\n";
        return 0;
    }
    return lab_connection_command(argc,argv);
#endif
}
}

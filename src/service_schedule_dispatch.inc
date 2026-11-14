// Accept client-originated schedule events through the same preparation/capture
// pipeline as NAS-originated jobs. The queue stays durable across disconnects.
void service_schedule_tick(Store& store,const SavedAuth& auth,const Endpoint& endpoint,
    const Value::Array& tasks,const Value::Array& running,const std::optional<Value>& binding,
    const RegisterRunningResult& register_result) {
    // An existing capture/handshake owns the single backup worker.
    for (const auto name : {"service-machine-pending.pstream","service-machine-recapture.pstream",
                            "service-machine-event.pstream"})
        if (store.read(name)) return;
    if (binding) {
        const auto job = store.read("backup-job.pstream",backup_limits);
        if (!number(*binding,"claimed_run") || !job || !number(backup_job_status(*job,auth),"terminal")) return;
    }
    for (const auto& name : store.names()) {
        if (!name.starts_with("service-schedule-event-") || !name.ends_with(".pstream")) continue;
        auto event = *store.read(name.c_str());
        const auto& owner = field(event,"task_owner");
        validate_machine_task_owner(owner,auth);
        const auto task_id = number(owner,"task_id");
        const auto task = std::find_if(tasks.begin(),tasks.end(),[&](const Value& candidate) {
            return field(candidate,"id") == field(owner,"task_id") &&
                field(candidate,"task_uuid") == field(owner,"task_uuid");
        });
        if (task == tasks.end()) { store.remove(name.c_str()); continue; }
        const auto existing = std::find_if(running.begin(),running.end(),[&](const Value& run) {
            return number(run,"type") == 0 && number(run,"task_id") == task_id && number(run,"status") < 3;
        });
        if (!number(event,"attempted") && existing != running.end()) {
            store.remove(name.c_str()); // event deduplication suppresses this event.
            continue;
        }
        (void)validate_task_policy(*task,true);
        std::uint64_t base = 0, base_snapshot = 0;
        BackupRun run{};
        if (number(event,"attempted")) {
            // add_backup_task is non-idempotent. Reconcile its response from the
            // authenticated task's running record; never repeat uncertain adds.
            if (existing == running.end())
                throw BackupRetry("scheduled backup creation awaits its NAS running-task identity");
            const auto observed = backup_event_state(endpoint,auth,task_id,number(*existing,"id"));
            if (!observed || !observed->run.version_id || !observed->run.result_id)
                throw BackupRetry("scheduled backup creation awaits its NAS preparation");
            run = observed->run;
            base = number(event,"base_version_id");
            base_snapshot = number(event,"base_snapshot_id");
        } else {
            const auto requested = backup_base_version(endpoint,auth,task_id);
            const auto catalog = machine_snapshots(store);
            if (const auto* snapshot = catalog.base(text(*task,"task_uuid"),requested)) {
                base = requested;
                base_snapshot = snapshot->id;
            }
            run = trigger_scheduled_backup(endpoint,auth,task_id,base,[&] {
                set(event,"attempted",Value{std::uint64_t{1}});
                set(event,"base_version_id",Value{base});
                set(event,"base_snapshot_id",Value{base_snapshot});
                store.write(name.c_str(),event);
            });
        }
        store.write("service-machine-event.pstream",Value{Value::Object{
            {"task_owner",owner},{"task_uuid",field(*task,"task_uuid")},{"run",Value{run.running_task_id}},
            {"base_version_id",Value{base}},{"base_snapshot_id",Value{base_snapshot}},
            {"handshake_sent",Value{std::uint64_t{1}}},
            {"preparation",prepared_backup_value({run,base})}}});
        register_result({run.running_task_id,task_id,run.version_id,run.result_id});
        store.remove(name.c_str());
        std::cout << "Scheduled backup triggered for task " << task_id << ", NAS job "
                  << run.running_task_id << ".\n" << std::flush;
        return;
    }
}

// Private service implementation. Included after the machine capture helpers;
// all mutations run on the thread holding Store's exclusive lifetime lock.
std::string cache_point_name(std::uint64_t sequence) {
    return "backup-cache-"+std::to_string(sequence)+".pstream";
}
bool cache_point_ready(const Value& point) {
    const auto state = text(point,"cache_state");
    return state == "cached" || state == "partial_cached";
}
void validate_cache_owner(const Value& point, const Value& owner) {
    if (number(point,"cache_format") != 1 || field(point,"task_owner") != owner)
        throw Error("backup cache belongs to another NAS, account, task or NAS task ownership");
}
std::vector<Value> cache_points(Store& store, const Value& owner) {
    std::vector<Value> result;
    for (const auto& name : store.names()) {
        if (!name.starts_with("backup-cache-") || !name.ends_with(".pstream")) continue;
        auto point = *store.read(name.c_str(),backup_limits);
        for (const auto key : {"ds_id","device_uuid","username"})
            if (field(field(point,"task_owner"),key) != field(owner,key))
                throw Error("backup cache belongs to another NAS, device or account");
        if (field(field(point,"task_owner"),"task_id") != field(owner,"task_id") ||
            field(field(point,"task_owner"),"task_uuid") != field(owner,"task_uuid")) continue;
        validate_cache_owner(point,owner);
        if (cache_point_name(number(point,"sequence")) != name) throw Error("backup cache sequence differs from its journal");
        result.push_back(std::move(point));
    }
    std::sort(result.begin(),result.end(),[](const auto& a,const auto& b) {
        return number(a,"sequence") < number(b,"sequence");
    });
    return result;
}
std::filesystem::path cache_point_directory(const Value& point, bool admission = false) {
    return backup_cache_directory(backup_cache_policy(field(point,"task")),text(field(point,"task"),"task_uuid"),
        admission)/text(point,"id");
}
void save_cache_point(Store& store, const Value& point) {
    store.write(cache_point_name(number(point,"sequence")).c_str(),point,backup_limits);
}
Value cache_ranges(std::span<const ChangedExtent> ranges) {
    Value::Array result;
    for (const auto& range : ranges)
        result.push_back(Value{Value::Object{{"offset",Value{range.offset}},{"length",Value{range.length}}}});
    return Value{std::move(result)};
}
std::vector<ChangedExtent> cache_ranges(const Value& ranges) {
    std::vector<ChangedExtent> result;
    for (const auto& range : std::get<Value::Array>(ranges.data))
        result.push_back({number(range,"offset"),number(range,"length")});
    return result;
}
std::vector<std::filesystem::path> cache_excluded_files(Store& store, const Value& owner) {
    std::vector<std::filesystem::path> result;
    for (const auto& point : cache_points(store,owner)) {
        if (!cache_point_ready(point) && text(point,"cache_state") != "uploading") continue;
        const auto directory = cache_point_directory(point);
        for (const auto& image : std::get<Value::Array>(field(point,"images").data))
            for (const auto key : {"header","data"})
                result.push_back(directory/text(field(image,"files"),key));
    }
    return result;
}
void cache_activity(const Endpoint& endpoint, const SavedAuth& auth, Value& point,
    std::uint64_t code, const std::string& volume = {}) {
    // Offline activities stay with the capture until a NAS result exists.
    Value::Array logs;
    if (fields(point).contains("cache_logs")) logs = std::get<Value::Array>(field(point,"cache_logs").data);
    logs.push_back(Value{Value::Object{{"type",Value{code}},{"time",Value{server_time_now()}},
        {"volume",Value{volume}}}});
    set(point,"cache_logs",Value{std::move(logs)});
    (void)endpoint; (void)auth;
}
void cache_publish_activity(const Endpoint& endpoint, const SavedAuth& auth, Value& point, Store& store) {
    if (!fields(point).contains("upload_job") || !fields(field(point,"upload_job")).contains("result_id")) return;
    auto& logs = std::get<Value::Array>(std::get<Value::Object>(point.data).at("cache_logs").data);
    for (auto& log : logs) {
        if (fields(log).contains("sent")) continue;
        auto parameters = fields(log).contains("parameters") ? field(log,"parameters") :
            Value{Value::Object{{"volume_name",field(log,"volume")}}};
        auto& values = std::get<Value::Object>(parameters.data);
        for (const auto key : {"running_task_id","task_id","result_id"})
            values[key] = field(field(point,"upload_job"),key);
        values["id"] = field(field(point,"upload_job"),"running_task_id");
        values["task_uuid"] = field(field(point,"task"),"task_uuid");
        std::ostringstream json;
        print_json(json,parameters);
        report_script_activity(endpoint,auth,number(field(point,"upload_job"),"running_task_id"),
            number(log,"type"),number(log,"time"),json.str());
        set(log,"sent",Value{std::uint64_t{1}});
        save_cache_point(store,point);
    }
}
std::optional<Value> cache_capture_base(Store& store, const Value& owner, const SavedAuth& auth,
                                        const Value& target) {
    std::optional<Value> base;
    const auto catalog = machine_snapshots(store);
    std::uint64_t selected_id = 0;
    const auto select = [&](const Value& candidate) {
        const auto capture = capture_journal_from_value(field(candidate,"source_capture"));
        const auto* snapshot = catalog.capture(capture.id);
        if (!snapshot || snapshot->id <= selected_id) return;
        if (!backup_cache_base_eligible(capture,target) ||
            text(candidate,"image_name") != machine_physical_image_name(capture.plan,capture.plan,
                machine_disk_image_name(text(capture.plan,"disk")))) return;
        (void)validate_machine_incremental_base(candidate,auth,true);
        // A saved NAS job is not itself evidence that its local capture is
        // still the exact configured, owned journal.
        if (capture_journal_value(inspect_machine_capture(text(capture.reservation,"directory"))) !=
            capture_journal_value(capture))
            throw Error("cached base differs from its retained capture journal");
        selected_id = snapshot->id;
        base = candidate;
    };
    // A partial replay replaces backup-job.pstream too. Its preceding complete
    // NAS base remains eligible in the archived jobs, never the partial point.
    for (const auto& name : store.names()) {
        if (!name.starts_with("backup-job") || !name.ends_with(".pstream")) continue;
        const auto current = *store.read(name.c_str(),backup_limits);
        if (number(current,"task_id") != number(owner,"task_id") ||
            !fields(current).contains("source_capture") ||
            text(backup_job_status(current,auth),"phase") != "complete") continue;
        select(current);
    }
    for (const auto& point : cache_points(store,owner)) {
        const auto state = text(point,"cache_state");
        if (state == "cached") select(point);
        else if (state == "uploaded") select(field(point,"upload_job"));
    }
    return base;
}
void cache_write_point(Store& store, Value& point, const SavedAuth& auth, const Endpoint& endpoint) {
    const auto state = text(point,"cache_state");
    if (cache_point_ready(point)) {
        finish_machine_capture(text(field(field(point,"source_capture"),"reservation"),"directory"));
        return;
    }
    if (state != "capturing" && state != "writing") return;
    if (!fields(point).contains("source_capture")) {
        // Intent preceded capture reservation, so no source was acquired.
        set(point,"cache_state",Value{std::string("error")});
        save_cache_point(store,point);
        return;
    }
    auto capture = inspect_machine_capture(text(field(field(point,"source_capture"),"reservation"),"directory"));
    const auto reserved = capture_journal_from_value(field(point,"source_capture"));
    if (fields(point).contains("local_snapshot_id")) {
        auto catalog = machine_snapshots(store);
        if (!catalog.capture(reserved.id)) {
            catalog.attach(number(point,"local_snapshot_id"),reserved);
            save_machine_snapshots(store,catalog);
        }
    }
    if (reserved.phase == CapturePhase::prepared) verify_machine_reservation(reserved,capture);
    else if (capture_journal_value(capture) != capture_journal_value(reserved))
        throw Error("cache capture differs from its retained journal");
    if (capture.phase != CapturePhase::ready) {
        capture = inspect_machine_capture(text(capture.reservation,"directory"),true,&capture);
        set(point,"source_capture",capture_journal_value(capture));
        set(point,"cache_state",Value{std::string("error")});
        save_cache_point(store,point);
        return;
    }
    set(point,"source_capture",capture_journal_value(capture));
    if (!fields(point).contains("capture_logs_imported")) {
        auto logs = std::get<Value::Array>(field(point,"cache_logs").data);
        for (const auto& log : capture.logs)
            logs.push_back(Value{Value::Object{{"type",field(log,"log_type")},
                {"time",field(log,"log_time")},{"parameters",field(log,"parameters")}}});
        set(point,"cache_logs",Value{std::move(logs)});
        set(point,"capture_logs_imported",Value{std::uint64_t{1}});
    }
    const auto directory = cache_point_directory(point);
    auto ready = std::make_unique<ReadyMachineCapture>(text(capture.reservation,"directory"));
    const auto deltas = machine_incremental(field(point,"base"),*ready,machine_disk_image_name(text(capture.plan,"disk")),endpoint,auth,
        nullptr,true);
    auto disks = machine_metadata_disks(*ready,machine_disk_image_name(text(capture.plan,"disk")),true,deltas);
    for (std::size_t index = 0; index < disks.size(); ++index) disks[index].delta = &deltas[index].plan;
    const auto metadata = fixed_machine_metadata(disks,number(capture.reservation,"snapshot_time"));
    set(point,"snapshot_info",Value{metadata});
    set(point,"cache_state",Value{std::string("writing")});
    set(point,"image_count",Value{static_cast<std::uint64_t>(disks.size())});
    save_cache_point(store,point);
    Value::Array images;
    for (std::size_t index = 0; index < disks.size(); ++index) {
        const auto basename = "image-"+std::to_string(index);
        remove_backup_cache_attempt(directory,basename);
        const auto unused = machine_unused_ranges(disks[index]);
        const auto reread = disk_reread_ranges(disks[index],&deltas[index]);
        cache_activity(endpoint,auth,point,7063,disks[index].image_name);
        const BackupImage image{disks[index].source,disks[index].image_name,unused,reread};
        auto files = write_backup_cache_image(directory,basename,image,deltas[index],
            validate_task_policy(field(point,"task"),true),endpoint.cancelled);
        images.push_back(Value{Value::Object{{"name",Value{image.name}},{"size",Value{image.source->size()}},
            {"sha256",Value{std::string{}}},{"base_sha256",Value{std::string{}}},
            {"unused_ranges",cache_ranges(unused)},{"reread_ranges",cache_ranges(reread)},
            {"filesystem_allocation",Value{std::uint64_t{1}}},
            {"ranges",delta_plan_value(deltas[index].plan)},{"machine_policy",*deltas[index].machine_policy},{"files",std::move(files)}}});
        cache_activity(endpoint,auth,point,7064,disks[index].image_name);
        set(point,"images",Value{images});
        save_cache_point(store,point);
    }
    set(point,"image_name",field(images.front(),"name"));
    set(point,"image_size",field(images.front(),"size"));
    set(point,"image_sha256",Value{std::string{}});
    set(point,"data_format",Value{std::uint64_t{1}});
    set(point,"unused_ranges",field(images.front(),"unused_ranges"));
    set(point,"schema",Value{std::uint64_t{images.size() == 1 ? 9U : 7U}});
    set(point,"incremental",Value{Value::Object{{"ranges",field(images.front(),"ranges")},
        {"base_snapshot_id",Value{capture_journal_from_value(field(field(point,"base"),"source_capture")).id}}}});
    set(point,"images",Value{std::move(images)});
    set(point,"cache_state",Value{std::string(backup_cache_capture_partial(capture) ? "partial_cached" : "cached")});
    // The durable cache publication precedes ending snapshot reads.
    save_cache_point(store,point);
    ready.reset();
    finish_machine_capture(text(capture.reservation,"directory"));
}
void cache_capture_point(Store& store, const Value& owner, std::optional<Value>& binding,
    const Value& task, const SavedAuth& auth, const Endpoint& endpoint, std::uint64_t due,
    const Value* local_event = nullptr) {
    const auto planned = service_machine_capture_provider().plan(machine_working_directory().string(),task);
    const auto base = cache_capture_base(store,owner,auth,machine_capture_target(planned));
    if (!base) {
        if (!local_event) throw BackupRetry("offline cache requires a completed online base (7031)");
        auto rejected = *local_event;
        set(rejected,"state",Value{std::string("error")});
        set(rejected,"error",Value{std::string("cache requires a completed online base (7031)")});
        store.write(("service-cache-event-"+text(*local_event,"event_id")+".pstream").c_str(),rejected,backup_limits);
        store.remove(cache_event_name(number(owner,"task_id")).c_str());
        std::cerr << "Local cache event failed: no completed online base (7031)." << std::endl;
        return;
    }
    if (const auto job = store.read("backup-job.pstream",backup_limits);
        job && !number(backup_job_status(*job,auth),"terminal"))
        throw BackupRetry("unfinished NAS backup retains its snapshot; offline capture deferred");
    if (binding) {
        if (!number(*binding,"claimed_run"))
            throw BackupRetry("an unconsumed source precedes the local cache event");
        finish_machine_capture(text(*binding,"capture_directory"));
        store.write(service_run_archive(number(*binding,"claimed_run")).c_str(),*binding);
        store.remove("service-source.pstream"); binding.reset();
    }
    auto catalog = machine_snapshots(store);
    const auto base_id = catalog.capture(text(field(*base,"source_capture"),"id"))->id;
    const auto local_snapshot = catalog.prepare(number(owner,"task_id"),text(task,"task_uuid"),0,base_id,
        cleanup_machine_snapshot_resource,
        [&](const MachineSnapshotCatalog& saved) { save_machine_snapshots(store,saved); });
    preflight_service_machine();
    const auto parent = backup_cache_directory(backup_cache_policy(task),text(task,"task_uuid"));
    const auto id = random_hex(16);
    const auto directory = parent/id;
    if (mkdir(directory.c_str(),0700)) throw Error("cannot reserve cached restore point directory");
    {
        File parent_fd(open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if (fsync(parent_fd.fd)) throw Error("cannot persist cached restore point directory");
    }
    std::uint64_t sequence = 1;
    for (const auto& name : store.names())
        if (name.starts_with("backup-cache-") && name.ends_with(".pstream"))
            sequence = std::max(sequence,number(*store.read(name.c_str(),backup_limits),"sequence")+1);
    auto base_view = *base;
    for (const auto key : {"base","cache_logs","upload_job","task_owner","task"})
        std::get<Value::Object>(base_view.data).erase(key);
    Value point{Value::Object{{"cache_format",Value{std::uint64_t{1}}},{"sequence",Value{sequence}},
        {"id",Value{id}},{"task_owner",owner},{"task",task},{"base",std::move(base_view)},{"due",Value{due}},
        {"local_snapshot_id",Value{local_snapshot}},
        {"task_id",field(owner,"task_id")},{"cache_logs",Value{Value::Array{}}},
        {"cache_state",Value{std::string("capturing")}}}};
    if (local_event) set(point,"local_event_id",field(*local_event,"event_id"));
    save_cache_point(store,point);
    // If the process dies before this unlink, restart finds the point by its
    // event identity rather than acquiring a second restore point.
    if (local_event) store.remove(cache_event_name(number(owner,"task_id")).c_str());
    const auto exclusions = machine_internal_files(store);
    try {
        const auto capture = service_machine_capture_provider().capture(ServiceMachineCaptureRequest{
            MachineJobPlan{task,local_event ? *local_event : Value{},planned,{}},[&](const CaptureJournal& capture) {
                set(point,"source_capture",capture_journal_value(capture));
                save_cache_point(store,point);
                catalog.attach(local_snapshot,capture);
                save_machine_snapshots(store,catalog);
            },endpoint.cancelled,[&](const Value& plan) {
                check_machine_capture_directory(plan);
                (void)validate_machine_task_policy(task,plan,true);
            },SnapshotBoundaryHooks{{},{},{},
                [&](const Value& plan) { return machine_task_missing_mounts(task,plan); }},exclusions,[] { return service_stop.load() || service_reload.load(); }});
        set(point,"source_capture",capture_journal_value(capture));
        save_cache_point(store,point);
        cache_write_point(store,point,auth,endpoint);
    } catch (...) {
        cache_activity(endpoint,auth,point,7065);
        if (!cache_point_ready(point) && !(endpoint.cancelled && endpoint.cancelled())) {
            set(point,"cache_state",Value{std::string("error")});
        }
        save_cache_point(store,point);
        if (service_stop || service_reload) throw Cancelled();
        throw;
    }
}
Value cache_resolved_base(Store& store, const Value& point, const Value& owner, const SavedAuth& auth) {
    const auto& original = field(point,"base");
    if (!fields(original).contains("cache_state")) {
        if (text(backup_job_status(original,auth),"phase") != "complete") throw Error("cached NAS base is not complete");
        return original;
    }
    for (const auto& parent : cache_points(store,owner))
        if (number(parent,"sequence") == number(original,"sequence")) {
            if (text(parent,"cache_state") != "uploaded" ||
                text(backup_job_status(field(parent,"upload_job"),auth),"phase") != "complete")
                throw BackupRetry("cached predecessor has not completed on the NAS");
            return field(parent,"upload_job");
        }
    throw Error("cached predecessor journal is absent");
}
void cache_replay_point(Store& store, Value& point, const Value& owner, const SavedAuth& auth,
    const Endpoint& connected, const Value& current_task, const RegisterRunningResult& register_result,
    const TaskView& task_view) {
    auto endpoint = connected;
    endpoint.cached_backup = true;
    endpoint.backup_encryption = task_transfer_encrypted(current_task);
    endpoint.backup_trigger_type = 0;
    endpoint.backup_app_aware = task_app_aware(field(point,"task"));
    const auto directory = cache_point_directory(point);
    const bool partial = backup_cache_capture_partial(capture_journal_from_value(field(point,"source_capture")));
    const auto base = cache_resolved_base(store,point,owner,auth);
    if (backup_result(endpoint,auth,number(owner,"task_id"),number(base,"result_id")) != "complete")
        throw Error("NAS no longer retains the cached predecessor");
    std::vector<std::unique_ptr<CachedBackupImage>> sources;
    std::vector<BackupImage> images;
    std::vector<IncrementalBackup> deltas;
    for (const auto& image : std::get<Value::Array>(field(point,"images").data)) {
        sources.push_back(std::make_unique<CachedBackupImage>(directory,field(image,"files")));
        const auto size = number(image,"size");
        auto delta = delta_plan_from_value(field(image,"ranges"),size);
        delta.filesystem_allocation = true;
        auto reread = cache_ranges(field(image,"reread_ranges"));
        images.push_back({&sources.back()->source(),text(image,"name"),
            cache_ranges(field(image,"unused_ranges")),reread});
        deltas.push_back({number(base,"version_id"),number(base,"result_id"),number(base,"running_task_id"),
            capture_journal_from_value(field(base,"source_capture")).id,"",std::move(delta),std::move(reread),field(image,"machine_policy")});
        validate_backup_cache_image_policy(field(image,"files"),images.back(),deltas.back(),
            validate_task_policy(field(point,"task"),true));
    }
    auto saved = fields(point).contains("upload_job") ? std::optional<Value>{field(point,"upload_job")} : std::nullopt;
    const auto persist = [&](const Value& job) {
        auto bound = job;
        set(bound,"task_id",field(owner,"task_id"));
        set(bound,"source_capture",field(point,"source_capture"));
        set(bound,"service_source",field(field(point,"source_capture"),"id"));
        set(bound,"cache_sequence",field(point,"sequence"));
        set(point,"upload_job",bound);
        set(point,"cache_state",Value{std::string("uploading")});
        save_cache_point(store,point);
        store.write("backup-job.pstream",bound,backup_limits);
        remember_machine_version(store,bound);
        endpoint.service_status->backup(bound);
        if (fields(bound).contains("result_id"))
            register_result({number(bound,"running_task_id"),number(bound,"task_id"),
                number(bound,"version_id"),number(bound,"result_id")});
        saved = std::move(bound);
    };
    if (saved) {
        if (text(backup_job_status(*saved,auth),"phase") == "prepare" &&
            !number(*saved,"running_task_id"))
            throw BackupRetry("cache creation reply was lost; the NAS run must be reconciled before replay");
        auto recovering = *saved;
        recover_service_backup(endpoint,auth,recovering,persist);
        saved = std::move(recovering);
        if (text(backup_job_status(*saved,auth),"phase") == "planned") saved.reset();
    } else if (const auto previous = store.read("backup-job.pstream",backup_limits)) {
        if (!number(backup_job_status(*previous,auth),"terminal"))
            throw BackupRetry("another unfinished backup precedes cache replay");
        store.write(("backup-job-"+std::to_string(number(*previous,"running_task_id"))+"-"+
            std::to_string(number(*previous,"result_id"))+".pstream").c_str(),*previous,backup_limits);
    }
    cache_publish_activity(endpoint,auth,point,store);
    if (!saved || !number(backup_job_status(*saved,auth),"terminal")) {
        // Snapshot preparation emits this for cached-upload snapshot reuse too.
        // Replay uses trigger 0; offline capture uses 5 and emits no start.
        historical_backup_start(storage_path(false),text(field(point,"task"),"name"),
            endpoint.backup_trigger_type,0);
        for (const auto& image : images) cache_activity(endpoint,auth,point,7057,image.name);
        save_cache_point(store,point);
        const auto retained = saved;
        auto transfer_endpoint = endpoint;
        transfer_endpoint.backup_task_uuid = text(field(point,"task"),"task_uuid");
        run_service_backup(transfer_endpoint,auth,task_view,number(owner,"task_id"),saved,persist,
            [&](const Endpoint& transfer,const SaveBackupJob& save) {
                if (!retained) create_cached_images_job(transfer,auth,number(owner,"task_id"),images,deltas,
                    std::get<pstream::Bytes>(field(point,"snapshot_info").data),save,
                    validate_task_policy(field(point,"task"),true),
                    partial ? BackupOutcome::partial : BackupOutcome::complete);
                else if (images.size() > 1) resume_images_job(transfer,auth,images,*retained,save);
                else resume_image_job(transfer,auth,*images.front().source,*retained,save,
                    images.front().unused_ranges,images.front().reread_ranges);
            });
    }
    const auto summary = backup_job_status(field(point,"upload_job"),auth);
    if (!number(summary,"terminal")) return;
    if (text(summary,"phase") == "complete" || text(summary,"phase") == "partial")
        for (const auto& image : images) cache_activity(endpoint,auth,point,7058,image.name);
    save_cache_point(store,point);
    cache_publish_activity(endpoint,auth,point,store);
    if (text(summary,"phase") == "cancel") {
        cache_activity(endpoint,auth,point,1126);
        save_cache_point(store,point);
        cache_publish_activity(endpoint,auth,point,store);
        Value::Array attempts;
        if (fields(point).contains("cancelled_uploads"))
            attempts = std::get<Value::Array>(field(point,"cancelled_uploads").data);
        attempts.push_back(field(point,"upload_job"));
        set(point,"cancelled_uploads",Value{std::move(attempts)});
        std::get<Value::Object>(point.data).erase("upload_job");
        set(point,"cache_state",Value{std::string(partial ? "partial_cached" : "cached")});
        save_cache_point(store,point);
        return;
    }
    const auto successful = text(summary,"phase") == "complete" || text(summary,"phase") == "partial";
    set(point,"cache_state",Value{std::string(successful ?
        (partial || text(summary,"phase") == "partial" ? "partial_uploaded" : "uploaded") : "merged")});
    save_cache_point(store,point);
    // Readers must close before unlink, including on Windows fixtures.
    sources.clear();
    for (const auto& image : std::get<Value::Array>(field(point,"images").data))
        remove_backup_cache_image(directory,field(image,"files"));
    if (!successful) {
        for (auto child : cache_points(store,owner)) {
            if (number(child,"sequence") <= number(point,"sequence") || !cache_point_ready(child)) continue;
            set(child,"cache_state",Value{std::string("merged")}); save_cache_point(store,child);
            for (const auto& image : std::get<Value::Array>(field(child,"images").data))
                remove_backup_cache_image(cache_point_directory(child),field(image,"files"));
        }
    }
}
// Returns true while a local cache chain owns dispatch ordering.
bool service_cache_tick(Store& store, const Value& owner, std::optional<Value>& binding,
    const SavedAuth& auth, const Endpoint& endpoint, const RegisterRunningResult& register_result, const TaskView& task_view, bool online,
    std::uint64_t connected_at) {
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    auto policy_record = store.read(cache_task_name(number(owner,"task_id")).c_str(),backup_limits);
    if (!policy_record) return false;
    if (field(*policy_record,"task_owner") != owner) throw Error("cached task policy belongs to another NAS task ownership");
    const auto task = field(*policy_record,"task");
    const auto policy = backup_cache_policy(task);
    auto points = cache_points(store,owner);
    if (const auto event = store.read(cache_event_name(number(owner,"task_id")).c_str(),backup_limits)) {
        if (field(*event,"task_owner") != owner) throw Error("local cache event belongs to another NAS task ownership");
        if (std::any_of(points.begin(),points.end(),[&](const auto& point) {
                return fields(point).contains("local_event_id") &&
                    field(point,"local_event_id") == field(*event,"event_id");
            })) store.remove(cache_event_name(number(owner,"task_id")).c_str());
    }
    for (auto& point : points) {
        const auto state = text(point,"cache_state");
        if (state == "capturing" || state == "writing") {
            cache_write_point(store,point,auth,endpoint);
            return true;
        }
        if (cache_point_ready(point)) finish_machine_capture(
            text(field(field(point,"source_capture"),"reservation"),"directory"));
        if (state == "error" && fields(point).contains("source_capture") && !fields(point).contains("cleanup_complete")) {
            try {
                auto capture = inspect_machine_capture(text(field(field(point,"source_capture"),"reservation"),"directory"));
                if (capture.phase == CapturePhase::ready) finish_machine_capture(text(capture.reservation,"directory"));
                else (void)inspect_machine_capture(text(capture.reservation,"directory"),true,&capture);
                if (fields(point).contains("image_count"))
                    for (std::uint64_t index = 0; index < number(point,"image_count"); ++index)
                        remove_backup_cache_attempt(cache_point_directory(point),"image-"+std::to_string(index));
                set(point,"cleanup_complete",Value{std::uint64_t{1}});
                save_cache_point(store,point);
            } catch (const Error& error) {
                std::cerr << "Failed local cache cleanup deferred: " << error.what() << '\n';
            }
        }
    }
    points = cache_points(store,owner);
    if (!number(*policy_record,"assigned")) return std::any_of(points.begin(),points.end(),[](const Value& point) {
        return cache_point_ready(point) || text(point,"cache_state") == "uploading";
    });
    if (const auto event = store.read(cache_event_name(number(owner,"task_id")).c_str(),backup_limits)) {
        if (field(*event,"task_uuid") != field(task,"task_uuid"))
            throw Error("local cache event task identity changed");
        // Explicit type-4 events do not depend on disconnect expiry, a schedule
        // or the automatic replay pause. Disabled policy still rejects them.
        if (!policy.enabled) {
            auto rejected = *event;
            set(rejected,"state",Value{std::string("disabled")});
            store.write(("service-cache-event-"+text(*event,"event_id")+".pstream").c_str(),rejected,backup_limits);
            store.remove(cache_event_name(number(owner,"task_id")).c_str());
        } else {
            if (backup_cache_write_event(*event,owner,*policy_record,text(*event,"event_id"),
                number(*event,"due")) != *event)
                throw Error("queued local cache event differs from its assigned policy");
            cache_capture_point(store,owner,binding,task,auth,endpoint,number(*event,"due"),&*event);
            return true;
        }
    }
    auto queued = std::find_if(points.begin(),points.end(),[](const auto& p) {
        return cache_point_ready(p) || text(p,"cache_state") == "uploading";
    });
    if (online && queued != points.end()) {
        if (policy.enabled && policy.paused) return false;
        if (now >= connected_at && now-connected_at >= 60) {
            if (binding && number(*binding,"claimed_run")) {
                const auto prior = store.read("backup-job.pstream",backup_limits);
                if (prior && !number(backup_job_status(*prior,auth),"terminal")) return true;
                store.write(service_run_archive(number(*binding,"claimed_run")).c_str(),*binding);
                store.remove("service-source.pstream"); binding.reset();
            }
            try {
                cache_replay_point(store,*queued,owner,auth,endpoint,task,register_result,task_view);
            } catch (const TransportError&) { throw; }
            catch (const BackupRetry&) { throw; }
            catch (const Cancelled&) { throw; }
            catch (const BackupStateError&) { throw; }
            catch (const Error& error) {
                cache_activity(endpoint,auth,*queued,7059);
                cache_activity(endpoint,auth,*queued,7061);
                save_cache_point(store,*queued);
                if (fields(*queued).contains("upload_job")) {
                    auto failed = field(*queued,"upload_job");
                    if (!number(failed,"running_task_id"))
                        throw BackupRetry("cache creation has no NAS running-task identity; retained for reconciliation");
                    auto cached_endpoint = endpoint;
                    cached_endpoint.cached_backup = true;
                    fail_service_backup(cached_endpoint,auth,failed,[&](const Value& job) {
                        set(*queued,"upload_job",job);
                        save_cache_point(store,*queued);
                        store.write("backup-job.pstream",job,backup_limits);
                    });
                    cache_publish_activity(endpoint,auth,*queued,store);
                }
                for (auto point : cache_points(store,owner)) {
                    if (number(point,"sequence") < number(*queued,"sequence")) continue;
                    const auto state = text(point,"cache_state");
                    if (!cache_point_ready(point) && state != "uploading") continue;
                    set(point,"cache_state",Value{std::string("merged")});
                    save_cache_point(store,point);
                    try {
                        for (const auto& image : std::get<Value::Array>(field(point,"images").data))
                            remove_backup_cache_image(cache_point_directory(point),field(image,"files"));
                    } catch (const Error& cleanup) {
                        std::cerr << "Invalid cache files retained for inspection: " << cleanup.what() << '\n';
                    }
                }
                std::cerr << "Cached restore-point chain invalidated: " << error.what() << '\n';
            }
        }
        return true;
    }
    if (online || !policy.enabled ||
        !backup_disconnect_expired(number(*policy_record,"last_online"),disconnect_timeout(),
            static_cast<std::int64_t>(now))) return queued != points.end();
    const auto schedule_name = schedule_event_name(number(owner,"task_id"));
    const auto scheduled = store.read(schedule_name.c_str());
    if (!scheduled || number(*scheduled,"attempted")) return queued != points.end();
    if (field(*scheduled,"task_owner") != owner)
        throw Error("scheduled cache event belongs to another NAS task ownership");
    const auto due = number(*scheduled,"due");
    cache_capture_point(store,owner,binding,task,auth,endpoint,due);
    store.remove(schedule_name.c_str());
    std::cout << "Offline incremental restore point cached locally.\n" << std::flush;
    return true;
}
void refresh_cache_task(Store& store, const Value& owner, const Value::Array& tasks,
    const Endpoint& endpoint, const SavedAuth& auth) {
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    for (auto task : tasks) {
        if (number(task,"id") != number(owner,"task_id")) continue;
        const auto policy = backup_cache_policy(task);
        if (policy.enabled && (policy.volume_uuid == "{SystemVolume}" || policy.volume_uuid == "{DataVolume}")) {
            task = translate_backup_cache_task(std::move(task),mounted_volume_nodes());
            update_backup_cache_policy(endpoint,auth,task);
        }
        const auto previous = store.read(cache_task_name(number(owner,"task_id")).c_str(),backup_limits);
        if (!backup_cache_policy(task).enabled && !previous) return;
        Value record{Value::Object{{"task_owner",owner},{"task",task},{"last_online",Value{now}},
            {"assigned",Value{std::uint64_t{1}}}}};
        store.write(cache_task_name(number(owner,"task_id")).c_str(),record,backup_limits);
        return;
    }
    if (const auto previous = store.read(cache_task_name(number(owner,"task_id")).c_str(),backup_limits)) {
        auto retired = *previous;
        set(retired,"assigned",Value{std::uint64_t{0}});
        store.write(cache_task_name(number(owner,"task_id")).c_str(),retired,backup_limits);
    }
}

std::vector<std::filesystem::path> machine_internal_files(Store& store) {
    std::vector<std::filesystem::path> result;
    for (const auto& name : store.names()) {
        if (name.starts_with("service-cache-task-") && name.ends_with(".pstream")) {
            const auto policy = *store.read(name.c_str(),backup_limits);
            auto files = cache_excluded_files(store,field(policy,"task_owner"));
            result.insert(result.end(),files.begin(),files.end());
        }
    }
    const auto add = [&](const Value& saved) {
        const auto capture = capture_journal_from_value(saved);
        const auto& reserved = capture.reservation;
        if (!number(reserved,"raw_storage_ready")) return;
        const auto& task = field(reserved,"raw_cache_policy");
        const auto policy = backup_cache_policy(task);
        const auto directory = policy.enabled ?
            backup_cache_directory(policy,text(task,"task_uuid"),false)/("capture-"+capture.id) :
            std::filesystem::path{text(reserved,"raw_directory")};
        const auto file = [&](const Value& output,const std::string& name) {
            if (std::holds_alternative<std::monostate>(output.data)) return;
            const auto path = directory/name;
            // Retention can already have removed a file while its catalog row
            // remains. Only currently present files have extents to exclude.
            if (std::filesystem::exists(path)) result.push_back(path);
        };
        file(field(reserved,"output"),"raw.cache");
        const auto& disks = std::get<Value::Array>(field(reserved,"disks").data);
        for (std::size_t index = 0; index < disks.size(); ++index)
            file(field(disks[index],"output"),"raw-"+std::to_string(index+1)+".cache");
    };
    const auto catalog = machine_snapshots(store).value();
    for (const auto& row : std::get<Value::Array>(field(catalog,"snapshots").data)) {
        if (fields(row).contains("capture")) add(field(row,"capture"));
        for (const auto& previous : std::get<Value::Array>(field(row,"superseded").data)) add(previous);
    }
    return result;
}

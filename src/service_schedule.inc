// official agent scheduler owns its cadence independently of the backup/cache worker.
// Store writes are atomic; this thread only owns service-schedule-event-* files.
Value machine_task_identity(const SavedAuth&,const Value&);
std::string schedule_event_name(std::uint64_t task) {
    return "service-schedule-event-"+std::to_string(task)+".pstream";
}
class ServiceSchedules {
    Store& store_;
    void save() {
        store_.write("service-schedules.pstream",Value{Value::Object{
            {"ds_id",Value{auth_.ds_id}},{"device_uuid",Value{auth_.device_uuid}},
            {"username",Value{auth_.username}},{"timezone",Value{std::to_string(timezone_)}},
            {"scheduler",scheduler_.state()}}});
    }
    std::mutex mutex_;
    TaskScheduler scheduler_;
    Value::Array tasks_;
    SavedAuth auth_;
    std::int64_t offset_ = 0, timezone_ = 0;
    bool time_ready_ = false;
    std::set<std::uint64_t> active_;
    std::atomic_bool stop_{false};
    std::future<void> worker_;
    std::exception_ptr failure_;
    bool has_backup_event(std::uint64_t task) {
        if (active_.contains(task)) return true;
        for (const auto name : {"service-machine-event.pstream","service-machine-pending.pstream",
                                "service-machine-recapture.pstream"}) {
            if (const auto event = store_.read(name,backup_limits))
                if (number(field(*event,"task_owner"),"task_id") == task) return true;
        }
        if (const auto binding = store_.read("service-source.pstream",backup_limits)) {
            if (number(*binding,"task_id") == task) {
                const auto job = store_.read("backup-job.pstream",backup_limits);
                if (!number(*binding,"claimed_run") || !job ||
                    !number(backup_job_status(*job,auth_),"terminal")) return true;
            }
        }
        for (const auto& name : store_.names()) {
            if (!name.starts_with("backup-cache-") || !name.ends_with(".pstream")) continue;
            const auto point = *store_.read(name.c_str(),backup_limits);
            if (number(field(point,"task_owner"),"task_id") == task &&
                (text(point,"cache_state") == "capturing" || text(point,"cache_state") == "writing")) return true;
        }
        return false;
    }
    void enqueue(const std::vector<ScheduledTask>& due) {
        for (const auto& event : due) {
            const auto id = number(event.task,"id");
            const auto name = schedule_event_name(id);
            // Event queuing advances time before event deduplication.
            if (has_backup_event(id) || store_.read(name.c_str())) continue;
            store_.write(name.c_str(),Value{Value::Object{
                {"task_owner",machine_task_identity(auth_,event.task)},
                {"due",Value{event.due}},{"attempted",Value{std::uint64_t{0}}}}});
        }
    }
public:
    ServiceSchedules(Store& store,const SavedAuth& auth) : store_(store),auth_(auth) {
        if (const auto saved = store_.read("service-schedules.pstream")) {
            if (text(*saved,"ds_id") != auth.ds_id || text(*saved,"device_uuid") != auth.device_uuid ||
                text(*saved,"username") != auth.username) throw Error("saved schedules belong to another NAS/account");
            scheduler_.restore(field(*saved,"scheduler"));
            offset_ = std::stoll(text(field(*saved,"scheduler"),"offset"));
            timezone_ = std::stoll(text(*saved,"timezone"));
            time_ready_ = true;
            for (const auto& entry : std::get<Value::Array>(field(field(*saved,"scheduler"),"entries").data))
                tasks_.push_back(field(entry,"task"));
        }
        worker_ = std::async(std::launch::async,[this] {
            try {
                while (!stop_) {
                    {
                        std::lock_guard lock(mutex_);
                        if (const auto saved = store_.read("server-time.pstream")) {
                            const auto current = server_time_from_value(*saved);
                            if (const auto offset = server_time_offset(current)) {
                                if (!time_ready_) {
                                    scheduler_.update(tasks_,*offset);
                                    time_ready_ = true;
                                    offset_ = *offset;
                                    timezone_ = current.timezone;
                                    save();
                                } else if (*offset != offset_ || current.timezone != timezone_) {
                                    enqueue(scheduler_.timezone(*offset,current.timezone-timezone_));
                                }
                                if (*offset != offset_ || current.timezone != timezone_) {
                                    offset_ = *offset;
                                    timezone_ = current.timezone;
                                    save();
                                }
                            }
                        }
                        if (time_ready_) {
                            const auto before = scheduler_.state();
                            enqueue(scheduler_.poll());
                            if (scheduler_.state() != before) save();
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::seconds{1});
                }
            } catch (...) {
                std::lock_guard lock(mutex_);
                failure_ = std::current_exception();
            }
        });
    }
    ~ServiceSchedules() { stop_ = true; worker_.wait(); }
    void update(const Value::Array& tasks,const SavedAuth& auth,bool reset = false) {
        std::lock_guard lock(mutex_);
        if (failure_) std::rethrow_exception(failure_);
        const bool changed = tasks != tasks_ || auth.ds_id != auth_.ds_id ||
            auth.username != auth_.username || auth.device_uuid != auth_.device_uuid;
        auth_ = auth;
        if (!changed && !reset) return;
        tasks_ = tasks;
        if (const auto saved = store_.read("server-time.pstream")) {
            const auto current = server_time_from_value(*saved);
            const auto offset = server_time_offset(current);
            time_ready_ = offset.has_value();
            if (offset) {
                offset_ = *offset;
                timezone_ = current.timezone;
            }
        }
        if (time_ready_) { scheduler_.update(tasks_,offset_); save(); }
        for (const auto& name : store_.names()) {
            if (!name.starts_with("service-schedule-event-") || !name.ends_with(".pstream")) continue;
            const auto event = *store_.read(name.c_str());
            const auto& owner = field(event,"task_owner");
            if (text(owner,"ds_id") != auth.ds_id || text(owner,"device_uuid") != auth.device_uuid ||
                text(owner,"username") != auth.username || std::none_of(tasks.begin(),tasks.end(),[&](const Value& task) {
                    return field(task,"id") == field(owner,"task_id") &&
                        field(task,"task_uuid") == field(owner,"task_uuid");
                })) store_.remove(name.c_str());
        }
    }
    void active(std::set<std::uint64_t> tasks) {
        std::lock_guard lock(mutex_);
        if (failure_) std::rethrow_exception(failure_);
        active_ = std::move(tasks);
    }
};

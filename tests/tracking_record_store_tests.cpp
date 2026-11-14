#include "opensabba/tracking_record.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <source_location>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace opensabba;
using namespace opensabba::pstream;
namespace fs = std::filesystem;
namespace {
void check(bool ok, std::source_location at = std::source_location::current()) {
    if (!ok) throw Error("tracking store invariant failed at "+std::to_string(at.line()));
}
template<class F> void rejects(F operation) {
    bool rejected = false;
    try { operation(); } catch (const std::exception&) { rejected = true; }
    check(rejected);
}
Value integer(std::uint64_t value) { return Value{value}; }
Value string(std::string value) { return Value{std::move(value)}; }
const Value& field(const Value& value, const char* key) {
    return std::get<Value::Object>(value.data).at(key);
}
void set(Value& value, const char* key, Value next) {
    std::get<Value::Object>(value.data)[key] = std::move(next);
}
Value volume(std::string device = "/dev/dm-0", std::string uuid = "6445f0de-2bf8-41ce-8627-486bda099468") {
    return Value{Value::Object{{"device",string(std::move(device))},{"filesystem_uuid",string(std::move(uuid))}}};
}
Value reserved(bool next = false) {
    return Value{Value::Object{{"minor",integer(0)},{"tracking_filesystem_uuid",field(volume(),"filesystem_uuid")},
        {"cow_relative",string(next ? "/.synosnap_data/1700001000_22222222-2222-4222-8222-222222222222" :
                                     "/.synosnap_data/1700000000_11111111-1111-4111-8111-111111111111")},
        {"cow",Value{Value::Object{{"inode",integer(next ? 102 : 101)},{"device",integer(253)}}}}}};
}
Value snapshot(bool next = false) {
    return Value{Value::Object{{"uuid",string("401a2bf9a42e4597ba7278fb03ebc337")},
        {"sequence",integer(next ? 8 : 7)}}};
}
struct Temporary {
    fs::path root;
    Temporary() {
        const auto pattern = (fs::temp_directory_path()/"opensabba-tracking-store-XXXXXX").string();
        std::vector<char> name(pattern.begin(),pattern.end());
        name.push_back('\0');
        const auto made = mkdtemp(name.data());
        check(made != nullptr);
        root = made;
    }
    ~Temporary() { fs::remove_all(root); }
};
void write(const fs::path& path, std::string_view bytes, mode_t mode = 0700) {
    std::ofstream file(path,std::ios::binary);
    file << bytes;
    file.close();
    check(file.good() && chmod(path.c_str(),mode) == 0);
}
std::string read(const fs::path& path) {
    std::ifstream file(path,std::ios::binary);
    check(file.good());
    return std::string((std::istreambuf_iterator<char>(file)),{});
}
std::string read_fd(int fd) {
    struct stat st{};
    check(fstat(fd,&st) == 0);
    std::string result(static_cast<std::size_t>(st.st_size),'\0');
    check(pread(fd,result.data(),result.size(),0) == static_cast<ssize_t>(result.size()));
    return result;
}
struct stat inspect(const fs::path& path) {
    struct stat st{};
    check(lstat(path.c_str(),&st) == 0);
    return st;
}
std::optional<MachineTrackingOwnerRecord> find(const MachineTrackingRecords& store,
    const Value& volume, const Value& reservation = reserved()) {
    return store.find(volume,static_cast<std::uint32_t>(std::get<std::uint64_t>(field(reservation,"minor").data)),
        std::get<std::string>(field(reservation,"cow_relative").data));
}
void atomic_replace_and_renumber() {
    Temporary temporary;
    const auto directory = temporary.root/"records";
    MachineTrackingRecords store(directory);
    check(!find(store,volume()));
    store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false);
    const auto path = directory/"reload_dm-0";
    const auto old = read(path);
    const auto old_stat = inspect(path);
    check((old_stat.st_mode & 0777) == 0700 && old_stat.st_uid == geteuid());
    const int captured = open(path.c_str(),O_RDONLY|O_CLOEXEC);
    check(captured >= 0);
    auto renumbered = volume("/dev/dm-7");
    store.publish(renumbered,reserved(true),snapshot(true),"/usr/bin/sabba's client",true);
    const auto current = read(directory/"reload_dm-7");
    check(read(path) == old && read_fd(captured) == old);
    check(close(captured) == 0);
    check(machine_tracking_record_owner(current) == machine_tracking_owner(renumbered,reserved(true),snapshot(true)));
    // A UUID may have multiple retained commands. Resolve only the exact
    // history/driver COW and minor, never a filename/mtime winner.
    check(!find(store,renumbered));
    check(find(store,renumbered,reserved(true))->owner == *machine_tracking_record_owner(current));
    store.publish(renumbered,reserved(true),snapshot(true),"/usr/bin/opensabba",false);
    check(read(path) == old && inspect(directory/"reload_dm-7").st_ino != old_stat.st_ino);
    store.retire(renumbered);
    check(!fs::exists(directory/"reload_dm-7") && read(path) == old);
    store.retire(renumbered);
}
void logical_hook_names() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    auto root = volume("/dev/dm-0"), absent = volume("/dev/dm-3");
    for (auto* v : {&root,&absent}) set(*v,"lv_uuid",string("lv"));
    set(root,"logical_path",string("/dev/testvg/root"));
    set(absent,"logical_path",string("/dev/testvg/absent"));
    auto other = reserved(); set(other,"minor",integer(2));
    store.publish(root,reserved(),snapshot(),"/usr/bin/opensabba",false);
    store.publish(absent,other,snapshot(),"/usr/bin/opensabba",false);
    const auto saved_absent = read(temporary.root/"reload_absent");
    set(root,"device",string("/dev/dm-3")); // absent device removed; root renumbered
    store.publish(root,reserved(),snapshot(true),"/usr/bin/opensabba",true);
    const auto command = read(temporary.root/"reload_root");
    check(command.find("'/dev/testvg/root'") != command.npos && command.find("/dev/dm-") == command.npos);
    check(command.find("/dev/disk/by-uuid") == command.npos);
    check(read(temporary.root/"reload_absent") == saved_absent);
    set(absent,"device",string("/dev/dm-8"));
    store.publish(absent,other,snapshot(true),"/usr/bin/opensabba",true);
    check(read(temporary.root/"reload_absent").find("'/dev/testvg/absent'") != command.npos);
    check(!fs::exists(temporary.root/"reload_dm-0") && !fs::exists(temporary.root/"reload_dm-8"));
}
void duplicate_and_command_agreement() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false);
    const auto original = read(temporary.root/"reload_dm-0");
    write(temporary.root/"reload_duplicate",original);
    check(find(store,volume())->owner == machine_tracking_owner(volume(),reserved(),snapshot()));
    // A stale duplicate does not block publishing the current basename.
    store.publish(volume(),reserved(true),snapshot(true),"/usr/bin/opensabba",true);
    check(find(store,volume())->owner == machine_tracking_owner(volume(),reserved(),snapshot()));
    check(find(store,volume(),reserved(true))->owner == machine_tracking_owner(volume(),reserved(true),snapshot(true)));
    fs::remove(temporary.root/"reload_duplicate");
    auto tampered = original;
    tampered.replace(tampered.rfind(" 0\n"),3," 1\n");
    write(temporary.root/"reload_dm-0",tampered);
    rejects([&] { find(store,volume()); });
    // Publication does not parse whatever record it replaces (fopen "w").
    store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false);
    check(read(temporary.root/"reload_dm-0") == original);
}
void missing_origin_basename_capture_setup() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root/"records");
    const auto old = volume("/dev/dm-3","326c56b2-1111-4111-8111-111111111111");
    const auto fresh = volume("/dev/dm-3","7719bcc2-2222-4222-8222-222222222222");
    auto old_reservation = reserved();
    set(old_reservation,"tracking_filesystem_uuid",field(old,"filesystem_uuid"));
    auto next = reserved(true);
    set(next,"tracking_filesystem_uuid",field(fresh,"filesystem_uuid"));
    const auto history = temporary.root/"old-history";
    const auto cow = temporary.root/"old-cow";
    write(history,"independent old snapshot history",0600);
    write(cow,"old origin COW data",0600);
    const auto history_inode = inspect(history).st_ino, cow_inode = inspect(cow).st_ino;
    store.publish(old,old_reservation,snapshot(),"/usr/bin/opensabba",false);
    check(!find(store,fresh,next));
    check(find(store,old,old_reservation).has_value());
    struct Control final : MachineTrackingControl {
        std::optional<Value> slot;
        int creates = 0;
        std::optional<Value> information(std::uint32_t) override { return slot; }
        void verify_prior_cow(const Value&) override { check(false); }
        Value close_prior(const Value&,const Value&,const Value&) override { check(false); return {}; }
        void release(const Value&) override { check(false); }
        void retire_record(const Value&,const Value&) override { check(false); }
        void create(std::uint32_t minor,const std::string& origin,const std::string& cow,std::uint64_t) override {
            ++creates;
            slot = snapshot(true);
            set(*slot,"minor",integer(minor));
            set(*slot,"origin_path",string(origin));
            set(*slot,"cow_path",string(cow));
        }
        void renew(const Value&,const std::string&,std::uint64_t) override { check(false); }
    } control;
    set(next,"cow_path",field(next,"cow_relative"));
    const auto acquired = transition_machine_tracking(next,fresh,0,control);
    check(control.creates == 1);
    store.publish(fresh,next,acquired,"/usr/bin/opensabba",true);
    const auto record = read(temporary.root/"records/reload_dm-3");
    check(find(store,fresh,next)->owner == machine_tracking_owner(fresh,next,acquired));
    check(record.find("'/dev/dm-3'") != std::string::npos);
    check(record.find("reload-snapshot") != std::string::npos);
    // the official agent Reload-record creation changes only the basename file. The displaced
    // embedded owner disappears; independent history and COW stay orphaned.
    check(read(history) == "independent old snapshot history" && inspect(history).st_ino == history_inode);
    check(read(cow) == "old origin COW data" && inspect(cow).st_ino == cow_inode);
    check(!find(store,old,old_reservation));
    // A later last-history deletion uses the saved old bdev basename, even
    // though the file now contains the fresh origin's command.
    store.retire(old);
    check(!fs::exists(temporary.root/"records/reload_dm-3"));
    check(fs::exists(history) && fs::exists(cow));
}
void per_origin_history_retirement() {
    Temporary temporary;
    MachineTrackingHistory history(temporary.root);
    auto root = reserved(), selected = reserved(true);
    set(selected,"minor",integer(1));
    const auto journal = temporary.root/"capture.pstream";
    write(journal,"immutable capture and CBT evidence",0600);
    const auto original = read(journal);
    check(!history.retired(root) && !history.retired(selected));
    // Bad-state cleanup deletes one origin's history, independently of its
    // capture siblings and the immutable evidence used for prior transfers.
    history.retire(root);
    check(history.retired(root) && !history.retired(selected));
    std::vector<std::uint32_t> allocated;
    for (const auto* saved : {&root,&selected})
        if (!history.retired(*saved))
            allocated.push_back(static_cast<std::uint32_t>(std::get<std::uint64_t>(field(*saved,"minor").data)));
    check(machine_tracking_free_minor(allocated) == 0);
    history.retire(root); // Lost retirement reply is idempotent.
    check(read(journal) == original && history.retired(root));
    // A later deletion retires the other history; journals stay evidence,
    // rather than reappearing as allocated database entries after restart.
    MachineTrackingHistory reopened(temporary.root);
    check(reopened.retired(root) && !reopened.retired(selected));
    reopened.retire(selected);
    check(reopened.retired(selected) && read(journal) == original);
    auto changed = root;
    set(changed,"minor",integer(3));
    rejects([&] { reopened.retired(changed); });
}
void shell_reload_arguments() {
    Temporary temporary;
    const auto records = temporary.root/"records";
    const auto helper = temporary.root/"sabba's client";
    const auto arguments = temporary.root/"arguments";
    write(helper,"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$OPENSABBA_STORE_ARGUMENTS\"\n");
    MachineTrackingRecords store(records);
    for (const int phase : {0,1}) {
        const bool active = phase != 0;
        store.publish(volume(),reserved(),snapshot(),helper.string(),active);
        const auto owner = find(store,volume());
        check(owner.has_value());
        const auto record = records/owner->name;
        const auto child = fork();
        check(child >= 0);
        if (!child) {
            if (setenv("OPENSABBA_STORE_ARGUMENTS",arguments.c_str(),1))
                _exit(126);
            execl("/bin/sh","sh",record.c_str(),static_cast<char*>(nullptr));
            _exit(127);
        }
        int status{};
        check(waitpid(child,&status,0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        check(read(arguments) == std::string("snapshot\nreload-")+(active ? "snapshot\n" : "incremental\n")+
            std::get<std::string>(field(volume(),"device").data)+"\n"+
            std::get<std::string>(field(reserved(),"cow_relative").data)+"\n0\n");
    }
}
void pending_publication() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false);
    const auto path = temporary.root/"reload_dm-0";
    const auto pending = temporary.root/".reload_dm-0.tmp";
    const auto original = read(path);
    // Real partial temporary files are neither boot glob matches nor owners.
    write(pending,"#!/bin/sh\n# opensabba-tracking-owner-v1 dead");
    check(find(store,volume())->owner == machine_tracking_owner(volume(),reserved(),snapshot()));
    check(read(path) == original);
    store.publish(volume(),reserved(true),snapshot(true),"/usr/bin/opensabba",true);
    check(!fs::exists(pending));
    const auto current = read(path);
    check(machine_tracking_record_owner(current) == machine_tracking_owner(volume(),reserved(true),snapshot(true)));
    // An insecure interrupted temporary is refused before truncation. The
    // committed record and the failed temporary remain available for inspection.
    write(pending,"public temporary evidence",0644);
    rejects([&] { store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false); });
    check(read(path) == current && read(pending) == "public temporary evidence");
    fs::remove(pending);
    const auto outside = temporary.root/"unrelated-evidence";
    write(outside,"unrelated evidence");
    check(symlink(outside.c_str(),pending.c_str()) == 0);
    rejects([&] { store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false); });
    check(read(outside) == "unrelated evidence" && read(path) == current);
    fs::remove(pending);
    check(link(outside.c_str(),pending.c_str()) == 0);
    rejects([&] { store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false); });
    check(read(outside) == "unrelated evidence" && read(path) == current);
}
void restrictive_permissions() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    const auto previous_umask = umask(0777);
    try { store.publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false); }
    catch (...) { umask(previous_umask); throw; }
    umask(previous_umask);
    const auto path = temporary.root/"reload_dm-0";
    check((inspect(path).st_mode & 0777) == 0700);
    check(chmod(path.c_str(),0755) == 0);
    rejects([&] { find(store,volume()); });
    check(chmod(path.c_str(),0700) == 0);
    check(chmod(temporary.root.c_str(),0777) == 0);
    rejects([&] { find(store,volume()); });
    rejects([&] { store.publish(volume(),reserved(true),snapshot(true),"/usr/bin/opensabba",true); });
    check(chmod(temporary.root.c_str(),0700) == 0);
    if (geteuid() == 0) {
        check(chown(path.c_str(),1,static_cast<gid_t>(-1)) == 0);
        rejects([&] { find(store,volume()); });
        check(chown(path.c_str(),0,static_cast<gid_t>(-1)) == 0);
    }
    const auto link = temporary.root/"directory-link";
    check(symlink(temporary.root.c_str(),link.c_str()) == 0);
    MachineTrackingRecords linked(link);
    rejects([&] { find(linked,volume()); });
}
void command_only_is_not_ownership() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    const auto path = temporary.root/"reload_dm-0";
    const std::string stale = "#!/bin/sh\nexec '/old/client' snapshot reload-incremental "
        "'/dev/disk/by-uuid/6445f0de-2bf8-41ce-8627-486bda099468' "
        "'/.synosnap_data/1700000000_11111111-1111-4111-8111-111111111111' 0\n";
    write(path,stale);
    check(!find(store,volume()));
    // Reservation alone leaves the boot command unchanged. Only a successful
    // setup/history insertion can replace this saved basename.
    const auto reservation_owner = machine_tracking_reservation_owner(volume(),reserved(true));
    rejects([&] { machine_tracking_record(reservation_owner,"/usr/bin/opensabba",true); });
    check(read(path) == stale && !find(store,volume()));
    store.publish(volume(),reserved(true),snapshot(true),"/usr/bin/opensabba",true);
    check(find(store,volume(),reserved(true))->owner == machine_tracking_owner(volume(),reserved(true),snapshot(true)));
    // History-authorized deletion also removes a command-only record.
    fs::remove(path);
    write(path,stale);
    store.retire(volume());
    check(!fs::exists(path));
}
void successful_root_and_selected_history() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    const auto root = volume();
    const auto selected = volume("/dev/dm-1","eafde985-1755-4153-9611-0411b0ead9c6");
    auto selected_reservation = reserved(true);
    set(selected_reservation,"minor",integer(1));
    set(selected_reservation,"tracking_filesystem_uuid",field(selected,"filesystem_uuid"));
    check(!find(store,root) && !find(store,selected,selected_reservation));
    store.publish(root,reserved(),snapshot(),"/usr/bin/opensabba",true);
    check(find(store,root).has_value() && !find(store,selected,selected_reservation));
    store.publish(selected,selected_reservation,snapshot(),"/usr/bin/opensabba",true);
    check(find(store,selected,selected_reservation).has_value());
    store.retire(root);
    check(!find(store,root) && fs::exists(temporary.root/"reload_dm-1"));
    const auto foreign = volume("/dev/dm-1","ffffffff-ffff-ffff-ffff-ffffffffffff");
    auto foreign_reservation = reserved();
    set(foreign_reservation,"tracking_filesystem_uuid",field(foreign,"filesystem_uuid"));
    store.publish(foreign,foreign_reservation,snapshot(),"/usr/bin/opensabba",true);
    check(!find(store,selected,selected_reservation));
    check(find(store,foreign)->owner == machine_tracking_owner(foreign,foreign_reservation,snapshot()));
    store.retire(selected);
    check(!fs::exists(temporary.root/"reload_dm-1"));
}
void independent_history_database() {
    Temporary temporary;
    MachineTrackingDatabaseStore store(temporary.root/"tracking-history.pstream");
    auto history = store.load();
    check(!history.last(volume()) && history.minors().empty());
    // Old immutable journals and boot commands cannot populate an absent DB.
    write(temporary.root/"capture.pstream","old capture evidence",0600);
    MachineTrackingRecords(temporary.root).publish(volume(),reserved(),snapshot(),"/usr/bin/opensabba",false);
    check(!store.load().last(volume()));
    auto row = reserved();
    set(row,"device",field(volume(),"device"));
    set(row,"snapshot",snapshot());
    set(row,"directory",string(temporary.root.string()));
    set(row,"capture_id",string("first"));
    history.add(row);
    store.save(history);
    const auto first = store.load().last(volume());
    check(first && field(*first,"history_id") == integer(1));
    set(row,"capture_id",string("second"));
    history.add(row);
    store.save(history);
    auto reopened = store.load();
    const auto last = reopened.last(volume());
    check(last && field(*last,"history_id") == integer(2));
    check(field(*last,"capture_id") == string("second"));
    const auto removed = reopened.remove_before(*last);
    check(removed.size() == 2 && reopened.minors().empty());
    store.save(reopened);
    reopened = store.load();
    check(!reopened.last(volume()));
    reopened.add(row);
    store.save(reopened);
    check(field(*store.load().last(volume()),"history_id") == integer(3));
    check(read(temporary.root/"capture.pstream") == "old capture evidence");
    check((inspect(temporary.root/"tracking-history.pstream").st_mode & 0077) == 0);
}
void failed_setup_has_no_reload_record() {
    Temporary temporary;
    MachineTrackingRecords store(temporary.root);
    struct Control final : MachineTrackingControl {
        std::optional<Value> information(std::uint32_t) override { return {}; }
        void verify_prior_cow(const Value&) override { check(false); }
        Value close_prior(const Value&,const Value&,const Value&) override { check(false); return {}; }
        void release(const Value&) override { check(false); }
        void retire_record(const Value&,const Value&) override { check(false); }
        void create(std::uint32_t,const std::string&,const std::string&,std::uint64_t) override {
            throw Error("setup ENOSPC");
        }
        void renew(const Value&,const std::string&,std::uint64_t) override { check(false); }
    } control;
    auto reservation = reserved();
    set(reservation,"cow_path",field(reservation,"cow_relative"));
    rejects([&] {
        const auto current = transition_machine_tracking(reservation,volume(),0,control);
        store.publish(volume(),reservation,current,"/usr/bin/opensabba",true);
    });
    check(!find(store,volume()) && fs::is_empty(temporary.root));
    // Internal reservation evidence must never be serializable as a reload,
    // including after setup failure and process death.
    rejects([&] { machine_tracking_record(
        machine_tracking_reservation_owner(volume(),reservation),"/usr/bin/opensabba",true); });
    check(fs::is_empty(temporary.root));
}

}
int main() {
    try {
        atomic_replace_and_renumber();
        logical_hook_names();
        duplicate_and_command_agreement();
        missing_origin_basename_capture_setup();
        per_origin_history_retirement();
        shell_reload_arguments();
        pending_publication();
        restrictive_permissions();
        command_only_is_not_ownership();
        successful_root_and_selected_history();
        independent_history_database();
        failed_setup_has_no_reload_record();
        std::cout << "native tracking file-store tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}

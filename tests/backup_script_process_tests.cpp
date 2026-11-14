#include "opensabba/backup_scripts.hpp"
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <thread>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
namespace {
void check(bool value) { if (!value) throw Error("script process invariant failed"); }
BackupScript script(std::string_view content) {
    return {true,0,".py",pstream::Bytes(content.begin(),content.end())};
}
std::string read(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
}
int permissions(const std::filesystem::path& path) {
    struct stat info{}; check(!stat(path.c_str(),&info)); return info.st_mode & 0777;
}
bool alive(int pid) {
    const auto status = read("/proc/"+std::to_string(pid)+"/stat");
    const auto closing = status.rfind(')');
    return !status.empty() && closing != status.npos && status[closing+2] != 'Z';
}
void wait_dead(int pid) {
    for (int at = 0; at < 200 && alive(pid); ++at)
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    check(!alive(pid));
}
template<class F> void rejects(F function) {
    try { function(); } catch (const Error&) { return; }
    throw Error("expected script process rejection");
}
}
int main() {
    try {
        char root[] = "/tmp/opensabba-scripts-XXXXXX";
        check(mkdtemp(root));
        const std::filesystem::path directory(root);
        const auto program = script("#!/unavailable\nprintf '%s\\n' \"$0\" \"$#\" \"$PWD\" \"$OPENSABBA_SCRIPT_TEST\"; printf err >&2; touch mask; exit 7\n");
        setenv("OPENSABBA_SCRIPT_TEST","inherited",1);
        auto result = execute_backup_script(program,true,false,directory,27);
        check(result.log_type == 7046 && result.exit_code == 7 && result.has_output);
        check(read(directory/"pre27.log") == (directory/"pre.py").string()+"\n0\n"+directory.string()+"\ninherited\nerr");
        check(permissions(directory/"pre27.log") == 0644 &&
              permissions(directory/"pre.py") == 0600 && permissions(directory/"mask") == 0666);
        std::ofstream(directory/"blocked") << "not a directory";
        result = execute_backup_script(program,true,true,directory/"blocked"/"script",28);
        check(result.log_type == 7053 && !result.has_output);
        result = execute_backup_script(program,false,true,directory,28);
        check(result.log_type == 7051 && result.exit_code == 7);
        result = execute_backup_script(script("kill -TERM $$\n"),true,false,directory,29);
        check(result.log_type == 7046 && result.exit_code == -1);
        for (const bool pre : {true,false}) for (const bool stop : {false,true}) {
            const auto run = 40+static_cast<unsigned>(pre)*2+static_cast<unsigned>(stop);
            const auto failed = execute_backup_script(script("echo failure; exit 37\n"),pre,stop,directory,run);
            check(failed.exit_code == 37 && !failed.cancelled && failed.has_output &&
                failed.log_type == (pre ? 7045U : 7049U)+(stop ? 2 : 1));
        }
        const auto sleeper = script("sleep 10 &\necho $!\nwait\n");
        result = execute_backup_script(sleeper,true,true,directory,30,{},std::chrono::milliseconds{250});
        check(result.log_type == 7048);
        auto child = std::stoi(read(directory/"pre30.log"));
        wait_dead(child);
        auto deadline = std::chrono::steady_clock::now()+std::chrono::milliseconds{150};
        result = execute_backup_script(sleeper,false,false,directory,31,
            [&] { return std::chrono::steady_clock::now() > deadline; });
        check(result.cancelled && result.log_type == 0 && !result.has_output);
        check(!std::filesystem::exists(directory/"post31.log"));
        wait_dead(std::stoi(read(directory/"post31.log.tmp")));
        // the official agent enters execution before testing an already-set service abort.
        // It leaves temporary output and publishes no post result.
        result = execute_backup_script(sleeper,false,false,directory,35,[] { return true; });
        check(result.cancelled && result.log_type == 0 && !result.has_output);
        check(std::filesystem::exists(directory/"post35.log.tmp") &&
              !std::filesystem::exists(directory/"post35.log"));

        BackupScripts policy{script("echo run >> marker\n"),{},false};
        auto journal = new_script_run(policy,2,32,"task-uuid");
        Value durable;
        const auto save = [&](const Value& state) { durable = pstream::decode(pstream::encode(state)); };
        run_backup_script_once(journal,policy,true,directory,save);
        auto restarted = durable;
        run_backup_script_once(restarted,policy,true,directory,save);
        check(read(directory/"marker") == "run\n");
        journal = new_script_run(policy,2,33,"task-uuid");
        int saves = 0;
        rejects([&] { run_backup_script_once(journal,policy,true,directory,[&](const Value& state) {
            if (++saves == 2) throw Error("lost durable result");
            save(state);
        }); });
        check(read(directory/"marker") == "run\nrun\n");
        rejects([&] { run_backup_script_once(durable,policy,true,directory,save); });
        check(read(directory/"marker") == "run\nrun\n");

        // Killing the owning agent kills the script group, including children.
        const auto owner = fork(); check(owner >= 0);
        if (!owner) {
            execute_backup_script(script("sleep 10 &\necho $! > survivor\nwait\n"),true,false,directory,34);
            _exit(0);
        }
        for (int at = 0; at < 200 && read(directory/"survivor").empty(); ++at)
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        child = std::stoi(read(directory/"survivor"));
        kill(owner,SIGKILL); int status{}; waitpid(owner,&status,0);
        wait_dead(child);
        std::filesystem::remove_all(directory);
        std::cout << "Linux backup script process tests passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

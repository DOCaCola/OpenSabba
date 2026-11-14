#include "opensabba/backup_scripts.hpp"
#include "opensabba/task_policy.hpp"
#include <iostream>
using namespace opensabba;
using pstream::Value;
using pstream::Error;
namespace {
Value n(std::uint64_t value) { return Value{value}; }
void check(bool value) { if (!value) throw Error("backup script invariant failed"); }
template<class F> void rejects(F operation) {
    try { operation(); } catch (const std::exception&) { return; }
    throw Error("invalid backup script state was accepted");
}
}
int main() {
    try {
        Value::Object settings{{"pre_script_enabled",n(1)},{"post_script_enabled",n(0)},
            {"pre_script_extension",Value{std::string(".py")}},{"pre_script_error",n(0)},
            {"script_exec_mode",n(1)}};
        Value wire{Value::Object{{"pre_post_script_setting",Value{settings}},
            {"pre_script_content",Value{pstream::Bytes{0,1,255}}}}};
        auto fields = task_script_policy(wire);
        check(fields.size() == 3 && !fields.contains("pre_script_content"));
        fields.merge(task_script_execution_policy(wire));
        auto policy = backup_scripts(Value{fields});
        check(policy.pre.content == pstream::Bytes({0,1,255}) && policy.stop_on_failure);
        fields["compression"] = n(0);
        rejects([&] { validate_task_policy(Value{fields}); });
        check(validate_task_policy(Value{fields},true) == TransferCompression::none);
        fields["pre_script_content"] = Value{pstream::Bytes(32768,42)};
        check(backup_scripts(Value{fields}).pre.error == 0);
        fields["pre_script_content"] = Value{pstream::Bytes(32769,42)};
        check(backup_scripts(Value{fields}).pre.error == 7055);
        fields["pre_script_extension"] = Value{std::string("/../../bad")};
        rejects([&] { backup_scripts(Value{fields}); });
        std::get<Value::Object>(wire.data)["pre_script_content"] = Value{std::string("not a buffer")};
        rejects([&] { task_script_execution_policy(wire); });

        policy.pre.error = 7054;
        policy.pre.content.clear();
        auto journal = new_script_run(policy,2,27,"task-uuid");
        auto restored = pstream::decode(pstream::encode(journal));
        validate_script_run(restored,policy,2,27,"task-uuid");
        check(retained_backup_scripts(restored).pre.error == 7054);
        rejects([&] { validate_script_run(restored,policy,2,28,"task-uuid"); });
        auto changed = policy; changed.post.enabled = true;
        rejects([&] { validate_script_run(restored,changed,2,27,"task-uuid"); });
        rejects([&] { new_script_run(policy,2,27,"../escape"); });
        int saves = 0;
        const auto save = [&](const Value&) { ++saves; };
        rejects([&] { run_backup_script_once(journal,policy,true,"unused",save); });
        check(saves == 2 && backup_scripts_failed(journal));
        rejects([&] { run_backup_script_once(journal,policy,true,"unused",save); });
        check(saves == 2);
        policy.stop_on_failure = false;
        journal = new_script_run(policy,2,27,"task-uuid");
        run_backup_script_once(journal,policy,true,"unused",save);
        check(!backup_scripts_failed(journal));
        auto& pre = std::get<Value::Object>(journal.data).at("pre");
        pre = Value{Value::Object{{"phase",Value{std::string("intent")}}}};
        rejects([&] { run_backup_script_once(journal,policy,true,"unused",save); });
        std::cout << "Backup script policy and journal tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

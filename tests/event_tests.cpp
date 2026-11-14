#include "opensabba/events.hpp"
#include "opensabba/volume_nodes.hpp"
#include <iostream>
#include <stdexcept>
#include <future>
using opensabba::pstream::Value;
using opensabba::EventInbox;

void check(bool value) { if (!value) throw std::runtime_error("event test failed"); }
template<class F> void rejects(F call) {
    try { call(); } catch (const opensabba::pstream::Error&) { return; }
    throw std::runtime_error("invalid event accepted");
}
Value event(std::uint64_t id, const char* action) {
    return Value{Value::Object{{"id", Value{id}}, {"action", Value{std::string(action)}},
        {"opaque", Value{std::string("retained private payload")}}}};
}
int main() {
    opensabba::SavedAuth auth{"user", "uuid", "TOKEN", "nas"};
    EventInbox inbox(auth);
    const auto change = event(1, "change_task"), backup = event(2, "update_running_task");
    inbox.merge({change, backup, event(3, "future_action")});
    check(inbox.needs_task_refresh() && inbox.held_ids().size() == 3);
    const auto before = inbox.serialize();
    auto legacy = before;
    auto& legacy_fields = std::get<Value::Object>(legacy.data);
    legacy_fields["format"] = Value{std::uint64_t{1}};
    legacy_fields.erase("running_task_snapshot");
    check(EventInbox(auth, legacy).serialize() == before);
    inbox.merge({change});
    check(inbox.serialize() == before);
    rejects([&] { inbox.merge({event(4, "change_task"), event(1, "different")}); });
    check(inbox.serialize() == before); // A bad batch does not partially commit.
    rejects([&] { inbox.merge({event(0, "change_task")}); });
    EventInbox recovered(auth, before);
    recovered.finish_task_refresh({Value{Value::Object{{"id", Value{std::uint64_t{27}}}}}});
    check(recovered.ready_ids() == Value::Array{Value{std::uint64_t{1}}});
    EventInbox ack_retry(auth, recovered.serialize());
    check(ack_retry.ready_ids() == recovered.ready_ids());
    rejects([&] { ack_retry.acknowledged({Value{std::uint64_t{2}}}); });
    ack_retry.acknowledged(ack_retry.ready_ids());
    check(ack_retry.held_ids().size() == 2 && !ack_retry.needs_task_refresh());
    check(ack_retry.needs_running_refresh());
    ack_retry.finish_running_refresh({Value{Value::Object{{"id", Value{std::uint64_t{99}}}}}});
    EventInbox job_refresh(auth, ack_retry.serialize());
    check(job_refresh.ready_ids() == Value::Array{Value{std::uint64_t{2}}});
    job_refresh.acknowledged(job_refresh.ready_ids());
    check(!job_refresh.needs_running_refresh() && job_refresh.held_ids().size() == 1);
    // Notification completion acknowledges the NAS list refresh, independent
    // of local transfer history, task ownership and acquisition progress.
    const Value::Array no_jobs;
    const auto job = [](std::uint64_t task, std::uint64_t status, std::uint64_t active) {
        return Value::Array{Value{Value::Object{{"id",Value{std::uint64_t{12}}},
            {"task_id",Value{task}},{"type",Value{std::uint64_t{0}}},
            {"status",Value{status}},{"is_backing_up",Value{active}}}}};
    };
    for (const auto& jobs : {no_jobs,job(999,1,1),job(7,0,0),job(7,1,1)}) {
        EventInbox update(auth);
        update.observe_tasks({Value{Value::Object{{"id",Value{std::uint64_t{7}}}}}});
        update.register_running_result({27,7,42,112});
        update.merge({event(3,"update_running_task"),event(4,"future_action")});
        check(update.ready_ids().empty() && update.needs_running_refresh());
        update.finish_running_refresh(jobs);
        EventInbox durable(auth,update.serialize());
        check(durable.ready_ids() == Value::Array{Value{std::uint64_t{3}}} &&
            std::get<Value::Object>(durable.serialize().data).at("running_task_snapshot") == Value{jobs});
        // Refresh cannot retire or replace the executing task's result history.
        check(update.running_result(7,42)->result == 112);
        durable.acknowledged(durable.ready_ids());
        check(durable.held_ids() == Value::Array{Value{std::uint64_t{4}}});
    }
    EventInbox results(auth);
    // the official agent keeps handler insertion order, updates the same running event in
    // place, and removes only the first matching task/version history.
    results.register_running_result({27,7,42,112});
    results.register_running_result({28,7,42,113});
    results.register_running_result({27,7,42,114});
    check(results.running_result(7,42)->result == 114);
    check(!results.running_result(7,0) && !results.running_result(0,42));
    results.retire_running_result(7,42);
    check(results.running_result(7,42)->result == 113);
    check(!EventInbox(auth,results.serialize()).running_result(7,42));
    results.retire_running_result(7,42);
    check(!results.running_result(7,42));
    auto publishing = std::async(std::launch::async,[&] {
        for (std::uint64_t id = 1; id <= 1000; ++id) results.register_running_result({29,8,43,id});
    });
    for (unsigned i = 0; i < 100; ++i) results.merge({});
    publishing.get();
    check(results.running_result(8,43)->result == 1000);
    auto result_event = event(9,"get_running_task_result");
    std::get<Value::Object>(result_event.data)["task_id"] = Value{std::uint64_t{27}};
    std::get<Value::Object>(result_event.data)["version_id"] = Value{std::uint64_t{4}};
    results.merge({result_event});
    results.observe_tasks({Value{Value::Object{{"id",Value{std::uint64_t{27}}}}}});
    check(results.task_result_requests() == Value::Array{result_event});
    Value reply{Value::Object{
        {"backup_result",Value{Value::Object{{"last_success_time",Value{std::uint64_t{123}}},
            {"last_backup_status",Value{std::string("failure")}}}}},
        {"running_task_result",Value{Value::Object{{"task_id",Value{std::uint64_t{27}}},
            {"job_action",Value{std::string("backup")}},{"status",Value{std::string("failure")}},
            {"time_start",Value{std::uint64_t{456}}}}}}}};
    results.prepare_task_result(9,112,reply);
    EventInbox pending_result(auth,results.serialize());
    check(pending_result.task_result(9) == std::optional<Value>{reply} &&
          pending_result.task_result_id(9) == 112 && pending_result.ready_ids().empty() &&
          pending_result.task_result_requests() == Value::Array{result_event});
    results.finish_task_result(9,reply);
    EventInbox retry_results(auth,results.serialize());
    check(retry_results.task_result_requests().empty());
    check(retry_results.ready_ids() == Value::Array{Value{std::uint64_t{9}}});
    const auto saved_results = std::get<Value::Object>(retry_results.serialize().data);
    check(!saved_results.contains("backup_result_snapshot"));
    check(std::get<Value::Object>(std::get<Value::Array>(saved_results.at("task_snapshot").data)[0].data)
        .at("last_backup_success_time") == Value{std::uint64_t{456}});
    auto missing_task_result = results.serialize();
    auto& receipt = std::get<Value::Object>(std::get<Value::Array>(
        std::get<Value::Object>(missing_task_result.data).at("receipts").data)[0].data);
    receipt.erase("task_result");
    rejects([&] { EventInbox bad(auth,missing_task_result); });
    retry_results.acknowledged(retry_results.ready_ids());
    check(retry_results.held_ids().empty());
    for (const auto& response : {Value{Value::Object{}},Value{Value::Object{
        {"running_task_result",Value{Value::Object{{"job_action",Value{std::string("unknown")}}}}}}}}) {
        EventInbox no_history(auth);
        no_history.merge({result_event});
        no_history.finish_task_result(9,response);
        check(EventInbox(auth,no_history.serialize()).ready_ids() == Value::Array{Value{std::uint64_t{9}}});
    }
    // A result's timestamp comes from its activity, including failure; its
    // last-success summary comes independently from backup_result.
    for (const auto status : {"complete","partial_success","failure","cancel","incomplete"}) {
        EventInbox observed(auth);
        observed.observe_tasks({Value{Value::Object{{"id",Value{std::uint64_t{27}}},
            {"last_backup_success_time",Value{std::uint64_t{1}}}}}});
        observed.merge({result_event});
        auto response = reply;
        auto& activity = std::get<Value::Object>(
            std::get<Value::Object>(response.data).at("running_task_result").data);
        activity["status"] = Value{std::string(status)};
        observed.finish_task_result(9,response);
        const auto saved = std::get<Value::Object>(observed.serialize().data);
        const auto& task = std::get<Value::Object>(
            std::get<Value::Array>(saved.at("task_snapshot").data).front().data);
        const bool timestamps = std::string_view(status) != "cancel" && std::string_view(status) != "incomplete";
        check(task.at("last_backup_success_time") == Value{std::uint64_t{timestamps ? 456U : 1U}});
    }
    EventInbox missing_task(auth);
    missing_task.merge({result_event});
    rejects([&] { missing_task.finish_task_result(9,reply); });
    check(missing_task.ready_ids().empty());
    EventInbox limits(auth);
    limits.merge({event(10,"update_backup_bandwidth"),event(11,"future_action")});
    check(limits.needs_bandwidth_refresh() && limits.ready_ids().empty());
    const auto pending_limits = limits.serialize();
    rejects([&] { limits.acknowledged({Value{std::uint64_t{10}}}); });
    limits.finish_bandwidth_refresh(1024);
    EventInbox saved_limits(auth,limits.serialize());
    check(!saved_limits.needs_bandwidth_refresh());
    check(saved_limits.ready_ids() == Value::Array{Value{std::uint64_t{10}}});
    auto missing_result = limits.serialize();
    std::get<Value::Object>(missing_result.data)["bandwidth_snapshot"] = Value{};
    rejects([&] { EventInbox bad(auth,missing_result); });
    saved_limits.acknowledged(saved_limits.ready_ids());
    check(saved_limits.held_ids() == Value::Array{Value{std::uint64_t{11}}});
    EventInbox absent_rate(auth,pending_limits);
    absent_rate.finish_bandwidth_refresh({});
    check(EventInbox(auth,absent_rate.serialize()).ready_ids() == limits.ready_ids());
    absent_rate.merge({event(12,"update_backup_bandwidth")});
    check(absent_rate.needs_bandwidth_refresh());
    absent_rate.finish_bandwidth_refresh(0);
    const auto snapshot = std::get<Value::Object>(absent_rate.serialize().data).at("bandwidth_snapshot");
    check(std::get<Value::Object>(snapshot.data).at("backup_bandwidth") == Value{std::uint64_t{0}});
    EventInbox nodes(auth);
    Value task{Value::Object{
        {"subaction",Value{std::string("list_nodes")}},
        {"node_path",Value{std::string{}}},
        {"dir_only",Value{std::uint64_t{1}}},
        {"event_id",Value{std::uint64_t{581}}}}};
    Value request{Value::Object{
        {"id",Value{std::uint64_t{581}}},{"action",Value{std::string("act_client")}},
        {"webapi_task",task}}};
    nodes.merge({request});
    check(nodes.node_requests() == Value::Array{request});
    auto volumes = opensabba::volume_node_values({
        {"/","ext4","root-uuid",1024,512,512},
        {"/mnt/data","ext4","lv-uuid",2048,1024,1024},
        {"/boot","vfat","",512,256,256}});
    check(volumes.size() == 3);
    check(std::get<Value::Object>(volumes[0].data).at("is_system_drive") ==
          Value{std::uint64_t{1}});
    check(std::get<Value::Object>(volumes[1].data).at("volume_name") ==
          Value{std::string("lv-uuid")});
    check(std::get<Value::Object>(volumes[2].data).at("volume_name") ==
          Value{std::string{}});
    Value result{Value::Object{
        {"event_id",Value{std::uint64_t{581}}},
        {"error_code",Value{std::uint64_t{0}}},
        {"node_list",Value{volumes}}}};
    nodes.prepare_node_result(581,result);
    EventInbox retry(auth,nodes.serialize());
    check(retry.node_results() == Value::Array{result} && retry.ready_ids().empty());
    rejects([&] { retry.acknowledged({Value{std::uint64_t{581}}}); });
    retry.node_result_sent(581);
    EventInbox ack_nodes(auth,retry.serialize());
    check(ack_nodes.ready_ids() == Value::Array{Value{std::uint64_t{581}}});
    ack_nodes.acknowledged(ack_nodes.ready_ids());
    check(ack_nodes.held_ids().empty());
    EventInbox empty_nodes(auth);
    auto no_dirs = task;
    std::get<Value::Object>(no_dirs.data)["dir_only"] = Value{std::uint64_t{0}};
    auto empty_request = request;
    std::get<Value::Object>(empty_request.data)["webapi_task"] = no_dirs;
    empty_nodes.merge({empty_request});
    check(empty_nodes.node_requests() == Value::Array{empty_request});
    Value empty_result{Value::Object{
        {"event_id",Value{std::uint64_t{581}}},
        {"error_code",Value{std::uint64_t{0}}}}};
    empty_nodes.prepare_node_result(581,empty_result);
    check(EventInbox(auth,empty_nodes.serialize()).node_results() ==
          Value::Array{empty_result});
    EventInbox children(auth);
    auto child_request = request;
    auto& child_task = std::get<Value::Object>(
        std::get<Value::Object>(child_request.data).at("webapi_task").data);
    child_task["node_path"] = Value{std::string("/")};
    children.merge({child_request});
    check(children.node_requests() == Value::Array{child_request});
    const Value failed_result{Value::Object{
        {"event_id",Value{std::uint64_t{581}}},
        {"error_code",Value{UINT64_MAX - 1}}}}; // the official agent sign-extended -ENOENT.
    children.prepare_node_result(581,failed_result);
    EventInbox failed_retry(auth,children.serialize());
    check(failed_retry.node_requests().empty() &&
          failed_retry.node_results() == Value::Array{failed_result});
    failed_retry.node_result_sent(581);
    EventInbox failed_ack(auth,failed_retry.serialize());
    check(failed_ack.ready_ids() == Value::Array{Value{std::uint64_t{581}}});
    failed_ack.acknowledged(failed_ack.ready_ids());
    check(failed_ack.held_ids().empty());
    for (auto bad : {Value{std::string("1")},Value{std::uint64_t{2}}}) {
        EventInbox malformed(auth);
        child_task["dir_only"] = bad;
        malformed.merge({child_request});
        check(malformed.node_requests().empty());
    }
    child_task["dir_only"] = Value{std::uint64_t{1}};
    child_task["node_path"] = Value{std::string("/bad\0path",9)};
    EventInbox nul_path(auth);
    nul_path.merge({child_request});
    check(nul_path.node_requests().empty());
    for (const auto code : {std::uint64_t{1},std::uint64_t{UINT32_MAX},UINT64_MAX-INT32_MAX-1}) {
        auto malformed_result = failed_result;
        std::get<Value::Object>(malformed_result.data)["error_code"] = Value{code};
        rejects([&] { opensabba::validate_client_node_result(malformed_result); });
    }
    auto error_with_nodes = failed_result;
    std::get<Value::Object>(error_with_nodes.data)["node_list"] = Value{Value::Array{}};
    rejects([&] { opensabba::validate_client_node_result(error_with_nodes); });
    rejects([&] { nodes.prepare_node_result(581,Value{}); });
    auth.ds_id = "another-nas";
    rejects([&] { EventInbox foreign(auth, before); });
    const auto retained = ack_retry.serialize();
    const auto& receipts = std::get<Value::Array>(
        std::get<Value::Object>(retained.data).at("receipts").data);
    check(std::get<Value::Object>(receipts.front().data).at("payload") == backup);
    std::cout << "Event receipt, replay, unsupported retention, and identity tests passed\n";
}

"""Service reload during a real CLI upload to an independent loopback NAS."""
from pstream_peer import upload_value
from upload_timing import full_record, record_timing
from automatic_machine_service import provide_capture, catalog_snapshot, no_snapshot_before_handshake

import hashlib
import copy
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

from test_backup_cli import Server as BaseServer, Reader
from test_login import value
from test_probe import check, wire
from test_service import wait_for
from test_snapshot import FS_UUID, filesystem
from test_layout import mbr_entry
from proxy_peer import Proxy
import shutil


from machine_service_specimens import machine_disk, machine_plan, external_disk, lvm_disk


class Nas(BaseServer):
    def __init__(self, *args):
        self.upload_started = threading.Event()
        self.finished = threading.Event()
        self.complete = False
        self.target = bytearray()
        self.extra_target = bytearray()
        self.lv_target = bytearray()
        self.generation = 1
        self.prepared_runs = set()
        self.long_poll_started = threading.Event()
        self.long_poll_count = 0
        self.result_id = 14
        self.base_version = 9
        self.edit_interrupted = False
        self.interrupt_second = False
        self.interrupted = threading.Event()
        self.allow_drop = threading.Event()
        self.upload_attempts = 0
        self.full_transfer = False
        self.rewrite = False
        self.events, self.event_replies, self.event_done = [], [], []
        self.event_rate_applied = threading.Event()
        self.first_record_finished = threading.Event()
        self.second_record_started = threading.Event()
        self.bandwidth_event_done_at = None
        self.bandwidth_lift_done_at = None
        self.bandwidth_response = event_updated_rate
        self.event_rate_observation = None
        self.record_timings = []
        self.result_queries = []
        self.source_details = []
        super().__init__(*args)
        # Bound read-ahead across the intentional disconnect. The offset oracle
        # below still permits any number of legitimate changed-range replays.
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(60 if source_error_test else 15)
                check(value(peer)["action"] == "encrypt_channel", "plaintext request")
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    req = value(tls)
                    action = req["action"]
                    op = req.get("subaction", action)
                    self.requests.append(op)
                    if action == "query_server_info":
                        response = dict(ds_id="test-nas")
                    else:
                        check(req["token"] == "test-token", "wrong token")
                        if action == "auth_admin":
                            response = {}
                        elif action == "auth":
                            if self.generation == 1 and self.upload_started.is_set():
                                self.edit_interrupted = True
                            response = dict(ds_id="test-nas", token="test-token")
                        elif action == "heart_beat":
                            response = {}
                        elif action == "get_timezone":
                            response = dict(timezone="0", epoch=str(int(time.time())))
                        elif action == "get_task":
                            task = dict(id=2, name="Reload fixture", compression=0, encryption=1,
                                        task_uuid="fixture-task",
                                        source_type=3 if multi_test else 2,
                                        backup_external=1 if lvm_test else 0)
                            if multi_test:
                                task["custom_volume"] = ["/", "/data"]
                            response = dict(task_list=[task])
                        elif action == "get_running_task" and self.edit_interrupted and self.generation == 1 and not self.complete:
                            response = dict(running_task_list=[dict(id=self.run_id, task_id=2, type=0, status=2,
                                detail_status=6, version_id=9, result_id=self.result_id, is_backing_up=0,
                                backup_task=dict(data_format=1,error_code=0,is_cbt=0,
                                    resume_info=json.dumps({name:dict(current="0",transfer_current="0") for name in
                                        ((wire_primary,wire_secondary,"fixture_vg=selected.img") if lvm_test else
                                         (wire_primary,wire_secondary) if multi_test else (wire_primary,))})))])
                        elif action == "get_running_task":
                            response = dict(running_task_list=[] if self.complete else [
                                dict(id=self.run_id, task_id=2, type=0, status=int(self.run_id in self.prepared_runs),
                                     version_id=8+self.generation if self.run_id in self.prepared_runs else 0,
                                     result_id=self.result_id if self.run_id in self.prepared_runs else 0,
                                     is_backing_up=0, backup_task=dict(data_format=1,error_code=0,resume_info=''))] if not self.interrupted.is_set() else [
                                dict(id=self.run_id, task_id=2, type=0, status=2, detail_status=6,
                                     version_id=8+self.generation, result_id=self.result_id,
                                     is_backing_up=0, backup_task=dict(data_format=1,error_code=0,is_cbt=1,
                                         base_version_id=self.base_version,
                                         resume_info=json.dumps({
                                             wire_primary:dict(current=str(
                                                               single_resume_offset if single_incremental_test
                                                               else len(self.target)),
                                                               transfer_current=str(len(self.target))),
                                             **({wire_secondary:
                                                 dict(current=str(1536*1024),
                                                      transfer_current=str(1536*1024))}
                                                if multi_test else {}),
                                             **({"fixture_vg=selected.img":dict(current=str(2*1024*1024),
                                                                        transfer_current=str(2*1024*1024))}
                                                if lvm_test else {})})))])
                        elif action == "get_running_task_result":
                            self.result_queries.append(req)
                            response = {} if "result_id" not in req else dict(
                                backup_result=dict(last_success_time=1234,last_backup_status="failure"),
                                running_task_result=dict(
                                task_id=2, result_id=req["result_id"], time_start=1234,
                                job_action="backup", status="complete" if active_events_test and any(
                                event["id"] == 904 for event in self.events) or
                                req["result_id"] < self.result_id or self.complete else "incomplete"))
                            if source_error_test and self.complete and "result_id" in req:
                                response["running_task_result"]["status"] = "error"
                        elif action == "get_portal_link":
                            check(req["address"] == "127.0.0.1", "wrong portal host")
                            response = dict(url="https://fixture.invalid/recovery")
                        elif action == "pull_event":
                            response = dict(event_list=[event for event in self.events
                                if event["id"] not in req["event_list"]])
                        elif action == "act_client_result":
                            receipt = next(r for r in self.event_inbox()["receipts"]
                                           if r["payload"]["id"] == req["event_id"])
                            check(receipt["node_result"] == {k:req[k] for k in receipt["node_result"]},
                                  "picker response preceded durable immutable receipt")
                            self.event_replies.append(req)
                            response = {}
                        elif action == "done_event":
                            ids = req["done_events"]
                            receipts = self.event_inbox()["receipts"]
                            check(all(any(r["payload"]["id"] == id and r["state"] == "ack_pending"
                                          for r in receipts) for id in ids),
                                  "event ACK preceded durable handler result")
                            if 901 in ids:
                                check(self.event_inbox()["bandwidth_snapshot"] == dict(backup_bandwidth=event_updated_rate),
                                      "event ACK preceded durable bandwidth policy")
                                self.bandwidth_event_done_at = time.monotonic()
                            if 908 in ids:
                                check(self.event_inbox()["bandwidth_snapshot"] == dict(backup_bandwidth=0),
                                      "bulk-upload lift ACK preceded durable unlimited policy")
                                self.bandwidth_lift_done_at = time.monotonic()
                            if 904 in ids:
                                task = next(t for t in self.event_inbox()["task_snapshot"] if t["id"] == 2)
                                check(task["last_backup_success_time"] == 1234,
                                      "result ACK preceded durable task timestamp")
                            self.events = [event for event in self.events if event["id"] not in ids]
                            self.event_done.extend(ids)
                            response = {}
                        elif action == "long_poll":
                            check(req["timeout"] == 400, 'long-poll subscription differs from official agent')
                            self.long_poll_count += 1
                            self.long_poll_started.set()
                            deadline = time.monotonic()+req["timeout"]
                            while not self.events and not self.stopped.is_set() and time.monotonic() < deadline:
                                self.stopped.wait(.05)
                            response = dict(has_event=int(bool(self.events)))
                        elif action == "get_backup_bandwidth":
                            response = dict(backup_bandwidth=self.bandwidth_response)
                        elif op == "result_detail" and source_error_test:
                            check(not self.complete and len(req["logs"]) == 1,
                                  "source activity followed completion")
                            log = req["logs"][0]
                            check(log["log_type"] == 7020 and log["running_task_id"] == self.run_id,
                                  "wrong terminal source activity")
                            check(json.loads(log["other_params"]) == dict(
                                id=self.run_id,running_task_id=self.run_id,task_id=2,
                                task_uuid="fixture-task",result_id=self.result_id,error_code="61"),
                                "source activity fields differ from official agent")
                            self.source_details.append(log["log_type"])
                            response = {}
                        elif op == "get_base_version":
                            check(automatic_test and req["task_id"] == 2,
                                  "unexpected incremental base selection")
                            response = dict(base_version_id=self.base_version if self.generation >= 2 else 0)
                        elif op == "update_backup_task":
                            check(self.run_id not in self.prepared_runs, 'service repeated its prepared capture handshake')
                            if automatic_test:
                                no_snapshot_before_handshake(self.root,self.run_id)
                            self.prepared_runs.add(self.run_id)
                            if self.generation >= 2 and not self.full_transfer:
                                check(req["base_version_id"] == self.base_version and req["is_cbt"] == 1,
                                      "service lost multi-disk incremental base")
                            elif self.full_transfer:
                                check(req["base_version_id"] == 0 and req["is_cbt"] == 0,
                                      "ineligible source inherited an incremental NAS base")
                            response = dict(running_task_id=self.run_id,
                                            version_id=8+self.generation,
                                            result_id=self.result_id, data_format=1)
                        elif op == "update_device_spec":
                            if automatic_test:
                                check(self.long_poll_started.wait(3), 'capture suppressed the independent long-poll worker')
                                catalog_snapshot(self.root,self.run_id,8+self.generation,
                                    self.base_version if self.generation > 1 else 0)
                            spec = json.loads(req["snapshot_info"])
                            check(spec["device_spec"]["is_bootable"] is True,
                                  "validated root/boot capture was not marked bootable")
                            if multi_test:
                                check(len(spec["device_spec"]["images"]) == (3 if lvm_test else 2) and
                                      len(spec["disk_images"]) == (3 if lvm_test else 2),
                                      "missing additional disk or LV metadata")
                                check(spec["disk_images"][1]["disk_number"] == "1" and
                                      any(i["type"] == 5 for i in spec["disk_images"][1]["intervals"]),
                                      "unselected partition was not excluded")
                                if lvm_test:
                                    check(spec["device_spec"]["volume_groups"] == plan['lvm']['volume_groups'],
                                          "VG/PV/LV inventory was coupled to captured images")
                                    vg = spec["device_spec"]["volume_groups"][0]
                                    pv_layout = next(i for i in
                                                     spec["device_spec"]["disk_layout"][str(pv_index)]
                                                     if i["file_system"] == "LVM2_member")
                                    check(vg["name"] == "fixture_vg" and
                                          vg["uuid"] == group["uuid"] and
                                          vg["physical_volumes"][0]["uuid"] ==
                                          group["physical_volumes"][0]["uuid"] and
                                          vg["physical_volumes"][0]["name"] == pv_path and
                                          vg["logical_volumes"][0]["uuid"] ==
                                          group["logical_volumes"][0]["uuid"] and
                                          spec["disk_images"][2]["disk_number"] == "-1" and
                                          spec["disk_images"][2]["image_name"] == "fixture_vg=selected.img" and
                                          spec["device_spec"]["mount_map"][lv_mount]["image_path"] ==
                                          "fixture_vg=selected.img" and
                                          pv_layout["device_name"] == pv_path and
                                          spec["disk_images"][pv_index]["image_name"] ==
                                          (wire_primary if primary_pv else wire_secondary) and
                                          next(i for i in spec["disk_images"][pv_index]["intervals"]
                                               if i["file_system"] == "LVM2_member")["alias_name"] ==
                                          pv_path,
                                          "LVM physical/logical image metadata lost identity: "+
                                          repr((spec["device_spec"]["volume_groups"],
                                                spec["disk_images"][2],
                                                spec["device_spec"]["mount_map"].get(lv_mount))))
                                if self.generation >= 2 and not self.full_transfer:
                                    check("is_cbt" not in spec and all(
                                        int(i["transfer_length"]) == int(i["length"])
                                        if self.rewrite or (lvm_test and index == pv_index) or
                                           (omitted_base and self.generation == 2 and index == 1) else
                                        int(i["transfer_length"]) < int(i["length"])
                                        for index,i in enumerate(spec["device_spec"]["images"])),
                                        "multi-incremental metadata omitted a disk delta: "+
                                        repr(spec["device_spec"]["images"]))
                            response = {}
                        elif op == "upload_block":
                            self.upload_attempts += 1
                            attempt = self.upload_attempts
                            check(req["resume"] == int((self.generation == 2 and
                                  self.interrupted.is_set()) or (self.generation == 1 and self.edit_interrupted)), "wrong service upload resume flag")
                            tls.sendall(wire(dict(success=1, backup_bandwidth=
                                event_initial_rate if active_events_test and attempt == 1 else 0)))
                            held_blocks = []
                            if active_events_test and attempt == 1:
                                nas = self
                                class RecordReader:
                                    def __init__(self, started_event, threshold):
                                        self.received = bytearray()
                                        self.started = None
                                        self.started_event = started_event
                                        self.threshold = threshold
                                    def recv(self, count):
                                        part = tls.recv(count)
                                        if part and self.started is None:
                                            self.started = time.monotonic()
                                        self.received.extend(part)
                                        # Publish the event only after the first
                                        # old-rate write is already in flight.
                                        if len(self.received) >= self.threshold:
                                            self.started_event.set()
                                        return part
                                reader = RecordReader(nas.upload_started,event_initial_rate)
                                first = upload_value(reader)
                                first_done = time.monotonic()
                                check(first.get("offset") == 0 and first.get("length") == mib and
                                      first.get("buffer") == self.image[:mib] and
                                      bytes(reader.received) == wire(first),
                                      "first paced record differs from its exact source/wire bytes")
                                # SetBandwidth freezes the current record's
                                # rate. A 1 MiB record plus framing needs nine
                                # writes at 128 KiB/s; the first is immediate.
                                first_timing = record_timing(first,event_initial_rate)
                                minimum = first_timing["arrival_us"]/1000000
                                elapsed = first_done-reader.started
                                check(minimum == 8 and minimum-.25 <= elapsed <= minimum+4,
                                      f"current record did not retain its old rate: {elapsed=}, {minimum=}")
                                check(self.bandwidth_event_done_at is not None and
                                      reader.started <= self.bandwidth_event_done_at < first_done,
                                      "bandwidth event was not acknowledged during the paced record")
                                self.first_record_finished.set()
                                # Performance framing is much smaller than one full-rate
                                # write; this witness necessarily includes record2
                                # data and proves its fixed rate was sampled already.
                                second_reader = RecordReader(nas.second_record_started,event_updated_rate) if progress_test else tls
                                second = upload_value(second_reader) # Also drains official agent performance.
                                second_done = time.monotonic()
                                next_elapsed = second_done-first_done
                                check(second.get("offset") == mib and second.get("length") == mib and
                                      second.get("buffer") == self.image[mib:2*mib],
                                      "second record differs from its exact source bytes")
                                if event_updated_rate:
                                    next_timing = record_timing(second,event_updated_rate)
                                    next_minimum = next_timing["arrival_us"]/1000000
                                    check(next_minimum == 10 and next_minimum-.25 <= next_elapsed < next_minimum+2,
                                          f"next record did not use the event's new rate: {next_elapsed=}")
                                    check(self.bandwidth_lift_done_at is not None and
                                          first_done <= self.bandwidth_lift_done_at < second_done,
                                          "bulk-upload lift was not acknowledged during record2")
                                else:
                                    check(next_elapsed < 2,
                                          f"next record did not use the event's unlimited rate: {next_elapsed=}")
                                self.event_rate_observation = dict(first_elapsed=elapsed,
                                    minimum=minimum, next_elapsed=next_elapsed, next_rate=event_updated_rate)
                                held_blocks = [(first,event_initial_rate),(second,event_updated_rate)]
                                self.event_rate_applied.set()
                            else:
                                self.upload_started.set()
                            # Active controls after record2: two result ACKs and
                            # one status query, each <=3.5s, plus2.5s scheduling.
                            check(self.release.wait(13 if active_events_test else 30),
                                  "test never released upload")
                            if self.edit_interrupted and attempt == 1:
                                return
                            while True:
                                block, rate = held_blocks.pop(0) if held_blocks else (upload_value(tls),0)
                                if "close" in block:
                                    check(bytes(self.target) == self.image, "upload data differs")
                                    if multi_test:
                                        check(bytes(self.extra_target) == extra_image_bytes,
                                              "selected additional disk upload differs")
                                    if lvm_test:
                                        check(bytes(self.lv_target) == lv_image_bytes,
                                              "selected LV upload differs")
                                    tls.sendall(wire(dict(close=1)))
                                    return
                                self.record_timings.append(dict(image=block["image_name"],offset=block["offset"],
                                    **record_timing(block,rate)))
                                target = (self.lv_target if block["image_name"] == "fixture_vg=selected.img"
                                          else self.extra_target if block["image_name"] == wire_secondary
                                          else self.target)
                                check(block["image_name"] in (
                                      (wire_primary,wire_secondary,"fixture_vg=selected.img") if lvm_test else
                                      (wire_primary,wire_secondary) if multi_test else (wire_primary,)),
                                      "unselected image was uploaded")
                                if self.generation == 1 or self.full_transfer:
                                    check(block["offset"] == len(target) and block["changed"] == 1,
                                          "incorrect upload range")
                                    excluded_block = any(
                                        begin <= block["offset"] and
                                        block["offset"]+block["length"] <= end
                                        for begin,end in unused_by_name[block["image_name"]])
                                    check(block["used"] == int(not excluded_block) and
                                          block["is_interval_cbt"] == 0,
                                          "full upload lost the capture's unused interval policy")
                                    if block["used"]:
                                        check(len(block["buffer"]) == block["length"], "short upload block")
                                        target.extend(block["buffer"])
                                    else:
                                        check("buffer" not in block and
                                              block["changed_length"] == 0 and
                                              any(begin <= block["offset"] and
                                                  block["offset"]+block["length"] <= end
                                                  for begin,end in unused_by_name[block["image_name"]]),
                                              "unused partition sent payload or wrong range")
                                        target.extend(bytes(block["length"]))
                                else:
                                    at, length = block["offset"], block["length"]
                                    affected = self.rewrite or (omitted_base and self.generation == 2 and
                                                block["image_name"] == wire_secondary and
                                                mib <= at < 17*mib)
                                    check(block["is_interval_cbt"] == int(not affected) and
                                          at+length <= len(target),
                                          "service incremental range outside the saved disk")
                                    if affected:
                                        check(block["changed"] == 1,
                                              "previously omitted filesystem inherited absent base bytes")
                                    check(block["used"] == int(not any(
                                        begin <= at and at+length <= end
                                        for begin,end in unused_by_name[block["image_name"]])),
                                        "incremental upload lost the capture's unused interval policy")
                                    if not block["used"]:
                                        check(block["changed"] == 1 and "buffer" not in block and
                                              block["changed_length"] == 0 and
                                              any(begin <= at and at+length <= end
                                                  for begin,end in unused_by_name[block["image_name"]]),
                                              "incremental unused partition sent payload")
                                    elif block["changed"]:
                                        check(len(block["buffer"]) == length, "short incremental block")
                                        target[at:at+length] = block["buffer"]
                                    else:
                                        check("buffer" not in block and block["changed_length"] == 0,
                                              "inherited interval uploaded data")
                                    if (self.interrupt_second and self.generation == 2 and
                                            block["image_name"] == (
                                                wire_primary if single_incremental_test else
                                                "fixture_vg=selected.img" if lvm_test else wire_secondary) and
                                            ((single_incremental_test and not block["used"]) or
                                             (not single_incremental_test and
                                              (not block["changed"] or affected) and
                                              at+length >= 2*1024*1024))):
                                        self.interrupt_second = False
                                        self.interrupted.set()
                                        check(self.allow_drop.wait(10), "test did not stop interrupted service")
                                        return
                        elif action == "unlink_connection":
                            response = {}
                        elif op == "check_complete" and source_error_test:
                            check(req["status"] == "error" and req["result_id"] == self.result_id and
                                  req["running_task_id"] == self.run_id and req["is_cbt"] == 0,
                                  "source failure completed with the wrong status/identity")
                            check(self.source_details == [7020] and not self.extra_target,
                                  "source failure omitted 7020 or continued to another image")
                            self.complete = True
                            response = dict(status="error")
                            self.finished.set()
                        elif op == "check_complete" and logout_test:
                            check(req["status"] == "cancel", "logout did not cancel interrupted backup")
                            self.complete = True
                            response = dict(status="cancel")
                        elif op == "check_complete":
                            check(req["status"] == "complete", "reload cancelled NAS job")
                            if self.generation >= 2 and not self.full_transfer:
                                check(req["is_cbt"] == int(not self.rewrite and not (omitted_base and self.generation == 2)),
                                      "completion differs from actual filesystem CBT contexts")
                            elif self.full_transfer:
                                check(req["is_cbt"] == 0, "new full completion retained an incremental base")
                            check(bytes(self.target) == self.image, "premature completion")
                            if multi_test:
                                check(bytes(self.extra_target) == extra_image_bytes,
                                      "additional image incomplete")
                            if lvm_test:
                                check(bytes(self.lv_target) == lv_image_bytes, "logical image incomplete")
                            self.complete = True
                            response = dict(status="complete")
                            self.finished.set()
                        else:
                            raise AssertionError(f"unexpected operation {op}")
                    tls.sendall(wire(response))
        except (EOFError, ssl.SSLEOFError, ssl.SSLZeroReturnError,
                ConnectionResetError, BrokenPipeError):
            # Reload/stop cancels observer sockets, not the upload.
            pass
        except Exception as error:
            self.errors.append(repr(error))

    def event_inbox(self):
        return value(Reader((self.root/"opensabba/events.pstream").read_bytes()))

from snapshot_service_fixture import SnapshotSources

exe, openssl, fixture = sys.argv[1:4]
options = sys.argv[4:]
active_events_test = 'active-events' in options
event_initial_rate = 128*1024
progress_test = 'progress' in options
check(not progress_test or active_events_test, "progress requires the bounded bandwidth-event scenario")
source_error_test = 'source-error' in options
omitted_base = 'omitted-base' in options
mib = 1024*1024
logout_test = 'logout' in options
proxy_test = 'proxy' in options
primary_pv = 'lvm-root' in options
lvm_test = 'lvm-incremental' in options or primary_pv
incremental_test = 'multi-incremental' in options or lvm_test
single_incremental_test = 'single-incremental' in options
automatic_test = incremental_test or single_incremental_test
multi_test = 'multi' in options or incremental_test
wire_primary = 'sda.img' if automatic_test or primary_pv else 'reload-test'
# Ten full-rate writes plus a tiny final framing fragment: enough time for
# visibility and the zero-policy ACK, without a deferred final sleep that
# could overlap the held-control phase.
event_updated_rate = len(wire(full_record(wire_primary,mib,mib)))//10 if progress_test else 0
# NAS-provisioned captures derive every physical image name, including the
# non-PV sibling of a machine whose root filesystem is an LV.
wire_secondary = 'sdc.img' if automatic_test else 'reload-test-disk-1'
pv_path = '/dev/sda2' if primary_pv else '/dev/sdc1'
pv_index = 0 if primary_pv else 1
lv_mount = '/' if primary_pv else '/data'
exe, fixture = str(Path(exe).resolve()), str(Path(fixture).resolve())
with tempfile.TemporaryDirectory(prefix='opensabba-direct-service-') as temporary:
    root = Path(temporary)
    part = filesystem(root)
    image_bytes, boot, boot_size, root_offset = machine_disk(part)
    plan = machine_plan(image_bytes, boot, boot_size, root_offset, len(part))
    extra_image_bytes = lv_image_bytes = None
    if multi_test:
        if lvm_test:
            pv_disk_bytes, lv_image_bytes, pv_plan, lv_plan, group = lvm_disk(root)
            if primary_pv:
                mib = 1024*1024
                image_bytes[root_offset:root_offset+16*mib] = pv_disk_bytes[mib:17*mib]
                image_bytes[466] = 0x8e
                plan['layout']['partitions'][1]['mbr_type'] = 0x8e
                excluded = dict(pv_plan['excluded'][0], partition=2, device='/dev/sda2', offset=root_offset)
                lv_plan = dict(lv_plan, mount_path='/')
                group['physical_volumes'][0]['name'] = '/dev/sda2'
                extra_image_bytes, extra_plan = external_disk(root)
                extra_plan['disk'] = '/dev/sdc'
                plan.update(disk='/dev/sda', root=lv_plan, excluded=[excluded, *plan['excluded']],
                            other_disk_count=1, selected_extra=[], additional_disks=[extra_plan],
                            lvm=dict(volume_groups=[group], selected_lvs=[lv_plan]))
            else:
                extra_image_bytes, extra_plan = pv_disk_bytes, pv_plan
                plan.update(other_disk_count=1, selected_extra=[lv_plan], additional_disks=[extra_plan],
                            lvm=dict(volume_groups=[group], selected_lvs=[lv_plan]))
        else:
            extra_image_bytes, extra_plan = external_disk(root)
            plan.update(other_disk_count=1, selected_extra=[], additional_disks=[extra_plan])
    if lvm_test:
        # official agent sends global VG/PV/LV inventory independently of disk uploads.
        # A selected VG's extra PV and an unrelated VG must not stop a ready
        # capture, nor add payload images to this explicit source selection.
        group['physical_volumes'].append(dict(name='/dev/sdd1',uuid='uncaptured-pv',size=4*mib))
        group['total_size'] += 4*mib
        plan['lvm']['volume_groups'].append(dict(name='unrelated',uuid='unrelated-vg',
            extent_size=4*mib,mda_size=4096,total_size=4*mib,
            physical_volumes=[dict(name='/dev/sde1',uuid='unrelated-pv',size=4*mib)],
            logical_volumes=[dict(name='idle',uuid='idle-lv',file_system='',size=4*mib)]))
    image_bytes = bytes(image_bytes)
    single_resume_offset = plan['excluded'][-1]['offset']+1024*1024+512
    unused_by_name = {wire_primary: [(i['offset'], i['offset']+i['length']) for i in plan['excluded']]}
    if multi_test:
        unused_by_name[wire_secondary] = [(i['offset'],i['offset']+i['length']) for i in extra_plan['excluded']]
    if lvm_test:
        unused_by_name['fixture_vg=selected.img'] = []
    sources = SnapshotSources(root)
    journal, capture = sources.capture(plan, image_bytes, extra_image_bytes, lv_image_bytes)
    if omitted_base:
        check(incremental_test and not lvm_test, 'omitted-base fixture needs physical multi-incremental')
        # Independently constructed, durably retired acquisition failure. The
        # production reader must omit this volume in the first NAS version,
        # then reread its entire range when the next capture is healthy.
        journal['reservation']['extras'][0].update(
            snapshot=dict(acquisition_error=28), attempted=1, released=1)
        (capture/'capture.pstream').write_bytes(wire(journal))
        healthy_extra_bytes = extra_image_bytes
        omitted_extra = bytearray(extra_image_bytes)
        omitted_extra[mib:17*mib] = bytes(16*mib)
        extra_image_bytes = bytes(omitted_extra)
        unused_by_name[wire_secondary].insert(0, (mib, 17*mib))
    cert, key = root/'cert.pem', root/'key.pem'
    subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:transfer.test.invalid'],
                   check=True, capture_output=True)
    config = root/'config'
    private = config/'opensabba'
    private.mkdir(parents=True, mode=0o700)
    nas = Nas(config, cert, key, image_bytes, 'reload')
    session = dict(format=2, host='127.0.0.1', port=nas.port, ca_file=str(cert), username='test-user',
                   device_uuid='test-device', token='test-token', ds_id='test-nas', registration_state='confirmed')
    proxy = None
    if proxy_test:
        proxy = Proxy(nas.port)
        proxy.authority = f'transfer.test.invalid:{nas.port}'.encode()
        proxy.credentials = b'transfer-user:transfer-proxy-secret'
        session.update(host='transfer.test.invalid', proxy_host='127.0.0.1', proxy_port=proxy.port,
                       proxy_username='transfer-user', proxy_password='transfer-proxy-secret')
    saved = private/'session.pstream'
    saved.write_bytes(wire(session))
    saved.chmod(0o600)
    env = dict(os.environ, XDG_CONFIG_HOME=str(config), LD_PRELOAD=fixture,
               OPENSABBA_SOURCE_FIXTURE=str(sources.manifest), OPENSABBA_SOURCE_TRACE=str(sources.trace))

    def cli(*args, timeout=15):
        if args and args[0] == "--logout":
            args += ("--quiet", "--username", "test-admin", "--password", "admin-password-837")
        return subprocess.run([exe, *args], env=env, capture_output=True, text=True, timeout=timeout)

    def start():
        return subprocess.Popen([exe, 'service', 'run'], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    def stop(process):
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=8)
        check(process.returncode == 0, out+err)
        return out, err

    process = None
    try:
        if automatic_test:
            capture = provide_capture(env,sources,capture,
                    dict(source_type=3,custom_volume=['/','/data']) if multi_test else dict(source_type=2))
        else:
            # This OpenSabba diagnostic binds a single full source; it has no
            # official agent automatic-event/base-selection semantics.
            bound = cli('service', 'bind-machine', str(capture), '--task', '2', '--image-name', 'reload-test')
            check(bound.returncode == 0, bound.stdout+bound.stderr)
            bound_reads = sum(int(line.split()[3]) for line in sources.trace.read_text().splitlines()
                              if line.startswith('snap '))
            check(0 < bound_reads < len(part)//4, f'binding bulk-read snapshot payload: {bound_reads}')
        if source_error_test:
            payload = part.index(b'OpenSabba independent restore specimen\n')
            fault_at = payload//512*512
            env["OPENSABBA_SOURCE_READ_FAULT"] = f"/dev/synosnap2 {fault_at} 512 61 0 0"
        process = start()
        if not nas.upload_started.wait(10):
            process.terminate()
            out, err = process.communicate(timeout=5)
            raise AssertionError(f'upload never started: {nas.errors} {out} {err}')
        if progress_test:
            # Two images share one transfer context. official agent updates progress
            # for prepared buffers, subject to its same-second guard. Observe
            # exactly two prepared MiB while the second record is paced. The
            # journal records phases only and never carries transfer counters.
            visibility_deadline = 0
            def visible_transfer():
                remaining = visibility_deadline-time.monotonic()
                if remaining <= 0:
                    return False
                status = cli("-s", "--skip-portal", timeout=min(3.5,remaining))
                job = value(Reader((private/"backup-job.pstream").read_bytes()))
                total = sum(image["size"] for image in job["images"])
                return (time.monotonic() <= visibility_deadline and status.returncode == 0 and
                        nas.second_record_started.is_set() and not nas.event_rate_applied.is_set() and
                        "Service Status: Backing up... - 2.00 MB" in status.stdout and
                        f" / {total/1024/1024:.2f} MB (" in status.stdout and
                        "0.00 Bytes/s" not in status.stdout and
                        job["phase"] == "upload" and
                        all("sent_bytes" not in image for image in job["images"]))
        if active_events_test:
            picker = root/"active-picker"
            picker.mkdir()
            (picker/"child").mkdir()
            held_job = value(Reader((private/"backup-job.pstream").read_bytes()))
            nas.events = [
                dict(id=901, action="update_backup_bandwidth"),
                dict(id=902, action="act_client", webapi_task=dict(
                    event_id=902, subaction="list_nodes", node_path=str(picker), dir_only=1)),
                dict(id=903, action="act_client", webapi_task=dict(
                    event_id=903, subaction="list_nodes", node_path="", dir_only=1))]
            wait_for(lambda: set(nas.event_done) == {901,902,903},
                     "backup held control-event acknowledgments", seconds=3.5)
            if progress_test:
                # Send the bandwidth event while the first record is in flight.
                # Record2 uses floor(encoded-size/10)B/s:10s to its last byte. Visibility(3s)
                # plus the zero-policy ACK(3.5s) fit before it can finish.
                # No later record may inherit the deliberately slow policy.
                check(nas.first_record_finished.wait(13),
                      f"first paced record did not finish: {nas.errors}")
                visibility_deadline = time.monotonic()+3
                wait_for(visible_transfer,
                         "visible multi-image progress did not match prepared buffers before journal saves",seconds=3)
                nas.bandwidth_response = 0
                nas.events = [dict(id=908, action="update_backup_bandwidth")]
                wait_for(lambda: 908 in nas.event_done,
                         "bulk-upload unlimited policy was not acknowledged",seconds=3.5)
            # The in-flight record must finish at its sampled old rate. The
            # next record observes the event's new policy on the same channel.
            check(nas.event_rate_applied.wait(13 if progress_test else 15),
                  f"event policy did not apply at the next record: {nas.errors}")
            print(f"bandwidth event record timing: {nas.event_rate_observation}", flush=True)
            check(nas.requests.count("get_backup_bandwidth") == (2 if progress_test else 1),
                  "bandwidth query was not owned exclusively by the event")
            check(not nas.release.is_set() and not nas.complete, "control fixture released backup")
            current_job = value(Reader((private/"backup-job.pstream").read_bytes()))
            check(current_job["phase"] == held_job["phase"] == "upload" and
                  current_job["running_task_id"] == held_job["running_task_id"] and
                  current_job["result_id"] == held_job["result_id"],
                  "control handler changed active backup identity or phase")
            directory = next(r for r in nas.event_replies if r["event_id"] == 902)
            check(directory["node_list"] == [dict(name="child",path=str(picker/"child"),is_dir=1)],
                  "active backup directory picker result differs")
        if active_events_test:
            nas.events = [dict(id=904, action="get_running_task_result", task_id=2,
                               version_id=held_job["version_id"])]
            wait_for(lambda: 904 in nas.event_done, "backup result ACK stalled behind held upload",seconds=3.5)
            check(nas.result_queries[-1].get("result_id") == held_job["result_id"],
                  "active backup result lost process-local history")
            current_job = value(Reader((private/"backup-job.pstream").read_bytes()))
            check(current_job["phase"] == "upload" and "resolution" not in current_job,
                  "terminal result event changed active transfer state")
            visible = cli('--status',timeout=3.5)
            check(visible.returncode == 0 and 'Service Status: Idle - Failed\n' in visible.stdout and
                  'Recovery portal: https://fixture.invalid/recovery\n' in visible.stdout,
                  'active result did not update visible service status')
            nas.events = [dict(id=905, action="get_running_task_result", task_id=2,
                               version_id=held_job["version_id"])]
            wait_for(lambda: 905 in nas.event_done, "retired backup result ACK stalled",seconds=3.5)
            check("result_id" not in nas.result_queries[-1], "progress re-registered retired result")
        if source_error_test:
            nas.release.set()
            check(nas.finished.wait(45), f"source failure did not complete: {nas.errors}")
            wait_for(lambda: value(Reader((private/"backup-job.pstream").read_bytes()))["phase"] == "error",
                     "source error completion was not durable")
            check(process.poll() is None and nas.requests.count("check_complete") == 1,
                  "source error stopped the daemon or repeated completion")
            picker = root/"after-error"
            picker.mkdir()
            (picker/"child").mkdir()
            nas.events = [dict(id=906,action="act_client",webapi_task=dict(
                event_id=906,subaction="list_nodes",node_path=str(picker),dir_only=1))]
            wait_for(lambda: 906 in nas.event_done,"daemon stopped handling events after source error",seconds=5)
            reply = next(row for row in nas.event_replies if row["event_id"] == 906)
            check(reply["node_list"] == [dict(name="child",path=str(picker/"child"),is_dir=1)],
                  "daemon returned the wrong post-error picker result")
            wait_for(lambda: nas.long_poll_count >= 2,
                     "daemon did not rearm its independent NAS subscription",seconds=5)
            nas.events = [dict(id=907,action="act_client",webapi_task=dict(
                event_id=907,subaction="list_nodes",node_path=str(picker),dir_only=1))]
            wait_for(lambda: 907 in nas.event_done,
                     "idle queue worker waited for long-poll after terminal source error",seconds=5)
            out, err = stop(process)
            process = None
        elif logout_test:
            result = cli('--logout')
            out, err = process.communicate(timeout=8)
            check(process.returncode == 0, out+err)
            check(result.returncode == 1 and saved.exists() and
                  'cannot release all owned capture snapshots' in result.stderr,
                  result.stdout+result.stderr)
            record = value(Reader((private/'backup-job.pstream').read_bytes()))
            check(record['resolution'] == dict(state='resolved',outcome='cancel'),
                  'logout did not persist exact NAS cancellation outcome')
            check(nas.requests.count('auth_admin') == 1 and nas.requests.count('unlink_connection') == 0 and
                  nas.requests.count('check_complete') == 1,
                  'logout erased ownership before snapshot cleanup or replayed cancellation')
            # The source fixture deliberately rejects every driver mutation.
            # Independently complete its synthetic release record, then verify
            # retry consumes that evidence without replaying NAS cancellation.
            released = copy.deepcopy(journal)
            released['reservation']['snapshot_released'] = 1
            for extra in released['reservation']['extras']:
                extra['released'] = 1
            release_record = capture/'release.pstream'
            release_record.write_bytes(wire(released))
            release_record.chmod(0o600)
            result = cli('--logout')
            check(result.returncode == 0 and not saved.exists(),result.stdout+result.stderr)
            check(nas.requests.count('auth_admin') == 2 and nas.requests.count('unlink_connection') == 1 and
                  nas.requests.count('check_complete') == 1,
                  'logout retry replayed cancellation or omitted unlink')
            process = None
        elif active_events_test:
            # The event is an observation, not a transfer disposition. Keep
            # the same process/channel alive and complete the held upload.
            # Reconnect reconciliation belongs to the reload scenarios: this
            # peer deliberately reports a terminal result for the event.
            nas.release.set()
            check(nas.finished.wait(15), f'active upload did not continue after result event: {nas.errors}')
            wait_for(lambda: value(Reader((private/'backup-job.pstream').read_bytes()))['phase'] == 'complete',
                     'active upload completion was not durable')
            completed = value(Reader((private/'backup-job.pstream').read_bytes()))
            check(completed['running_task_id'] == held_job['running_task_id'] and
                  completed['result_id'] == held_job['result_id'] and
                  current_job['phase'] == 'upload' and
                  'resolution' not in completed,
                  'transfer worker did not advance the same journal after the result event')
            check(nas.upload_attempts == 1 and not nas.edit_interrupted and
                  nas.requests.count('check_complete') == 1,
                  'result event interrupted or replaced the live transfer')
            out, err = stop(process)
            process = None
        else:
            auth_before, heartbeat_before = nas.requests.count('auth'), nas.requests.count('heart_beat')
            result = cli('--reload','-q')
            check(result.returncode == 0,result.stdout+result.stderr)
            wait_for(lambda: nas.requests.count('auth') == auth_before+1, 'edit did not stop old worker/reconnect')
            check(process.poll() is None and nas.edit_interrupted,'edit terminated service or waited for held upload')
            nas.release.set()
            check(nas.finished.wait(15), f'full backup did not finish after edit: {nas.errors}')
            wait_for(lambda: nas.requests.count('long_poll') >= 1, 'observation did not restart')
            for unused in range(2):
                result = cli('--reload','-q')
                check(result.returncode == 0,result.stdout+result.stderr)
            status = json.loads(cli('backup', 'status', '--json').stdout)
            check(status['phase'] == 'complete', 'full completion was not durable')
            out, err = stop(process)
            process = None
            check(out.count('Service reload:') == 3, 'connection edits were lost')
            check(nas.requests.count('upload_block') == 2 and nas.requests.count('check_complete') == 1,
                  'edit did not resume interrupted upload exactly once')
            base_job = value(Reader((private/'backup-job.pstream').read_bytes()))
            if automatic_test:
                local = catalog_snapshot(config,27,9)
                check(local['capture']['id'] == base_job['source_capture']['id'],
                      'full backup did not update the acquired local snapshot')
            check(base_job['direct_intervals'] == 1 and base_job['image_sha256'] == '',
                  'service did not use digest-free direct source')
            if incremental_test or single_incremental_test:
                mib = 1024*1024
                if omitted_base:
                    extra_image_bytes = healthy_extra_bytes
                    unused_by_name[wire_secondary].remove((mib, 17*mib))
                next_primary = bytearray(image_bytes)
                next_primary[(boot+3*mib+4096 if primary_pv else root_offset+2*mib+4096)] ^= 0x19
                image_bytes = bytes(next_primary)
                if multi_test:
                    next_extra = bytearray(extra_image_bytes)
                    next_extra[(4*mib if primary_pv or not lvm_test else 20*mib)+4096] ^= 0x35
                    if not lvm_test:
                        next_extra[6*mib+4096] ^= 0x27
                    extra_image_bytes = bytes(next_extra)
                if lvm_test:
                    next_lv = bytearray(lv_image_bytes)
                    next_lv[4*mib+4096] ^= 0x27
                    next_lv[6*mib+4096] ^= 0x52
                    lv_image_bytes = bytes(next_lv)
                snapshot_reads_before = sources.read_mark()
                # Independent source-read oracle, in each snapshot's own
                # coordinates. Never derive permissions from the agent's CBT
                # plan or bytes which happened to arrive before process death.
                cbt_block = 65536
                lv_reads = [(4*mib, cbt_block), (6*mib, cbt_block)] if lvm_test else None
                expected_reads = {"/dev/synosnap2":
                    lv_reads if primary_pv else [(2*mib, cbt_block)]}
                if multi_test:
                    if lvm_test and not primary_pv:
                        expected_reads["/dev/synosnap3"] = lv_reads
                    elif omitted_base:
                        expected_reads["/dev/synosnap3"] = [(0, extra_plan["selected_extra"][0]["length"])]
                    else:
                        expected_reads["/dev/synosnap3"] = [(3*mib, cbt_block)]
                        if not primary_pv:
                            expected_reads["/dev/synosnap3"].append((5*mib, cbt_block))
                if lvm_test:
                    # Richer live discovery describes the same logical image.
                    # Its valid generation ancestry still permits inheritance.
                    selected = plan['root'] if primary_pv else plan['selected_extra'][0]
                    for segment in selected['segments']:
                        segment.update(type='linear', mapping=[], kernel_topology={})
                journal, capture = sources.capture(plan, image_bytes, extra_image_bytes, lv_image_bytes)
                capture = provide_capture(env,sources,capture,
                    dict(source_type=3,custom_volume=['/','/data']) if multi_test else dict(source_type=2))
                nas.generation, nas.run_id, nas.result_id = 2, 28, 15
                nas.image, nas.complete = image_bytes, False
                nas.upload_started.clear()
                nas.finished.clear()
                def refused_policy(record, reason, initial_capture=False):
                    path = private/'backup-job.pstream'
                    path.write_bytes(wire(record))
                    before = path.read_bytes()
                    operations = (nas.upload_attempts, nas.requests.count('update_backup_task'),
                                  nas.requests.count('check_complete'))
                    rejected = cli('service', 'run')
                    check(rejected.returncode != 0 and reason in rejected.stdout+rejected.stderr,
                          'altered interval policy was accepted: '+rejected.stdout+rejected.stderr)
                    preparations = nas.requests.count('update_backup_task')-operations[1]
                    # official agent handshakes and captures before planning the image
                    # against a retained base. A bad base still cannot upload,
                    # complete or replace the old backup journal.
                    check(before == path.read_bytes() and nas.upload_attempts == operations[0] and
                          nas.requests.count('check_complete') == operations[2] and
                          preparations in ((0,1) if initial_capture else (0,)),
                          'invalid policy changed retained state or sent backup data')

                legacy_base = copy.deepcopy(base_job)
                legacy_base['schema'] = 4 if multi_test else 2
                for entry in legacy_base['images'] if multi_test else [legacy_base]:
                    del entry['unused_ranges']
                changed_base = copy.deepcopy(base_job)
                entry = next(item for item in changed_base['images'] if item['unused_ranges']) if multi_test else changed_base
                entry['unused_ranges'][0]['length'] -= 512
                refused_policy(changed_base, 'base unused intervals changed', initial_capture=True)
                (private/'backup-job.pstream').write_bytes(wire(base_job))
                nas.interrupt_second = True
                process = start()
                if not nas.interrupted.wait(15):
                    process.terminate()
                    out, err = process.communicate(timeout=5)
                    raise AssertionError(f'incremental interruption missing: {nas.errors} {out} {err}')
                process.kill()
                out, err = process.communicate(timeout=5)
                process = None
                nas.allow_drop.set()
                paused = value(Reader((private/'backup-job.pstream').read_bytes()))
                check(paused['phase'] == 'upload' and paused['schema'] == (7 if multi_test else 9),
                      'incremental upload evidence not retained after process death')
                archive = private/'backup-job-27-14.pstream'
                check(value(Reader(archive.read_bytes())) == base_job, 'exact full base was not archived')
                changed_unused = copy.deepcopy(paused)
                entry = next(item for item in changed_unused['images'] if item['unused_ranges']) if multi_test else changed_unused
                entry['unused_ranges'][0]['length'] -= 512
                refused_policy(changed_unused, 'unused')
                (private/'backup-job.pstream').write_bytes(wire(paused))
                changed_base = copy.deepcopy(base_job)
                changed_base['source_capture']['plan']['layout']['disk_id'] = '12345678'
                archive.write_bytes(wire(changed_base))
                refused_policy(paused, 'capture changed')
                check(archive.read_bytes() == wire(changed_base), 'resume rewrote its retained base')
                archive.write_bytes(wire(legacy_base))
                refused_policy(paused, 'retained image plans')
                archive.write_bytes(wire(base_job))
                # A changed saved plan must be refused before another upload or completion.
                altered = copy.deepcopy(paused)
                policy = altered['images'][0 if omitted_base else -1] if multi_test else altered['incremental']
                inherited = next(i for i,r in enumerate(policy['ranges']) if not r['changed'] and r['length']>8192)
                interval = policy['ranges'][inherited]
                policy['ranges'][inherited:inherited+1] = [
                    dict(offset=interval['offset'],length=4096,changed=0),
                    dict(offset=interval['offset']+4096,length=4096,changed=1),
                    dict(offset=interval['offset']+8192,length=interval['length']-8192,changed=0)]
                (private/'backup-job.pstream').write_bytes(wire(altered))
                uploads, completions = nas.upload_attempts, nas.requests.count('check_complete')
                rejected = cli('service', 'run')
                check(rejected.returncode != 0 and 'retained image plans' in rejected.stdout+rejected.stderr,
                      'changed saved interval plan was accepted: '+rejected.stdout+rejected.stderr)
                check(nas.upload_attempts == uploads and nas.requests.count('check_complete') == completions,
                      'invalid plan changed the NAS job')
                (private/'backup-job.pstream').write_bytes(wire(paused))
                process = start()
                if not nas.finished.wait(20):
                    process.terminate()
                    out, err = process.communicate(timeout=5)
                    raise AssertionError(f'resume did not finish: {nas.errors} {out} {err}')
                wait_for(lambda: value(Reader((private/'backup-job.pstream').read_bytes()))['phase']=='complete',
                         'resumed completion not durable')
                record = value(Reader((private/'backup-job.pstream').read_bytes()))
                entries = record['images'] if multi_test else [record]
                check(record['incremental']['base_version_id'] == 9 and nas.upload_attempts == 4,
                      'resume changed the base or replayed upload')
                check(entries[-1]['resume_offset'] == (2*mib if lvm_test else 1536*1024)
                      if multi_test else record['resume_offset'] == single_resume_offset,
                      'resume ignored per-image NAS checkpoint')
                check(bytes(nas.target) == image_bytes and
                      (not multi_test or bytes(nas.extra_target) == extra_image_bytes) and
                      (not lvm_test or bytes(nas.lv_target) == lv_image_bytes), 'NAS reconstruction differs')
                out, err = stop(process)
                process = None
                check(nas.requests.count('check_complete') == 2, 'completion was repeated or omitted')
                sources.verify_incremental_reads(snapshot_reads_before, expected_reads)
                if incremental_test and not lvm_test:
                    previous_record = record
                    next_primary, next_extra = bytearray(image_bytes), bytearray(extra_image_bytes)
                    next_primary[root_offset+3*mib+8192] ^= 0x41
                    next_extra[6*mib+8192] ^= 0x52
                    image_bytes, extra_image_bytes = bytes(next_primary), bytes(next_extra)
                    journal, capture = sources.capture(plan, image_bytes, extra_image_bytes)
                    capture = provide_capture(env,sources,capture,
                    dict(source_type=3,custom_volume=['/','/data']) if multi_test else dict(source_type=2))
                    nas.generation, nas.run_id, nas.result_id, nas.base_version = 3, 29, 16, 10
                    nas.image, nas.complete = image_bytes, False
                    nas.interrupted.clear()
                    nas.finished.clear()
                    process = start()
                    check(nas.finished.wait(20), f'third generation failed: {nas.errors}')
                    wait_for(lambda: value(Reader((private/'backup-job.pstream').read_bytes()))['phase']=='complete',
                             'third generation completion not durable')
                    record = value(Reader((private/'backup-job.pstream').read_bytes()))
                    check(record['schema'] == 7 and record['incremental']['base_version_id'] == 10 and
                          record['incremental']['base_result_id'] == 15 and
                          record['incremental']['base_running_task_id'] == 28 and
                          value(Reader((private/'backup-job-28-15.pstream').read_bytes())) == previous_record,
                          'third generation lost the completed incremental base')
                    check(bytes(nas.target) == image_bytes and bytes(nas.extra_target) == extra_image_bytes,
                          'third generation reconstructed wrong disks')
                    out, err = stop(process)
                    process = None
                    check(nas.requests.count('check_complete') == 3, 'third completion repeated or omitted')
                # Layout metadata changes preserve compatible origins and the
                # selected NAS base; an old local wire policy rereads its image.
                previous_record = record
                previous_generation = nas.generation
                next_plan = copy.deepcopy(plan)
                if single_incremental_test:
                    # A valid old wire policy is also an eligibility decision,
                    # while the exact same policy remains forbidden for resume.
                    previous_record = copy.deepcopy(record)
                    previous_record['schema'] = 3
                    del previous_record['unused_ranges']
                else:
                    next_plan['layout']['disk_id'] = '12345678'
                    changed_primary = bytearray(image_bytes)
                    changed_primary[440:444] = bytes.fromhex('12345678')
                    image_bytes = bytes(changed_primary)
                journal, capture = sources.capture(next_plan, image_bytes, extra_image_bytes, lv_image_bytes)
                capture = provide_capture(env,sources,capture,
                    dict(source_type=3,custom_volume=['/','/data']) if multi_test else dict(source_type=2))
                nas.base_version = 8+previous_generation
                nas.generation, nas.run_id, nas.result_id = previous_generation+1, nas.run_id+1, nas.result_id+1
                nas.image, nas.complete, nas.full_transfer = image_bytes, False, False
                nas.rewrite = single_incremental_test
                nas.interrupted.clear()
                nas.finished.clear()
                # Even when a full decision is possible, corrupted retained
                # evidence must be rejected before replacing the old journal.
                damaged = copy.deepcopy(record)
                entry = next(item for item in damaged['images'] if item['unused_ranges']) if multi_test else damaged
                entry['unused_ranges'][0]['length'] -= 512
                refused_policy(damaged, 'base unused intervals changed', initial_capture=True)
                (private/'backup-job.pstream').write_bytes(wire(previous_record))
                process = start()
                if not nas.finished.wait(20):
                    process.terminate()
                    out, err = process.communicate(timeout=5)
                    raise AssertionError(f'fresh interval transfer did not finish: {nas.errors} {out} {err}')
                wait_for(lambda: value(Reader((private/'backup-job.pstream').read_bytes()))['phase']=='complete',
                         'fresh interval completion not durable')
                full = value(Reader((private/'backup-job.pstream').read_bytes()))
                check(full['schema'] == (7 if multi_test else 9) and
                      full['incremental']['base_version_id'] == nas.base_version,
                      'fresh interval decision lost the NAS base')
                old_archive = private/f'backup-job-{previous_record["running_task_id"]}-{previous_record["result_id"]}.pstream'
                check(value(Reader(old_archive.read_bytes())) == previous_record,
                      'fresh full decision changed completed base evidence')
                out, err = stop(process)
                process = None
                check('starting a full backup' not in out, 'fresh layout change discarded compatible origins')
        if proxy:
            check(len(proxy.requests) >= len(nas.requests) > 5 and not proxy.errors, str(proxy.errors))
            check('transfer-proxy-secret' not in out+err, 'proxy credential leaked')
        check(not nas.errors, str(nas.errors))
        paced = [record for record in nas.record_timings if record["rate"]]
        check(len(paced) == (2 if progress_test else 1 if active_events_test else 0),
              "scenario left a positive rate outside its bounded witness records")
        print("computed upload timeline:",dict(records=len(nas.record_timings),
            wire_bytes=sum(record["wire_bytes"] for record in nas.record_timings),
            paced_records=paced,scheduled_us=sum(record["complete_us"] for record in paced)))
        sources.verify_reads()
        print('PASS direct snapshot service transfer/reload/restart/unused policy', options)
    finally:
        nas.release.set()
        nas.allow_drop.set()
        if process and process.poll() is None:
            process.terminate()
            process.communicate(timeout=8)
        nas.close()
        if proxy:
            proxy.close()

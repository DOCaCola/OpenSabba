"""Synthetic prepared/ready metadata plus bounded lifecycle mutations.

No auth records, devices, network access or source payloads are needed.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from test_probe import wire, check


def main():
    driver = str(Path(sys.argv[1]).resolve())
    fixture = json.loads((Path(__file__).parent /
                          "fixtures/post-restore-tracking/synthetic-reservations.json").read_text())
    before, after = fixture["prepared"], fixture["ready"]
    with tempfile.TemporaryDirectory(prefix="reservation-recovery-") as temporary:
        root = Path(temporary)

        def verify(current, expected=True, prepared=before):
            original, progressed = root/"prepared", root/"current"
            original.write_bytes(wire(prepared))
            progressed.write_bytes(wire(current))
            result = subprocess.run([driver, "verify", str(original), str(progressed)],
                                    capture_output=True, text=True, timeout=10)
            check((result.returncode == 0) == expected,
                  f"reservation result {result.returncode}: {result.stderr}")

        def each(journal):
            return [journal["reservation"], *journal["reservation"]["extras"]]

        # Old by-UUID ownership is not imported into the literal-bdev format.
        verify(after, False)
        # Reuse the synthetic topology/reservation specimen for the current format's
        # lifecycle model, without rewriting the base fixture itself.
        for specimen in (before, after):
            volumes = [specimen["plan"]["root"], *specimen["plan"]["selected_extra"]]
            for reservation, volume in zip(each(specimen), volumes):
                reservation["prior"]["durable_owner"].update(
                    format=2, device=volume["logical_path"] if "lv_uuid" in volume else volume["device"])
        verify(after)
        verify(before)
        # Same ready journal can be rechecked after process restart/publication
        # loss; no field is rewritten or silently removed from saved records.
        original_wire = wire(after)
        verify(copy.deepcopy(after))
        check(wire(after) == original_wire, "verification rewrote capture progress")
        for phase in ("snapshot-intent", "snapshot-active", "root-copy-intent",
                      "recovery-required", "aborted"):
            current = copy.deepcopy(after)
            current["phase"] = phase
            current["artifact"] = None
            for reservation in each(current):
                reservation.pop("filesystem_unused", None)
                reservation.pop("cache_unused", None)
            verify(current)
        # Acquisition persistence can precede the returned root/extra identity.
        current = copy.deepcopy(after)
        current.update(phase="snapshot-intent", snapshot=None, artifact=None)
        for reservation in each(current):
            reservation.pop("filesystem_unused", None)
            reservation.pop("cache_unused", None)
        current["reservation"]["extras"][0]["snapshot"] = None
        verify(current)
        early = copy.deepcopy(current)
        early["phase"] = "static-copied"
        early["reservation"]["snapshot_time"] = 0
        verify(early, False)
        missing = copy.deepcopy(after)
        missing["snapshot"] = None
        verify(missing, False)
        # Healthy initialized ownership renews without inventing transfer history.
        renewal_before, renewal_after = copy.deepcopy(before), copy.deepcopy(after)
        for original, progress in zip(each(renewal_before), each(renewal_after)):
            prior = original["prior"]
            saved = prior["durable_owner"]["snapshot"]
            prior["snapshot"].update(saved, active=1, unverified=0, error_code="0")
            progress["prior"] = copy.deepcopy(prior)
            progress["tracking_recovery"] = "durable-owner-renewed-without-history"
        renewal_after["snapshot"].update(
            renewal_before["reservation"]["prior"]["durable_owner"]["snapshot"])
        renewal_after["snapshot"]["sequence"] += 1
        for original, progress in zip(renewal_before["reservation"]["extras"],
                                      renewal_after["reservation"]["extras"]):
            progress["snapshot"].update(original["prior"]["durable_owner"]["snapshot"])
            progress["snapshot"]["sequence"] += 1
        verify(renewal_after, prepared=renewal_before)
        unverified_before, unverified_after = copy.deepcopy(renewal_before), copy.deepcopy(renewal_after)
        for original, progress in zip(each(unverified_before), each(unverified_after)):
            original["prior"]["snapshot"].update(
                active=0, unverified=1, error_code="-22", uuid="0"*32, sequence=0)
            progress["prior"] = copy.deepcopy(original["prior"])
        verify(unverified_after, False, unverified_before)
        for role in ("root", "extra"):
            def mutate(change, expected=False, source=after, prepared=before):
                current = copy.deepcopy(source)
                reservation = current["reservation"] if role == "root" else current["reservation"]["extras"][0]
                snapshot = current["snapshot"] if role == "root" else reservation["snapshot"]
                change(current, reservation, snapshot)
                verify(current, expected, prepared)
            for value in ("unknown", 1, "durable-owner-renewed-without-history"):
                mutate(lambda j, r, s, value=value: r.update(tracking_recovery=value))
            original_reservation = before["reservation"] if role == "root" else before["reservation"]["extras"][0]
            old_uuid = original_reservation["prior"]["durable_owner"]["snapshot"]["uuid"]
            for field, value in (("uuid", old_uuid), ("sequence", 2), ("minor", 200),
                                 ("origin_path", "/dev/foreign"), ("cow_path", "/.synosnap_data/foreign")):
                mutate(lambda j, r, s, field=field, value=value: s.update({field: value}))
            for field, value in (("changes", b"\0"), ("previous_capture_id", "a"*32),
                                 ("previous_directory", "/foreign"), ("unrecognized_progress", 1)):
                mutate(lambda j, r, s, field=field, value=value: r.update({field: value}))
            for field in ("minor", "cow_relative", "tracking_filesystem_uuid"):
                mutate(lambda j, r, s, field=field: r.update({field: 200 if field == "minor" else "foreign"}))
            mutate(lambda j, r, s: r["cow"].update(inode=99999))
            mutate(lambda j, r, s: r["prior"]["durable_owner"]["cow"].update(inode=99999))
            mutate(lambda j, r, s: r["prior"]["durable_owner"]["snapshot"].update(sequence=999))
            mutate(lambda j, r, s: r.pop("tracking_recovery"), expected=True)
            mutate(lambda j, r, s: r.update({("snapshot_attempted" if role == "root" else "attempted"): 0}))
            omitted = copy.deepcopy(after)
            if role == "root":
                omitted["snapshot"] = dict(acquisition_error=28)
                omitted["reservation"]["snapshot_released"] = 1
            else:
                omitted["reservation"]["extras"][0].update(snapshot=dict(acquisition_error=28), released=1)
            verify(omitted)
            for field, value in (("uuid", "e"*32), ("sequence", 999)):
                mutate(lambda j, r, s, field=field, value=value: s.update({field: value}),
                       source=renewal_after, prepared=renewal_before)
            mutate(lambda j, r, s: r.update(tracking_recovery="durable-owner-fresh-chain"),
                   source=renewal_after, prepared=renewal_before)
        # An otherwise ordinary capture cannot add a recovery label to bypass
        # reservation identity comparison.
        ordinary_before, ordinary_after = copy.deepcopy(before), copy.deepcopy(after)
        for original, progress in zip(each(ordinary_before), each(ordinary_after)):
            original["prior"].pop("durable_owner")
            progress["prior"].pop("durable_owner")
        verify(ordinary_after, False, ordinary_before)
    print("Synthetic reservation recovery, renewal and identity/ancestry refusals passed")


if __name__ == "__main__":
    main()

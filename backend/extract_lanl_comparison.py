
import csv
import gzip
import hashlib
import heapq
import json
from collections import defaultdict
from pathlib import Path

from extract_lanl_features import (
    AUTH_COLUMNS,
    FEATURE_COLUMNS,
    OUTPUT_COLUMNS,
    HistoricalFeatures,
    read_labelled_events,
    validate_target_record,
)
from app.services.ingestion.lanl_comparison import (
    dataset_day,
    dataset_hour,
    prior_positive_contamination_reasons,
    is_candidate_eligible,
    is_qualifying_lanl_event,
    relaxed_profile_key,
    exact_hour_profile_key,
)

DATA_DIR = Path("datasets/lanl")
AUTH_FILE = DATA_DIR / "auth.txt.gz"
TRAIN_FILE = DATA_DIR / "positive_train.csv"
TEST_FILE = DATA_DIR / "positive_test.csv"
SUMMARY_FILE = DATA_DIR / "comparison_audit.json"
CANDIDATE_CEILING_AUDIT_FILE = (
    DATA_DIR / "candidate_ceiling_audit.json"
)

SEED = 42
TRAIN_RATIO = 1
TEST_RATIOS = (10, 100, 1000)
ONE_HOUR = 3600


def percentage(numerator, denominator):
    if denominator == 0:
        return None
    return round((numerator / denominator) * 100, 6)


class CandidateCeilingAudit:
    def __init__(self, source_computers, known_relaxed_strata,
                 known_exact_strata, labelled_line_count=0):
        self.source_computers = set(source_computers)
        self.known_relaxed_strata = set(known_relaxed_strata)
        self.known_exact_strata = set(known_exact_strata)
        self.labelled_line_count = labelled_line_count

        self.records_scanned = 0
        self.raw_total = 0
        self.raw_by_source = defaultdict(int)
        self.raw_by_day = defaultdict(int)
        self.raw_by_source_and_day = defaultdict(
            lambda: defaultdict(int)
        )
        self.raw_by_result = defaultdict(int)

        self.unlabelled_total = 0
        self.unlabelled_relaxed_matches = 0
        self.unlabelled_exact_matches = 0
        self.unlabelled_by_result = defaultdict(int)

    def record(self, line_number, fields, labelled_by_line):
        self.records_scanned += 1
        timestamp = int(fields[0])

        if not is_qualifying_lanl_event(
            fields,
            self.source_computers,
        ):
            return

        day = dataset_day(timestamp)
        source = fields[3]
        result = fields[8]

        self.raw_total += 1
        self.raw_by_source[source] += 1
        self.raw_by_day[day] += 1
        self.raw_by_source_and_day[source][day] += 1
        self.raw_by_result[result] += 1

        if line_number in labelled_by_line:
            return

        self.unlabelled_total += 1
        self.unlabelled_by_result[result] += 1

        if relaxed_profile_key(fields, timestamp) in (
            self.known_relaxed_strata
        ):
            self.unlabelled_relaxed_matches += 1

        if exact_hour_profile_key(fields, timestamp) in (
            self.known_exact_strata
        ):
            self.unlabelled_exact_matches += 1

    def report(self):
        additional = (
            self.unlabelled_relaxed_matches
            - self.unlabelled_exact_matches
        )

        return {
            "status": "completed",
            "completion_scope": "candidate_discovery_pass",
            "audit_type": "four_host_candidate_ceiling",
            "source_computers": sorted(self.source_computers),
            "qualifying_profile": {
                "authentication_type": "NTLM",
                "logon_type": "Network",
                "orientation": "LogOn",
                "results": ["Success", "Fail"],
            },
            "raw_population": {
                "total": self.raw_total,
                "by_source_computer": {
                    key: self.raw_by_source[key]
                    for key in sorted(self.raw_by_source)
                },
                "by_dataset_day": {
                    str(key): self.raw_by_day[key]
                    for key in sorted(self.raw_by_day)
                },
                "by_source_computer_and_day": {
                    source: {
                        str(day): days[day]
                        for day in sorted(days)
                    }
                    for source, days in sorted(
                        self.raw_by_source_and_day.items()
                    )
                },
                "by_result": {
                    key: self.raw_by_result[key]
                    for key in ("Success", "Fail")
                    if key in self.raw_by_result
                },
            },
            "unlabelled_population": {
                "total": self.unlabelled_total,
                "same_host_day_profile_matches": (
                    self.unlabelled_relaxed_matches
                ),
                "exact_hour_strata_matches": (
                    self.unlabelled_exact_matches
                ),
                "additional_matches_without_hour_restriction": (
                    additional
                ),
                "exact_hour_match_percentage": percentage(
                    self.unlabelled_exact_matches,
                    self.unlabelled_relaxed_matches,
                ),
                "population_lost_to_hour_restriction_percentage":
                    percentage(
                        additional,
                        self.unlabelled_relaxed_matches,
                    ),
                "by_result": {
                    key: self.unlabelled_by_result[key]
                    for key in ("Success", "Fail")
                    if key in self.unlabelled_by_result
                },
            },
            "methodology": {
                "raw_counts_include_labelled_records": True,
                "unlabelled_counts_exclude_labelled_lines": True,
                "contamination_filters_applied": False,
                "sampling_applied": False,
                "timestamp_window_applied": False,
                "matching_tier_redesign_applied": False,
            },
            "dataset": str(AUTH_FILE),
            "records_scanned": self.records_scanned,
            "labelled_lines": self.labelled_line_count,
        }


def read_csv(path):
    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def matching_key(row):
    timestamp = int(row["timestamp"])

    return (
        row["source_computer"],
        dataset_day(timestamp),
        dataset_hour(timestamp),
        row["authentication_type"],
        row["logon_type"],
        row["orientation"],
        row["result"],
    )


def build_strata(rows):
    counts = defaultdict(int)

    for row in rows:
        counts[matching_key(row)] += 1

    return counts

def discover_candidate_entities(
    auth_file,
    labelled_by_line,
    candidate_keys,
    candidate_ceiling_audit=None,
):
    """
    Discover entities used by unlabelled records matching positive strata.

    This is a lightweight prepass: it stores entity IDs, not full records.
    """
    candidate_users = set()
    candidate_sources = set()
    candidate_destinations = set()

    records_scanned = 0

    print("Starting candidate entity discovery pass...")

    with gzip.open(auth_file, "rt", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            fields = line.rstrip("\r\n").split(",")

            if len(fields) != 9:
                raise ValueError(
                    f"Invalid record at line {line_number}"
                )

            records_scanned += 1
            if candidate_ceiling_audit is not None:
                candidate_ceiling_audit.record(
                    line_number,
                    fields,
                    labelled_by_line,
                )

            if records_scanned % 50_000_000 == 0:
                print(
                    f"Discovery scanned {records_scanned:,} records | "
                    f"Candidate users: {len(candidate_users):,} | "
                    f"Candidate destinations: "
                    f"{len(candidate_destinations):,}"
                )

            # Exclude every known exact or probable labelled record.
            if line_number in labelled_by_line:
                continue

            timestamp = int(fields[0])

            key = (
                fields[3],
                dataset_day(timestamp),
                dataset_hour(timestamp),
                fields[5],
                fields[6],
                fields[7],
                fields[8],
            )

            if key not in candidate_keys:
                continue

            candidate_users.add(fields[1])
            candidate_sources.add(fields[3])
            candidate_destinations.add(fields[4])

    print(
        "Candidate entity discovery complete: "
        f"{records_scanned:,} records scanned, "
        f"{len(candidate_users):,} users, "
        f"{len(candidate_sources):,} source computers, "
        f"{len(candidate_destinations):,} destination computers."
    )

    return (
        candidate_users,
        candidate_sources,
        candidate_destinations,
    )

def build_positive_history(rows):
    history = {
        "source_users": defaultdict(list),
        "source_computers": defaultdict(list),
        "destination_computers": defaultdict(list),
    }

    for row in rows:
        timestamp = int(row["timestamp"])
        history["source_users"][row["source_user"]].append(timestamp)
        history["source_computers"][row["source_computer"]].append(timestamp)
        history["destination_computers"][
            row["destination_computer"]
        ].append(timestamp)

    for entity_map in history.values():
        for timestamps in entity_map.values():
            timestamps.sort()

    return history


def stable_priority(line_number):
    value = f"{SEED}:{line_number}".encode("utf-8")
    return int(hashlib.sha256(value).hexdigest(), 16)


def add_to_reservoir(reservoir, quota, line_number, row):
    if quota <= 0:
        return

    priority = stable_priority(line_number)
    item = (-priority, -line_number, row)

    if len(reservoir) < quota:
        heapq.heappush(reservoir, item)
    elif item[:2] > reservoir[0][:2]:
        heapq.heapreplace(reservoir, item)


def ordered_reservoir(reservoir):
    return sorted(
        reservoir,
        key=lambda item: (-item[0], -item[1]),
    )


def make_control_row(line_number, fields, features):
    row = dict(zip(AUTH_COLUMNS, fields))

    row.update({
        "line_number": line_number,
        "ground_truth_label": "unlabelled_control",
        "label_confidence": "provisional",
        "matching_method": "matched_unlabelled",
        "redteam_reference_key": "",
    })

    row.update(features)
    return row


def write_controls(path, rows):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main():
    audit_temp_file = CANDIDATE_CEILING_AUDIT_FILE.with_suffix(
        ".json.tmp"
    )

    # Prevent a previous run's report from appearing current.
    CANDIDATE_CEILING_AUDIT_FILE.unlink(missing_ok=True)
    audit_temp_file.unlink(missing_ok=True)

    print("Loading labelled records and positive partitions...")

    labelled_by_line, target_users, target_sources, target_destinations = (
        read_labelled_events()
    )

    all_labels = list(labelled_by_line.values())
    train_positives = read_csv(TRAIN_FILE)
    test_positives = read_csv(TEST_FILE)

    if len(train_positives) != 598 or len(test_positives) != 104:
        raise ValueError(
            "Unexpected positive partition sizes: "
            f"train={len(train_positives)}, test={len(test_positives)}"
        )

    positive_source_computers = {
        row["source_computer"]
        for row in train_positives + test_positives
    }
    if len(positive_source_computers) != 4:
        raise ValueError(
            "Expected four unique positive source computers, "
            f"found {len(positive_source_computers)}: "
            f"{sorted(positive_source_computers)}"
        )

    train_strata = build_strata(train_positives)
    test_strata = build_strata(test_positives)
    known_exact_strata = set(train_strata) | set(test_strata)

    known_relaxed_strata = set()
    for row in train_positives + test_positives:
        timestamp = int(row["timestamp"])
        known_relaxed_strata.add((
            row["source_computer"],
            dataset_day(timestamp),
            row["authentication_type"],
            row["logon_type"],
            row["orientation"],
            row["result"],
        ))

    candidate_ceiling_audit = CandidateCeilingAudit(
        positive_source_computers,
        known_relaxed_strata,
        known_exact_strata,
        labelled_line_count=len(labelled_by_line),
    )

    # Probable labels are included in contamination checks,
    # but never treated as positive training or test examples.
    positive_history = build_positive_history(all_labels)

    same_timestamp_entities = defaultdict(
        lambda: {
            "users": set(),
            "sources": set(),
            "destinations": set(),
        }
    )

    for row in all_labels:
        timestamp = int(row["timestamp"])
        same_timestamp_entities[timestamp]["users"].add(row["source_user"])
        same_timestamp_entities[timestamp]["sources"].add(
            row["source_computer"]
        )
        same_timestamp_entities[timestamp]["destinations"].add(
            row["destination_computer"]
        )

    train_reservoirs = defaultdict(list)
    test_reservoirs = defaultdict(list)

    train_quotas = {
        key: count * TRAIN_RATIO
        for key, count in train_strata.items()
    }

    test_quotas = {
        key: count * max(TEST_RATIOS)
        for key, count in test_strata.items()
    }

    candidate_keys = set(train_quotas) | set(test_quotas)

    (
        candidate_users,
        candidate_sources,
        candidate_destinations,
    ) = discover_candidate_entities(
        AUTH_FILE,
        labelled_by_line,
        candidate_keys,
        candidate_ceiling_audit,
    )

    # Write the completed discovery audit to a temporary file first.
    with audit_temp_file.open("w", encoding="utf-8") as file:
        json.dump(candidate_ceiling_audit.report(), file, indent=2)
        file.write("\n")

    # Publish only after the temporary report has been written.
    audit_temp_file.replace(CANDIDATE_CEILING_AUDIT_FILE)

    # Track both labelled entities and entities found among candidates.
    tracked_users = target_users | candidate_users
    tracked_sources = target_sources | candidate_sources
    tracked_destinations = target_destinations | candidate_destinations

    print(
        "Expanded historical tracking sets: "
        f"{len(tracked_users):,} users, "
        f"{len(tracked_sources):,} source computers, "
        f"{len(tracked_destinations):,} destination computers."
    )

    stats = {
        "records_scanned": 0,
        "invalid_records": 0,
        "labelled_records": 0,
        "matching_candidates": 0,

        # Existing exclusive rejection counters.
        "contaminated_candidates": 0,
        "untracked_entity_candidates": 0,

        # Independent contamination counters.
        "prior_contamination_candidates": 0,
        "same_timestamp_contamination_candidates": 0,

        # Independent entity-level prior overlap counters.
        "prior_contamination_reasons": {
            "source_user": 0,
            "source_computer": 0,
            "destination_computer": 0,
        },

        # Independent same-timestamp overlap counters.
        "same_timestamp_reasons": {
            "source_user": 0,
            "source_computer": 0,
            "destination_computer": 0,
        },

        # Independent untracked-entity counters.
        "untracked_entity_reasons": {
            "source_user": 0,
            "source_computer": 0,
            "destination_computer": 0,
        },

        # Number of candidates with any untracked entity,
        # including candidates already rejected as contaminated.
        "candidates_with_untracked_entities": 0,

        "eligible_train_candidates": 0,
        "eligible_test_candidates": 0,
    }

    engine = HistoricalFeatures()
    current_timestamp = None
    pending_events = []
    pending_candidates = []
    found_labels = set()
    previous_timestamp = -1

    def process_group(timestamp, events, candidates):
        # Calculate candidate features before updating the current
        # timestamp group, preserving strictly prior-only features.
        for line_number, fields, partition, key in candidates:
            features = engine.calculate(fields, timestamp)

            row = make_control_row(line_number, fields, features)

            if partition == "train":
                stats["eligible_train_candidates"] += 1
                add_to_reservoir(
                    train_reservoirs[key],
                    train_quotas[key],
                    line_number,
                    row,
                )
            else:
                stats["eligible_test_candidates"] += 1
                add_to_reservoir(
                    test_reservoirs[key],
                    test_quotas[key],
                    line_number,
                    row,
                )

        # Update histories only after every event at this timestamp
        # has had its features calculated.
        engine.update(
            events,
            timestamp,
            tracked_users,
            tracked_sources,
            tracked_destinations,
        )

    print("Starting comparison candidate feature extraction pass...")
    print("The compressed authentication archive will be read for the second time.")

    with gzip.open(AUTH_FILE, "rt", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            fields = line.rstrip("\r\n").split(",")

            if len(fields) != 9:
                stats["invalid_records"] += 1
                raise ValueError(
                    f"Invalid record at line {line_number}"
                )

            timestamp = int(fields[0])

            if timestamp < previous_timestamp:
                raise ValueError(
                    f"Timestamp ordering violation at line {line_number}"
                )

            if current_timestamp is not None and timestamp != current_timestamp:
                process_group(
                    current_timestamp,
                    pending_events,
                    pending_candidates,
                )
                pending_events = []
                pending_candidates = []

            current_timestamp = timestamp
            previous_timestamp = timestamp
            stats["records_scanned"] += 1

            if stats["records_scanned"] % 50_000_000 == 0:
                print(
                    f"Scanned {stats['records_scanned']:,} records | "
                    f"Matched candidates: {stats['matching_candidates']:,} | "
                    f"Eligible train: {stats['eligible_train_candidates']:,} | "
                    f"Eligible test: {stats['eligible_test_candidates']:,}"
                )

            if line_number in labelled_by_line:
                validate_target_record(
                    labelled_by_line[line_number],
                    fields,
                    line_number,
                )
                found_labels.add(line_number)
                stats["labelled_records"] += 1

            # Keep history for the same entity sets used by the
            # original, already-validated feature extractor.
            relevant = (
                fields[1] in tracked_users
                or fields[3] in tracked_sources
                or fields[4] in tracked_destinations
            )

            if relevant:
                pending_events.append(fields)

            # Never use known exact or probable labelled records as controls.
            if line_number in labelled_by_line:
                continue

            key = (
                fields[3],
                dataset_day(timestamp),
                dataset_hour(timestamp),
                fields[5],
                fields[6],
                fields[7],
                fields[8],
            )

            if key in train_quotas:
                partition = "train"
            elif key in test_quotas:
                partition = "test"
            else:
                continue

            stats["matching_candidates"] += 1

            candidate = {
                "timestamp": timestamp,
                "source_user": fields[1],
                "source_computer": fields[3],
                "destination_computer": fields[4],
            }


            # --------------------------------------------------
            # DIAGNOSTIC: independently evaluate every rejection
            # reason before applying the original rejection order.
            # --------------------------------------------------

            # 1. Prior positive contamination within one hour.
            prior_reasons = prior_positive_contamination_reasons(
                candidate,
                positive_history,
                ONE_HOUR,
            )

            if prior_reasons:
                stats["prior_contamination_candidates"] += 1

                for reason in prior_reasons:
                    stats["prior_contamination_reasons"][reason] += 1

            # 2. Same-timestamp entity overlap.
            simultaneous = same_timestamp_entities.get(timestamp)
            simultaneous_reasons = []

            if simultaneous:
                if fields[1] in simultaneous["users"]:
                    simultaneous_reasons.append("source_user")

                if fields[3] in simultaneous["sources"]:
                    simultaneous_reasons.append("source_computer")

                if fields[4] in simultaneous["destinations"]:
                    simultaneous_reasons.append("destination_computer")

            if simultaneous_reasons:
                stats["same_timestamp_contamination_candidates"] += 1

                for reason in simultaneous_reasons:
                    stats["same_timestamp_reasons"][reason] += 1

            # 3. Check feature-engine entity coverage.
            untracked_reasons = []

            if fields[1] not in target_users:
                untracked_reasons.append("source_user")

            if fields[3] not in target_sources:
                untracked_reasons.append("source_computer")

            if fields[4] not in target_destinations:
                untracked_reasons.append("destination_computer")

            if untracked_reasons:
                stats["candidates_with_untracked_entities"] += 1

                for reason in untracked_reasons:
                    stats["untracked_entity_reasons"][reason] += 1

            # --------------------------------------------------
            # APPLY ORIGINAL REJECTION ORDER.
            # Candidate selection remains unchanged.
            # --------------------------------------------------

            if not is_candidate_eligible(
                prior_reasons,
                simultaneous_reasons,
                untracked_reasons,
            ):
                stats["contaminated_candidates"] += 1
                continue

            if untracked_reasons:
                stats["untracked_entity_candidates"] += 1

            pending_candidates.append(
                (line_number, fields, partition, key)
            )

        if current_timestamp is not None:
            process_group(
                current_timestamp,
                pending_events,
                pending_candidates,
            )

    missing_labels = set(labelled_by_line) - found_labels

    if missing_labels:
        raise ValueError(
            f"Missing labelled records: {len(missing_labels)}"
        )

    # Materialize the selected nested samples.
    train_rows = []
    for key, reservoir in train_reservoirs.items():
        selected = ordered_reservoir(reservoir)
        train_rows.extend(item[2] for item in selected[:train_quotas[key]])

    test_rows_by_ratio = {ratio: [] for ratio in TEST_RATIOS}

    for key, reservoir in test_reservoirs.items():
        selected = ordered_reservoir(reservoir)
        positive_count = test_strata[key]

        for ratio in TEST_RATIOS:
            quota = positive_count * ratio
            test_rows_by_ratio[ratio].extend(
                item[2] for item in selected[:quota]
            )

    write_controls(
        DATA_DIR / "comparison_controls_train.csv",
        train_rows,
    )

    for ratio, rows in test_rows_by_ratio.items():
        write_controls(
            DATA_DIR / f"comparison_controls_test_1to{ratio}.csv",
            rows,
        )

    # Record per-stratum availability and shortfalls.
    stratum_audit = []

    for partition, strata, reservoirs, quotas in (
        ("train", train_strata, train_reservoirs, train_quotas),
        ("test", test_strata, test_reservoirs, test_quotas),
    ):
        for key, positive_count in strata.items():
            selected_count = len(reservoirs.get(key, []))
            stratum_audit.append({
                "partition": partition,
                "stratum": list(key),
                "positive_count": positive_count,
                "maximum_control_quota": quotas[key],
                "eligible_selected": selected_count,
                "shortfall": max(0, quotas[key] - selected_count),
            })

    summary = {
        "seed": SEED,
        "matching_fields": [
        "source_computer",
        "dataset_day",
        "dataset_relative_hour",
        "authentication_type",
        "logon_type",
        "orientation",
        "result",
        ],
        "contamination_window_seconds": ONE_HOUR,

        "control_policy": {
            "control_label": "unlabelled_provisional_control",
            "verified_benign": False,
            "probable_labels_used_as_controls": False,
            "prior_positive_contamination": {
                "enabled": True,
                "window_seconds": ONE_HOUR,
                "entity_fields": [
                    "source_user",
                    "source_computer",
                    "destination_computer",
                ],
            },
            "same_timestamp_entity_overlap": {
                "enabled": True,
                "entity_fields": [
                    "source_user",
                    "source_computer",
                    "destination_computer",
                ],
            },
            "untracked_entity_policy": (
                "diagnostic_only_not_a_rejection_condition"
            ),
            "historical_feature_tracking": (
                "positive_and_discovered_candidate_entities"
            ),
        },
        "raw_entity_ids_used_as_model_features": False,
        "stats": stats,
        "output_counts": {
            "train_controls": len(train_rows),
            **{
                f"test_controls_1to{ratio}": len(rows)
                for ratio, rows in test_rows_by_ratio.items()
            },
        },
        "strata": stratum_audit,
    }

    with SUMMARY_FILE.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print("\n========== COMPARISON EXTRACTION COMPLETE ==========")
    print(json.dumps(stats, indent=2))
    print("\nSelected controls:")
    print(f"Training 1:1: {len(train_rows)}")

    for ratio, rows in test_rows_by_ratio.items():
        print(f"Testing 1:{ratio}: {len(rows)}")

    print(f"\nAudit summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()

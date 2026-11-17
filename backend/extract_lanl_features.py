
import csv
import gzip
from collections import defaultdict, deque
from pathlib import Path


DATA_DIR = Path("datasets/lanl")

AUTH_FILE = DATA_DIR / "auth.txt.gz"
LABEL_FILE = DATA_DIR / "labeled_events.csv"
OUTPUT_FILE = DATA_DIR / "labeled_features.csv"
PARTIAL_FILE = DATA_DIR / "labeled_features.csv.partial"

AUTH_COLUMNS = [
    "timestamp",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "authentication_type",
    "logon_type",
    "orientation",
    "result",
]

FEATURE_COLUMNS = [
    "user_auth_count_5m",
    "user_auth_count_1h",
    "user_failure_count_1h",
    "user_unique_destinations_1h",
    "source_auth_count_5m",
    "source_auth_count_1h",
    "source_failure_count_1h",
    "destination_auth_count_1h",
    "destination_unique_source_users_1h",
]

OUTPUT_COLUMNS = [
    "line_number",
    *AUTH_COLUMNS,
    "ground_truth_label",
    "label_confidence",
    "matching_method",
    "redteam_reference_key",
    *FEATURE_COLUMNS,
]

FIVE_MINUTES = 300
ONE_HOUR = 3600

EXPECTED_LABELLED_RECORDS = 716


def read_labelled_events():
    with LABEL_FILE.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    if len(rows) != EXPECTED_LABELLED_RECORDS:
        raise ValueError(
            f"Expected {EXPECTED_LABELLED_RECORDS} labelled rows, "
            f"found {len(rows)}"
        )

    target_by_line = {}

    for row in rows:
        line_number = int(row["line_number"])

        if line_number in target_by_line:
            raise ValueError(
                f"Duplicate authentication line number: {line_number}"
            )

        target_by_line[line_number] = row

    target_users = {row["source_user"] for row in rows}
    target_sources = {row["source_computer"] for row in rows}
    target_destinations = {row["destination_computer"] for row in rows}

    return target_by_line, target_users, target_sources, target_destinations


def prune_history(history, cutoff):
    while history and history[0][0] < cutoff:
        history.popleft()


class HistoricalFeatures:

    def __init__(self):
        self.user_history = defaultdict(deque)
        self.source_history = defaultdict(deque)
        self.destination_history = defaultdict(deque)

    def calculate(self, fields, timestamp):
        source_user = fields[1]
        source_computer = fields[3]
        destination_computer = fields[4]

        cutoff_1h = timestamp - ONE_HOUR
        cutoff_5m = timestamp - FIVE_MINUTES

        # User history:
        # (timestamp, destination_computer, result)
        user_events = self.user_history[source_user]
        prune_history(user_events, cutoff_1h)

        user_count_5m = sum(
            1 for event in user_events
            if event[0] >= cutoff_5m
        )

        user_count_1h = len(user_events)

        user_failures_1h = sum(
            1 for event in user_events
            if event[2].lower() in ("fail", "failure")
        )

        user_unique_destinations = len({
            event[1] for event in user_events
        })

        # Source computer history:
        # (timestamp, result)
        source_events = self.source_history[source_computer]
        prune_history(source_events, cutoff_1h)

        source_count_5m = sum(
            1 for event in source_events
            if event[0] >= cutoff_5m
        )

        source_count_1h = len(source_events)

        source_failures_1h = sum(
            1 for event in source_events
            if event[1].lower() in ("fail", "failure")
        )

        # Destination history:
        # (timestamp, source_user)
        destination_events = self.destination_history[
            destination_computer
        ]
        prune_history(destination_events, cutoff_1h)

        destination_count_1h = len(destination_events)

        destination_unique_users = len({
            event[1] for event in destination_events
        })

        return {
            "user_auth_count_5m": user_count_5m,
            "user_auth_count_1h": user_count_1h,
            "user_failure_count_1h": user_failures_1h,
            "user_unique_destinations_1h": user_unique_destinations,
            "source_auth_count_5m": source_count_5m,
            "source_auth_count_1h": source_count_1h,
            "source_failure_count_1h": source_failures_1h,
            "destination_auth_count_1h": destination_count_1h,
            "destination_unique_source_users_1h": destination_unique_users,
        }

    def update(self, events, timestamp, target_users,
               target_sources, target_destinations):

        cutoff = timestamp - ONE_HOUR

        for fields in events:
            source_user = fields[1]
            result = fields[8]
            source_computer = fields[3]
            destination_computer = fields[4]

            if source_user in target_users:
                history = self.user_history[source_user]
                prune_history(history, cutoff)
                history.append((
                    timestamp,
                    destination_computer,
                    result,
                ))

            if source_computer in target_sources:
                history = self.source_history[source_computer]
                prune_history(history, cutoff)
                history.append((
                    timestamp,
                    result,
                ))

            if destination_computer in target_destinations:
                history = self.destination_history[destination_computer]
                prune_history(history, cutoff)
                history.append((
                    timestamp,
                    source_user,
                ))


def validate_target_record(expected, actual_fields, line_number):
    for column, actual in zip(AUTH_COLUMNS, actual_fields):
        expected_value = expected[column]

        if str(expected_value) != str(actual):
            raise ValueError(
                f"Source record mismatch at line {line_number}, "
                f"field {column}: expected {expected_value!r}, "
                f"found {actual!r}"
            )


def main():
    print("Loading labelled events...")

    (
        target_by_line,
        target_users,
        target_sources,
        target_destinations,
    ) = read_labelled_events()

    print(f"Target records: {len(target_by_line)}")
    print(f"Target users: {len(target_users)}")
    print(f"Target source computers: {len(target_sources)}")
    print(f"Target destination computers: {len(target_destinations)}")

    print("\nStarting chronological feature extraction...")
    print("This reads the complete compressed authentication archive.")

    engine = HistoricalFeatures()

    processed_records = 0
    invalid_records = 0
    relevant_events = 0
    extracted_records = 0
    previous_timestamp = -1

    current_timestamp = None
    pending_events = []
    pending_targets = []
    found_target_lines = set()

    def process_timestamp_group(timestamp, events, targets, writer):
        nonlocal extracted_records

        # First calculate every target event using strictly earlier
        # timestamps. Events at the current timestamp are not included.
        for line_number, labelled_row, fields in targets:
            features = engine.calculate(fields, timestamp)

            output_row = dict(labelled_row)
            output_row.update(features)

            writer.writerow(output_row)
            extracted_records += 1

        # Only after calculating the current group do we update history.
        engine.update(
            events,
            timestamp,
            target_users,
            target_sources,
            target_destinations,
        )

    with gzip.open(AUTH_FILE, "rt", encoding="utf-8") as source:
        with PARTIAL_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as output:

            writer = csv.DictWriter(
                output,
                fieldnames=OUTPUT_COLUMNS,
            )
            writer.writeheader()

            for line_number, line in enumerate(source, start=1):
                fields = line.rstrip("\r\n").split(",")

                if len(fields) != 9:
                    invalid_records += 1
                    raise ValueError(
                        f"Invalid authentication record at line "
                        f"{line_number}: expected 9 fields, "
                        f"found {len(fields)}"
                    )

                timestamp = int(fields[0])

                if timestamp < previous_timestamp:
                    raise ValueError(
                        f"Timestamp ordering violation at line "
                        f"{line_number}: {timestamp} < "
                        f"{previous_timestamp}"
                    )

                # Flush the previous timestamp group before processing
                # events from the next timestamp.
                if current_timestamp is not None and (
                    timestamp != current_timestamp
                ):
                    process_timestamp_group(
                        current_timestamp,
                        pending_events,
                        pending_targets,
                        writer,
                    )

                    pending_events = []
                    pending_targets = []

                current_timestamp = timestamp
                previous_timestamp = timestamp
                processed_records += 1

                # Capture labelled records by their original line number.
                if line_number in target_by_line:
                    labelled_row = target_by_line[line_number]

                    validate_target_record(
                        labelled_row,
                        fields,
                        line_number,
                    )

                    pending_targets.append((
                        line_number,
                        labelled_row,
                        fields,
                    ))

                    found_target_lines.add(line_number)

                # Only retain events that contribute to a target entity's
                # historical feature calculations.
                if (
                    fields[1] in target_users
                    or fields[3] in target_sources
                    or fields[4] in target_destinations
                ):
                    pending_events.append(fields)
                    relevant_events += 1

                if processed_records % 50_000_000 == 0:
                    print(
                        f"Processed {processed_records:,} records | "
                        f"Relevant events: {relevant_events:,} | "
                        f"Features extracted: {extracted_records}"
                    )

            # Process the final timestamp group.
            if current_timestamp is not None:
                process_timestamp_group(
                    current_timestamp,
                    pending_events,
                    pending_targets,
                    writer,
                )

    missing_lines = set(target_by_line) - found_target_lines

    if missing_lines:
        raise ValueError(
            f"{len(missing_lines)} labelled records were not found. "
            f"First missing line numbers: {sorted(missing_lines)[:10]}"
        )

    if extracted_records != EXPECTED_LABELLED_RECORDS:
        raise ValueError(
            f"Expected {EXPECTED_LABELLED_RECORDS} feature rows, "
            f"found {extracted_records}"
        )

    # Publish the final output only after every validation succeeds.
    PARTIAL_FILE.replace(OUTPUT_FILE)

    print("\n========== FEATURE EXTRACTION COMPLETE ==========")
    print(f"Authentication records scanned: {processed_records:,}")
    print(f"Invalid records: {invalid_records}")
    print(f"Relevant historical events: {relevant_events:,}")
    print(f"Labelled feature rows: {extracted_records}")
    print("Timestamp ordering: Validated across complete archive")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

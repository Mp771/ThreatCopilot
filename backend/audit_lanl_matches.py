
import csv
import gzip
import json
from collections import Counter
from pathlib import Path

from app.services.ingestion.redteam_matcher import (
    build_redteam_key_set,
    parse_auth_record,
)

# --------------------------------------------------
# FILE PATHS
# --------------------------------------------------

AUTH_FILE = Path("datasets/lanl/auth.txt.gz")
REDTEAM_FILE = Path("datasets/lanl/redteam.txt.gz")
OUTPUT_DIR = Path("datasets/lanl")

MATCHED_FILE = OUTPUT_DIR / "matched_records.csv"
UNMATCHED_FILE = OUTPUT_DIR / "unmatched_reference_keys.csv"
CONTEXT_FILE = OUTPUT_DIR / "unmatched_timestamp_context.csv"
SUMMARY_FILE = OUTPUT_DIR / "lanl_match_summary.txt"
CHECKPOINT_FILE = OUTPUT_DIR / "lanl_match_counts.json"

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

KEY_COLUMNS = [
    "timestamp",
    "source_user",
    "source_computer",
    "destination_computer",
]

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# 1. LOAD REFERENCE KEYS USING TESTED MATCHER
# --------------------------------------------------

print("Loading LANL red-team reference keys...", flush=True)

with gzip.open(REDTEAM_FILE, "rt") as file:
    redteam_keys = build_redteam_key_set(file)

print("Unique reference keys:", len(redteam_keys))

# Confirm the expected key structure.
if not all(
    isinstance(value, str)
    for key in redteam_keys
    for value in key
):
    raise TypeError("Reference keys must contain strings.")

match_counts = {
    key: 0 for key in redteam_keys
}

# --------------------------------------------------
# 2. PREPARE TIMESTAMP CONTEXT WINDOW
# --------------------------------------------------

reference_timestamps = {
    int(key[0]) for key in redteam_keys
}

context_window = {
    timestamp + offset
    for timestamp in reference_timestamps
    for offset in (-1, 0, 1)
}

# Store only records near reference timestamps.
# We will filter for unmatched timestamps after the scan.
context_rows = []

# --------------------------------------------------
# 3. INITIALIZE COUNTERS
# --------------------------------------------------

total_auth_records = 0
invalid_records = 0
total_match_occurrences = 0

day_counts = Counter()
auth_type_counts = Counter()
logon_type_counts = Counter()
orientation_counts = Counter()
result_counts = Counter()

# --------------------------------------------------
# 4. ONE FULL PASS THROUGH AUTHENTICATION ARCHIVE
# --------------------------------------------------

print("\nStarting single-pass authentication scan...", flush=True)

with gzip.open(AUTH_FILE, "rt") as auth_file, \
     MATCHED_FILE.open(
         "w", newline="", encoding="utf-8"
     ) as output:

    writer = csv.DictWriter(
        output,
        fieldnames=["line_number"] + AUTH_COLUMNS,
    )
    writer.writeheader()

    for line_number, line in enumerate(auth_file, start=1):

        fields = line.strip().split(",")

        if len(fields) != 9 or not fields[0].isdigit():
            invalid_records += 1
            continue

        try:
            key = parse_auth_record(line)
        except ValueError:
            invalid_records += 1
            continue

        total_auth_records += 1

        # Progress is independent of whether a match is found.
        if total_auth_records % 50_000_000 == 0:
            print(
                f"Processed {total_auth_records:,} records | "
                f"Matches: {total_match_occurrences:,}",
                flush=True,
            )

        timestamp = int(fields[0])

        # Collect context during this same archive pass.
        if timestamp in context_window:
            context_rows.append((line_number, fields))

        # Exact reference matching.
        if key not in match_counts:
            continue

        match_counts[key] += 1
        total_match_occurrences += 1

        # Preserve the complete original authentication record.
        record = dict(zip(AUTH_COLUMNS, fields))
        record["line_number"] = line_number
        writer.writerow(record)

        # Research summaries.
        day_counts[timestamp // 86400] += 1
        auth_type_counts[fields[5]] += 1
        logon_type_counts[fields[6]] += 1
        orientation_counts[fields[7]] += 1
        result_counts[fields[8]] += 1

# --------------------------------------------------
# 5. SAVE CHECKPOINT IMMEDIATELY AFTER THE SCAN
# --------------------------------------------------

matched_keys = {
    key for key, count in match_counts.items()
    if count > 0
}

unmatched_keys = [
    key for key, count in match_counts.items()
    if count == 0
]

duplicates = {
    key: count for key, count in match_counts.items()
    if count > 1
}

checkpoint = {
    "authentication_records": total_auth_records,
    "invalid_records": invalid_records,
    "unique_reference_keys": len(redteam_keys),
    "unique_matched_keys": len(matched_keys),
    "unmatched_reference_keys": len(unmatched_keys),
    "total_match_occurrences": total_match_occurrences,
    "match_counts": {
        ",".join(key): count
        for key, count in match_counts.items()
    },
}

CHECKPOINT_FILE.write_text(
    json.dumps(checkpoint, indent=2),
    encoding="utf-8",
)

print("\nMatching checkpoint saved.", flush=True)

# --------------------------------------------------
# 6. SAVE UNMATCHED REFERENCE KEYS
# --------------------------------------------------

with UNMATCHED_FILE.open(
    "w", newline="", encoding="utf-8"
) as output:

    writer = csv.DictWriter(
        output,
        fieldnames=KEY_COLUMNS,
    )
    writer.writeheader()

    for key in sorted(
        unmatched_keys,
        key=lambda item: int(item[0]),
    ):
        writer.writerow(dict(zip(KEY_COLUMNS, key)))

# --------------------------------------------------
# 7. FILTER AND DIAGNOSE UNMATCHED TIMESTAMP CONTEXT
# --------------------------------------------------

unmatched_timestamps = {
    int(key[0]) for key in unmatched_keys
}

context_timestamps = {
    timestamp + offset
    for timestamp in unmatched_timestamps
    for offset in (-1, 0, 1)
}

context_record_count = 0
diagnostic_counts = Counter()

print("\nProcessing saved timestamp context...", flush=True)

with CONTEXT_FILE.open(
    "w", newline="", encoding="utf-8"
) as output:

    context_columns = [
        "line_number",
        *AUTH_COLUMNS,
        "candidate_reference_keys",
        "single_field_mismatch",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=context_columns,
    )
    writer.writeheader()

    for line_number, fields in context_rows:

        timestamp = int(fields[0])

        # Keep only context belonging to unmatched timestamps.
        if timestamp not in context_timestamps:
            continue

        auth_key = (
            fields[0],
            fields[1],
            fields[3],
            fields[4],
        )

        candidate_diagnostics = []

        for reference_key in unmatched_keys:

            reference_timestamp = int(reference_key[0])

            if abs(timestamp - reference_timestamp) > 1:
                continue

            equal_fields = [
                auth_key[index] == reference_key[index]
                for index in range(4)
            ]

            # Exactly one differing field.
            if sum(equal_fields) == 3:

                mismatch_index = equal_fields.index(False)
                mismatch_field = KEY_COLUMNS[mismatch_index]

                diagnostic_counts[mismatch_field] += 1

                candidate_diagnostics.append(
                    f"{','.join(reference_key)} "
                    f"[mismatch: {mismatch_field}]"
                )

        record = dict(zip(AUTH_COLUMNS, fields))
        record["line_number"] = line_number

        record["candidate_reference_keys"] = " | ".join(
            candidate_diagnostics
        )

        record["single_field_mismatch"] = " | ".join(
            sorted({
                item.split("[mismatch: ")[1].rstrip("]")
                for item in candidate_diagnostics
            })
        )

        writer.writerow(record)
        context_record_count += 1

# --------------------------------------------------
# 8. GENERATE SUMMARY
# --------------------------------------------------

def format_counter(title, counter):
    lines = [title]

    for key, count in sorted(counter.items()):
        lines.append(f"  {key}: {count}")

    return lines


report = [
    "LANL RED-TEAM MATCH AUDIT",
    "=" * 50,
    f"Authentication records: {total_auth_records:,}",
    f"Invalid authentication records: {invalid_records:,}",
    f"Unique reference keys: {len(redteam_keys)}",
    f"Unique matched keys: {len(matched_keys)}",
    f"Unmatched reference keys: {len(unmatched_keys)}",
    f"Matching occurrences: {total_match_occurrences:,}",
    f"Keys occurring more than once: {len(duplicates)}",
    f"Nearby context records saved: {context_record_count:,}",
    "",
]

report += format_counter(
    "MATCHED EVENTS BY RELATIVE DAY", day_counts
)
report += [""]

report += format_counter(
    "AUTHENTICATION TYPE", auth_type_counts
)
report += [""]

report += format_counter(
    "LOGON TYPE", logon_type_counts
)
report += [""]

report += format_counter(
    "AUTHENTICATION ORIENTATION", orientation_counts
)
report += [""]

report += format_counter(
    "AUTHENTICATION RESULT", result_counts
)
report += [""]

report += format_counter(
    "SINGLE-FIELD DIAGNOSTIC CANDIDATES",
    diagnostic_counts,
)
report += ["", "DUPLICATED MATCHING KEYS"]

for key, count in sorted(
    duplicates.items(),
    key=lambda item: int(item[0][0]),
):
    report.append(
        f"  Occurrences: {count} | Key: {key}"
    )

report += ["", "UNMATCHED REFERENCE KEYS"]

for key in sorted(
    unmatched_keys,
    key=lambda item: int(item[0]),
):
    report.append("  " + ",".join(key))

report_text = "\n".join(report)

SUMMARY_FILE.write_text(
    report_text,
    encoding="utf-8",
)

# --------------------------------------------------
# 9. FINAL RESULTS
# --------------------------------------------------

print("\n========== AUDIT COMPLETE ==========")
print(report_text)

print("\nGenerated files:")

for path in [
    MATCHED_FILE,
    UNMATCHED_FILE,
    CONTEXT_FILE,
    SUMMARY_FILE,
    CHECKPOINT_FILE,
]:
    print(f"{path}: {path.stat().st_size:,} bytes")

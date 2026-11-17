
import csv
from pathlib import Path
from collections import Counter

DATA_DIR = Path("datasets/lanl")

MATCHED_FILE = DATA_DIR / "matched_records.csv"
UNMATCHED_FILE = DATA_DIR / "unmatched_reference_keys.csv"
CONTEXT_FILE = DATA_DIR / "unmatched_timestamp_context.csv"
OUTPUT_FILE = DATA_DIR / "labeled_events.csv"

OUTPUT_COLUMNS = [
    "line_number",
    "timestamp",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "authentication_type",
    "logon_type",
    "orientation",
    "result",
    "ground_truth_label",
    "label_confidence",
    "matching_method",
    "redteam_reference_key",
]


def read_csv(path):
    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def make_reference_key(row):
    return ",".join([
        row["timestamp"],
        row["source_user"],
        row["source_computer"],
        row["destination_computer"],
    ])


def main():
    print("Loading audit files...")

    exact_records = read_csv(MATCHED_FILE)
    unmatched_references = read_csv(UNMATCHED_FILE)
    context_records = read_csv(CONTEXT_FILE)

    # Preserve every exact matching occurrence, including duplicates.
    for row in exact_records:
        row["ground_truth_label"] = "redteam_exact"
        row["label_confidence"] = "high"
        row["matching_method"] = "exact_four_field_match"
        row["redteam_reference_key"] = make_reference_key(row)

    # Build the set of reference keys that remain unmatched.
    unmatched_keys = {
        make_reference_key(row)
        for row in unmatched_references
    }

    # Select only the individually identified probable candidates.
    probable_records = []

    for row in context_records:
        candidate_text = row.get("candidate_reference_keys", "")

        if not candidate_text:
            continue

        if row.get("single_field_mismatch") != "destination_computer":
            raise ValueError(
                "Unexpected mismatch type: "
                + str(row.get("single_field_mismatch"))
            )

        reference_key = candidate_text.split(" [mismatch:", 1)[0]

        if reference_key not in unmatched_keys:
            raise ValueError(
                f"Candidate does not match an unmatched reference: {reference_key}"
            )

        probable = dict(row)
        probable["ground_truth_label"] = "redteam_probable"
        probable["label_confidence"] = "probable"
        probable["matching_method"] = (
            "same_timestamp_user_source_destination_alias_candidate"
        )
        probable["redteam_reference_key"] = reference_key

        probable_records.append(probable)

    # Validate before writing anything.
    probable_key_counts = Counter(
        row["redteam_reference_key"] for row in probable_records
    )

    if len(exact_records) != 702:
        raise ValueError(
            f"Expected 702 exact occurrences, found {len(exact_records)}"
        )

    if len(unmatched_keys) != 14:
        raise ValueError(
            f"Expected 14 unmatched references, found {len(unmatched_keys)}"
        )

    if len(probable_records) != 14:
        raise ValueError(
            f"Expected 14 probable candidates, found {len(probable_records)}"
        )

    if set(probable_key_counts) != unmatched_keys:
        raise ValueError(
            "Probable candidates do not cover all unmatched reference keys."
        )

    if any(count != 1 for count in probable_key_counts.values()):
        raise ValueError(
            "A probable reference key has multiple candidate records."
        )

    all_records = exact_records + probable_records

    # Write the labelled subset.
    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=OUTPUT_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(all_records)

    exact_keys = {
        row["redteam_reference_key"] for row in exact_records
    }

    print("\n========== LABEL BUILD COMPLETE ==========")
    print(f"Exact occurrences:       {len(exact_records)}")
    print(f"Unique exact keys:       {len(exact_keys)}")
    print(f"Probable occurrences:    {len(probable_records)}")
    print(f"Probable unique keys:    {len(probable_key_counts)}")
    print(f"Total labelled records:  {len(all_records)}")
    print(f"Unique reference keys:   {len(exact_keys | unmatched_keys)}")
    print(f"Output:                  {OUTPUT_FILE}")

    print("\nLABEL DISTRIBUTION")
    for label, count in Counter(
        row["ground_truth_label"] for row in all_records
    ).items():
        print(f"{label}: {count}")


if __name__ == "__main__":
    main()

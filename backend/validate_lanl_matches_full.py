import gzip

AUTH_FILE = "datasets/lanl/auth.txt.gz"
REDTEAM_FILE = "datasets/lanl/redteam.txt.gz"

# Load unique reference keys.
redteam_keys = set()

with gzip.open(REDTEAM_FILE, "rt") as file:
    for line in file:
        if line.strip():
            redteam_keys.add(tuple(line.strip().split(",")))

matched_keys = set()
total_auth_records = 0
total_match_occurrences = 0
invalid_records = 0

print("Unique red-team keys:", len(redteam_keys))
print("Starting full authentication archive scan...")

with gzip.open(AUTH_FILE, "rt") as file:
    for line in file:
        fields = line.strip().split(",")

        if len(fields) != 9 or not fields[0].isdigit():
            invalid_records += 1
            continue

        total_auth_records += 1

        key = (
            fields[0],
            fields[1],
            fields[3],
            fields[4],
        )

        if key in redteam_keys:
            matched_keys.add(key)
            total_match_occurrences += 1

        if total_auth_records % 50_000_000 == 0:
            print(
                f"Processed {total_auth_records:,} records | "
                f"Matches: {total_match_occurrences:,}",
                flush=True,
            )

unmatched_keys = redteam_keys - matched_keys

print("\n========== FULL VALIDATION ==========")
print("Authentication records:", f"{total_auth_records:,}")
print("Invalid records:", f"{invalid_records:,}")
print("Unique red-team reference keys:", len(redteam_keys))
print("Unique reference keys matched:", len(matched_keys))
print("Reference keys not found:", len(unmatched_keys))
print("Total matching authentication occurrences:",
      f"{total_match_occurrences:,}")

if redteam_keys:
    coverage = len(matched_keys) / len(redteam_keys) * 100
    print(f"Reference-key coverage: {coverage:.2f}%")
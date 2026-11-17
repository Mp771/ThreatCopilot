import gzip

AUTH_FILE = "datasets/lanl/auth.txt.gz"
REDTEAM_FILE = "datasets/lanl/redteam.txt.gz"

TARGET_TIMESTAMP = 150885

# Load unique red-team reference keys.
redteam_keys = set()

with gzip.open(REDTEAM_FILE, "rt") as file:
    for line in file:
        fields = line.strip().split(",")

        if len(fields) == 4:
            redteam_keys.add(tuple(fields))

print("Unique red-team reference keys:", len(redteam_keys))

# Check all authentication records at the target timestamp.
total = 0
matches = 0

with gzip.open(AUTH_FILE, "rt") as file:
    for line in file:
        fields = line.strip().split(",")

        if len(fields) != 9 or not fields[0].isdigit():
            continue

        timestamp = int(fields[0])

        if timestamp < TARGET_TIMESTAMP:
            continue

        if timestamp > TARGET_TIMESTAMP:
            break

        total += 1

        key = (
            fields[0],
            fields[1],
            fields[3],
            fields[4],
        )

        if key in redteam_keys:
            matches += 1
            print("MATCH:", line.rstrip())

print("\n--- Validation Results ---")
print("Authentication records at timestamp:", total)
print("Exact red-team matches:", matches)
print("Unmatched records:", total - matches)
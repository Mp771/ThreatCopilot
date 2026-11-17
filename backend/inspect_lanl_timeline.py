import gzip

AUTH_FILE = "datasets/lanl/auth.txt.gz"
TARGET_TIMESTAMP = 150885
RECORDS_TO_DISPLAY = 10

found = False
count = 0

with gzip.open(AUTH_FILE, "rt") as file:
    for line in file:
        fields = line.strip().split(",")

        if not fields or not fields[0].isdigit():
            continue

        timestamp = int(fields[0])

        if timestamp >= TARGET_TIMESTAMP:
            if not found:
                print("First authentication record at/after timestamp:",
                      TARGET_TIMESTAMP)
                found = True

            print(line.rstrip())
            count += 1

            if count == RECORDS_TO_DISPLAY:
                break

print("Records displayed:", count)

if not found:
    print("No matching timestamp found.")
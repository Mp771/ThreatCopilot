import gzip

path = "datasets/lanl/auth.txt.gz"

previous_timestamp = -1
records_checked = 0
out_of_order = 0

with gzip.open(path, "rt", encoding="utf-8") as file:
    for line in file:
        fields = line.rstrip().split(",")

        if len(fields) != 9:
            continue

        timestamp = int(fields[0])

        if timestamp < previous_timestamp:
            out_of_order += 1

        previous_timestamp = timestamp
        records_checked += 1

        if records_checked % 10_000_000 == 0:
            print(
                f"Checked {records_checked:,} records | "
                f"Out-of-order: {out_of_order}"
            )

        if records_checked >= 50_000_000:
            break

print("\nORDER CHECK")
print("Records checked:", records_checked)
print("Out-of-order records:", out_of_order)
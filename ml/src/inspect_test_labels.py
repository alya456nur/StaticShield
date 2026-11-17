
import json
from collections import Counter
from pathlib import Path

# EMBER dataset folder
DATASET_DIR = Path(r"C:\Users\user\Documents\DEGREE\SEM 6\CSP650\ember2018")

TEST_FILE = DATASET_DIR / "test_features.jsonl"

def inspect_test_labels():
    if not TEST_FILE.exists():
        print("ERROR: test_features.jsonl not found!")
        return

    label_counts = Counter()
    total_records = 0

    print("Inspecting EMBER test dataset...")

    with open(TEST_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            record = json.loads(line)
            label = record.get("label", "Missing")

            label_counts[label] += 1
            total_records += 1

    print("\n" + "=" * 40)
    print("EMBER TEST DATASET SUMMARY")
    print("=" * 40)

    print(f"Total records: {total_records}")

    for label, count in sorted(label_counts.items(), key=lambda x: str(x[0])):
        print(f"Label {label}: {count}")

    if 0 in label_counts and 1 in label_counts:
        print("\nTest dataset contains labelled samples.")
        print("Suitable for independent model evaluation.")

    elif -1 in label_counts:
        print("\nTest dataset contains unlabelled samples (-1).")
        print("Cannot calculate supervised evaluation metrics.")

    else:
        print("\nCheck the labels before proceeding.")


if __name__ == "__main__":
    inspect_test_labels()

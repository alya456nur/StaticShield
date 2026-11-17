
import json
from pathlib import Path

# EMBER dataset folder
DATASET_DIR = Path(r"C:\Users\user\Documents\DEGREE\SEM 6\CSP650\ember2018")

def inspect_dataset():
    print("=" * 60)
    print("EMBER 2018 DATASET INSPECTION")
    print("=" * 60)

    if not DATASET_DIR.exists():
        print(f"Dataset folder not found: {DATASET_DIR}")
        return

    # List all JSONL files
    jsonl_files = sorted(DATASET_DIR.glob("*.jsonl"))

    if not jsonl_files:
        print("No JSONL files found.")
        return

    print("\n1. FILES FOUND")

    for file_path in jsonl_files:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        print(f"- {file_path.name} ({size_mb:.2f} MB)")

    print("\n2. SAMPLE RECORD INSPECTION")

    for file_path in jsonl_files:
        print(f"\nFile: {file_path.name}")

        with file_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                try:
                    record = json.loads(line)

                    print(f"First valid record: line {line_number}")
                    print("Available fields:")
                    print(list(record.keys()))

                    print("\nLabel:", record.get("label", "Not available"))
                    print("SHA256:", record.get("sha256", "Not available"))

                    # Show feature groups without printing large arrays
                    feature_groups = [
                        "general",
                        "header",
                        "section",
                        "imports",
                        "exports",
                        "datadirectories",
                        "histogram",
                        "byteentropy",
                        "strings"
                    ]

                    print("\nFeature group availability:")

                    for group in feature_groups:
                        value = record.get(group)

                        if isinstance(value, dict):
                            description = f"Dictionary ({len(value)} fields)"
                        elif isinstance(value, list):
                            description = f"List ({len(value)} items)"
                        elif value is not None:
                            description = type(value).__name__
                        else:
                            description = "Not found"

                        print(f"- {group}: {description}")

                    break

                except json.JSONDecodeError:
                    print(f"Invalid JSON at line {line_number}")
                    break

    print("\n" + "=" * 60)
    print("INSPECTION COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    inspect_dataset()

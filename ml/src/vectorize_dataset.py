
import json
import random
from pathlib import Path

import numpy as np
from tqdm import tqdm
from ember.features import PEFeatureExtractor


# ============================================================
# CONFIGURATION
# ============================================================
# EMBER dataset folder
DATASET_DIR = Path(r"C:\Users\user\Documents\DEGREE\SEM 6\CSP650\ember2018")

# Project directories
PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_DIR = PROJECT_ROOT / "ml" / "data" / "processed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# EMBER 2018 feature version
FEATURE_VERSION = 2
EXPECTED_FEATURE_DIM = 2381

# Initial sample sizes.
# Increase these later after confirming that processing works.
MAX_TRAIN_SAMPLES = 100_000
MAX_TEST_SAMPLES = 30_000

RANDOM_STATE = 42


# ============================================================
# FIND DATASET FILES
# ============================================================

def get_dataset_files():

    train_files = sorted(
        DATASET_DIR.glob("train_features_*.jsonl")
    )

    test_file = DATASET_DIR / "test_features.jsonl"

    if not train_files:
        raise FileNotFoundError(
            "No train_features_*.jsonl files found. "
            f"Check your dataset directory: {DATASET_DIR}"
        )

    print("\nTraining files found:")

    for file in train_files:
        print(f"- {file.name}")

    if test_file.exists():
        print(f"\nTest file found: {test_file.name}")
    else:
        print("\nNo test_features.jsonl found.")

    return train_files, test_file if test_file.exists() else None


# ============================================================
# READ JSONL RECORDS
# ============================================================

def read_records(file_paths):

    for file_path in file_paths:

        with file_path.open("r", encoding="utf-8") as file:

            for line_number, line in enumerate(file, start=1):

                try:
                    record = json.loads(line)

                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Invalid JSON in {file_path.name}, "
                        f"line {line_number}"
                    ) from error

                yield record


# ============================================================
# RANDOMLY SELECT LABELLED RECORDS
# ============================================================

def select_samples(file_paths, max_samples, description):

    rng = random.Random(RANDOM_STATE)

    selected_indices = []
    total_records = 0
    labelled_records = 0

    print(f"\nSelecting {description} samples...")

    for record_index, record in enumerate(
        tqdm(read_records(file_paths), desc=description)
    ):

        total_records += 1

        label = record.get("label")

        # EMBER uses -1 for unlabeled records.
        if label not in (0, 1):
            continue

        labelled_records += 1

        # Reservoir sampling gives a random sample without
        # loading all records into memory.
        if len(selected_indices) < max_samples:

            selected_indices.append(record_index)

        else:

            replacement_index = rng.randrange(labelled_records)

            if replacement_index < max_samples:
                selected_indices[replacement_index] = record_index

    selected_indices.sort()

    print(f"\nTotal records: {total_records:,}")
    print(f"Labelled records: {labelled_records:,}")
    print(f"Selected records: {len(selected_indices):,}")

    return set(selected_indices)


# ============================================================
# CONVERT JSONL RECORDS INTO FEATURE VECTORS
# ============================================================

def vectorize_samples(
    file_paths,
    selected_indices,
    output_name,
    extractor
):

    if not selected_indices:
        print(f"\nNo labelled samples available for {output_name}.")
        return None

    sample_count = len(selected_indices)

    feature_path = OUTPUT_DIR / f"X_{output_name}.npy"
    label_path = OUTPUT_DIR / f"y_{output_name}.npy"

    # Create disk-backed NumPy arrays.
    X = np.lib.format.open_memmap(
        feature_path,
        mode="w+",
        dtype=np.float32,
        shape=(sample_count, extractor.dim)
    )

    y = np.lib.format.open_memmap(
        label_path,
        mode="w+",
        dtype=np.int8,
        shape=(sample_count,)
    )

    output_index = 0

    print(f"\nVectorising {output_name}...")

    for record_index, record in enumerate(
        tqdm(read_records(file_paths), desc=output_name)
    ):

        if record_index not in selected_indices:
            continue

        label = record.get("label")

        if label not in (0, 1):
            continue

        try:
            # Convert the existing EMBER JSONL features.
            feature_vector = extractor.process_raw_features(record)

        except Exception as error:
            raise RuntimeError(
                f"Feature conversion failed at record {record_index}"
            ) from error

        if len(feature_vector) != EXPECTED_FEATURE_DIM:
            raise ValueError(
                f"Unexpected feature dimension: {len(feature_vector)}"
            )

        X[output_index] = feature_vector
        y[output_index] = label

        output_index += 1

    X.flush()
    y.flush()

    del X
    del y

    print(f"\nSaved: {feature_path}")
    print(f"Saved: {label_path}")

    print(f"Processed samples: {output_index:,}")

    return feature_path, label_path


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("EMBER 2018 DATASET VECTORIZATION")
    print("=" * 60)

    if not DATASET_DIR.exists():
        raise FileNotFoundError(
            f"Dataset directory does not exist: {DATASET_DIR}"
        )

    # Initialise the official EMBER feature extractor.
    extractor = PEFeatureExtractor(
        feature_version=FEATURE_VERSION,
        print_feature_warning=False
    )

    print(f"\nFeature version: {FEATURE_VERSION}")
    print(f"Feature dimensions: {extractor.dim}")

    if extractor.dim != EXPECTED_FEATURE_DIM:
        raise ValueError(
            f"Expected {EXPECTED_FEATURE_DIM} features, "
            f"but received {extractor.dim}."
        )

    train_files, test_file = get_dataset_files()

    # Select a random subset of labelled training records.
    train_indices = select_samples(
        train_files,
        MAX_TRAIN_SAMPLES,
        "Training data"
    )

    vectorize_samples(
        train_files,
        train_indices,
        "train",
        extractor
    )

    # The official test file may contain unlabeled records.
    # Only labelled records can be used for supervised evaluation.
    if test_file:

        test_indices = select_samples(
            [test_file],
            MAX_TEST_SAMPLES,
            "Test data"
        )

        vectorize_samples(
            [test_file],
            test_indices,
            "test",
            extractor
        )

    print("\n" + "=" * 60)
    print("VECTORIZATION COMPLETED")
    print("=" * 60)

    print(f"\nOutput directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()

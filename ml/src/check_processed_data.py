
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "ml" / "data" / "processed"

for name in ["train", "test"]:

    X_path = DATA_DIR / f"X_{name}.npy"
    y_path = DATA_DIR / f"y_{name}.npy"

    print(f"\n{name.upper()} DATA")

    if not X_path.exists() or not y_path.exists():
        print("Files not found. This dataset split may not exist.")
        continue

    X = np.load(X_path, mmap_mode="r")
    y = np.load(y_path, mmap_mode="r")

    print("Feature shape:", X.shape)
    print("Label shape:", y.shape)
    print("Feature data type:", X.dtype)
    print("Label data type:", y.dtype)

    unique, counts = np.unique(y, return_counts=True)

    print("\nClass distribution:")

    for label, count in zip(unique, counts):
        name_label = "Benign" if label == 0 else "Malicious"
        print(f"{name_label}: {count:,}")

    print("\nFirst feature vector dimensions:", len(X[0]))

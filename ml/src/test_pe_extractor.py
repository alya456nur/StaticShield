
import numpy as np

from pathlib import Path
from ember.features import PEFeatureExtractor


# Change this to a trusted Windows executable on your computer.
TEST_FILE = Path(r"C:\Users\user\AppData\Local\Discord\Discord.exe")


def main():

    print("=" * 55)
    print("EMBER RAW PE FEATURE EXTRACTION TEST")
    print("=" * 55)

    if not TEST_FILE.exists():
        raise FileNotFoundError(
            f"Test executable not found: {TEST_FILE}"
        )

    print("\nReading executable...")

    bytez = TEST_FILE.read_bytes()

    print("File:", TEST_FILE.name)
    print("File size:", len(bytez), "bytes")

    # Check Windows PE signature
    if not bytez.startswith(b"MZ"):
        raise ValueError("File does not have a valid MZ signature.")

    print("\nInitializing EMBER feature extractor...")

    extractor = PEFeatureExtractor(
        feature_version=2,
        print_feature_warning=False
    )

    print("Expected dimensions:", extractor.dim)

    print("\nExtracting static features...")

    features = extractor.feature_vector(bytez)

    features = np.asarray(features, dtype=np.float32)

    print("\nEXTRACTION RESULTS")
    print("-" * 40)

    print("Feature shape:", features.shape)
    print("Data type:", features.dtype)
    print("All values finite:", np.isfinite(features).all())

    if features.shape != (2381,):
        raise ValueError(
            f"Expected 2381 features, got {features.shape}"
        )

    if not np.isfinite(features).all():
        raise ValueError("Feature vector contains invalid values.")

    print("\nSUCCESS!")
    print("Raw PE feature extraction is working.")


if __name__ == "__main__":
    main()

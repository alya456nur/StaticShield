
from pathlib import Path

import joblib
import numpy as np

from ember.features import PEFeatureExtractor


# Project paths
ROOT_DIR = Path(__file__).resolve().parents[2]

TEST_FILE = Path(r"C:\Users\user\AppData\Local\Discord\Discord.exe")

RF_MODEL_PATH = ROOT_DIR / "models" / "random_forest.joblib"
LGBM_MODEL_PATH = ROOT_DIR / "models" / "lightgbm.joblib"

# Selected classification thresholds
RF_THRESHOLD = 0.50
LGBM_THRESHOLD = 0.52


def main():
    print("=" * 60)
    print("EMBER PE FILE MODEL PREDICTION TEST")
    print("=" * 60)

    # Check files
    if not TEST_FILE.exists():
        raise FileNotFoundError(f"Test file not found: {TEST_FILE}")

    if not RF_MODEL_PATH.exists():
        raise FileNotFoundError(f"Random Forest model not found: {RF_MODEL_PATH}")

    if not LGBM_MODEL_PATH.exists():
        raise FileNotFoundError(f"LightGBM model not found: {LGBM_MODEL_PATH}")

    # Extract features
    print("\nReading executable...")
    bytez = TEST_FILE.read_bytes()

    if not bytez.startswith(b"MZ"):
        raise ValueError("Invalid Windows PE file signature.")

    print("File:", TEST_FILE.name)
    print("Size:", len(bytez), "bytes")

    print("\nExtracting EMBER features...")

    extractor = PEFeatureExtractor(
        feature_version=2,
        print_feature_warning=False
    )

    features = extractor.feature_vector(bytez)
    features = np.asarray(features, dtype=np.float32)

    if features.shape != (2381,):
        raise ValueError(f"Expected 2381 features, got {features.shape}")

    if not np.isfinite(features).all():
        raise ValueError("Feature vector contains invalid values.")

    # Convert to a single-row input
    X = features.reshape(1, -1)

    print("Feature shape:", X.shape)

    # Load models
    print("\nLoading trained models...")

    rf_model = joblib.load(RF_MODEL_PATH)
    lgbm_model = joblib.load(LGBM_MODEL_PATH)

    print("Random Forest loaded.")
    print("LightGBM loaded.")

    # Random Forest prediction
    print("\n" + "=" * 60)
    print("RANDOM FOREST PREDICTION")
    print("=" * 60)

    rf_probability = rf_model.predict_proba(X)[0][1]
    rf_result = (
        "MALICIOUS"
        if rf_probability >= RF_THRESHOLD
        else "BENIGN"
    )

    print(f"Malicious probability: {rf_probability:.4f}")
    print(f"Threshold: {RF_THRESHOLD:.2f}")
    print("Prediction:", rf_result)

    # LightGBM prediction
    print("\n" + "=" * 60)
    print("LIGHTGBM PREDICTION")
    print("=" * 60)

    lgbm_probability = lgbm_model.predict_proba(X)[0][1]
    lgbm_result = (
        "MALICIOUS"
        if lgbm_probability >= LGBM_THRESHOLD
        else "BENIGN"
    )

    print(f"Malicious probability: {lgbm_probability:.4f}")
    print(f"Threshold: {LGBM_THRESHOLD:.2f}")
    print("Prediction:", lgbm_result)

    print("\n" + "=" * 60)
    print("PREDICTION TEST COMPLETED")
    print("=" * 60)

    print("\nNote: These predictions are experimental.")
    print("They do not establish that the executable is safe.")


if __name__ == "__main__":
    main()

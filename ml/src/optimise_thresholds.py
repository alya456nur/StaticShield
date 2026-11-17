
import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "ml" / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "models"
RESULT_DIR = PROJECT_ROOT / "ml" / "results"

RANDOM_STATE = 42
MAX_SAMPLES = 30_000
VALIDATION_SIZE = 0.20

THRESHOLDS = np.round(
    np.arange(0.50, 0.551, 0.01), 2
)


# ============================================================
# RECONSTRUCT ORIGINAL VALIDATION DATA
# ============================================================

def load_validation_data():

    print("\nReconstructing original validation split...")

    X = np.load(DATA_DIR / "X_train.npy", mmap_mode="r")
    y = np.load(DATA_DIR / "y_train.npy", mmap_mode="r")

    all_indices = np.arange(len(y))

    sample_count = min(MAX_SAMPLES, len(y))

    if sample_count < len(y):

        selected_indices, _ = train_test_split(
            all_indices,
            train_size=sample_count,
            random_state=RANDOM_STATE,
            stratify=y
        )

    else:
        selected_indices = all_indices

    y_sample = np.asarray(
        y[selected_indices],
        dtype=np.int8
    )

    # Reconstruct the exact original validation indices.
    _, validation_indices = train_test_split(
        selected_indices,
        test_size=VALIDATION_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_sample
    )

    X_val = np.asarray(
        X[validation_indices],
        dtype=np.float32
    )

    y_val = np.asarray(
        y[validation_indices],
        dtype=np.int8
    )

    print("Validation feature shape:", X_val.shape)
    print("Validation label shape:", y_val.shape)

    print("Benign samples:", np.sum(y_val == 0))
    print("Malicious samples:", np.sum(y_val == 1))

    return X_val, y_val


# ============================================================
# EVALUATE DIFFERENT CLASSIFICATION THRESHOLDS
# ============================================================

def evaluate_thresholds(model, model_name, X_val, y_val):

    print("\n" + "=" * 65)
    print(f"{model_name.upper()} - THRESHOLD OPTIMISATION")
    print("=" * 65)

    probabilities = model.predict_proba(X_val)[:, 1]

    results = []

    for threshold in THRESHOLDS:

        predictions = (
            probabilities >= threshold
        ).astype(np.int8)

        tn, fp, fn, tp = confusion_matrix(
            y_val,
            predictions,
            labels=[0, 1]
        ).ravel()

        accuracy = accuracy_score(y_val, predictions)

        precision = precision_score(
            y_val,
            predictions,
            zero_division=0
        )

        recall = recall_score(
            y_val,
            predictions,
            zero_division=0
        )

        f1 = f1_score(
            y_val,
            predictions,
            zero_division=0
        )

        false_positive_rate = (
            fp / (fp + tn)
            if (fp + tn) > 0 else 0.0
        )

        results.append({
            "Model": model_name,
            "Threshold": threshold,
            "Accuracy": accuracy,
            "Precision": precision,
            "Recall": recall,
            "F1-score": f1,
            "False Positive Rate": false_positive_rate,
            "True Negative": int(tn),
            "False Positive": int(fp),
            "False Negative": int(fn),
            "True Positive": int(tp)
        })

    dataframe = pd.DataFrame(results)

    print(
        dataframe[
            [
                "Threshold",
                "Accuracy",
                "Precision",
                "Recall",
                "F1-score",
                "False Positive Rate"
            ]
        ].to_string(index=False, float_format="%.4f".__mod__)
    )

    return dataframe


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print("EMBER MALWARE DETECTION - THRESHOLD OPTIMISATION")
    print("=" * 65)

    X_val, y_val = load_validation_data()

    print("\nLoading trained models...")

    rf_model = joblib.load(
        MODEL_DIR / "random_forest.joblib"
    )

    lgbm_model = joblib.load(
        MODEL_DIR / "lightgbm.joblib"
    )

    rf_results = evaluate_thresholds(
        rf_model,
        "Random Forest",
        X_val,
        y_val
    )

    lgbm_results = evaluate_thresholds(
        lgbm_model,
        "LightGBM",
        X_val,
        y_val
    )

    # Combine results
    all_results = pd.concat(
        [rf_results, lgbm_results],
        ignore_index=True
    )

    output_path = (
        RESULT_DIR / "threshold_optimisation.csv"
    )

    all_results.to_csv(
        output_path,
        index=False
    )

    # Show LightGBM thresholds that maintain at least
    # 95% recall as candidates for further consideration.
    candidates = lgbm_results[
        lgbm_results["Recall"] >= 0.95
    ]

    print("\n" + "=" * 65)
    print("LIGHTGBM CANDIDATES WITH RECALL >= 95%")
    print("=" * 65)

    if candidates.empty:
        print("No tested threshold meets the recall requirement.")
    else:
        print(
            candidates[
                [
                    "Threshold",
                    "Accuracy",
                    "Precision",
                    "Recall",
                    "F1-score",
                    "False Positive Rate"
                ]
            ].to_string(
                index=False,
                float_format="%.4f".__mod__
            )
        )

    print("\nResults saved to:", output_path)

    print("\nTHRESHOLD OPTIMISATION COMPLETED")


if __name__ == "__main__":
    main()


import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "ml" / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "models"
RESULT_DIR = PROJECT_ROOT / "ml" / "results"

RESULT_DIR.mkdir(parents=True, exist_ok=True)

# Selected using validation data only
MODEL_THRESHOLDS = {
    "Random Forest": 0.50,
    "LightGBM": 0.52
}


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(name, model, threshold, X_test, y_test):

    print("\n" + "=" * 60)
    print(f"{name.upper()} - SELECTED THRESHOLD TEST EVALUATION")
    print("=" * 60)

    # Obtain probability of malicious class
    probabilities = model.predict_proba(X_test)[:, 1]

    # Apply selected classification threshold
    predictions = (
        probabilities >= threshold
    ).astype(np.int8)

    # Calculate metrics
    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test, predictions, zero_division=0
    )

    recall = recall_score(
        y_test, predictions, zero_division=0
    )

    f1 = f1_score(
        y_test, predictions, zero_division=0
    )

    roc_auc = roc_auc_score(y_test, probabilities)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ).ravel()

    false_positive_rate = fp / (fp + tn)

    results = {
        "Model": name,
        "Threshold": threshold,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-score": f1,
        "ROC-AUC": roc_auc,
        "False Positive Rate": false_positive_rate,
        "True Negative": int(tn),
        "False Positive": int(fp),
        "False Negative": int(fn),
        "True Positive": int(tp)
    }

    print(f"Selected threshold: {threshold:.2f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1:.4f}")
    print(f"ROC-AUC: {roc_auc:.4f}")
    print(f"False Positive Rate: {false_positive_rate:.4f}")

    print("\nConfusion Matrix:")
    print(f"True Negative:  {tn}")
    print(f"False Positive: {fp}")
    print(f"False Negative: {fn}")
    print(f"True Positive:  {tp}")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Benign", "Malicious"],
            zero_division=0
        )
    )

    return results


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("EMBER MALWARE DETECTION")
    print("FINAL SELECTED THRESHOLD EVALUATION")
    print("=" * 60)

    # Load independent test data
    print("\nLoading independent test dataset...")

    X_test = np.load(
        DATA_DIR / "X_test.npy",
        mmap_mode="r"
    )

    y_test = np.load(
        DATA_DIR / "y_test.npy",
        mmap_mode="r"
    )

    print("Test features:", X_test.shape)
    print("Test labels:", y_test.shape)

    if X_test.shape[1] != 2381:
        raise ValueError("Unexpected feature dimensions.")

    if len(X_test) != len(y_test):
        raise ValueError("Test feature and label counts differ.")

    # Load models
    print("\nLoading trained models...")

    models = {
        "Random Forest": joblib.load(
            MODEL_DIR / "random_forest.joblib"
        ),
        "LightGBM": joblib.load(
            MODEL_DIR / "lightgbm.joblib"
        )
    }

    results = []

    # Evaluate each model using its selected threshold
    for name, model in models.items():

        result = evaluate_model(
            name,
            model,
            MODEL_THRESHOLDS[name],
            X_test,
            y_test
        )

        results.append(result)

    # Save final comparison
    comparison = pd.DataFrame(results)

    output_path = (
        RESULT_DIR / "selected_threshold_evaluation.csv"
    )

    comparison.to_csv(output_path, index=False)

    print("\n" + "=" * 60)
    print("FINAL MODEL COMPARISON")
    print("=" * 60)

    print(comparison.to_string(index=False))

    print("\nResults saved to:", output_path)

    print("\nFINAL EVALUATION COMPLETED")


if __name__ == "__main__":
    main()

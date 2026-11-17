
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# Project directories
BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "ml" / "data" / "processed"
MODEL_DIR = BASE_DIR / "models"
RESULT_DIR = BASE_DIR / "ml" / "results"

RESULT_DIR.mkdir(parents=True, exist_ok=True)


def evaluate_model(name, model, X_test, y_test):
    print("\n" + "=" * 55)
    print(f"{name.upper()} - TEST EVALUATION")
    print("=" * 55)

    start_time = time.time()

    # Predict class labels and probabilities
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    evaluation_time = time.time() - start_time

    # Calculate evaluation metrics
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    roc_auc = roc_auc_score(y_test, probabilities)

    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    false_positive_rate = fp / (fp + tn)

    results = {
        "Model": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-score": f1,
        "ROC-AUC": roc_auc,
        "False Positive Rate": false_positive_rate,
        "True Negative": int(tn),
        "False Positive": int(fp),
        "False Negative": int(fn),
        "True Positive": int(tp),
        "Evaluation Time (seconds)": evaluation_time
    }

    print(f"Accuracy:            {accuracy:.4f}")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1-score:            {f1:.4f}")
    print(f"ROC-AUC:             {roc_auc:.4f}")
    print(f"False Positive Rate: {false_positive_rate:.4f}")

    print("\nConfusion Matrix:")
    print(f"True Negative:  {tn}")
    print(f"False Positive: {fp}")
    print(f"False Negative: {fn}")
    print(f"True Positive:  {tp}")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Benign", "Malicious"]
    ))

    print(f"Evaluation time: {evaluation_time:.2f} seconds")

    return results


def main():
    print("=" * 55)
    print("EMBER MALWARE DETECTION - FINAL TEST EVALUATION")
    print("=" * 55)

    # Load independent test data
    print("\nLoading test dataset...")

    X_test = np.load(DATA_DIR / "X_test.npy", mmap_mode="r")
    y_test = np.load(DATA_DIR / "y_test.npy", mmap_mode="r")

    print(f"Test features: {X_test.shape}")
    print(f"Test labels:   {y_test.shape}")

    if X_test.shape[1] != 2381:
        raise ValueError("Unexpected feature dimensions!")

    if len(X_test) != len(y_test):
        raise ValueError("Test features and labels do not match!")

    # Load trained models
    print("\nLoading trained models...")

    rf_model = joblib.load(MODEL_DIR / "random_forest.joblib")
    lgbm_model = joblib.load(MODEL_DIR / "lightgbm.joblib")

    # Evaluate models
    results = []

    results.append(
        evaluate_model("Random Forest", rf_model, X_test, y_test)
    )

    results.append(
        evaluate_model("LightGBM", lgbm_model, X_test, y_test)
    )

    # Save comparison
    comparison = pd.DataFrame(results)

    output_file = RESULT_DIR / "test_evaluation.csv"
    comparison.to_csv(output_file, index=False)

    print("\n" + "=" * 55)
    print("FINAL TEST MODEL COMPARISON")
    print("=" * 55)

    print(comparison.to_string(index=False))

    print(f"\nResults saved to: {output_file}")
    print("\nTEST EVALUATION COMPLETED")


if __name__ == "__main__":
    main()

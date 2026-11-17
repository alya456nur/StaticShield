
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "ml" / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "models"
RESULT_DIR = PROJECT_ROOT / "ml" / "results"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

# Start with a manageable sample for your laptop.
MAX_SAMPLES = 30_000

VALIDATION_SIZE = 0.20
EXPECTED_FEATURES = 2381


# ============================================================
# LOAD DATA
# ============================================================

def load_dataset():

    X_path = DATA_DIR / "X_train.npy"
    y_path = DATA_DIR / "y_train.npy"

    if not X_path.exists() or not y_path.exists():
        raise FileNotFoundError(
            "Processed training files not found. "
            "Run vectorize_dataset.py first."
        )

    print("Loading processed training data...")

    X = np.load(X_path, mmap_mode="r")
    y = np.load(y_path, mmap_mode="r")

    print("Original feature shape:", X.shape)
    print("Original label shape:", y.shape)

    if X.shape[0] != y.shape[0]:
        raise ValueError("Feature and label counts do not match.")

    if X.shape[1] != EXPECTED_FEATURES:
        raise ValueError(
            f"Expected {EXPECTED_FEATURES} features, "
            f"received {X.shape[1]}."
        )

    if not np.isin(y, [0, 1]).all():
        raise ValueError("Unexpected labels found. Expected only 0 and 1.")

    return X, y


# ============================================================
# SELECT A STRATIFIED SAMPLE
# ============================================================

def prepare_data(X, y):

    sample_count = min(MAX_SAMPLES, len(y))

    all_indices = np.arange(len(y))

    if sample_count < len(y):

        selected_indices, _ = train_test_split(
            all_indices,
            train_size=sample_count,
            random_state=RANDOM_STATE,
            stratify=y
        )

    else:
        selected_indices = all_indices

    X_sample = np.asarray(X[selected_indices], dtype=np.float32)
    y_sample = np.asarray(y[selected_indices], dtype=np.int8)

    X_train, X_val, y_train, y_val = train_test_split(
        X_sample,
        y_sample,
        test_size=VALIDATION_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_sample
    )

    print("\nDATA SPLIT")
    print("-" * 40)
    print("Total selected samples:", len(y_sample))
    print("Training samples:", len(y_train))
    print("Validation samples:", len(y_val))

    print("\nTraining class distribution:")
    print("Benign:", np.sum(y_train == 0))
    print("Malicious:", np.sum(y_train == 1))

    print("\nValidation class distribution:")
    print("Benign:", np.sum(y_val == 0))
    print("Malicious:", np.sum(y_val == 1))

    return X_train, X_val, y_train, y_val


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(model, X_val, y_val, model_name):

    predictions = model.predict(X_val)
    probabilities = model.predict_proba(X_val)[:, 1]

    tn, fp, fn, tp = confusion_matrix(
        y_val,
        predictions,
        labels=[0, 1]
    ).ravel()

    false_positive_rate = (
        fp / (fp + tn) if (fp + tn) > 0 else 0.0
    )

    metrics = {
        "Model": model_name,
        "Accuracy": accuracy_score(y_val, predictions),
        "Precision": precision_score(
            y_val, predictions, zero_division=0
        ),
        "Recall": recall_score(
            y_val, predictions, zero_division=0
        ),
        "F1-score": f1_score(
            y_val, predictions, zero_division=0
        ),
        "ROC-AUC": roc_auc_score(y_val, probabilities),
        "False Positive Rate": false_positive_rate,
        "True Negative": int(tn),
        "False Positive": int(fp),
        "False Negative": int(fn),
        "True Positive": int(tp)
    }

    print(f"\n{model_name} EVALUATION")
    print("=" * 50)

    for metric, value in metrics.items():

        if isinstance(value, float):
            print(f"{metric}: {value:.4f}")
        else:
            print(f"{metric}: {value}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_val,
            predictions,
            target_names=["Benign", "Malicious"],
            zero_division=0
        )
    )

    return metrics


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

def train_random_forest(X_train, y_train, X_val, y_val):

    print("\nTraining Random Forest...")
    start_time = time.time()

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    elapsed = time.time() - start_time

    print(f"Random Forest training time: {elapsed:.2f} seconds")

    model_path = MODEL_DIR / "random_forest.joblib"
    joblib.dump(model, model_path)

    print("Saved:", model_path)

    metrics = evaluate_model(
        model,
        X_val,
        y_val,
        "Random Forest"
    )

    metrics["Training Time (seconds)"] = elapsed

    return metrics


# ============================================================
# TRAIN LIGHTGBM
# ============================================================

def train_lightgbm(X_train, y_train, X_val, y_val):

    print("\nTraining LightGBM...")
    start_time = time.time()

    model = LGBMClassifier(
        objective="binary",
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbosity=-1
    )

    model.fit(X_train, y_train)

    elapsed = time.time() - start_time

    print(f"LightGBM training time: {elapsed:.2f} seconds")

    model_path = MODEL_DIR / "lightgbm.joblib"
    joblib.dump(model, model_path)

    print("Saved:", model_path)

    metrics = evaluate_model(
        model,
        X_val,
        y_val,
        "LightGBM"
    )

    metrics["Training Time (seconds)"] = elapsed

    return metrics


# ============================================================
# SAVE COMPARISON RESULTS
# ============================================================

def save_results(results):

    dataframe = pd.DataFrame(results)

    output_path = RESULT_DIR / "model_comparison.csv"

    dataframe.to_csv(output_path, index=False)

    print("\nMODEL COMPARISON")
    print("=" * 60)

    print(
        dataframe[
            [
                "Model",
                "Accuracy",
                "Precision",
                "Recall",
                "F1-score",
                "ROC-AUC",
                "False Positive Rate"
            ]
        ].to_string(index=False)
    )

    print("\nComparison saved to:", output_path)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("EMBER MALWARE DETECTION - MODEL TRAINING")
    print("=" * 60)

    X, y = load_dataset()

    X_train, X_val, y_train, y_val = prepare_data(X, y)

    results = []

    rf_results = train_random_forest(
        X_train, y_train, X_val, y_val
    )
    results.append(rf_results)

    lgbm_results = train_lightgbm(
        X_train, y_train, X_val, y_val
    )
    results.append(lgbm_results)

    save_results(results)

    # Save training configuration for reproducibility.
    configuration = {
        "random_state": RANDOM_STATE,
        "max_samples": MAX_SAMPLES,
        "validation_size": VALIDATION_SIZE,
        "feature_dimensions": EXPECTED_FEATURES,
        "feature_version": 2
    }

    with open(
        RESULT_DIR / "training_configuration.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(configuration, file, indent=4)

    print("\n" + "=" * 60)
    print("MODEL TRAINING COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()

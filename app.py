
from pathlib import Path
from datetime import datetime, timezone
import uuid

import joblib
import numpy as np

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from ember.features import PEFeatureExtractor


# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "frontend"
MODEL_DIR = ROOT_DIR / "models"

RANDOM_FOREST_PATH = MODEL_DIR / "random_forest.joblib"
LIGHTGBM_PATH = MODEL_DIR / "lightgbm.joblib"

RANDOM_FOREST_THRESHOLD = 0.50
LIGHTGBM_THRESHOLD = 0.52
MAX_FILE_SIZE = 300 * 1024 * 1024  # 300 MB

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR / "static"),
    static_url_path="/static"
)

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Load the trained model once when Flask starts.
print("Loading Random Forest model...")
random_forest_model = joblib.load(RANDOM_FOREST_PATH)
print("Random Forest loaded.")

print("Loading LightGBM model...")
lightgbm_model = joblib.load(LIGHTGBM_PATH)
print("LightGBM model loaded successfully.")

# Initialize EMBER feature extractor.
print("Initializing EMBER feature extractor...")
extractor = PEFeatureExtractor(
    feature_version=2,
    print_feature_warning=False
)
print("EMBER feature extractor ready.")


# --------------------------------------------------
# FRONTEND ROUTES
# --------------------------------------------------

ALLOWED_PAGES = {
    "index.html",
    "scan.html",
    "results.html",
    "history.html",
    "about.html"
}


@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<page>")
def frontend_pages(page):
    if page not in ALLOWED_PAGES:
        return jsonify({"error": "Page not found."}), 404

    return send_from_directory(FRONTEND_DIR, page)


def classify(model, features, threshold):
    """Return a model's independent binary prediction and probability."""
    probabilities = model.predict_proba(features)[0]
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("The loaded model does not contain malicious class label 1.")

    malicious_probability = float(probabilities[classes.index(1)])
    prediction = "Malware" if malicious_probability >= threshold else "Benign"
    confidence = (
        malicious_probability if prediction == "Malware"
        else 1.0 - malicious_probability
    )
    return {
        "prediction": prediction,
        "maliciousProbability": malicious_probability,
        "confidence": confidence,
        "threshold": threshold
    }

# --------------------------------------------------
# MALWARE SCANNING API
# --------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan_file():
    uploaded_file = request.files.get("file")
    if uploaded_file is None:
        return jsonify({"error": "No file was uploaded."}), 400

    filename = secure_filename(uploaded_file.filename or "")
    if not filename:
        return jsonify({"error": "Invalid filename."}), 400
    if not filename.lower().endswith(".exe"):
        return jsonify({"error": "Only Windows PE (.exe) files are accepted."}), 400

    try:
        # Process the upload in memory; it is not written to disk.
        bytez = uploaded_file.read(MAX_FILE_SIZE + 1)
        if not bytez:
            return jsonify({"error": "The uploaded file is empty."}), 400
        if len(bytez) > MAX_FILE_SIZE:
            return jsonify({"error": "File exceeds the 300 MB upload limit."}), 413
        if not bytez.startswith(b"MZ"):
            return jsonify({"error": "Invalid Windows executable signature."}), 400

        print(f"Extracting EMBER v2 features: {filename}")
        feature_vector = np.asarray(extractor.feature_vector(bytez), dtype=np.float32)
        if feature_vector.shape != (2381,):
            raise ValueError(
                f"Expected 2,381 EMBER features, received {feature_vector.shape}."
            )
        if not np.isfinite(feature_vector).all():
            raise ValueError("Extracted features contain invalid numeric values.")

        X = feature_vector.reshape(1, -1)

        # Both models receive exactly the same extracted feature vector.
        rf_result = classify(random_forest_model, X, RANDOM_FOREST_THRESHOLD)
        lgbm_result = classify(lightgbm_model, X, LIGHTGBM_THRESHOLD)

        agreement = rf_result["prediction"] == lgbm_result["prediction"]
        overall_prediction = (
            rf_result["prediction"] if agreement else "Disagreement"
        )

        result = {
            "id": str(uuid.uuid4()),
            "fileName": filename,
            "fileSize": len(bytez),
            "fileType": "Windows PE Executable",
            "uploadedAt": datetime.now(timezone.utc).isoformat(),
            "analysisType": "Static analysis",
            "featureVersion": 2,
            "featureCount": 2381,
            "models": {
                "randomForest": rf_result,
                "lightGBM": lgbm_result
            },
            "modelsAgree": agreement,
            "overallPrediction": overall_prediction,
            "note": (
                "The two models are reported independently; their probabilities "
                "are not averaged. A benign classification does not guarantee "
                "that a file is safe."
            )
        }

        print(
            f"Random Forest: {rf_result['prediction']} "
            f"({rf_result['maliciousProbability']:.4f})"
        )
        print(
            f"LightGBM: {lgbm_result['prediction']} "
            f"({lgbm_result['maliciousProbability']:.4f})"
        )
        return jsonify(result), 200

    except Exception:
        app.logger.exception("File scanning failed.")
        return jsonify({
            "error": (
                "File analysis failed. Check that both model files and the "
                "EMBER feature extractor are correctly installed."
            )
        }), 500


# --------------------------------------------------
# ERROR HANDLING
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "File exceeds the 300 MB upload limit."
    }), 413


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    print("\nStaticShield backend starting...")
    print("Open http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

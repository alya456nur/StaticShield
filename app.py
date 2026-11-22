
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

LIGHTGBM_PATH = MODEL_DIR / "lightgbm.joblib"

LIGHTGBM_THRESHOLD = 0.52
MAX_FILE_SIZE = 300 * 1024 * 1024  # 300 MB

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR / "static"),
    static_url_path="/static"
)

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Load the trained model once when Flask starts.
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


# --------------------------------------------------
# MALWARE SCANNING API
# --------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan_file():

    # Check uploaded file.
    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({
            "error": "No file was uploaded."
        }), 400

    filename = secure_filename(uploaded_file.filename or "")

    if not filename:
        return jsonify({
            "error": "Invalid filename."
        }), 400

    if not filename.lower().endswith(".exe"):
        return jsonify({
            "error": "Only Windows PE (.exe) files are accepted."
        }), 400

    try:
        # Read file into memory.
        bytez = uploaded_file.read()

        if not bytez:
            return jsonify({
                "error": "The uploaded file is empty."
            }), 400

        if not bytez.startswith(b"MZ"):
            return jsonify({
                "error": "Invalid Windows executable file."
            }), 400

        # Extract EMBER features.
        print(f"Scanning: {filename}")

        features = extractor.feature_vector(bytez)
        features = np.asarray(features, dtype=np.float32)

        if features.shape != (2381,):
            raise ValueError("Unexpected EMBER feature dimensions.")

        if not np.isfinite(features).all():
            raise ValueError("Invalid values detected in extracted features.")

        X = features.reshape(1, -1)

        # Obtain malicious probability.
        probabilities = lightgbm_model.predict_proba(X)[0]

        malicious_index = list(lightgbm_model.classes_).index(1)
        malicious_probability = float(probabilities[malicious_index])

        # Apply selected threshold.
        prediction = (
            "Malware"
            if malicious_probability >= LIGHTGBM_THRESHOLD
            else "Benign"
        )

        # Confidence of the predicted class.
        confidence = (
            malicious_probability
            if prediction == "Malware"
            else 1.0 - malicious_probability
        )

        # Prepare result.
        result = {
            "id": str(uuid.uuid4()),
            "fileName": filename,
            "fileSize": len(bytez),
            "fileType": "PE Executable",
            "uploadedAt": datetime.now(timezone.utc).isoformat(),
            "algorithm": "LightGBM",
            "prediction": prediction,
            "maliciousProbability": malicious_probability,
            "confidence": confidence,
            "threshold": LIGHTGBM_THRESHOLD,
            "falsePositiveNote": (
                "Experimental prediction based on EMBER 2018 v2. "
                "A benign classification does not guarantee that "
                "the file is safe."
            )
        }

        print(f"Prediction: {prediction}")
        print(f"Malicious probability: {malicious_probability:.4f}")

        return jsonify(result), 200

    except Exception as error:
        app.logger.exception("File scanning failed.")

        return jsonify({
            "error": "File analysis failed. Please check the file and try again."
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

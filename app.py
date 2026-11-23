
from pathlib import Path
from datetime import datetime, timezone
import os
import uuid

import joblib
import numpy as np
import firebase_admin

from firebase_admin import auth, storage
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

MAX_FILE_SIZE = 300 * 1024 * 1024

# Set this environment variable to your exact Firebase Storage bucket name.
FIREBASE_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET")

if not FIREBASE_STORAGE_BUCKET:
    raise RuntimeError("FIREBASE_STORAGE_BUCKET environment variable is missing.")

# Cloud Run provides its service account credentials automatically.
if not firebase_admin._apps:
    firebase_admin.initialize_app(
        options={"storageBucket": FIREBASE_STORAGE_BUCKET}
    )


# --------------------------------------------------
# FLASK APPLICATION
# --------------------------------------------------

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR / "static"),
    static_url_path="/static"
)

# The API receives only small JSON requests, not the executable itself.
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


# --------------------------------------------------
# LOAD MODELS
# --------------------------------------------------

print("Loading Random Forest model...")
random_forest_model = joblib.load(RANDOM_FOREST_PATH)
print("Random Forest loaded.")

print("Loading LightGBM model...")
lightgbm_model = joblib.load(LIGHTGBM_PATH)
print("LightGBM loaded successfully.")

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
# FIREBASE AUTHENTICATION
# --------------------------------------------------

def get_authenticated_user():
    """Verify the Firebase ID token supplied by the browser."""

    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        raise ValueError("Missing Firebase authentication token.")

    id_token = authorization.split(" ", 1)[1].strip()

    if not id_token:
        raise ValueError("Missing Firebase authentication token.")

    return auth.verify_id_token(id_token)


# --------------------------------------------------
# MODEL CLASSIFICATION
# --------------------------------------------------

def classify(model, features, threshold):
    probabilities = model.predict_proba(features)[0]
    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "The loaded model does not contain malicious class label 1."
        )

    malicious_probability = float(probabilities[classes.index(1)])

    prediction = (
        "Malware"
        if malicious_probability >= threshold
        else "Benign"
    )

    confidence = (
        malicious_probability
        if prediction == "Malware"
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

    # Authenticate the Firebase user.
    try:
        user = get_authenticated_user()
    except Exception:
        return jsonify({
            "error": "Authentication failed. Please refresh and try again."
        }), 401

    uid = user["uid"]

    data = request.get_json(silent=True) or {}

    storage_path = data.get("storagePath", "")
    original_filename = secure_filename(data.get("fileName", ""))

    if not storage_path or not original_filename:
        return jsonify({
            "error": "Missing uploaded file information."
        }), 400

    if not original_filename.lower().endswith(".exe"):
        return jsonify({
            "error": "Only Windows PE (.exe) files are accepted."
        }), 400

    # Only accept incoming/<authenticated-user-id>/<filename>.
    path_parts = storage_path.split("/")

    if (
        len(path_parts) != 3
        or path_parts[0] != "incoming"
        or path_parts[1] != uid
        or not path_parts[2]
        or path_parts[2] in {".", ".."}
    ):
        return jsonify({
            "error": "Invalid or unauthorized Storage object path."
        }), 403

    bucket = storage.bucket()
    blob = bucket.blob(storage_path)

    bytez = None

    try:
        # Confirm the uploaded object exists.
        if not blob.exists():
            return jsonify({
                "error": "Uploaded file was not found. Please upload it again."
            }), 404

        blob.reload()

        file_size = blob.size

        if file_size is None or file_size <= 0:
            return jsonify({
                "error": "The uploaded file is empty."
            }), 400

        if file_size > MAX_FILE_SIZE:
            return jsonify({
                "error": "File exceeds the 300 MB upload limit."
            }), 413

        print(f"Downloading temporary upload: {original_filename}")

        # Download privately using the Cloud Run service account.
        bytez = blob.download_as_bytes()

        if not bytez:
            return jsonify({
                "error": "The uploaded file is empty."
            }), 400

        if len(bytez) > MAX_FILE_SIZE:
            return jsonify({
                "error": "File exceeds the 300 MB upload limit."
            }), 413

        if not bytez.startswith(b"MZ"):
            return jsonify({
                "error": "Invalid Windows executable signature."
            }), 400

        # Extract EMBER v2 features.
        print(f"Extracting EMBER v2 features: {original_filename}")

        feature_vector = np.asarray(
            extractor.feature_vector(bytez),
            dtype=np.float32
        )

        if feature_vector.shape != (2381,):
            raise ValueError(
                f"Expected 2,381 EMBER features, received "
                f"{feature_vector.shape}."
            )

        if not np.isfinite(feature_vector).all():
            raise ValueError(
                "Extracted features contain invalid numeric values."
            )

        X = feature_vector.reshape(1, -1)

        # Run both models independently.
        rf_result = classify(
            random_forest_model,
            X,
            RANDOM_FOREST_THRESHOLD
        )

        lgbm_result = classify(
            lightgbm_model,
            X,
            LIGHTGBM_THRESHOLD
        )

        agreement = (
            rf_result["prediction"] == lgbm_result["prediction"]
        )

        overall_prediction = (
            rf_result["prediction"]
            if agreement
            else "Disagreement"
        )

        result = {
            "id": str(uuid.uuid4()),
            "fileName": original_filename,
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
                "The two models are reported independently; their "
                "probabilities are not averaged. A benign classification "
                "does not guarantee that a file is safe."
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
                "File analysis failed. Check the backend logs "
                "for more information."
            )
        }), 500

    finally:
        # Release the downloaded file bytes.
        bytez = None

        # Delete the temporary upload, including after analysis errors.
        try:
            blob.delete()
            print(f"Temporary upload deleted: {storage_path}")
        except Exception:
            app.logger.exception(
                "Could not delete temporary Storage object: %s",
                storage_path
            )


# --------------------------------------------------
# ERROR HANDLING
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "Request exceeds the allowed size."
    }), 413


# --------------------------------------------------
# LOCAL DEVELOPMENT
# --------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    print("\nStaticShield backend starting...")
    print(f"Listening on port {port}")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

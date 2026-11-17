# Web-Based Static Malware Detection System

A web-based static malware detection system for Windows Portable Executable (PE) files using Machine Learning algorithms and the EMBER dataset.

## About the Project

This project aims to develop a web-based malware detection system that identifies potentially malicious Windows PE files through static analysis and machine learning.

The system uses extracted static features from the EMBER dataset to train and evaluate two machine learning algorithms:

- **Random Forest**
- **LightGBM (Light Gradient Boosting Machine)**

Users will be able to upload Windows PE files through a web interface and receive a classification result indicating whether a file is **Malicious** or **Benign**, without executing the uploaded file.

The system is designed without mandatory user registration or login and uses local storage for scan-related information instead of a centralized online database.

## Project Objectives

1. To identify and prepare suitable static features from the EMBER dataset for Windows PE malware detection.
2. To develop a web-based static malware detection system integrating Random Forest and LightGBM.
3. To evaluate the functionality and detection performance of the developed system using appropriate machine learning evaluation metrics.

## Key Features

- Web-based file upload interface.
- Static analysis of Windows PE files.
- Machine learning-based malware classification.
- Integration of Random Forest and LightGBM.
- Malicious and benign classification results.
- Local storage for scan-related information.
- No mandatory login or registration.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development and machine learning |
| Flask | Web application framework |
| HTML | Web page structure |
| CSS | Interface styling |
| JavaScript | Frontend interactions |
| SQLite | Local relational database |
| Scikit-learn | Random Forest and model evaluation |
| LightGBM | Gradient boosting classification |
| EMBER Dataset | Static PE feature dataset |

## Dataset

This project uses the **EMBER (Endgame Malware BEnchmark for Research)** dataset, which contains extracted features from Windows PE files for machine learning-based malware classification.

Dataset repository: https://github.com/elastic/ember

The dataset is used for model training, testing and evaluation.

## Machine Learning Models

Two machine learning algorithms are selected for this project:

### Random Forest
An ensemble learning algorithm that combines multiple decision trees to perform classification.

### LightGBM
A gradient boosting framework that uses tree-based learning to provide efficient classification performance.

Both models will be evaluated and compared using the same evaluation dataset.

## Evaluation Metrics

The models will be evaluated using:

- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC
- Confusion Matrix
- False Positive Rate

## Project Structure

```text
MalwareDetectionSystem/
│
├── app.py
├── frontend/
│
├── ml/
│   ├── dataset/
│   │   └── ember/
│   ├── notebooks/
│   ├── src/
│   └── results/
│
├── models/
│
├── database/
│
├── uploads/
│
└── requirements.txt
```

## Project Scope

- Focuses on static malware analysis.
- Supports Windows Portable Executable (PE) files.
- Uses Random Forest and LightGBM.
- Uses the EMBER dataset for model development.
- Does not execute uploaded files for dynamic analysis.
- Does not require user login or registration.

## Disclaimer

This project is developed for academic and educational purposes as part of a Final Year Project (FYP).

It is intended as a prototype for machine learning-based static malware detection and should not be considered a replacement for professional antivirus software or comprehensive security solutions.

## Author

Developed as part of a Bachelor of Computer Science Final Year Project.

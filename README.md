# Web-Based Static Malware Detection System

A web-based static malware detection system for Windows Portable Executable (PE) files using Machine Learning algorithms and the EMBER dataset.

## About the Project

This project aims to develop a web-based malware detection system that identifies potentially malicious Windows PE files through static analysis and machine learning.

The system uses extracted static features from the EMBER dataset to train and evaluate two machine learning algorithms:

- **Random Forest**
- **LightGBM (Light Gradient Boosting Machine)**

Users will be able to upload Windows PE files through a web interface and receive a classification result indicating whether a file is **Malicious** or **Benign**, without executing the uploaded file.

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

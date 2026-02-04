![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_App-black?logo=flask)
![ML](https://img.shields.io/badge/Machine_Learning-Random_Forest-green)
![Security](https://img.shields.io/badge/Cybersecurity-Ransomware-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

Ransomware Web Detector

A Flask-based web application to detect ransomware using Machine Learning and VirusTotal analysis.

Features

File upload via web UI

VirusTotal hash-based scanning

ML-based ransomware detection (Random Forest)

Async file scanning

Clean result report (hash, detections, verdict)

Setup (Arch / Linux)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Run the App
python app.py


Train ML Model
python model.py

Tech Stack

Python

Flask

Scikit-learn

Random Forest

VirusTotal API

Notes

Configure VirusTotal API in assets/VTIsMalicious.py

ML result returns True / False for ransomware

Author

Roshan Kumar

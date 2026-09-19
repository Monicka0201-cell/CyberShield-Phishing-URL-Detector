# CyberShield – Phishing URL Detection System

## 1. Project description
CyberShield is an academic defensive cybersecurity application that analyzes a URL without opening it. It extracts structural URL features, applies transparent risk rules, calculates a risk score, and classifies the URL as **Legitimate**, **Suspicious**, or **Phishing**.

## 2. Technology stack
- Python 3.10+
- Streamlit
- pandas
- scikit-learn
- urllib.parse / ipaddress / re
- matplotlib / seaborn (optional for report generation)

## 3. Folder structure
```
CyberShield_Phishing_URL_Detector/
├── app.py
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   └── detector.py
├── data/
│   └── sample_urls.csv
├── tests/
│   └── test_urls.py
├── screenshots/
├── reports/
└── models/
```

## 4. Installation
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 5. Run
```bash
streamlit run app.py
```

## 6. Sample inputs
- `https://www.google.com`
- `https://github.com/login`
- `http://192.168.1.50/login`
- `http://example.com@198.51.100.7/login`
- `http://tinyurl.com/abc123`

## 7. Expected output
The application displays:
- Classification
- Risk score from 0–100
- Reasons for the decision
- Extracted URL features

## 8. Dataset
`data/sample_urls.csv` is a synthetic academic dataset created specifically for testing the rule-based detector. It contains labelled examples and should not be interpreted as a real-world phishing feed.

## 9. Testing
Run:
```bash
python tests/test_urls.py
```

## 10. Safety
This project is for defensive education. It analyzes URL strings and does not visit or execute suspicious links. Use only authorized datasets and lab environments.

## 11. Limitations
- Rule-based detection can produce false positives and false negatives.
- It does not inspect webpage content, DNS records, certificates, or reputation feeds.
- The synthetic dataset is not representative of the full internet.
- URL shortening is treated as a risk indicator, not proof of phishing.

## 12. Future scope
- Train a machine-learning classifier on a legally obtained labelled dataset.
- Add lexical entropy and character n-gram features.
- Add offline reputation feeds.
- Add batch CSV analysis and downloadable reports.
- Add explainable ML output.

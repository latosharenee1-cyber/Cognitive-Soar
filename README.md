# Cognitive SOAR – From Prediction to Attribution

Mini-SOAR app that (1) classifies URL features as **Benign/Malicious** using PyCaret, and
(2) if malicious, runs a **clustering** pipeline to attribute a likely actor profile
(**Organized Cybercrime**, **Hacktivist**, **State Sponsored**).

## How it works
- **train_model.py** builds two artifacts in `models/`:
  - `phishing_url_detector.pkl` (PyCaret classifier)
  - `threat_actor_profiler.joblib` (scikit-learn pipeline with K-Means + StandardScaler and a saved cluster→actor map)
- **app.py** gates attribution on the malicious verdict and shows the mapped actor profile with a short rationale.

## Quick start (Windows / PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
python train_model.py        # saves models/ files
streamlit run app.py


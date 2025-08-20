# Cognitive SOAR — From Prediction to Attribution

A lightweight triage application that upgrades simple **malicious vs. benign** detection with a second step: **threat attribution**. When a sample is malicious, the app assigns a likely actor profile (Organized Cybercrime, Hacktivist, or State Sponsored) using an unsupervised clustering pipeline. Everything runs in Streamlit and ships in a small Docker image.

## Why this matters
Binary verdicts filter noise but do not guide the next move. Pairing the verdict with a short actor profile speeds triage, clarifies handoffs, and points to the right playbook.

## Architecture at a glance
- **Detection (supervised):** Binary classifier trained with PyCaret during training; exported as a plain scikit‑learn estimator for inference.
- **Attribution (unsupervised):** scikit‑learn `Pipeline(StandardScaler → KMeans(k=3))` trained on malicious rows only; cluster id is mapped to a human label.
- **UI:** Streamlit page with two tabs — *Prediction* and *Threat Attribution*. Attribution appears only when the verdict is malicious.
- **Packaging:** Docker image for inference-time deps; reproducible local training.

## Live application (optional)
Hugging Face Space (Docker):  
https://huggingface.co/spaces/LaToshaRenee1-Cyber/Cognitive-Soar-Docker

## Quick start

### Local (inference only)
```bash
python -m venv .venv
# Windows
.\.venv\Scriptsctivate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

### Local (train + inference)
Training uses PyCaret in addition to the inference requirements.
```bash
python -m venv .venv && source .venv/bin/activate  # adapt for Windows
pip install -r requirements.txt
pip install pycaret==3.3.1

python train_model.py      # creates models/ artifacts
streamlit run app.py
```

### Docker
```bash
docker build -t cognitive-soar:prod .
docker run -p 8501:8501 cognitive-soar:prod
# open http://localhost:8501
```

## Artifacts (what each file is for)
- `models/phishing_url_detector.pkl` — PyCaret-formatted classifier saved during training (useful for local PyCaret tooling).
- `models/phishing_url_detector_sklearn.joblib` — **Classifier actually used by the app** (plain scikit‑learn; keeps the container lean).
- `models/threat_actor_profiler.joblib` — Attribution pipeline (`StandardScaler` + `KMeans(k=3)`) applied only when verdict is malicious.
- `models/cluster_mapping.txt` — Human‑readable mapping from numeric cluster id to profile name (Organized Cybercrime, Hacktivist, State Sponsored).

## How it works
The input form collects URL‑centric features (e.g., SSL present, shortener use, IP literal, political keyword, scaled length, subdomains, simple irregularity). The classifier returns a verdict and confidence. If benign, the flow ends. If malicious, the same feature vector goes through the clustering pipeline, which returns a cluster id that is mapped to a friendly profile label shown on the *Threat Attribution* tab.

## Testing
Manual test cases and screenshots live in `TESTING.md` and `figures/`:
- Benign inputs → Benign; attribution hidden.
- Malicious inputs that emphasize shortener and IP literal → Organized Cybercrime.
- Malicious inputs with political keyword → Hacktivist.
- Malicious inputs with valid SSL and cleaner structure → State Sponsored.

## Repository guide
- `app.py` — Streamlit UI; loads the sklearn classifier and clustering pipeline.
- `train_model.py` — Generates synthetic data, trains the classifier and clustering pipeline, and writes artifacts + mapping.
- `INSTALL.md` — Step‑by‑step setup for Windows/macOS/Linux and Docker.
- `TESTING.md` — Manual test plan with filenames to match figures.
- `.github/workflows/lint.yml` — Linting (flake8).

## Notes
- Keep dependency versions pinned for model compatibility across environments.
- The profiles are behavioral clusters — not attribution of identity. Treat them as leads that guide response.

## License
MIT (or your institution’s preferred license).

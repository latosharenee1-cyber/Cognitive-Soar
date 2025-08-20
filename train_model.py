"""
Train two models for Mini SOAR v2
1) A classifier for malicious vs benign
   - PyCaret workflow (to match the lecture)
   - PLUS a plain scikit-learn classifier saved with joblib for lightweight inference
2) A clustering model (scikit-learn) to attribute malicious samples to actor profiles
"""

from __future__ import annotations

import os
from typing import Dict

import joblib
import numpy as np
import pandas as pd
from pycaret.classification import (
    setup as cls_setup,
    compare_models,
    finalize_model,
    save_model,
)
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

RANDOM_STATE = 42

# One canonical list of features used everywhere
FEATURE_COLS = [
    "SSLfinal_State",
    "Prefix_Suffix",
    "Shortining_Service",
    "having_IP_Address",
    "URL_Length",
    "abnormal_URL_Structure",
    "num_subdomains",
    "has_political_keyword",
]


def generate_synthetic_data(n_each: int = 2000, include_benign: bool = True) -> pd.DataFrame:
    """
    Create synthetic samples with patterns matching three threat profiles + benign.
    Values are scaled or discrete to keep the UI simple.
    """
    rng = np.random.default_rng(RANDOM_STATE)

    def bern(p: float, size: int) -> np.ndarray:
        return rng.binomial(1, p, size)

    rows = []

    # State Sponsored
    size = n_each
    rows.append(
        pd.DataFrame(
            {
                "SSLfinal_State": bern(0.9, size),
                "Prefix_Suffix": bern(0.4, size),
                "Shortining_Service": bern(0.05, size),
                "having_IP_Address": bern(0.02, size),
                "URL_Length": rng.normal(0.65, 0.1, size),
                "abnormal_URL_Structure": rng.normal(0.25, 0.1, size),
                "num_subdomains": rng.poisson(2, size),
                "has_political_keyword": bern(0.02, size),
                "label": 1,
                "malicious_profile": "State Sponsored",
            }
        )
    )

    # Organized Cybercrime
    size = n_each
    rows.append(
        pd.DataFrame(
            {
                "SSLfinal_State": bern(0.5, size),
                "Prefix_Suffix": bern(0.6, size),
                "Shortining_Service": bern(0.7, size),
                "having_IP_Address": bern(0.4, size),
                "URL_Length": rng.normal(0.55, 0.15, size),
                "abnormal_URL_Structure": rng.normal(0.65, 0.15, size),
                "num_subdomains": rng.poisson(3, size),
                "has_political_keyword": bern(0.05, size),
                "label": 1,
                "malicious_profile": "Organized Cybercrime",
            }
        )
    )

    # Hacktivist
    size = n_each
    rows.append(
        pd.DataFrame(
            {
                "SSLfinal_State": bern(0.7, size),
                "Prefix_Suffix": bern(0.35, size),
                "Shortining_Service": bern(0.15, size),
                "having_IP_Address": bern(0.08, size),
                "URL_Length": rng.normal(0.5, 0.15, size),
                "abnormal_URL_Structure": rng.normal(0.45, 0.2, size),
                "num_subdomains": rng.poisson(1, size),
                "has_political_keyword": bern(0.35, size),
                "label": 1,
                "malicious_profile": "Hacktivist",
            }
        )
    )

    if include_benign:
        size = n_each
        rows.append(
            pd.DataFrame(
                {
                    "SSLfinal_State": bern(0.95, size),
                    "Prefix_Suffix": bern(0.05, size),
                    "Shortining_Service": bern(0.02, size),
                    "having_IP_Address": bern(0.01, size),
                    "URL_Length": rng.normal(0.45, 0.1, size),
                    "abnormal_URL_Structure": rng.normal(0.15, 0.1, size),
                    "num_subdomains": rng.poisson(1, size),
                    "has_political_keyword": bern(0.0, size),
                    "label": 0,
                    "malicious_profile": "Benign",
                }
            )
        )

    df = pd.concat(rows, ignore_index=True)
    # Clamp continuous values to [0, 1] since the UI sliders assume that range
    df["URL_Length"] = np.clip(df["URL_Length"], 0.0, 1.0)
    df["abnormal_URL_Structure"] = np.clip(df["abnormal_URL_Structure"], 0.0, 1.0)
    return df


def train_classifier_pycaret(df: pd.DataFrame, out_dir: str = "models") -> str:
    """
    PyCaret workflow (matches lecture): setup -> compare -> finalize -> save_model(base_path).
    Returns the *base path* used by PyCaret (without extension).
    """
    os.makedirs(out_dir, exist_ok=True)

    cls_setup(
        data=df[FEATURE_COLS + ["label"]],
        target="label",
        session_id=RANDOM_STATE,
        fold=5,
        train_size=0.8,
    )
    best = compare_models(include=["rf", "lr", "gbc"], n_select=1)
    final = finalize_model(best)

    base_path = os.path.join(out_dir, "phishing_url_detector")
    save_model(final, base_path)  # writes e.g. phishing_url_detector.pkl
    return base_path


def train_classifier_sklearn(df: pd.DataFrame, out_dir: str = "models") -> str:
    """
    Train and save a *plain scikit-learn* classifier to avoid PyCaret dependency at inference time.
    """
    os.makedirs(out_dir, exist_ok=True)

    X = df[FEATURE_COLS].astype(float)
    y = df["label"].astype(int)

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    )
    clf.fit(X, y)

    path = os.path.join(out_dir, "phishing_url_detector_sklearn.joblib")
    joblib.dump(clf, path)
    return path


def train_clustering(df: pd.DataFrame, out_dir: str = "models") -> str:
    """
    Fit a KMeans pipeline on malicious-only rows and persist it.
    """
    os.makedirs(out_dir, exist_ok=True)

    X = df[FEATURE_COLS].astype(float)

    pipe = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("kmeans", KMeans(n_clusters=3, n_init=20, random_state=RANDOM_STATE)),
        ]
    )
    pipe.fit(X)

    path = os.path.join(out_dir, "threat_actor_profiler.joblib")
    joblib.dump({"pipeline": pipe, "features": FEATURE_COLS, "cluster_order_hint": None}, path)
    return path


def build_cluster_label_map(df: pd.DataFrame, pipe: Pipeline) -> Dict[int, str]:
    """
    Inspect cluster centroids (in original feature space) and assign the most likely actor label.
    """
    X = df[FEATURE_COLS].astype(float)

    scaler: StandardScaler = pipe.named_steps["scaler"]
    kmeans: KMeans = pipe.named_steps["kmeans"]

    centroids = pd.DataFrame(
        scaler.inverse_transform(kmeans.cluster_centers_),
        columns=X.columns,
    )

    mapping: Dict[int, str] = {}
    for cid, c in centroids.iterrows():
        score_crime = 2 * c.Shortining_Service + 2 * c.having_IP_Address + c.abnormal_URL_Structure
        score_hackt = 2 * c.has_political_keyword + 0.5 * c.Prefix_Suffix
        score_state = 2 * c.SSLfinal_State - c.Shortining_Service - c.having_IP_Address

        best = int(np.argmax([score_crime, score_hackt, score_state]))
        if best == 0:
            mapping[cid] = "Organized Cybercrime"
        elif best == 1:
            mapping[cid] = "Hacktivist"
        else:
            mapping[cid] = "State Sponsored"

    return mapping


def main() -> None:
    out_dir = os.environ.get("MODEL_DIR", "models")
    os.makedirs(out_dir, exist_ok=True)

    # 1) Generate synthetic dataset
    df = generate_synthetic_data(n_each=2500, include_benign=True)

    # 2) Train classifier (PyCaret version to satisfy the lecture requirement)
    pycaret_base = train_classifier_pycaret(df, out_dir=out_dir)

    # 3) Train sklean-only classifier for lightweight inference in Docker/Spaces
    sk_path = train_classifier_sklearn(df, out_dir=out_dir)

    # 4) Train clustering on *malicious-only* samples
    clus_path = train_clustering(df[df["label"] == 1].copy(), out_dir=out_dir)

    # 5) Compute cluster -> actor map and store it alongside the pipeline
    payload = joblib.load(clus_path)
    mapping = build_cluster_label_map(df[df["label"] == 1], payload["pipeline"])
    payload["cluster_to_actor"] = mapping
    joblib.dump(payload, clus_path)

    # 6) Write a tiny text helper for humans
    with open(os.path.join(out_dir, "cluster_mapping.txt"), "w", encoding="utf-8") as f:
        for k, v in mapping.items():
            f.write(f"Cluster {k} => {v}\n")

    print("PyCaret classifier base path:      ", pycaret_base)
    print("Sklearn classifier saved at:       ", sk_path)
    print("Clustering pipeline saved at:      ", clus_path)
    print("Cluster mapping:                   ", mapping)


if __name__ == "__main__":
    main()
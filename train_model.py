"""
Train two models for Mini SOAR v2
1. A classifier for malicious vs benign
2. A clustering model to attribute malicious samples to actor profiles

Uses PyCaret for the classifier and scikit-learn for clustering.
"""
from __future__ import annotations

import os

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
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

RANDOM_STATE = 42


def generate_synthetic_data(n_each: int = 2000, include_benign: bool = True) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_STATE)

    def bern(p, size):
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
    df["URL_Length"] = np.clip(df["URL_Length"], 0.0, 1.0)
    df["abnormal_URL_Structure"] = np.clip(df["abnormal_URL_Structure"], 0.0, 1.0)
    return df


def train_classifier(df: pd.DataFrame, out_dir: str = "models") -> str:
    os.makedirs(out_dir, exist_ok=True)
    features = [
        "SSLfinal_State",
        "Prefix_Suffix",
        "Shortining_Service",
        "having_IP_Address",
        "URL_Length",
        "abnormal_URL_Structure",
        "num_subdomains",
        "has_political_keyword",
    ]
    cls_setup(
        data=df[features + ["label"]],
        target="label",
        session_id=RANDOM_STATE,
        fold=5,
        train_size=0.8,
    )
    best = compare_models(include=["rf", "lr", "gbc"], n_select=1)
    final = finalize_model(best)
    save_path = os.path.join(out_dir, "phishing_url_detector")
    save_model(final, save_path)
    return save_path


def train_clustering(df: pd.DataFrame, out_dir: str = "models") -> str:
    os.makedirs(out_dir, exist_ok=True)
    feature_cols = [
        "SSLfinal_State",
        "Prefix_Suffix",
        "Shortining_Service",
        "having_IP_Address",
        "URL_Length",
        "abnormal_URL_Structure",
        "num_subdomains",
        "has_political_keyword",
    ]
    X = df[feature_cols].astype(float)
    pipe = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("kmeans", KMeans(n_clusters=3, n_init=20, random_state=RANDOM_STATE)),
        ]
    )
    pipe.fit(X)
    path = os.path.join(out_dir, "threat_actor_profiler.joblib")
    joblib.dump({"pipeline": pipe, "features": feature_cols, "cluster_order_hint": None}, path)
    return path


def build_cluster_label_map(df: pd.DataFrame, pipe: Pipeline) -> dict:
    X = df[
        [
            "SSLfinal_State",
            "Prefix_Suffix",
            "Shortining_Service",
            "having_IP_Address",
            "URL_Length",
            "abnormal_URL_Structure",
            "num_subdomains",
            "has_political_keyword",
        ]
    ].astype(float)
    scaler = pipe.named_steps["scaler"]
    kmeans = pipe.named_steps["kmeans"]
    centroids = pd.DataFrame(
        scaler.inverse_transform(kmeans.cluster_centers_),
        columns=X.columns,
    )

    mapping = {}
    for cid, c in centroids.iterrows():
        score_crime = (
            2 * c.Shortining_Service
            + 2 * c.having_IP_Address
            + c.abnormal_URL_Structure
        )
        score_hackt = 2 * c.has_political_keyword + 0.5 * c.Prefix_Suffix
        score_state = (
            2 * c.SSLfinal_State
            - c.Shortining_Service
            - c.having_IP_Address
        )
        best = np.argmax([score_crime, score_hackt, score_state])
        if best == 0:
            mapping[cid] = "Organized Cybercrime"
        elif best == 1:
            mapping[cid] = "Hacktivist"
        else:
            mapping[cid] = "State Sponsored"
    return mapping


def main():
    out_dir = os.environ.get("MODEL_DIR", "models")
    os.makedirs(out_dir, exist_ok=True)
    df = generate_synthetic_data(n_each=2500, include_benign=True)
    cls_path_base = train_classifier(df, out_dir=out_dir)
    clus_path = train_clustering(df[df["label"] == 1].copy(), out_dir=out_dir)
    payload = joblib.load(clus_path)
    mapping = build_cluster_label_map(df[df["label"] == 1], payload["pipeline"])
    payload["cluster_to_actor"] = mapping
    joblib.dump(payload, clus_path)
    with open(os.path.join(out_dir, "cluster_mapping.txt"), "w", encoding="utf-8") as f:
        for k, v in mapping.items():
            f.write(f"Cluster {k} => {v}\n")
    print("Classifier saved at base:", cls_path_base)
    print("Clustering saved at:", clus_path)
    print("Cluster mapping:", mapping)


if __name__ == "__main__":
    main()

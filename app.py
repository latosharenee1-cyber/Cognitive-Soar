"""
Streamlit Mini SOAR v2
1) User enters URL features
2) Classifier predicts benign or malicious
3) If malicious, clustering pipeline predicts actor profile
"""
from __future__ import annotations

import os

import joblib
import pandas as pd
import streamlit as st
from pycaret.classification import load_model, predict_model

st.set_page_config(page_title="Cognitive SOAR", layout="wide")

MODEL_DIR = os.environ.get("MODEL_DIR", "models")
CLASSIFIER_PATH_BASE = os.path.join(MODEL_DIR, "phishing_url_detector")
CLUSTER_PATH = os.path.join(MODEL_DIR, "threat_actor_profiler.joblib")


@st.cache_resource
def _load_models():
    clf = load_model(CLASSIFIER_PATH_BASE)
    cluster_payload = joblib.load(CLUSTER_PATH)
    pipe = cluster_payload["pipeline"]
    features = cluster_payload["features"]
    mapping = cluster_payload.get("cluster_to_actor", {})
    return clf, pipe, features, mapping


# two blank lines after top-level def are required by flake8 (E305)
clf, cluster_pipe, feature_cols, cluster_map = _load_models()

st.title("Cognitive SOAR")
st.caption("From prediction to attribution with a dual model workflow")

basic_tab, attrib_tab = st.tabs(["Prediction", "Threat Attribution"])

with basic_tab:
    st.subheader("URL Feature Input")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        SSLfinal_State = st.selectbox("Valid SSL present", [0, 1], index=1)
        Prefix_Suffix = st.selectbox("Prefix Suffix pattern", [0, 1], index=0)
    with c2:
        Shortining_Service = st.selectbox("Uses URL shortener", [0, 1], index=0)
        having_IP_Address = st.selectbox("IP address literal", [0, 1], index=0)
    with c3:
        URL_Length = st.slider("Scaled URL length", 0.0, 1.0, 0.5, 0.01)
        abnormal_URL_Structure = st.slider(
            "Abnormal structure score",
            0.0,
            1.0,
            0.3,
            0.01,
        )
    with c4:
        num_subdomains = st.number_input(
            "Number of subdomains",
            min_value=0,
            max_value=10,
            value=1,
        )
        has_political_keyword = st.selectbox(
            "Contains political keyword",
            [0, 1],
            index=0,
        )

    sample = pd.DataFrame(
        [
            {
                "SSLfinal_State": int(SSLfinal_State),
                "Prefix_Suffix": int(Prefix_Suffix),
                "Shortining_Service": int(Shortining_Service),
                "having_IP_Address": int(having_IP_Address),
                "URL_Length": float(URL_Length),
                "abnormal_URL_Structure": float(abnormal_URL_Structure),
                "num_subdomains": int(num_subdomains),
                "has_political_keyword": int(has_political_keyword),
            }
        ]
    )

    st.markdown("### Step 1. Verdict")
    if st.button("Analyze URL", type="primary"):
        pred = predict_model(clf, data=sample.copy())

        if "prediction_label" in pred:
            label = int(pred.loc[0, "prediction_label"])
        else:
            label = int(pred.loc[0, "Label"])

        if "predict

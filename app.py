"""
Streamlit Mini SOAR v2
1) User enters URL features
2) Classifier predicts benign or malicious
3) If malicious, clustering pipeline predicts actor profile
"""
from __future__ import annotations

import math
import os
import joblib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Cognitive SOAR", layout="wide")

MODEL_DIR = os.environ.get("MODEL_DIR", "models")
CLASSIFIER_PATH = os.path.join(MODEL_DIR, "phishing_url_detector_sklearn.joblib")
CLUSTER_PATH = os.path.join(MODEL_DIR, "threat_actor_profiler.joblib")

@st.cache_resource
def _load_models():
    clf = joblib.load(CLASSIFIER_PATH)
    payload = joblib.load(CLUSTER_PATH)
    return clf, payload["pipeline"], payload["features"], payload.get("cluster_to_actor", {})

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
        abnormal_URL_Structure = st.slider("Abnormal structure score", 0.0, 1.0, 0.3, 0.01)
    with c4:
        num_subdomains = st.number_input("Number of subdomains", min_value=0, max_value=10, value=1)
        has_political_keyword = st.selectbox("Contains political keyword", [0, 1], index=0)

    sample = pd.DataFrame([{
        "SSLfinal_State": int(SSLfinal_State),
        "Prefix_Suffix": int(Prefix_Suffix),
        "Shortining_Service": int(Shortining_Service),
        "having_IP_Address": int(having_IP_Address),
        "URL_Length": float(URL_Length),
        "abnormal_URL_Structure": float(abnormal_URL_Structure),
        "num_subdomains": int(num_subdomains),
        "has_political_keyword": int(has_political_keyword),
    }])

    st.markdown("### Step 1. Verdict")
    if st.button("Analyze URL", type="primary"):
        X = sample[feature_cols] if set(feature_cols).issubset(sample.columns) else sample
        if hasattr(clf, "predict_proba"):
            prob = float(clf.predict_proba(X)[0, 1])
        elif hasattr(clf, "decision_function"):
            raw = float(clf.decision_function(X)[0])
            prob = 1.0 / (1.0 + math.exp(-raw))
        else:
            label_only = int(clf.predict(X)[0])
            prob = 0.7 if label_only == 1 else 0.3
        label = 1 if prob >= 0.5 else 0

        if label == 1:
            st.success(f"Verdict: MALICIOUS  (confidence {prob:.2f})")
            st.session_state["last_verdict_malicious"] = True
            st.session_state["last_sample"] = sample
        else:
            st.info(f"Verdict: BENIGN  (confidence {1.0 - prob:.2f})")
            st.session_state["last_verdict_malicious"] = False
            st.session_state["last_sample"] = sample

with attrib_tab:
    st.subheader("Actor profile attribution")
    if st.session_state.get("last_verdict_malicious") and st.session_state.get("last_sample") is not None:
        X = st.session_state["last_sample"][feature_cols]
        cluster_id = int(cluster_pipe.predict(X)[0])
        actor = cluster_map.get(cluster_id, f"Cluster {cluster_id}")
        st.metric("Predicted actor profile", actor)
        with st.expander("Why this profile", expanded=True):
            st.write(
                """
**Organized Cybercrime**
High volume/noisy; often shorteners & sometimes IP literals. Structure tricks and drive-by monetization.

**Hacktivist**
Opportunistic; political language may appear. Mixed tactics, moderate structure anomalies.

**State Sponsored**
Higher sophistication; valid SSL, subtle, low use of shorteners/IP literals. Patient and well-resourced.
                """
            )
        st.code(f"Cluster id: {cluster_id}  ->  {actor}")
    else:
        st.info("Run a prediction first. Attribution is only shown for malicious results.")

st.sidebar.header("About")
st.sidebar.write("Classifier (sklearn) + clustering pipeline for actor attribution.")
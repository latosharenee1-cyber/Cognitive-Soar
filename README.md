# Cognitive SOAR

From prediction to attribution. This upgrade adds an enrichment step to the
Mini SOAR lecture app by pairing a supervised detector with an unsupervised
profiler for likely actor attribution.

## What it does
- Predicts malicious vs benign from URL features using a PyCaret classifier
- If malicious, predicts a likely actor profile using a K Means pipeline
- Presents results in Streamlit with a Threat Attribution tab

## Quickstart
```bash
make install
make train
make run
```

Or with Docker:
```bash
make docker-up
```

Open http://localhost:8501

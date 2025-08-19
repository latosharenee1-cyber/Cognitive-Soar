\# Manual test notes



Purpose: quick steps to reproduce four cases and match screenshots.



\## How to run

1\. `streamlit run app.py`

2\. Open http://localhost:8501

3\. Enter values below → Analyze URL

4\. If verdict is MALICIOUS, open Threat Attribution tab



\## Test 1 — Benign

Values: SSL 1, Prefix/Suffix 0, Shortener 0, IP 0, URL length ~0.45, Abnormal ~0.15, Subdomains 1, Political 0  

Expected: BENIGN (no attribution)  

Screens: `figures/Set04\_Tests\_01\_Benign\_Inputs - 7.png`, `figures/Set04\_Tests\_02\_Benign\_Results - 8.png`



\## Test 2 — Organized Cybercrime

Values: SSL 0, Prefix/Suffix 1, Shortener 1, IP 1, URL length ~0.55, Abnormal ~0.65, Subdomains 3, Political 0  

Expected: MALICIOUS → Organized Cybercrime  

Screens: `figures/Set04\_Tests\_03\_Crime\_Inputs - 9.png`, `figures/Set04\_Tests\_04\_Crime\_Result - 10.png`, `figures/Set04\_Tests\_04b\_Crime\_Attribution - 11.png`



\## Test 3 — Hacktivist

Values: SSL 1, Prefix/Suffix 0, Shortener 0, IP 0, URL length ~0.50, Abnormal ~0.45, Subdomains 1, Political 1  

Expected: MALICIOUS → Hacktivist  

Screens: `figures/Set04\_Tests\_05\_Hacktivist\_Inputs - 12.png`, `figures/Set04\_Tests\_06\_Hacktivist\_Result - 13.png`, `figures/Set04\_Tests\_06b\_Hacktivist\_Attribution - 14.png`



\## Test 4 — State Sponsored

Values: SSL 1, Prefix/Suffix 1, Shortener 0, IP 0, URL length ~0.65, Abnormal ~0.25, Subdomains 2, Political 0  

Expected: MALICIOUS → State Sponsored  

Screens: `figures/Set04\_Tests\_07\_State\_Inputs - 15.png`, `figures/Set04\_Tests\_08\_State\_Result - 16.png`, `figures/Set04\_Tests\_08b\_State\_Attribution - 17.png`



Notes: Confidence varies; check the verdict and actor label. “~” means slider set close to that number.




# From Prediction to Attribution: Integrating Unsupervised Learning for Enhanced SOAR Triage

Security teams receive many binary alerts. Malicious or benign. This helps but does not answer who might be behind the alert. A likely actor profile changes the response path and the urgency.

This project adds an attribution step to a Mini SOAR app. A supervised model still delivers a detection verdict. When the verdict is malicious a second model offers a likely actor profile drawn from clusters in feature space.

## Methodology

### Feature engineering
Three malicious profiles are represented along with a benign class.
State Sponsored shows higher sophistication. Valid SSL is common. Shorteners and IP literals are rare. Organized Cybercrime is noisy. Shorteners are common. IP literals appear often. Abnormal structure scores are high. Hacktivist activity is opportunistic. Political keywords appear. The benign class looks clean with valid SSL and simple structure.

### Algorithm selection
Two tasks means two models. Supervised detection uses PyCaret for a strong baseline. The unsupervised step uses K Means with three clusters. K Means fits this dataset because the data generation creates three compact and balanced groups. Alternatives like DBSCAN focus on irregular shapes and noise. Gaussian Mixtures add complexity without clear gain here.

### Implementation
The training script builds both models. It generates synthetic samples, trains the classifier, then trains a K Means pipeline on malicious samples only. After training it inspects centroids to map numeric cluster ids to human labels. The Streamlit app loads both artifacts and shows the actor profile in a Threat Attribution tab only when the verdict is malicious.

## Results and discussion
On synthetic tests the classifier separates benign and malicious with high confidence. The clustering step yields three stable groups that align with the intended profiles. Context can shorten the loop from alert to action. Crime like patterns route to takedown and fraud workflows. State like patterns route to advanced response.

Attribution is a likelihood. In a real setting the pipeline needs calibration with curated examples and regular evaluation.

## Conclusion
Moving from detection to attribution increases the value of a SOAR pipeline. This approach adds that enrichment with small code and common libraries.

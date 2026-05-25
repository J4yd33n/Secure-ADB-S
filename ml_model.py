from sklearn.ensemble import IsolationForest
import numpy as np

# Simple anomaly scoring function
def anomaly_score(features):
    model = IsolationForest(contamination=0.1)
    features = np.array(features).reshape(1, -1)
    model.fit(np.random.rand(100, len(features[0])))
    score = -model.decision_function(features)[0]  # higher = more anomalous
    return min(max(score, 0), 1)  # keep score between 0 and 1

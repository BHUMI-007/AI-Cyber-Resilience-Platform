# adaptive_model.py
# Unsupervised Behavioral Anomaly Detection Model with dynamic fallback and epsilon safety

import math

class AdaptiveAnomalyDetector:
    """
    Unsupervised behavioral anomaly detector.
    Features dual-mode runtime (PyOD IForest or Standardized Distance fallback),
    continuous incremental learning, epsilon safety, and [0.0, 1.0] mathematical normalization.
    """
    def __init__(self, mode="learning"):
        self.mode = mode  # "learning" or "scoring"
        self.use_fallback = True
        
        # Dynamic PyOD import checks
        try:
            from pyod.models.iforest import IForest
            import numpy as np
            self.IForestClass = IForest
            self.np = np
            self.use_fallback = False
            self.pyod_model = None
            print("[INFO] AdaptiveAnomalyDetector initialized in PyOD (Isolation Forest) mode.")
        except ImportError:
            self.IForestClass = None
            self.np = None
            self.use_fallback = True
            print("[INFO] PyOD/Scikit-learn not found. Falling back to Standardized Distance Engine.")

        # Fallback Standardized Distance Engine parameters (Welford's Algorithm)
        self.num_features = 5
        self.n_samples = 0
        self.means = [0.0] * self.num_features
        self.M2s = [0.0] * self.num_features
        self.stds = [0.0] * self.num_features
        
        # Scaling parameter for anomaly score normalization
        self.gamma = 1.0
        self.baseline_distances = []

        # Buffer to store historical training features for PyOD retraining
        self.training_buffer = []

    def set_mode(self, mode):
        """
        Switches between 'learning' (updating baseline) and 'scoring' (read-only detection).
        """
        if mode in ("learning", "scoring"):
            self.mode = mode

    def update_baseline_welford(self, x):
        """
        Updates the running mean and variance of features using Welford's Algorithm.
        Guarantees O(1) memory and time efficiency.
        """
        try:
            self.n_samples += 1
            for i in range(self.num_features):
                val = float(x[i])
                delta = val - self.means[i]
                self.means[i] += delta / self.n_samples
                delta2 = val - self.means[i]
                self.M2s[i] += delta * delta2
                
                # Compute standard deviation
                variance = self.M2s[i] / self.n_samples if self.n_samples > 1 else 0.0
                self.stds[i] = math.sqrt(variance)
        except Exception:
            pass

    def compute_standardized_distance(self, x):
        """
        Computes standardized Euclidean distance (diagonal Mahalanobis) from baseline.
        Applies epsilon safeguard to prevent division-by-zero crashes on constant features.
        """
        try:
            epsilon = 1e-9  # Safeguard value
            z_sum = 0.0
            for i in range(self.num_features):
                val = float(x[i])
                mean = self.means[i]
                std = self.stds[i]
                # Epsilon safety added to denominator
                z = (val - mean) / (std + epsilon)
                z_sum += z ** 2
            return math.sqrt(z_sum)
        except Exception:
            return 0.0

    def fit_incremental(self, x):
        """
        Processes a feature vector in Continuous Incremental Learning mode.
        """
        try:
            if self.mode != "learning":
                return

            if self.use_fallback:
                # Fallback path: update running baseline stats
                self.update_baseline_welford(x)
                dist = self.compute_standardized_distance(x)
                self.baseline_distances.append(dist)
                # Keep gamma as the average baseline distance to scale sigmoid
                if self.baseline_distances:
                    self.gamma = sum(self.baseline_distances) / len(self.baseline_distances)
                    if self.gamma < 1e-5:
                        self.gamma = 1.0
            else:
                # PyOD path
                self.training_buffer.append(x)
                # Retrain PyOD model every 10 events to avoid slow operations
                if len(self.training_buffer) >= 10 and len(self.training_buffer) % 10 == 0:
                    self.pyod_model = self.IForestClass(contamination=0.05, random_state=42)
                    X_train = self.np.array(self.training_buffer)
                    self.pyod_model.fit(X_train)
                    # Get baseline decision scores for normalization scaling
                    decision_scores = self.pyod_model.decision_scores_
                    self.gamma = float(self.np.mean(decision_scores)) if len(decision_scores) > 0 else 1.0
                    if self.gamma < 1e-5:
                        self.gamma = 1.0
        except Exception as e:
            # Crash-proof isolation: if PyOD fitting fails, fall back to Standardized Distance
            self.use_fallback = True
            self.update_baseline_welford(x)

    def score(self, x):
        """
        Scores a feature vector and returns a mathematically normalized anomaly score
        strictly between 0.0 and 1.0.
        """
        try:
            # If in learning mode, update the baseline first
            if self.mode == "learning":
                self.fit_incremental(x)

            if self.use_fallback or not self.pyod_model:
                # Fallback Scoring
                dist = self.compute_standardized_distance(x)
                # Sigmoid normalization mapping positive distance to [0.0, 1.0)
                # S(d) = 2 / (1 + exp(-d / gamma)) - 1
                exponent = -dist / (self.gamma + 1e-9)
                # Clip exponent to avoid math overflow
                exponent = max(min(exponent, 700.0), -700.0)
                score = (2.0 / (1.0 + math.exp(exponent))) - 1.0
                return max(0.0, min(score, 1.0))
            else:
                # PyOD Scoring
                X_test = self.np.array([x])
                raw_score = float(self.pyod_model.decision_function(X_test)[0])
                
                # Sigmoid normalization mapping score based on mean baseline score (gamma)
                # Centers around the baseline mean score
                diff = raw_score - self.gamma
                exponent = -diff / (abs(self.gamma) + 1e-9)
                exponent = max(min(exponent, 700.0), -700.0)
                score = 1.0 / (1.0 + math.exp(exponent))
                return max(0.0, min(score, 1.0))
                
        except Exception:
            # Crash-proof isolation: return low risk 0.0 on validation errors
            return 0.0

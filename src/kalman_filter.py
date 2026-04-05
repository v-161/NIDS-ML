"""
Simplified Kalman Filter for Adaptive Normalization
"""

import numpy as np

class KalmanNormalizer:
    """
    Simplified Kalman filter for adaptive feature normalization
    Updates dynamically as new data arrives
    """
    
    def __init__(self, process_noise=0.01, measurement_noise=0.1):
        self.process_noise = process_noise  # How much the system changes
        self.measurement_noise = measurement_noise  # How noisy 
        
        # State variables
        self.state_mean = 0  # Current estimate of mean
        self.state_variance = 1  # Current uncertainty
        
    def update(self, measurement):
        """
        Update filter with new measurement
        Returns: Filtered value
        """
        # Prediction step
        predicted_mean = self.state_mean
        predicted_variance = self.state_variance + self.process_noise
        
        # Update step (Kalman gain)
        kalman_gain = predicted_variance / (predicted_variance + self.measurement_noise)
        
        # New estimate
        self.state_mean = predicted_mean + kalman_gain * (measurement - predicted_mean)
        self.state_variance = (1 - kalman_gain) * predicted_variance
        
        return self.state_mean
    
    def normalize(self, value):
        """
        Apply Kalman filter then normalize
        """
        filtered = self.update(value)
        # Normalize by standard deviation (sqrt of variance)
        std = np.sqrt(self.state_variance + 1e-6)
        return (value - filtered) / std

class AdaptivePreprocessor:
    """
    Apply Kalman filter to all features adaptively
    """
    
    def __init__(self, n_features):
        self.filters = [KalmanNormalizer() for _ in range(n_features)]
        
    def transform(self, X):
        """
        Transform features using Kalman filters
        X: numpy array of shape (samples, features)
        """
        X_transformed = X.copy()
        
        for i in range(X.shape[1]):  # For each feature
            for j in range(X.shape[0]):  # For each sample
                X_transformed[j, i] = self.filters[i].normalize(X_transformed[j, i])
        
        return X_transformed

# Test
if __name__ == "__main__":
    print("Testing Kalman Filter Normalizer...")
    
    # Generate noisy data
    np.random.seed(42)
    data = np.random.randn(100, 5) * 2 + 10  # Mean 10, variance 4
    
    # Apply Kalman filter
    preprocessor = AdaptivePreprocessor(5)
    filtered_data = preprocessor.transform(data)
    
    print(f"Original data mean: {data.mean():.2f}, std: {data.std():.2f}")
    print(f"Filtered data mean: {filtered_data.mean():.2f}, std: {filtered_data.std():.2f}")
    print("✅ Kalman filter working!")
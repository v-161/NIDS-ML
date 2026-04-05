"""
Adaptive Threshold Optimization (ATO)
Dynamically adjusts classification threshold based on recent traffic
"""

class AdaptiveThreshold:
    def __init__(self, base_threshold=0.5, window_size=20, sensitivity=0.5):
        """
        base_threshold: Default threshold (0.5)
        window_size: Number of recent predictions to track
        sensitivity: How aggressively to adapt (0.3 to 0.7)
        """
        self.base_threshold = base_threshold
        self.window_size = window_size
        self.sensitivity = sensitivity
        self.recent_attack_probs = []
        self.recent_predictions = []
        
    def update(self, attack_probability, prediction):
        """Update sliding window with latest prediction"""
        self.recent_attack_probs.append(attack_probability)
        self.recent_predictions.append(prediction)
        
        # Keep window size limited
        if len(self.recent_attack_probs) > self.window_size:
            self.recent_attack_probs.pop(0)
            self.recent_predictions.pop(0)
    
    def get_threshold(self):
        """Calculate adaptive threshold based on recent traffic"""
        if len(self.recent_attack_probs) < 10:
            return self.base_threshold
        
        # Calculate recent attack rate
        recent_attack_rate = sum(self.recent_predictions) / len(self.recent_predictions)
        
        # Dynamic adjustment: Lower threshold when attacks are suspected
        # This reduces false negatives during active attacks
        adjustment = self.sensitivity * recent_attack_rate
        adaptive_threshold = self.base_threshold * (1 - adjustment)
        
        # Keep threshold in reasonable range [0.3, 0.7]
        return max(0.3, min(0.7, adaptive_threshold))
    
    def get_stats(self):
        """Get current statistics"""
        if not self.recent_attack_probs:
            return {"window_size": 0, "current_threshold": self.base_threshold}
        
        return {
            "window_size": len(self.recent_attack_probs),
            "recent_attack_rate": sum(self.recent_predictions) / len(self.recent_predictions),
            "current_threshold": self.get_threshold(),
            "base_threshold": self.base_threshold
        }

# Test the ATO
if __name__ == "__main__":
    print("Testing Adaptive Threshold Optimization...")
    ato = AdaptiveThreshold(base_threshold=0.5, window_size=10)
    
    # Simulate increasing attack traffic
    for i in range(20):
        if i < 10:
            # Normal traffic period
            attack_prob = 0.2
            pred = 0
        else:
            # Attack period - probabilities increase
            attack_prob = 0.6 + (i-10) * 0.03
            pred = 1 if attack_prob > ato.get_threshold() else 0
        
        ato.update(attack_prob, pred)
        print(f"Step {i+1}: Attack Prob={attack_prob:.2f}, Threshold={ato.get_threshold():.2f}, Pred={pred}")
    
    print(f"\nFinal Stats: {ato.get_stats()}")
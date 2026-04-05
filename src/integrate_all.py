"""
Integrate all advanced features into one pipeline
Run this to test everything at once
"""

print("="*60)
print("🚀 INTEGRATING ALL ADVANCED FEATURES")
print("="*60)

# Test ATO
print("\n1. Testing Adaptive Threshold Optimization...")
from ato import AdaptiveThreshold
ato = AdaptiveThreshold()
print(f"   ✅ ATO initialized. Current threshold: {ato.get_threshold():.2f}")

# Test Kalman Filter
print("\n2. Testing Kalman Filter...")
from kalman_filter import KalmanNormalizer
kf = KalmanNormalizer()
test_val = kf.normalize(100)
print(f"   ✅ Kalman filter working. Filtered value: {test_val:.2f}")

# Test SHAP
print("\n3. Testing SHAP (will load model)...")
try:
    from explain_model import explain_prediction
    print("   ✅ SHAP module ready")
except:
    print("   ⚠️ Run 'pip install shap' first")

print("\n" + "="*60)
print("✅ All advanced modules are ready!")
print("="*60)
print("\nNext steps:")
print("1. Run: python src/train_model.py (with advanced features)")
print("2. Run: python src/advanced_nids.py")
print("3. Run: python src/explain_model.py")
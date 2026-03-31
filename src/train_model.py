"""
Simple NIDS Model Training Script
Trains Random Forest to detect network attacks
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("🚀 NIDS Model Training Started")
print("="*60)

# def col names for dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

print("\n📂 Loading dataset...")

# load data
train_data = pd.read_csv('data/KDDTrain+.txt', names=columns)
test_data = pd.read_csv('data/KDDTest+.txt', names=columns)

print(f"✅ Training: {train_data.shape[0]} rows, {train_data.shape[1]} cols")
print(f"✅ Test: {test_data.shape[0]} rows, {test_data.shape[1]} cols")

# prep features and labels
X_train = train_data.drop(['label', 'difficulty_level'], axis=1)
y_train = train_data['label']
X_test = test_data.drop(['label', 'difficulty_level'], axis=1)
y_test = test_data['label']

# convert to binary classification 
print("\n🏷️ Converting to binary classification...")
y_train_binary = (y_train != 'normal').astype(int)
y_test_binary = (y_test != 'normal').astype(int)

normal_count = (y_train_binary == 0).sum()
attack_count = (y_train_binary == 1).sum()
print(f"Training - Normal: {normal_count}, Attack: {attack_count}")
print(f"Testing - Normal: {(y_test_binary == 0).sum()}, Attack: {(y_test_binary == 1).sum()}")

# encode categorical features
print("\n🔧 Encoding categorical features...")
categorical_cols = ['protocol_type', 'service', 'flag']
encoders = {}

for col in categorical_cols:
    le = LabelEncoder()
    X_train[col] = le.fit_transform(X_train[col])
    X_test[col] = le.transform(X_test[col])
    encoders[col] = le
    print(f"  ✓ Encoded {col}")

# normalize features
print("\n📏 Normalizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("✓ Features normalized")

# train model
print("\n🤖 Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled, y_train_binary)
print("✓ Training complete!")

# evaluate
print("\n📊 Model Evaluation:")
print("-"*40)

train_pred = model.predict(X_train_scaled)
test_pred = model.predict(X_test_scaled)

print(f"Training Accuracy: {accuracy_score(y_train_binary, train_pred):.4f}")
print(f"Testing Accuracy: {accuracy_score(y_test_binary, test_pred):.4f}")

print("\nClassification Report:")
print(classification_report(y_test_binary, test_pred, target_names=['Normal', 'Attack']))

# Confusion Matrix
cm = confusion_matrix(y_test_binary, test_pred)
print("\nConfusion Matrix:")
print(f"True Negatives: {cm[0,0]} | False Positives: {cm[0,1]}")
print(f"False Negatives: {cm[1,0]} | True Positives: {cm[1,1]}")

# Save model
print("\n💾 Saving model...")
os.makedirs('models', exist_ok=True)
joblib.dump(model, 'models/nids_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(encoders, 'models/encoders.pkl')
print("✓ Model saved to 'models/' folder")

print("\n" + "="*60)
print("✨ Training Complete!")
print("="*60)
print("\nNext: python src/predict.py")
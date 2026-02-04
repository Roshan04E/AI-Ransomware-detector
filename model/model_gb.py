import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump

def train_and_save_model(feature_csv: str, model_path: str) -> None:
    dataset = pd.read_csv(feature_csv)
    X = dataset.drop(columns=['label'])
    y = dataset['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    model = GradientBoostingClassifier()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    dump(model, model_path)
    print(f"Model saved to {model_path}")

k = 7
feature_csv = f"./feature_datasets/ransomware_dna{k}.csv"  # Path to your feature matrix CSV
model_path = f"./model/gb/ransomware_model{k}_gb.joblib"  # Path to save the trained model

# Train the model and save it
train_and_save_model(feature_csv, model_path)

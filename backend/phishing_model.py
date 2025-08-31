import pandas as pd
import numpy as np
import re
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
import joblib

def get_dataset():
    """
    Loads the dataset and renames the columns to 'url' and 'label'
    """
    # Read the CSV file you downloaded
    df = pd.read_csv('backend/phishing_site_urls.csv')
    
    # *** IMPORTANT: Replace 'ACTUAL_URL_COLUMN_NAME' below with the name from your file's first row. ***
    df = df.rename(columns={'URL': 'url', 'Label': 'label'})
    
    # The labels are 'good' and 'bad'. We'll convert them to 1 and 0.
    df['label'] = df['label'].apply(lambda x: 1 if x == 'bad' else 0)

    return df

def extract_features(url):
    """
    Extracts a list of features from a single URL for the model.
    This is the core of our feature engineering.
    """
    features = []
    
    # 1. URL Length
    features.append(len(url))
    
    # 2. Number of Dots in the URL
    features.append(url.count('.'))
    
    # 3. Presence of an IP address instead of a domain name
    is_ip_address = bool(re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url))
    features.append(1 if is_ip_address else 0)
    
    # 4. Presence of '@' symbol
    features.append(1 if '@' in url else 0)
    
    # 5. Presence of '-' symbol
    features.append(1 if '-' in url else 0)
    
    # 6. Presence of '//' symbol
    features.append(1 if '//' in url else 0)
    
    # 7. Presence of 'https'
    features.append(1 if 'https' in url.lower() else 0)
    
    # 8. Suspicious keywords check
    keywords = ['secure', 'account', 'login', 'verify', 'paypal', 'banking', 'update', 'signin']
    contains_keyword = any(keyword in url.lower() for keyword in keywords)
    features.append(1 if contains_keyword else 0)
    
    return np.array(features).reshape(1, -1)

def get_reasons_from_features(url):
    """
    Analyzes a URL and returns a list of human-readable reasons for a verdict.
    """
    reasons = []
    
    if len(url) > 75:  # A common heuristic for phishing URLs
        reasons.append("URL is unusually long, which can be a sign of a malicious link.")
    
    if url.count('.') > 3:
        reasons.append("URL contains multiple dots, often used to obscure the real domain.")
        
    if bool(re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url)):
        reasons.append("URL contains an IP address instead of a domain name.")
        
    if '@' in url:
        reasons.append("The '@' symbol is present, which is often used to insert fake credentials.")
        
    if not url.startswith('https://'):
        reasons.append("The URL does not use a secure HTTPS connection.")
        
    keywords = ['secure', 'account', 'login', 'verify', 'paypal', 'banking', 'update', 'signin']
    if any(keyword in url.lower() for keyword in keywords):
        reasons.append("URL contains suspicious keywords (e.g., login, secure, verify).")
        
    if not reasons:
        reasons.append("No obvious suspicious signs found.")
        
    return reasons

def train_and_save_model():
    """
    This function trains the model and saves it. It should be run once.
    """
    print("Fetching and preparing dataset...")
    df = get_dataset()
    
    # Extract features for the entire dataset
    df['features'] = df['url'].apply(lambda x: extract_features(x).flatten())
    
    # Stack the features to create the training matrix (X)
    X = np.vstack(df['features'].values)
    y = df['label'].values
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train the Logistic Regression model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    print("\nModel Training and Evaluation Complete!")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(f"Precision: {precision_score(y_test, y_pred):.2f}")
    print(f"Recall: {recall_score(y_test, y_pred):.2f}")
    
    # Save the trained model to a file
    joblib.dump(model, 'backend/phishing_model.pkl')
    
    print("Model saved as 'backend/phishing_model.pkl'")

# --- To be run from the command line once to train the model ---
if __name__ == '__main__':
    train_and_save_model()
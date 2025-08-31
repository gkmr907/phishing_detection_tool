from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from phishing_model import extract_features, get_reasons_from_features
import numpy as np

# Create the Flask application
app = Flask(__name__)
CORS(app)  # This allows the frontend to make requests to this backend

# Load the trained model when the app starts
try:
    model = joblib.load('backend/phishing_model.pkl')
    print("Model loaded successfully.")
except FileNotFoundError:
    print("Error: Model file 'phishing_model.pkl' not found. Please run phishing_model.py first.")
    model = None

@app.route('/')
def home():
    """A simple test route to check if the API is running."""
    return "Phishing Detection API is running!"

@app.route('/scan', methods=['POST'])
def scan_url():
    """The main API endpoint to scan a URL for phishing."""
    if not model:
        return jsonify({'error': 'Model not loaded. Cannot process request.'}), 500

    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided.'}), 400

    try:
        # Step 1: Extract features from the URL
        features = extract_features(url)
        
        # Step 2: Get the model's prediction and probability
        prediction_proba = model.predict_proba(features)[0][1] # Probability of being phishing
        
        # Step 3: Implement the three-tiered verdict system
        verdict = ""
        if prediction_proba > 0.8:
            verdict = "Malicious"
        elif prediction_proba > 0.5:
            verdict = "Suspicious"
        else:
            verdict = "Safe"
        
        # Step 4: Get human-readable reasons for the verdict
        reasons = get_reasons_from_features(url)
        
        # Return a JSON response
        response = {
            'verdict': verdict,
            'score': float(f'{prediction_proba:.2f}'),
            'reasons': reasons
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# To run the app
if __name__ == '__main__':
    app.run(debug=True)
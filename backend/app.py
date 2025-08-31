from flask import Flask, request, jsonify
from flask_cors import CORS
from phishing_model import check_for_phishing_rules

# Create the Flask application
app = Flask(__name__)
CORS(app)  # This allows the frontend to make requests to this backend

@app.route('/')
def home():
    """A simple test route to check if the API is running."""
    return "Phishing Detection API is running!"

@app.route('/scan', methods=['POST'])
def scan_url():
    """The main API endpoint to scan a URL for phishing."""
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided.'}), 400

    try:
        # Get verdict, both scores, and reasons from our rules
        verdict, score_to_display, reasons = check_for_phishing_rules(url)
        
        # Return a JSON response
        response = {
            'verdict': verdict,
            'score': float(f'{score_to_display:.2f}'),
            'reasons': reasons
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# To run the app
if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import logging
import utils
import os

from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__, static_folder="static/build", static_url_path="")
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Production configuration
app.config.update(
    DEBUG=False,
    SECRET_KEY=os.getenv('SECRET_KEY', 'default-secret-key'),
    PREFERRED_URL_SCHEME='https'
)

# Rate limiting (100 requests per minute globally)
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    """Serve the React app."""
    logger.info(f"Static folder: {app.static_folder}")
    logger.info(f"Requested path: {path}")
    full_path = os.path.join(app.static_folder, path)
    logger.info(f"Full path: {full_path}")
    
    if path != "" and os.path.exists(full_path):
        logger.info(f"Serving file: {full_path}")
        return send_from_directory(app.static_folder, path)
    
    logger.info(f"Serving index.html from: {os.path.join(app.static_folder, 'index.html')}")
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")  # Specific limit for this endpoint
def analyze():
    """API endpoint to analyze URL/IP."""
    data = request.get_json()
    input_data = data.get('input_data', '').strip()
    logger.info(f"Analyzing input: {input_data}")

    try:
        if utils.is_valid_url(input_data):
            is_suspicious, score, reasons = utils.analyze_url(input_data)
            result = 'Suspicious' if is_suspicious else 'Safe'
        elif utils.is_valid_ip(input_data):
            is_suspicious, score, reasons = utils.analyze_ip(input_data)
            result = 'Suspicious' if is_suspicious else 'Safe'
        else:
            result = 'Invalid'
            score = 0
            reasons = ['Input is neither a valid URL nor IP address']
        
        return jsonify({'result': result, 'score': score, 'reasons': reasons})
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        return jsonify({'error': 'Something went wrong'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

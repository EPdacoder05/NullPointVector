from flask import Flask, render_template, jsonify, request
from cli import PhishGuardCLI
import logging

app = Flask(__name__)
cli = PhishGuardCLI()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    provider = data.get('provider')
    limit = int(data.get('limit', 100))
    
    if provider in ['yahoo', 'gmail', 'outlook']:
        results = cli.analyze_email(provider, limit)
        return jsonify({
            'success': True,
            'results': results
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Invalid provider'
        }), 400

if __name__ == '__main__':
    app.run(debug=True) 
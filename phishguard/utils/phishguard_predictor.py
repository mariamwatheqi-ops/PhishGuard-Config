from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

# Load trained model
with open('app/model/model.pkl', 'rb') as f:
    model = pickle.load(f)

@app.route('/')
def home():
    return "PhishGuard is running!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        body = data.get('body', '')
        text = subject + ' ' + body

        prediction = model.predict([text])[0]
        return jsonify({'label': int(prediction)}) 
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)


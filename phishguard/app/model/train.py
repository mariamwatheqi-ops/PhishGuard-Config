import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Load dataset
df = pd.read_csv('data/datasets/CEAS_08.csv')

# Combine subject and body
df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
X = df['text']
y = df['label']

# Build pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=1000)),
    ('clf', LogisticRegression(max_iter=1000))
])

# Train model
pipeline.fit(X, y)

# Save model
with open('app/model/model.pkl', 'wb') as f:
    pickle.dump(pipeline, f)

print("✅ Model trained and saved to app/model/model.pkl")

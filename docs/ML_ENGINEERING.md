# Machine Learning Engineering Guide

## Overview

The IDPS ML engine combines multiple approaches for threat detection:
- **Sentence Transformers** for semantic understanding
- **Feature Engineering** for behavioral analysis
- **Logistic Regression** for interpretable results
- **Neural Networks** for complex pattern recognition

## Core ML Components

### 1. Sentence Transformers (`PhishGuard/phish_mlm/phishing_detector.py`)

**Model**: `all-MiniLM-L6-v2`
- **Dimensions**: 384
- **Speed**: ~1000 sentences/second
- **Accuracy**: 85%+ on semantic similarity tasks

**Usage**:
```python
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('all-MiniLM-L6-v2')
embedding = model.encode("Suspicious email content")
# Returns: numpy array of shape (384,)
```

**Key Functions**:
```python
def generate_embedding(text):
    """Generate embedding for email content."""
    if text is None or not isinstance(text, str):
        return np.zeros(384, dtype=np.float32)
    return model.encode(text)
```

### 2. Feature Engineering (`FeatureEngineering` class)

**Purpose**: Extract behavioral and metadata features from emails

**Features Extracted**:
```python
feature_columns = [
    'hour_of_day',        # Time-based: 0-23
    'day_of_week',        # Time-based: 0-6 (Monday=0)
    'is_weekend',         # Boolean: 0 or 1
    'has_urgent_words',   # Content: urgent, immediate, action required
    'has_suspicious_domain', # Content: suspicious keywords
    'has_money_mentions', # Content: money, payment, bank, account
    'has_personal_info',  # Content: password, login, verify
    'url_count',          # Structure: number of URLs
    'attachment_count'    # Structure: attachment mentions
]
```

**Implementation**:
```python
def extract_features(self, email_data):
    """Extract features from email data."""
    df = pd.DataFrame(email_data)
    
    # Time-based features
    df['timestamp'] = pd.to_datetime(df['date'])
    df['hour_of_day'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
    
    # Content-based features
    df['has_urgent_words'] = df['subject'].str.contains(
        'urgent|immediate|action required', case=False
    ).astype(int)
    
    # Structure-based features
    df['url_count'] = df['body'].str.count(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    
    return df[self.feature_columns]
```

### 3. Neural Network (`SimpleNN` class)

**Architecture**:
```python
class SimpleNN(nn.Module):
    def __init__(self, input_size=384):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_size, 128),  # Input layer
            nn.ReLU(),                   # Activation
            nn.Dropout(0.2),             # Regularization
            nn.Linear(128, 64),          # Hidden layer
            nn.ReLU(),                   # Activation
            nn.Linear(64, 2)             # Output layer (binary)
        )
```

**Training Process**:
```python
def train_model(self, X, y):
    """Train the neural network."""
    self.scaler = StandardScaler()
    X_scaled = self.scaler.fit_transform(X)
    
    self.model = SimpleNN(input_size=X.shape[1]).to(self.device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
    
    X_tensor = torch.FloatTensor(X_scaled).to(self.device)
    y_tensor = torch.LongTensor(y).to(self.device)
    
    self.model.train()
    for epoch in range(30):
        optimizer.zero_grad()
        outputs = self.model(X_tensor)
        loss = criterion(outputs, y_tensor)
        loss.backward()
        optimizer.step()
```

### 4. Logistic Regression

**Implementation**:
```python
def train_logistic_regression(self, X, y):
    """Train logistic regression model."""
    self.scaler = StandardScaler()
    X_scaled = self.scaler.fit_transform(X)
    
    self.model = LogisticRegression(
        max_iter=2000, 
        solver='liblinear', 
        random_state=42
    )
    self.model.fit(X_scaled, y)
```

## Data Pipeline

### 1. Data Collection
```python
def fetch_training_data(self):
    """Fetch training data from database."""
    with self.conn.cursor() as cursor:
        cursor.execute("""
            SELECT embedding, label, subject, sender, date, body 
            FROM messages
            WHERE label IS NOT NULL AND message_type = 'email'
        """)
        rows = cursor.fetchall()
        
        # Convert to DataFrame
        data = [{
            'embedding': row[0], 
            'label': row[1], 
            'subject': row[2], 
            'sender': row[3], 
            'date': row[4], 
            'body': row[5]
        } for row in rows]
        
        df = pd.DataFrame(data)
        
        # Extract features
        features = self.feature_engineering.extract_features(df)
        
        # Combine embeddings with features
        X = np.column_stack([
            np.array([np.array(row[0]) for row in rows]), 
            features
        ])
        y = np.array([row[1] for row in rows])
        
        return X, y
```

### 2. Model Training
```python
def train_model(self, X, y):
    """Train ML model with data."""
    if len(X) == 0 or len(y) == 0:
        logger.warning("No data available for training.")
        return None
    
    if self.use_nn:
        return self._train_neural_network(X, y)
    else:
        return self._train_logistic_regression(X, y)
```

### 3. Prediction
```python
def predict(self, email_data):
    """Predict threat level for email."""
    # Generate embedding
    content = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
    embedding = generate_embedding(content)
    
    # Extract features
    features = self.feature_engineering.extract_features([email_data])
    
    # Combine embedding and features
    X = np.column_stack([embedding, features.iloc[0].values])
    
    # Scale features
    X_scaled = self.scaler.transform([X])
    
    # Make prediction
    if self.use_nn:
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)
            outputs = self.model(X_tensor)
            probs = torch.softmax(outputs, dim=1)
            pred = torch.argmax(probs, dim=1).item()
            confidence = torch.max(probs).item()
    else:
        pred = self.model.predict(X_scaled)[0]
        confidence = self.model.predict_proba(X_scaled)[0][pred]
    
    return pred, confidence
```

## Model Performance

### Metrics Tracked
- **Accuracy**: Overall prediction accuracy
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1-Score**: Harmonic mean of precision and recall
- **Confidence**: Model confidence in predictions

### Performance Benchmarks
- **Sentence Transformers**: ~1000 sentences/second
- **Feature Engineering**: ~100 emails/second
- **Logistic Regression**: ~1000 predictions/second
- **Neural Network**: ~500 predictions/second (GPU)

## Model Persistence

### Saving Models
```python
# Save scaler
joblib.dump(self.scaler, 'models/scaler.pkl')

# Save logistic regression
joblib.dump(self.model, 'models/logistic_regression.pkl')

# Save neural network
torch.save(self.model.state_dict(), 'models/neural_network.pth')
```

### Loading Models
```python
def load_model(self):
    """Load trained model."""
    if self.use_nn:
        if os.path.exists('models/neural_network.pth'):
            self.model = SimpleNN().to(self.device)
            self.model.load_state_dict(
                torch.load('models/neural_network.pth', map_location=self.device)
            )
            self.scaler = joblib.load('models/scaler.pkl')
    else:
        if os.path.exists('models/logistic_regression.pkl'):
            self.model = joblib.load('models/logistic_regression.pkl')
            self.scaler = joblib.load('models/scaler.pkl')
```

## Hyperparameter Tuning

### Logistic Regression
```python
from sklearn.model_selection import GridSearchCV

param_grid = {
    'C': [0.1, 1, 10, 100],
    'solver': ['liblinear', 'saga'],
    'max_iter': [1000, 2000, 5000]
}

grid_search = GridSearchCV(
    LogisticRegression(random_state=42),
    param_grid,
    cv=5,
    scoring='f1'
)
grid_search.fit(X_train, y_train)
```

### Neural Network
```python
# Learning rate tuning
learning_rates = [0.001, 0.01, 0.1]
batch_sizes = [32, 64, 128]
epochs = [20, 30, 50]

# Architecture tuning
hidden_sizes = [64, 128, 256]
dropout_rates = [0.1, 0.2, 0.3]
```

## Feature Importance Analysis

### Logistic Regression
```python
def analyze_feature_importance(self):
    """Analyze feature importance for logistic regression."""
    if not self.use_nn:
        feature_names = ['embedding'] + self.feature_engineering.feature_columns
        importance = np.abs(self.model.coef_[0])
        
        feature_importance = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False)
        
        return feature_importance
```

### Neural Network
```python
def analyze_neural_network_weights(self):
    """Analyze neural network layer weights."""
    if self.use_nn:
        weights = {}
        for name, param in self.model.named_parameters():
            weights[name] = param.data.cpu().numpy()
        return weights
```

## Model Evaluation

### Cross-Validation
```python
from sklearn.model_selection import cross_val_score

def evaluate_model(self, X, y):
    """Evaluate model using cross-validation."""
    if self.use_nn:
        # Custom cross-validation for neural networks
        scores = []
        kf = KFold(n_splits=5, shuffle=True, random_state=42)
        
        for train_idx, val_idx in kf.split(X):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]
            
            # Train model
            self._train_neural_network(X_train, y_train)
            
            # Evaluate
            score = self._evaluate_batch(X_val, y_val)
            scores.append(score)
        
        return np.mean(scores), np.std(scores)
    else:
        # Use sklearn cross-validation
        scores = cross_val_score(self.model, X, y, cv=5, scoring='f1')
        return scores.mean(), scores.std()
```

### Confusion Matrix
```python
from sklearn.metrics import confusion_matrix, classification_report

def generate_evaluation_report(self, X_test, y_test):
    """Generate comprehensive evaluation report."""
    y_pred = self.model.predict(X_test)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    # Classification report
    report = classification_report(y_test, y_pred)
    
    # ROC curve
    y_proba = self.model.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc_score = auc(fpr, tpr)
    
    return {
        'confusion_matrix': cm,
        'classification_report': report,
        'roc_curve': (fpr, tpr),
        'auc_score': auc_score
    }
```

## Production Deployment

### Model Versioning
```python
import mlflow

def log_model_experiment(self, X, y, params):
    """Log model experiment with MLflow."""
    mlflow.set_experiment("idps_phishing_detection")
    
    with mlflow.start_run():
        # Log parameters
        mlflow.log_params(params)
        
        # Train model
        self.train_model(X, y)
        
        # Evaluate model
        score = self.evaluate_model(X, y)
        mlflow.log_metric("f1_score", score)
        
        # Log model
        mlflow.sklearn.log_model(self.model, "model")
```

### A/B Testing
```python
def ab_test_models(self, X, y, model_a, model_b):
    """Compare two models using A/B testing."""
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Train both models
    model_a.train(X_train, y_train)
    model_b.train(X_train, y_train)
    
    # Evaluate
    score_a = model_a.evaluate(X_test, y_test)
    score_b = model_b.evaluate(X_test, y_test)
    
    # Statistical significance test
    from scipy import stats
    t_stat, p_value = stats.ttest_ind(score_a, score_b)
    
    return {
        'model_a_score': score_a,
        'model_b_score': score_b,
        'p_value': p_value,
        'significant': p_value < 0.05
    }
```

## Troubleshooting

### Common ML Issues

1. **Overfitting**: Add regularization, reduce model complexity
2. **Underfitting**: Increase model capacity, add features
3. **Class Imbalance**: Use SMOTE, adjust class weights
4. **Data Leakage**: Ensure proper train/test split
5. **Feature Scaling**: Always scale features for neural networks

### Performance Optimization

1. **Batch Processing**: Process emails in batches
2. **Caching**: Cache embeddings and features
3. **Parallel Processing**: Use multiprocessing for feature extraction
4. **GPU Acceleration**: Use CUDA for neural networks
5. **Model Quantization**: Reduce model size for deployment

## Future ML Enhancements

1. **Transformer Models**: BERT, GPT for better text understanding
2. **Graph Neural Networks**: Model sender relationships
3. **Reinforcement Learning**: Adaptive threat detection
4. **Federated Learning**: Privacy-preserving model training
5. **AutoML**: Automated hyperparameter optimization

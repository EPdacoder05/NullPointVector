import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

def run_analytics(conn):
    df = pd.read_sql("SELECT date, is_threat FROM messages WHERE message_type = 'sms'", conn)
    df['date'] = pd.to_datetime(df['date'])
    # Trend analysis
    trend = df.groupby(df['date'].dt.date)['spam'].mean()
    trend.plot(title='Spam Rate Over Time')
    plt.show()
    # Clustering
    embeddings = np.stack(df['embedding'].values)
    kmeans = KMeans(n_clusters=3).fit(embeddings)
    df['cluster'] = kmeans.labels_
    # Anomaly detection
    iso = IsolationForest(contamination=0.05)
    df['anomaly'] = iso.fit_predict(embeddings)
    print(df[['id', 'cluster', 'anomaly']].head())
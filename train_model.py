import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from url_features import extract_features

print("Starting model training...")

data = [
    # Legitimate URLs
    ("https://google.com", 0),
    ("https://microsoft.com", 0),
    ("https://amazon.com", 0),
    ("https://github.com", 0),
    ("https://wikipedia.org", 0),
    ("https://python.org", 0),
    ("https://apple.com", 0),
    ("https://linkedin.com", 0),
    ("https://gitam.edu", 0),
    ("https://youtube.com", 0),
    ("https://facebook.com", 0),
    ("https://instagram.com", 0),
    ("https://netflix.com", 0),
    ("https://stackoverflow.com", 0),
    ("https://reddit.com", 0),
    ("https://gmail.com", 0),
    ("https://dropbox.com", 0),
    ("https://adobe.com", 0),
    ("https://mozilla.org", 0),
    ("https://ubuntu.com", 0),

    # Phishing URLs
    ("http://login-verify-account.com", 1),
    ("http://secure-login-confirm.com", 1),
    ("http://bank-account-verification.com", 1),
    ("http://free-bonus-login.com", 1),
    ("http://verify-your-password.com", 1),
    ("http://account-update-security.com", 1),
    ("http://signin-confirm-user.com", 1),
    ("http://secure-bank-login123.com", 1),
    ("http://verify-account-security.com", 1),
    ("http://login-password-update.com", 1),
    ("http://paypal-login-verify.com", 1),
    ("http://amazon-account-confirm.com", 1),
    ("http://bank-login-security.com", 1),
    ("http://verify-payment-account.com", 1),
    ("http://secure-password-update.com", 1),
    ("http://login-user-confirm.com", 1),
    ("http://free-gift-bonus-login.com", 1),
    ("http://account-verify-security.com", 1),
    ("http://confirm-bank-password.com", 1),
    ("http://signin-account-update.com", 1)
]

X = []
y = []

for url, label in data:
    X.append(extract_features(url))
    y.append(label)

print("Features extracted.")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

print("Model trained successfully.")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)
f1 = f1_score(y_test, predictions)

print("\nModel Evaluation")
print("----------------")
print("Accuracy :", round(accuracy * 100, 2), "%")
print("Precision:", round(precision * 100, 2), "%")
print("Recall   :", round(recall * 100, 2), "%")
print("F1 Score :", round(f1 * 100, 2), "%")

joblib.dump(model, "phishing_model.pkl")

print("\nModel saved as phishing_model.pkl")
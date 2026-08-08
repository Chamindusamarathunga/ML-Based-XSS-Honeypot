"""
XSS Detection - ML Model Trainer
=================================
Project: Honeypot for Reflected and Stored XSS Attacks and Threat Detection
Author: Honeypot System (BTEC HND Final Year Project)

Description:
    This script trains a Machine Learning model to detect XSS payloads.
    It uses TF-IDF vectorization with a Logistic Regression classifier.

    Model Artifacts (saved in ml_model/ directory):
        - xss_model.pkl         : Trained Logistic Regression classifier
        - tfidf_vectorizer.pkl  : Fitted TF-IDF Vectorizer

Usage:
    python train_model.py
"""

import os
import glob
import json
import sys
import joblib
import numpy as np
from datetime import datetime

from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, roc_auc_score)

# Force UTF-8 output so special chars in payloads print cleanly on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# --- Configuration ---

PAYLOADS_DIR    = "payloads"
MODEL_DIR       = "ml_model"
MODEL_PATH      = os.path.join(MODEL_DIR, "xss_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
REPORT_PATH     = os.path.join(MODEL_DIR, "training_report.json")

os.makedirs(MODEL_DIR, exist_ok=True)

# --- 1. Load Malicious XSS Payloads (Class 1) ---

def load_malicious_payloads(payloads_dir):
    """
    Reads all *.txt files in the payloads directory and returns
    a deduplicated list of XSS payload strings.
    """
    payloads = set()
    txt_files = glob.glob(os.path.join(payloads_dir, "*.txt"))

    if not txt_files:
        raise FileNotFoundError(
            "No .txt payload files found in '{}'. ".format(payloads_dir) +
            "Please make sure the payloads directory is correct."
        )

    for file_path in txt_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and len(line) >= 3:
                        payloads.add(line)
        except Exception as e:
            print("  [WARN] Could not read {}: {}".format(file_path, e))

    print("  Loaded {:,} unique malicious payloads from {} files.".format(
        len(payloads), len(txt_files)))
    return list(payloads)


# --- 2. Generate Benign / Legitimate Samples (Class 0) ---

def generate_benign_samples():
    """
    Returns a curated list of benign text strings representing
    normal (non-attack) user inputs such as search queries,
    comments, names, email addresses, and form data.
    """
    benign = [
        # Plain search queries
        "how to bake a chocolate cake",
        "best programming languages 2024",
        "weather in london tomorrow",
        "python tutorial for beginners",
        "machine learning introduction",
        "flask web development guide",
        "what is cross site scripting",
        "top 10 movies 2024",
        "cheapest flights to paris",
        "online shopping deals",
        "history of artificial intelligence",
        "how does the internet work",
        "install python on windows",
        "git version control basics",
        "sql database tutorial",
        "css flexbox guide",
        "react js tutorial",
        "node js express server",
        "docker installation steps",
        "cybersecurity basics",
        "network security fundamentals",
        "penetration testing overview",
        "ethical hacking course",
        "OWASP top 10 vulnerabilities",
        "web application security",
        # Normal form comments
        "Great article, very informative!",
        "I love this website!",
        "Thank you for sharing this.",
        "Please update the FAQ section.",
        "Can you add a dark mode feature?",
        "This is very helpful, thanks!",
        "I disagree with the conclusion.",
        "Looking forward to more content.",
        "This helped me a lot. Thanks!",
        "Keep up the good work!",
        "I found a typo on page 3.",
        "The instructions were very clear.",
        "Nice design! Very clean.",
        "Could you provide more examples?",
        "Amazing! Learned something new today.",
        # Normal user names
        "John Smith", "Alice Johnson", "Bob Williams",
        "Emma Davis", "Michael Brown", "Olivia Taylor",
        "James Wilson", "Sophia Martinez", "Aiden Anderson",
        "Isabella Thomas", "Ethan Jackson", "Mia White",
        # Normal email formats
        "user@example.com", "alice.johnson@gmail.com",
        "bob123@yahoo.com", "support@company.org",
        "noreply@newsletter.net", "info@website.co.uk",
        # Normal numeric/symbolic inputs (not XSS)
        "12345", "100", "42", "$99.99", "3.14", "+94 70 123 4567",
        "10/10/1990", "01-Jan-2000", "2024-03-01",
        # Normal product-search / e-commerce
        "red running shoes size 10",
        "wireless noise cancelling headphones",
        "4K ultra HD television",
        "gaming laptop under 1000",
        "ergonomic office chair",
        "mechanical keyboard RGB",
        "iPhone 15 pro max case",
        "samsung galaxy s24 review",
        "microwave oven 20 litre",
        "yoga mat non slip",
        # Normal URL-like strings (no javascript)
        "/about", "/contact", "/products", "/login", "/register",
        "https://www.google.com", "https://github.com",
        "https://stackoverflow.com/questions",
        # HTML entities that are NOT attacks
        "&amp;", "&lt;", "&gt;", "&copy;", "&mdash;",
        # Short but legit
        "yes", "no", "ok", "hello", "hi", "bye", "thanks",
        "good", "bad", "1", "test", "abc", "name",
        # Code-like but harmless
        "print('hello world')",
        "int x = 5;",
        "SELECT name FROM users WHERE id=1",
        "import os",
        "def my_function():",
        "console.log('debug info')",
        "JSON.stringify({key: 'value'})",
        "const arr = [1, 2, 3];",
        "npm install express",
        "pip install flask",
        # Multilingual (normal text)
        "Hola mundo",
        "Bonjour le monde",
        "Guten Tag Welt",
        "ciao mondo",
        "Olá mundo",
    ]
    print("  Generated {:,} benign samples.".format(len(benign)))
    return benign


def augment_benign_samples(benign_base, target_count):
    """
    Augments the benign dataset by varying/shuffling samples so
    the class distribution is balanced against the XSS payloads.
    """
    rng = np.random.default_rng(seed=42)
    augmented = list(benign_base)
    while len(augmented) < target_count:
        idx = int(rng.integers(0, len(benign_base)))
        sample = benign_base[idx]
        choice = int(rng.integers(0, 10))
        if choice == 0:
            variation = sample + " "
        elif choice == 1:
            variation = " " + sample
        elif choice == 2:
            variation = sample.lower()
        elif choice == 3:
            variation = sample.upper()
        elif choice == 4:
            variation = sample.title()
        elif choice == 5:
            variation = sample + "!"
        elif choice == 6:
            variation = sample + "?"
        elif choice == 7:
            variation = "Please show me " + sample.lower()
        elif choice == 8:
            variation = "I am looking for " + sample.lower()
        else:
            variation = "Search: " + sample
        augmented.append(str(variation))
    return augmented[:target_count]


# --- 3. Feature Engineering ---

def build_vectorizer():
    """
    Creates a TF-IDF Vectorizer with character-level n-grams.
    Character n-grams are particularly effective for malicious
    payload detection because XSS attacks rely on specific character
    sequences (<, >, script, alert, etc.) regardless of word boundaries.
    """
    return TfidfVectorizer(
        analyzer="char_wb",      # character-level n-grams with word boundaries
        ngram_range=(2, 5),      # bigrams to 5-grams
        max_features=20000,
        sublinear_tf=True,       # apply log-normalization to TF
        min_df=1,
        strip_accents="unicode",
        lowercase=True,
    )


# --- 4. Train Model ---

def train(X_train, y_train):
    """
    Trains a Logistic Regression classifier. LR was chosen because:
    - It provides calibrated probability scores (useful for confidence reporting)
    - It is highly interpretable (good for academic projects)
    - It trains fast even on moderate-sized text datasets
    - It generalises well on sparse TF-IDF features
    """
    clf = LogisticRegression(
        C=1.0,
        solver="lbfgs",
        max_iter=1000,
        class_weight="balanced",   # handles class imbalance automatically
        random_state=42,
    )
    clf.fit(X_train, y_train)
    return clf


# --- 5. Evaluate & Report ---

def evaluate(clf, vectorizer, X_test, y_test):
    X_test_vec = vectorizer.transform(X_test)
    y_pred  = clf.predict(X_test_vec)
    y_proba = clf.predict_proba(X_test_vec)[:, 1]

    acc     = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    cm      = confusion_matrix(y_test, y_pred).tolist()
    report  = classification_report(y_test, y_pred,
                                    target_names=["Benign", "XSS"],
                                    output_dict=True)

    print("\n  +-------------------------------------+")
    print("  |       MODEL EVALUATION RESULTS      |")
    print("  +-------------------------------------+")
    print("  Accuracy  : {:.4f}  ({:.2f}%)".format(acc, acc * 100))
    print("  ROC-AUC   : {:.4f}".format(roc_auc))
    print("  Confusion Matrix (rows=Actual, cols=Predicted):")
    print("            Predicted Benign | Predicted XSS")
    print("  Actual Benign   {:>8d}   | {:>8d}".format(cm[0][0], cm[0][1]))
    print("  Actual XSS      {:>8d}   | {:>8d}".format(cm[1][0], cm[1][1]))
    print()
    print("  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "XSS"]))

    return {
        "accuracy": round(acc, 4),
        "roc_auc":  round(roc_auc, 4),
        "confusion_matrix": cm,
        "classification_report": report,
        "trained_at": datetime.utcnow().isoformat() + "Z",
    }


# --- 6. Quick Smoke-Test ---

def smoke_test(clf, vectorizer):
    test_cases = [
        # (text,                                             expected_label)
        ("<script>alert('XSS')</script>",                   "XSS"),
        ("<img src=x onerror=alert(1)>",                    "XSS"),
        ("javascript:eval(atob('YWxlcnQoMSk='))",           "XSS"),
        ("<svg onload=alert(document.cookie)>",             "XSS"),
        ("'><script>document.location='http://evil.com'",   "XSS"),
        ("<body onload=alert('XSS')>",                      "XSS"),
        ("hello world",                                     "Benign"),
        ("best restaurants in colombo",                     "Benign"),
        ("welcome to my website",                           "Benign"),
        ("SELECT * FROM users WHERE id = 1",                "Benign"),
        ("user@example.com",                                "Benign"),
        ("John Smith",                                      "Benign"),
    ]

    print("  +------------------------------------------------------------------------+")
    print("  |                        SMOKE TEST RESULTS                              |")
    print("  +------------------------------------------------------------------------+")
    print("  {:<55} {:<8} {:<10} {}".format("Input (truncated)", "Expected", "Predicted", "Confidence"))
    print("  " + "-" * 90)
    all_pass = True
    for text, expected in test_cases:
        vec   = vectorizer.transform([text])
        pred  = clf.predict(vec)[0]
        prob  = clf.predict_proba(vec)[0]
        label = "XSS" if pred == 1 else "Benign"
        conf  = max(prob) * 100
        ok    = "PASS" if label == expected else "FAIL"
        if label != expected:
            all_pass = False
        truncated = (text[:52] + "...") if len(text) > 55 else text
        print("  {:<55} {:<8} {:<10} {:>6.1f}%  {}".format(truncated, expected, label, conf, ok))
    print()
    if all_pass:
        print("  [OK] All smoke tests PASSED.")
    else:
        print("  [!!] Some smoke tests did not match. Review model thresholds.")


# --- Main ---

def main():
    print("=" * 70)
    print("  XSS ML Model Trainer")
    print("  Honeypot Project - BTEC HND Final Year")
    print("  Started: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("=" * 70)

    # 1. Load data
    print("\n[1/5] Loading XSS payloads...")
    malicious = load_malicious_payloads(PAYLOADS_DIR)

    print("\n[2/5] Generating benign samples...")
    benign_base = generate_benign_samples()
    # Balance the dataset: benign count = malicious count
    target_benign = max(len(malicious), len(benign_base))
    benign = augment_benign_samples(benign_base, target_count=target_benign)
    print("  Total benign samples after augmentation: {:,}".format(len(benign)))

    # 2. Build dataset
    X = malicious + benign
    y = [1] * len(malicious) + [0] * len(benign)
    print("\n  Dataset summary:")
    print("    XSS (malicious) : {:,}".format(len(malicious)))
    print("    Benign          : {:,}".format(len(benign)))
    print("    Total           : {:,}".format(len(X)))

    # 3. Train/test split
    print("\n[3/5] Splitting dataset (80% train / 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print("  Train size: {:,}  |  Test size: {:,}".format(len(X_train), len(X_test)))

    # 4. Fit TF-IDF
    print("\n[4/5] Fitting TF-IDF vectorizer...")
    vectorizer = build_vectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    print("  Vocabulary size (features): {:,}".format(len(vectorizer.vocabulary_)))

    # 5. Train
    print("\n[5/5] Training Logistic Regression classifier...")
    clf = train(X_train_vec, y_train)

    # 6. Evaluate
    print("\n[Evaluation] Running evaluation on test set...")
    metrics = evaluate(clf, vectorizer, X_test, y_test)

    # 7. Cross-validation
    print("[Cross-Validation] Running 5-fold cross-validation on full dataset...")
    X_all_vec = vectorizer.transform(X)
    cv_scores = cross_val_score(clf, X_all_vec, y, cv=5, scoring="roc_auc")
    print("  CV ROC-AUC: {:.4f} +/- {:.4f}".format(cv_scores.mean(), cv_scores.std()))
    metrics["cv_roc_auc_mean"] = round(float(cv_scores.mean()), 4)
    metrics["cv_roc_auc_std"]  = round(float(cv_scores.std()), 4)

    # 8. Smoke test
    print("\n[Smoke Test] Running quick inference checks...")
    smoke_test(clf, vectorizer)

    # 9. Save artifacts
    joblib.dump(clf,        MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    print("\n[DONE] Model artifacts saved:")
    print("    Classifier  : {}".format(MODEL_PATH))
    print("    Vectorizer  : {}".format(VECTORIZER_PATH))
    print("    Report      : {}".format(REPORT_PATH))
    print("\n  Training complete. You can now run app.py -- the ML model will be")
    print("  loaded automatically and used alongside the regex-based detector.")
    print("=" * 70)


if __name__ == "__main__":
    main()

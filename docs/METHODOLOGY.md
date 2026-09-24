# PhishGuard Methodology

This document outlines the methodological decisions, dataset preparation steps, and evaluation metrics used to develop the PhishGuard machine learning pipeline.

## 1. Dataset Preparation

The pipeline began with a raw dataset comprising full URLs (labeled as legitimate or phishing). To ensure data cleanliness:
- **Validation**: All URLs were parsed and normalized using the `urllib.parse` library to remove whitespace, insert implicit schemes, and drop malformed strings.
- **Deduplication**: Datasets were strictly deduplicated based on their normalized URL string to prevent identical samples from artificially inflating model confidence.

*Note on Tranco Comparison: An initial experiment evaluated Tranco Top 1M bare domains as a benign class source. This was rejected due to extreme structural bias (bare domains lack paths, queries, and specific schemes), which would have caused the model to simply learn that "having a path" equals "phishing". Instead, structurally comparable full URLs were utilized.*

## 2. Feature Extraction

PhishGuard relies exclusively on static, lexical feature extraction (no network requests). The `URLFeatureExtractor` produces 15 specific features:
1. `url_length`
2. `hostname_length`
3. `path_length`
4. `num_dots`
5. `num_hyphens`
6. `num_digits`
7. `num_subdomains`
8. `is_ipv4`
9. `has_at_symbol`
10. `has_punycode`
11. `num_percent_encoded`
12. `num_query_params`
13. `has_non_standard_port`
14. `uses_https`
15. `num_suspicious_keywords`

## 3. Leakage Prevention & Group-Aware Splitting

A major challenge in phishing classification is domain-level leakage. If `http://phish.com/1` is in the training set and `http://phish.com/2` is in the test set, the model may simply memorize the string `phish.com` rather than learning generalizable structural patterns.

To mitigate this, PhishGuard uses a **Group-Aware Split** (`sklearn.model_selection.GroupShuffleSplit`), grouping strictly by hostname.
- Training Hostnames and Test Hostnames are enforced to have **0 overlap**.

## 4. Model Comparison

Two distinct models were compared on the independent test set:
- **Logistic Regression**: Used as an interpretable linear baseline (with `StandardScaler`).
- **Random Forest**: Used as an ensemble non-linear classifier.

Random Forest drastically outperformed Logistic Regression across all metrics (Accuracy, Precision, Recall, F1, ROC-AUC) and was chosen for the current inference architecture.

## 5. Known Limitations

- **Dataset Provenance**: The dataset is a static snapshot and likely suffers from survivorship bias and temporal decay. Real-world threat landscapes shift rapidly.
- **Lexical Overlap**: Legitimate authentication endpoints heavily mirror the structural properties of credential harvesting endpoints. This inherently causes false positives.
- **Evasion**: Shortened URLs, massive redirects, and obfuscation techniques actively defeat lexical-only systems.
- **Generalization**: The reported 80%+ accuracy applies strictly to this held-out group partition. It is not indicative of absolute global phishing detection capabilities.

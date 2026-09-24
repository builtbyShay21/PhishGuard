# PhishGuard ML Pipeline

This directory contains the machine learning training and evaluation pipeline for PhishGuard.

- `train.py`: Data loading, feature extraction, group-aware splitting, model training, and model saving.
- `evaluate.py`: Test set evaluation, metric generation, and reporting.

Features are restricted exclusively to lexical attributes (static analysis).

No dynamic network requests are made during training or evaluation.

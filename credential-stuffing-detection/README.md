# Credential Stuffing Detection with Machine Learning

This project explores a machine learning-based approach for detecting credential stuffing-related abuse in payment gateway environments. It uses the IEEE-CIS Fraud Detection dataset as a proxy for downstream credential misuse patterns and implements a structured Random Forest pipeline for training, optimization, evaluation, explainability, calibration, and imbalance handling. The project is based on my bachelor thesis on optimizing machine learning-based detection of credential stuffing attacks in payment gateways.

## Project Goal

Credential stuffing attacks often rely on valid but previously leaked credentials, which makes them difficult to detect using static login rules alone. This project focuses on identifying suspicious behavior through transactional and contextual signals, using fraud labels as practical proxies when direct login-event labels are unavailable. The thesis motivation, dataset choice, and proxy-based modeling approach are described in the underlying research document.

## Dataset

This project uses the **IEEE-CIS Fraud Detection** dataset from Kaggle.

Dataset source: IEEE-CIS Fraud Detection on Kaggle: https://www.kaggle.com/competitions/ieee-fraud-detection/data

The dataset is **not included** in this repository due to size and licensing considerations. The project expects the original IEEE-CIS files to be placed locally in the `data/` directory before running the pipeline.

Expected files in the `data/` folder:

- `train_transaction.csv`
- `train_identity.csv`

## Approach

The pipeline:

- merges transaction and identity data
- selects a compact feature set relevant to fraud and credential-abuse proxies
- applies preprocessing and one-hot encoding
- trains a baseline Random Forest model
- optimizes the model using class weighting and `RandomizedSearchCV`
- evaluates performance using classification metrics and ROC-AUC
- simulates credential stuffing-like scenarios
- analyzes decision thresholds and operational risk buckets
- applies SHAP-based explainability
- evaluates calibration quality
- compares class-weighted optimization against SMOTE

The thesis also documents the use of a stratified 80/20 split, class-weight handling, RandomizedSearchCV, SHAP-based interpretability, operational thresholding, calibration, and SMOTE-based comparison.

## Project Structure

```text
credential-stuffing-detection/
├── data/
│   └── README.md
├── docs/
│   └── thesis.pdf
├── notebook/
│   └── model.ipynb
├── results/
├── src/
│   └── model.py
├── README.md
└── requirements.txt
```

## Features Used

The current modeling pipeline uses a compact set of transaction and card-related attributes:

- `TransactionAmt`
- `card1`
- `card2`
- `card4`
- `addr1`
- `dist1`

Categorical feature `card4` is one-hot encoded during preprocessing.

## Installation

Create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the Project

From the project root:

```bash
./venv/bin/python src/model.py --data-dir data --results-dir results
```

## Dataset and Model Artifacts

The following files are **not tracked in GitHub** because of repository size limits:

- `data/train_transaction.csv`
- `data/train_identity.csv`
- `results/optimized_random_forest.joblib`
- `results/random_forest_smote.joblib`

To reproduce the project locally:

1. Download the IEEE-CIS Fraud Detection dataset from Kaggle: https://www.kaggle.com/competitions/ieee-fraud-detection/data
2. Extract and place the following files in a local `data/` directory at the project root:
   - `data/train_transaction.csv`
   - `data/train_identity.csv`
3. Run the pipeline from the project root.

You may create the `data/` directory locally even though the raw dataset files are not stored in this repository.

The trained `.joblib` files are generated automatically in the `results/` directory when the pipeline completes successfully.

## Main Results

### Baseline vs Optimized Random Forest

| Metric | Baseline | Optimized |
|--------|---------:|----------:|
| Accuracy | 0.989 | 0.986 |
| Precision | 0.874 | 0.679 |
| Recall | 0.503 | 0.608 |
| F1-Score | 0.638 | 0.642 |
| ROC-AUC | 0.917 | 0.939 |

The optimized model improves recall and ROC-AUC, meaning it detects more fraudulent behavior and ranks risky transactions more effectively, at the cost of some precision.

## Operational Findings

The model supports a practical decision strategy using risk thresholds:

- **BLOCK** → high-risk transactions
- **REVIEW** → medium-risk transactions
- **ALLOW** → low-risk transactions

Example results:

- BLOCK fraud rate: **0.6786**
- REVIEW fraud rate: **0.1226**
- ALLOW fraud rate: **0.0059**

## Threshold Analysis

| Threshold | Precision | Recall | F1-Score |
|----------:|----------:|-------:|---------:|
| 0.2 | 0.402 | 0.717 | 0.515 |
| 0.3 | 0.545 | 0.683 | 0.606 |
| 0.5 | 0.679 | 0.608 | 0.642 |

## Ranking Performance

| K | Precision@K | Recall@K |
|---|------------:|---------:|
| 100 | 1.0000 | 0.1067 |
| 500 | 0.8660 | 0.4621 |
| 1000 | 0.6050 | 0.6457 |
| 2000 | 0.3485 | 0.7439 |

## Calibration

| Model | ROC-AUC |
|------|--------:|
| Uncalibrated | 0.939484 |
| Platt-scaled | 0.941097 |
| Isotonic | 0.940799 |

## SMOTE Comparison

| Metric | SMOTE RF |
|--------|---------:|
| Accuracy | 0.982883 |
| Precision | 0.570533 |
| Recall | 0.582711 |
| F1-Score | 0.576558 |
| ROC-AUC | 0.922727 |

## Key Outputs

Running the pipeline generates results in the `results/` directory:

- Confusion matrices
- ROC curves
- Feature importance plots
- Threshold analysis plots
- Ranking metrics tables
- Calibration curves
- SHAP explainability plots
- Saved trained models (generated locally, not included in the repository)
- Performance comparison tables

## Limitations

- No direct login or authentication data is used
- Fraud labels act as a proxy for credential stuffing behavior
- Limited feature set
- No real-time deployment

## Future Work

- Integrate authentication and session-level data
- Add behavioral and temporal features
- Experiment with ensemble models
- Deploy as a real-time system

## Academic Context

This project is based on my bachelor thesis:

**Optimization of Machine Learning-Based Detection of Credential Stuffing Attacks in Payment Gateways**

The full thesis is included in the `docs/` folder.
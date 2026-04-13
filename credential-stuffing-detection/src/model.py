#!/usr/bin/env python3
"""Credential stuffing detection using Random Forest on the IEEE-CIS dataset.

This script turns the original notebook workflow into a more structured, reproducible
pipeline. It:
- loads and merges the IEEE-CIS transaction and identity datasets
- prepares a compact feature set relevant to fraud / credential-abuse proxies
- trains a baseline Random Forest model
- optimizes the model with class weighting and RandomizedSearchCV
- evaluates model performance with metrics and visualizations
- runs simulated credential-stuffing scenarios
- performs threshold, ranking, calibration, and SMOTE-based analysis
- saves models and results to a results directory

Example:
    python model.py --data-dir ../data --results-dir ../results
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import shap
from imblearn.over_sampling import SMOTE
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import RandomizedSearchCV, train_test_split
from sklearn.utils.class_weight import compute_class_weight

RANDOM_STATE = 42
SELECTED_FEATURES = ["TransactionAmt", "card1",
                     "card2", "card4", "addr1", "dist1"]
SIMULATION_COLUMNS = ["TransactionAmt", "card1", "card2", "addr1"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Random Forest-based credential stuffing detection pipeline"
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("../data"),
        help="Directory containing train_transaction.csv and train_identity.csv",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("../results"),
        help="Directory where models, metrics, and plots will be saved",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split size (default: 0.2)",
    )
    parser.add_argument(
        "--shap-sample-size",
        type=int,
        default=1000,
        help="Maximum number of rows to use for SHAP analysis",
    )
    return parser.parse_args()


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def save_json(data: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def load_and_merge_datasets(data_dir: Path) -> pd.DataFrame:
    transaction_path = data_dir / "train_transaction.csv"
    identity_path = data_dir / "train_identity.csv"

    if not transaction_path.exists() or not identity_path.exists():
        raise FileNotFoundError(
            "Missing dataset files. Expected train_transaction.csv and train_identity.csv "
            f"inside: {data_dir.resolve()}"
        )

    transaction_df = pd.read_csv(transaction_path)
    identity_df = pd.read_csv(identity_path)

    print(f"Transaction shape: {transaction_df.shape}")
    print(f"Identity shape: {identity_df.shape}")

    df = pd.merge(transaction_df, identity_df, on="TransactionID", how="left")
    print(f"Combined dataset shape: {df.shape}")
    return df


def summarize_dataset(df: pd.DataFrame) -> dict[str, Any]:
    missing_summary = (df.isnull().mean().sort_values(
        ascending=False).head(10) * 100).round(2)
    summary = {
        "shape": list(df.shape),
        "column_count": int(len(df.columns)),
        "target_distribution": df["isFraud"].value_counts(dropna=False).to_dict(),
        "top_missing_percent": missing_summary.to_dict(),
        "numeric_columns": int(df.select_dtypes(include=np.number).shape[1]),
        "categorical_columns": int(df.select_dtypes(include=["object", "string"]).shape[1]),
    }

    print("\nDataset overview:")
    print(f"Shape: {summary['shape']}")
    print(f"Columns: {summary['column_count']}")
    print("Target distribution:")
    print(df["isFraud"].value_counts(dropna=False))
    print("\nTop missing columns (%):")
    print(missing_summary)
    print(
        f"\nNumeric columns: {summary['numeric_columns']}, "
        f"Categorical columns: {summary['categorical_columns']}"
    )
    return summary


def prepare_modeling_dataset(df: pd.DataFrame) -> pd.DataFrame:
    available_features = [
        feature for feature in SELECTED_FEATURES if feature in df.columns]
    print(f"\nUsing features: {available_features}")

    df_model = df[available_features + ["isFraud"]
                  ].dropna(subset=available_features + ["isFraud"]).copy()

    if "card4" in df_model.columns:
        df_model = pd.get_dummies(df_model, columns=["card4"], drop_first=True)
        print("Applied one-hot encoding to: card4")

    print(f"Final dataset shape for modeling: {df_model.shape}")
    return df_model


def split_features_target(
    df_model: pd.DataFrame, test_size: float
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    X = df_model.drop("isFraud", axis=1)
    y = df_model["isFraud"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    print("\nTraining and test sets created successfully.")
    print(f"Training size: {X_train.shape[0]}")
    print(f"Test size: {X_test.shape[0]}")
    print("Target class distribution (train):")
    print(y_train.value_counts(normalize=True).round(4))
    return X_train, X_test, y_train, y_test


def train_baseline_model(
    X_train: pd.DataFrame, y_train: pd.Series
) -> RandomForestClassifier:
    model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)
    print("\nBaseline Random Forest model trained successfully.")
    return model


def evaluate_model(
    model: RandomForestClassifier,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    label: str,
) -> dict[str, Any]:
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1_score": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix": confusion_matrix(y_test, predictions),
        "classification_report": classification_report(y_test, predictions, zero_division=0),
        "predictions": predictions,
        "probabilities": probabilities,
    }

    print(f"\n{label} Classification Report:")
    print(metrics["classification_report"])
    print(f"{label} Confusion Matrix:")
    print(metrics["confusion_matrix"])
    print(f"{label} ROC-AUC Score: {metrics['roc_auc']:.4f}")
    return metrics


def plot_confusion_matrix(cm: np.ndarray, title: str, output_path: Path) -> None:
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title(title)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_roc_curve(
    y_test: pd.Series,
    probabilities: np.ndarray,
    title: str,
    output_path: Path,
    color: str = "darkgreen",
) -> None:
    fpr, tpr, _ = roc_curve(y_test, probabilities)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, color=color, lw=2,
             label=f"ROC Curve (AUC = {roc_auc:.3f})")
    plt.plot([0, 1], [0, 1], color="gray", lw=1.5,
             linestyle="--", label="Random Guessing")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(title)
    plt.legend(loc="lower right")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def compute_class_weights(y_train: pd.Series) -> dict[int, float]:
    classes = np.unique(y_train)
    weights = compute_class_weight(
        class_weight="balanced", classes=classes, y=y_train)
    class_weights = dict(zip(classes, weights))
    print(f"Computed class weights: {class_weights}")
    return class_weights


def optimize_model(
    X_train: pd.DataFrame, y_train: pd.Series, class_weights: dict[int, float]
) -> tuple[RandomForestClassifier, dict[str, Any]]:
    param_dist = {
        "n_estimators": [100, 200, 300],
        "max_depth": [10, 20, 30, None],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"],
        "bootstrap": [True, False],
    }

    base_rf = RandomForestClassifier(
        random_state=RANDOM_STATE,
        class_weight=class_weights,
    )

    random_search = RandomizedSearchCV(
        estimator=base_rf,
        param_distributions=param_dist,
        n_iter=15,
        scoring="f1",
        cv=3,
        verbose=2,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    print("\nRunning randomized hyperparameter search...")
    random_search.fit(X_train, y_train)
    best_model = random_search.best_estimator_

    print("\nBest Parameters Found:")
    print(random_search.best_params_)
    return best_model, random_search.best_params_


def plot_feature_importance(
    model: RandomForestClassifier,
    X_train: pd.DataFrame,
    output_path: Path,
    top_n: int = 10,
) -> pd.DataFrame:
    feature_df = pd.DataFrame(
        {
            "Feature": X_train.columns,
            "Importance": model.feature_importances_,
        }
    ).sort_values(by="Importance", ascending=False)

    plt.figure(figsize=(10, 6))
    sns.barplot(x="Importance", y="Feature", data=feature_df.head(top_n))
    plt.title("Top 10 Feature Importances - Optimized Random Forest")
    plt.xlabel("Relative Importance")
    plt.ylabel("Feature")
    plt.tight_layout()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    return feature_df


def build_metrics_comparison(
    baseline_metrics: dict[str, Any],
    optimized_metrics: dict[str, Any],
) -> pd.DataFrame:
    comparison_df = pd.DataFrame(
        {
            "Metric": ["Accuracy", "Precision", "Recall", "F1-Score", "ROC AUC"],
            "Baseline Value": [
                round(baseline_metrics["accuracy"], 3),
                round(baseline_metrics["precision"], 3),
                round(baseline_metrics["recall"], 3),
                round(baseline_metrics["f1_score"], 3),
                round(baseline_metrics["roc_auc"], 3),
            ],
            "Optimized Value": [
                round(optimized_metrics["accuracy"], 3),
                round(optimized_metrics["precision"], 3),
                round(optimized_metrics["recall"], 3),
                round(optimized_metrics["f1_score"], 3),
                round(optimized_metrics["roc_auc"], 3),
            ],
        }
    )

    comparison_df["Improvement (%)"] = (
        (comparison_df["Optimized Value"] - comparison_df["Baseline Value"])
        / comparison_df["Baseline Value"]
        * 100
    ).round(2)

    print("\nFinal Performance Comparison (Baseline vs Optimized Model):")
    print(comparison_df.to_string(index=False))
    return comparison_df


def plot_metrics_comparison(comparison_df: pd.DataFrame, output_path: Path) -> None:
    melted = comparison_df.melt(
        id_vars="Metric", value_vars=["Baseline Value", "Optimized Value"]
    )
    plt.figure(figsize=(8, 5))
    sns.barplot(data=melted, x="Metric", y="value", hue="variable")
    plt.title("Baseline vs Optimized Random Forest Performance")
    plt.ylabel("Score")
    plt.xlabel("")
    plt.ylim(0, 1)
    plt.legend(title="")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def save_model_and_metrics(
    model: RandomForestClassifier,
    comparison_df: pd.DataFrame,
    results_dir: Path,
) -> None:
    joblib.dump(model, results_dir / "optimized_random_forest.joblib")
    comparison_df.to_csv(
        results_dir / "model_performance_comparison.csv", index=False)
    comparison_df.to_csv(
        results_dir / "final_model_comparison.csv", index=False)
    print("\nSaved optimized model and performance comparison tables.")


def build_simulated_cases(X_train: pd.DataFrame) -> pd.DataFrame:
    sim_data = pd.DataFrame(
        {
            "TransactionAmt": [1.0, 1200.0, 5.0, 250.0],
            "card1": [10000, 20000, 30000, 4500],
            "card2": [111, 444, 555, 999],
            "addr1": [100, 200, 300, 150],
            "card4_discover": [0, 0, 0, 0],
            "card4_mastercard": [1, 0, 0, 1],
            "card4_visa": [0, 1, 0, 0],
        }
    )

    expected_cols = list(X_train.columns)
    sim_data_aligned = sim_data.reindex(columns=expected_cols, fill_value=0)
    return sim_data_aligned


def run_simulations(
    model: RandomForestClassifier,
    X_train: pd.DataFrame,
    results_dir: Path,
) -> pd.DataFrame:
    print("\nRunning simulated credential stuffing detection tests...")
    sim_data_aligned = build_simulated_cases(X_train)
    sim_probs = model.predict_proba(sim_data_aligned)[:, 1]
    sim_preds = model.predict(sim_data_aligned)

    sim_results = sim_data_aligned.copy()
    sim_results["Predicted_Prob_Fraud"] = np.round(sim_probs, 6)
    sim_results["Predicted_Label"] = sim_preds
    sim_results["Case_Description"] = [
        "Tiny amount, high failed-login proxies (simulated)",
        "Large amount + many reuse signals (simulated)",
        "Very small amount, suspicious card combos (simulated)",
        "Medium amount, mixed signals (simulated)",
    ]

    sim_results.to_csv(
        results_dir / "simulated_credential_stuffing_results.csv", index=False)

    sim_results_sorted = sim_results.sort_values(
        "Predicted_Prob_Fraud", ascending=True)
    plt.figure(figsize=(7, 4))
    sns.barplot(
        x="Predicted_Prob_Fraud",
        y="Case_Description",
        hue="Case_Description",
        data=sim_results_sorted,
        palette="viridis",
        legend=False,
    )
    plt.xlabel("Predicted Fraud Probability")
    plt.ylabel("Simulated Scenario")
    plt.title("Simulated Credential Stuffing Detection – Fraud Probability by Case")
    plt.tight_layout()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.savefig(results_dir / "simulated_fraud_probability_chart.png",
                dpi=300, bbox_inches="tight")
    plt.close()

    return sim_results


def plot_precision_recall_thresholds(
    y_test: pd.Series,
    probabilities: np.ndarray,
    results_dir: Path,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    precision, recall, thresholds = precision_recall_curve(
        y_test, probabilities)

    plt.figure(figsize=(7, 5))
    plt.plot(thresholds, precision[:-1], label="Precision", color="steelblue")
    plt.plot(thresholds, recall[:-1], label="Recall", color="darkorange")
    plt.xlabel("Threshold")
    plt.ylabel("Score")
    plt.title("Precision vs Recall Across Decision Thresholds")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(results_dir / "precision_recall_thresholds.png",
                dpi=300, bbox_inches="tight")
    plt.close()

    print("Threshold analysis plot saved.")
    return precision, recall, thresholds


def evaluate_threshold_candidates(
    y_test: pd.Series,
    probabilities: np.ndarray,
) -> pd.DataFrame:
    threshold_candidates = [0.2, 0.3, 0.5]
    rows: list[dict[str, Any]] = []

    for threshold in threshold_candidates:
        preds = (probabilities >= threshold).astype(int)
        rows.append(
            {
                "Threshold": threshold,
                "Precision": round(precision_score(y_test, preds, zero_division=0), 3),
                "Recall": round(recall_score(y_test, preds, zero_division=0), 3),
                "F1-Score": round(f1_score(y_test, preds, zero_division=0), 3),
            }
        )

    threshold_df = pd.DataFrame(rows)
    print("\nThreshold comparison:")
    print(threshold_df.to_string(index=False))
    return threshold_df


def evaluate_ranking_metrics(y_test: pd.Series, probabilities: np.ndarray) -> pd.DataFrame:
    print("\nRanking-based evaluation (Precision@K / Recall@K)...")
    y_true = y_test.values
    sorted_idx = np.argsort(probabilities)[::-1]

    def precision_recall_at_k(k: int) -> tuple[float, float]:
        top_k = sorted_idx[:k]
        y_top = y_true[top_k]
        precision_k = y_top.mean()
        recall_k = y_top.sum() / y_true.sum()
        return float(precision_k), float(recall_k)

    rows: list[dict[str, Any]] = []
    for k in [100, 500, 1000, 2000]:
        precision_k, recall_k = precision_recall_at_k(k)
        rows.append(
            {
                "K": k,
                "Precision@K": round(precision_k, 4),
                "Recall@K": round(recall_k, 4),
            }
        )

    topk_df = pd.DataFrame(rows)
    print(topk_df.to_string(index=False))
    return topk_df


def evaluate_operational_policy(
    y_test: pd.Series,
    probabilities: np.ndarray,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    print("\nTwo-threshold operational policy...")
    t_block = 0.50
    t_review = 0.20

    policy = np.where(
        probabilities >= t_block,
        "BLOCK",
        np.where(probabilities >= t_review, "REVIEW", "ALLOW"),
    )

    policy_df = pd.DataFrame({"policy": policy, "count": 1}).groupby(
        "policy").count().reset_index()

    bucket_stats = []
    for bucket in ["BLOCK", "REVIEW", "ALLOW"]:
        idx = policy == bucket
        bucket_stats.append(
            {
                "Bucket": bucket,
                "Transactions": int(idx.sum()),
                "Fraud rate": round(float(y_test[idx].mean()), 4) if idx.sum() > 0 else np.nan,
            }
        )

    bucket_df = pd.DataFrame(bucket_stats)
    print(policy_df.to_string(index=False))
    print(bucket_df.to_string(index=False))
    return policy_df, bucket_df


def run_shap_analysis(
    model: RandomForestClassifier,
    X_test: pd.DataFrame,
    results_dir: Path,
    sample_size: int,
) -> None:
    print("\nRunning SHAP analysis...")
    shap_sample_size = min(sample_size, len(X_test))
    X_shap = X_test.sample(shap_sample_size, random_state=RANDOM_STATE)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_shap)

    # Normalize SHAP output so we always end up with a 2D matrix:
    # (samples, features) for the fraud / positive class.
    if isinstance(shap_values, list):
        shap_to_plot = np.array(shap_values[-1])
        expected_value = np.array(explainer.expected_value)[-1]
    else:
        shap_array = np.array(shap_values)
        expected_array = np.array(explainer.expected_value)

        if shap_array.ndim == 3:
            # Could be either (samples, features, classes) or (classes, samples, features).
            if shap_array.shape[-1] == 2:
                shap_to_plot = shap_array[:, :, 1]
                expected_value = expected_array[-1] if expected_array.ndim > 0 else expected_array
            elif shap_array.shape[0] == 2:
                shap_to_plot = shap_array[-1]
                expected_value = expected_array[-1] if expected_array.ndim > 0 else expected_array
            else:
                raise ValueError(
                    f"Unexpected 3D SHAP output shape: {shap_array.shape}")
        elif shap_array.ndim == 2:
            shap_to_plot = shap_array
            expected_value = expected_array[-1] if expected_array.ndim > 0 else expected_array
        else:
            raise ValueError(
                f"Unexpected SHAP output shape: {shap_array.shape}")

    if shap_to_plot.ndim != 2:
        raise ValueError(
            f"Normalized SHAP matrix must be 2D, got shape {shap_to_plot.shape}")

    plt.figure()
    shap.summary_plot(shap_to_plot, X_shap, plot_type="dot", show=False)
    plt.title("SHAP Summary Plot – Global Feature Impact (Fraud Class)")
    plt.tight_layout()
    plt.savefig(results_dir / "shap_summary_plot.png",
                dpi=300, bbox_inches="tight")
    plt.close()

    plt.figure()
    shap.summary_plot(shap_to_plot, X_shap, plot_type="bar", show=False)
    plt.title("SHAP Feature Importance – Fraud Class")
    plt.tight_layout()
    plt.savefig(results_dir / "shap_bar_plot.png",
                dpi=300, bbox_inches="tight")
    plt.close()

    sample_index = 0
    single_values = np.asarray(shap_to_plot[sample_index]).squeeze()
    single_data = np.asarray(X_shap.iloc[sample_index]).squeeze()
    base_value_array = np.asarray(expected_value).reshape(-1)
    base_value = float(base_value_array[-1])

    if single_values.ndim != 1:
        raise ValueError(
            f"Expected a single SHAP explanation vector, got shape {single_values.shape}. "
            f"Full normalized SHAP shape: {shap_to_plot.shape}"
        )

    explanation = shap.Explanation(
        values=single_values,
        base_values=base_value,
        data=single_data,
        feature_names=list(X_shap.columns),
    )

    plt.figure()
    shap.waterfall_plot(explanation, show=False)
    plt.tight_layout()
    plt.savefig(results_dir / "shap_waterfall_plot.png",
                dpi=300, bbox_inches="tight")
    plt.close()


def run_calibration_analysis(
    best_model: RandomForestClassifier,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    results_dir: Path,
) -> pd.DataFrame:
    print("\nRunning calibration analysis...")
    calibrated_sigmoid = CalibratedClassifierCV(
        estimator=best_model,
        method="sigmoid",
        cv=3,
    )
    calibrated_isotonic = CalibratedClassifierCV(
        estimator=best_model,
        method="isotonic",
        cv=3,
    )

    calibrated_sigmoid.fit(X_train, y_train)
    calibrated_isotonic.fit(X_train, y_train)

    probs_raw = best_model.predict_proba(X_test)[:, 1]
    probs_sigmoid = calibrated_sigmoid.predict_proba(X_test)[:, 1]
    probs_isotonic = calibrated_isotonic.predict_proba(X_test)[:, 1]

    plt.figure(figsize=(7, 5))
    for probs, label in [
        (probs_raw, "Uncalibrated RF"),
        (probs_sigmoid, "Platt-scaled RF"),
        (probs_isotonic, "Isotonic RF"),
    ]:
        frac_pos, mean_pred = calibration_curve(
            y_test, probs, n_bins=10, strategy="uniform")
        plt.plot(mean_pred, frac_pos, marker="o", label=label)

    plt.plot([0, 1], [0, 1], "k--", label="Perfect calibration")
    plt.xlabel("Mean predicted probability")
    plt.ylabel("Fraction of positives")
    plt.title("Calibration Curves – Fraud Probability Reliability")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(results_dir / "probability_calibration_curve.png",
                dpi=300, bbox_inches="tight")
    plt.close()

    calibration_df = pd.DataFrame(
        {
            "Model": ["Uncalibrated", "Platt-scaled", "Isotonic"],
            "ROC-AUC": [
                roc_auc_score(y_test, probs_raw),
                roc_auc_score(y_test, probs_sigmoid),
                roc_auc_score(y_test, probs_isotonic),
            ],
        }
    )
    print(calibration_df.to_string(index=False))
    calibration_df.to_csv(
        results_dir / "calibration_auc_comparison.csv", index=False)
    return calibration_df


def run_smote_experiment(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    results_dir: Path,
) -> pd.DataFrame:
    print("\nRunning SMOTE experiment...")
    smote = SMOTE(sampling_strategy="auto",
                  random_state=RANDOM_STATE, k_neighbors=5)
    X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

    print("Original training set class distribution:")
    print(y_train.value_counts())
    print("\nSMOTE-resampled training set class distribution:")
    print(pd.Series(y_train_smote).value_counts())

    rf_smote = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        max_depth=None,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
    )
    rf_smote.fit(X_train_smote, y_train_smote)

    y_pred_smote = rf_smote.predict(X_test)
    y_prob_smote = rf_smote.predict_proba(X_test)[:, 1]

    print("\nClassification Report (SMOTE Model):")
    print(classification_report(y_test, y_pred_smote, zero_division=0))
    roc_auc_smote = roc_auc_score(y_test, y_prob_smote)
    print(f"\nROC-AUC Score (SMOTE Model): {roc_auc_smote:.4f}")

    cm_smote = confusion_matrix(y_test, y_pred_smote)
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm_smote, annot=True, fmt="d", cmap="Purples", cbar=False)
    plt.title("Confusion Matrix – Random Forest with SMOTE")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.savefig(results_dir / "smote_confusion_matrix.png",
                dpi=300, bbox_inches="tight")
    plt.close()

    smote_summary = pd.DataFrame(
        {
            "Metric": ["Accuracy", "Precision", "Recall", "F1-Score", "ROC AUC"],
            "SMOTE RF": [
                accuracy_score(y_test, y_pred_smote),
                precision_score(y_test, y_pred_smote, zero_division=0),
                recall_score(y_test, y_pred_smote, zero_division=0),
                f1_score(y_test, y_pred_smote, zero_division=0),
                roc_auc_smote,
            ],
        }
    )

    print("\nSMOTE Model Performance Summary:")
    print(smote_summary.to_string(index=False))

    joblib.dump(rf_smote, results_dir / "random_forest_smote.joblib")
    smote_summary.to_csv(
        results_dir / "smote_model_performance.csv", index=False)
    return smote_summary


def main() -> None:
    args = parse_args()
    ensure_directory(args.results_dir)
    sns.set_theme(style="whitegrid")

    df = load_and_merge_datasets(args.data_dir)
    dataset_summary = summarize_dataset(df)
    save_json(dataset_summary, args.results_dir / "dataset_summary.json")

    df_model = prepare_modeling_dataset(df)
    X_train, X_test, y_train, y_test = split_features_target(
        df_model, args.test_size)

    baseline_model = train_baseline_model(X_train, y_train)
    baseline_metrics = evaluate_model(
        baseline_model, X_test, y_test, "Baseline Model")
    plot_confusion_matrix(
        baseline_metrics["confusion_matrix"],
        "Confusion Matrix - Baseline Random Forest",
        args.results_dir / "baseline_confusion_matrix.png",
    )
    plot_roc_curve(
        y_test,
        baseline_metrics["probabilities"],
        "ROC Curve - Baseline Random Forest",
        args.results_dir / "baseline_roc_curve.png",
        color="steelblue",
    )

    class_weights = compute_class_weights(y_train)
    best_model, best_params = optimize_model(X_train, y_train, class_weights)
    save_json(best_params, args.results_dir / "best_random_forest_params.json")

    optimized_metrics = evaluate_model(
        best_model, X_test, y_test, "Optimized Model")
    plot_confusion_matrix(
        optimized_metrics["confusion_matrix"],
        "Confusion Matrix - Optimized Random Forest",
        args.results_dir / "optimized_confusion_matrix.png",
    )
    plot_roc_curve(
        y_test,
        optimized_metrics["probabilities"],
        "ROC Curve - Optimized Random Forest",
        args.results_dir / "optimized_roc_curve.png",
        color="darkgreen",
    )

    feature_importance_df = plot_feature_importance(
        best_model,
        X_train,
        args.results_dir / "optimized_feature_importance.png",
    )
    feature_importance_df.to_csv(
        args.results_dir / "feature_importance.csv", index=False)

    comparison_df = build_metrics_comparison(
        baseline_metrics, optimized_metrics)
    save_model_and_metrics(best_model, comparison_df, args.results_dir)
    plot_metrics_comparison(
        comparison_df,
        args.results_dir / "baseline_vs_optimized_performance.png",
    )

    run_simulations(best_model, X_train, args.results_dir)

    precision, recall, thresholds = plot_precision_recall_thresholds(
        y_test,
        optimized_metrics["probabilities"],
        args.results_dir,
    )
    threshold_df = evaluate_threshold_candidates(
        y_test, optimized_metrics["probabilities"])
    threshold_df.to_csv(args.results_dir /
                        "threshold_comparison.csv", index=False)

    topk_df = evaluate_ranking_metrics(
        y_test, optimized_metrics["probabilities"])
    topk_df.to_csv(args.results_dir / "topk_ranking_metrics.csv", index=False)

    policy_df, bucket_df = evaluate_operational_policy(
        y_test, optimized_metrics["probabilities"])
    policy_df.to_csv(args.results_dir /
                     "operational_policy_counts.csv", index=False)
    bucket_df.to_csv(args.results_dir /
                     "operational_policy_buckets.csv", index=False)

    run_shap_analysis(best_model, X_test, args.results_dir,
                      args.shap_sample_size)
    run_calibration_analysis(best_model, X_train, y_train,
                             X_test, y_test, args.results_dir)
    run_smote_experiment(X_train, y_train, X_test, y_test, args.results_dir)

    save_json(
        {
            "baseline": {
                "accuracy": baseline_metrics["accuracy"],
                "precision": baseline_metrics["precision"],
                "recall": baseline_metrics["recall"],
                "f1_score": baseline_metrics["f1_score"],
                "roc_auc": baseline_metrics["roc_auc"],
            },
            "optimized": {
                "accuracy": optimized_metrics["accuracy"],
                "precision": optimized_metrics["precision"],
                "recall": optimized_metrics["recall"],
                "f1_score": optimized_metrics["f1_score"],
                "roc_auc": optimized_metrics["roc_auc"],
            },
        },
        args.results_dir / "metrics_summary.json",
    )

    print("\nPipeline completed successfully.")
    print(f"Results saved to: {args.results_dir.resolve()}")


if __name__ == "__main__":
    main()

"""
IronLedger — anomaly detector evaluation on the real HAI 20.07 ICS security dataset.

Dataset: Shin et al., "HAI 1.0: HIL-Based Augmented ICS Security Dataset",
USENIX CSET 2020. https://github.com/icsdataset/hai (CC BY-SA 4.0).

Methodology:
  - Train an Isolation Forest on NORMAL-ONLY operational data (train1 + train2,
    filtered to attack==0 rows — train2 turned out to contain 776 rows flagged
    attack==1, which we exclude rather than silently include).
  - Hold out 20% of that normal data purely to calibrate a detection threshold
    (99th percentile of its anomaly scores) — the model never sees this slice
    during fitting, avoiding threshold leakage.
  - Evaluate on test1 + test2, which contain real, labeled attack windows
    (not synthetic — these are actual injected attacks on a physical HIL
    testbed).
  - Report both point-wise metrics AND a range-based recall (did we flag at
    least one point inside each contiguous attack segment), because the
    dataset's own authors (Hwang et al., "Do You Know Existing Accuracy
    Metrics Overrate Time-Series Anomaly Detections?", ACM SAC 2022) show
    point-wise precision/recall overstates or understates performance for
    time-series anomaly detection. We don't implement their full eTaPR
    metric (out of scope here) but range-based recall is a reasonable,
    citable approximation of what it corrects for.
  - Compare against a naive 3-sigma statistical baseline — the same "hard
    threshold" idea our own physics-envelope layer uses — to show the ML
    model earns its complexity rather than assuming it.
"""
import json
import time
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve,
)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hai-data")
REPORT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(REPORT_DIR, "figures")
os.makedirs(OUT_DIR, exist_ok=True)

LABEL_COLS = ["attack", "attack_P1", "attack_P2", "attack_P3"]
RANDOM_STATE = 42

print("=== Loading data ===")
t0 = time.time()
train1 = pd.read_csv(f"{DATA_DIR}/train1.csv", sep=";")
train2 = pd.read_csv(f"{DATA_DIR}/train2.csv", sep=";")
test1 = pd.read_csv(f"{DATA_DIR}/test1.csv", sep=";")
test2 = pd.read_csv(f"{DATA_DIR}/test2.csv", sep=";")
print(f"loaded in {time.time()-t0:.1f}s | shapes: {train1.shape} {train2.shape} {test1.shape} {test2.shape}")

train1.columns = [c.strip() for c in train1.columns]
train2.columns = [c.strip() for c in train2.columns]
test1.columns = [c.strip() for c in test1.columns]
test2.columns = [c.strip() for c in test2.columns]

feature_cols = [c for c in train1.columns if c not in ["time"] + LABEL_COLS]
assert feature_cols == [c for c in test1.columns if c not in ["time"] + LABEL_COLS], "feature mismatch train/test"
print(f"feature columns: {len(feature_cols)}")

# --- Build normal-only training set, excluding the 776 mislabeled rows in train2 ---
train_all = pd.concat([train1, train2], ignore_index=True)
n_before = len(train_all)
train_normal = train_all[train_all["attack"] == 0].copy()
print(f"train rows: {n_before} total, {len(train_normal)} normal-only "
      f"({n_before - len(train_normal)} excluded as attack==1)")

for c in feature_cols:
    train_normal[c] = pd.to_numeric(train_normal[c], errors="coerce")
train_normal = train_normal.dropna(subset=feature_cols)

# 80/20 split: fit vs threshold-calibration (held out from fitting to avoid leakage)
rng = np.random.default_rng(RANDOM_STATE)
idx = rng.permutation(len(train_normal))
split = int(len(idx) * 0.8)
fit_idx, calib_idx = idx[:split], idx[split:]
X_fit_raw = train_normal.iloc[fit_idx][feature_cols].values
X_calib_raw = train_normal.iloc[calib_idx][feature_cols].values
print(f"fit set: {X_fit_raw.shape[0]} rows, calibration set: {X_calib_raw.shape[0]} rows")

# Subsample the fit set for tractable training time — IsolationForest doesn't
# need the full ~440k rows to characterize the normal operating envelope.
FIT_SAMPLE = 100_000
if X_fit_raw.shape[0] > FIT_SAMPLE:
    sample_idx = rng.choice(X_fit_raw.shape[0], FIT_SAMPLE, replace=False)
    X_fit_raw = X_fit_raw[sample_idx]
print(f"training on {X_fit_raw.shape[0]} rows after subsampling")

scaler = StandardScaler().fit(X_fit_raw)
X_fit = scaler.transform(X_fit_raw)
X_calib = scaler.transform(X_calib_raw)

# --- Test set ---
test_all = pd.concat([test1, test2], ignore_index=True)
for c in feature_cols:
    test_all[c] = pd.to_numeric(test_all[c], errors="coerce")
test_all = test_all.dropna(subset=feature_cols).reset_index(drop=True)
y_true = test_all["attack"].astype(int).values
X_test = scaler.transform(test_all[feature_cols].values)
print(f"test rows: {len(test_all)}, attack rate: {y_true.mean():.4f}")

print("\n=== Training Isolation Forest ===")
t0 = time.time()
model = IsolationForest(n_estimators=150, contamination="auto", random_state=RANDOM_STATE, n_jobs=-1)
model.fit(X_fit)
print(f"trained in {time.time()-t0:.1f}s")

# score_samples: higher = more normal. Flip sign so higher = more anomalous,
# matching the convention used in backend/app/anomaly.py.
calib_scores = -model.score_samples(X_calib)
threshold = np.percentile(calib_scores, 99)
print(f"threshold (99th pct of held-out normal scores): {threshold:.4f}")

test_scores = -model.score_samples(X_test)
y_pred = (test_scores > threshold).astype(int)

# --- Baseline: 3-sigma rule, same idea as our physics-envelope layer ---
# Calibrated the same way as the Isolation Forest (99th percentile of a
# held-out normal slice) rather than a naive fixed z=3 cutoff — a fixed
# per-feature threshold is unfairly prone to false alarms here: with 59
# roughly-independent features, the chance that at least ONE exceeds any
# fixed z-cutoff by chance alone is much higher than the nominal per-feature
# false-positive rate (the multiple-comparisons problem). We report both so
# the effect is visible rather than hidden.
train_mean = X_fit_raw.mean(axis=0)
train_std = X_fit_raw.std(axis=0) + 1e-9


def max_z_score(X_raw):
    return np.abs((X_raw - train_mean) / train_std).max(axis=1)


baseline_calib_scores = max_z_score(X_calib_raw)
baseline_threshold_calibrated = np.percentile(baseline_calib_scores, 99)
print(f"baseline calibrated threshold (99th pct of held-out normal max-z): {baseline_threshold_calibrated:.4f}")
print(f"baseline naive fixed threshold for comparison: 3.0")

baseline_score = max_z_score(test_all[feature_cols].values)  # continuous score for ROC-AUC
baseline_pred = (baseline_score > baseline_threshold_calibrated).astype(int)
baseline_pred_naive = (baseline_score > 3.0).astype(int)


def range_recall(y_true, y_pred):
    """Fraction of contiguous attack segments with >=1 flagged point inside."""
    segments, in_seg, start = [], False, None
    for i, v in enumerate(y_true):
        if v == 1 and not in_seg:
            in_seg, start = True, i
        elif v == 0 and in_seg:
            in_seg = False
            segments.append((start, i))
    if in_seg:
        segments.append((start, len(y_true)))
    if not segments:
        return float("nan"), 0
    hit = sum(1 for s, e in segments if y_pred[s:e].any())
    return hit / len(segments), len(segments)


def evaluate(name, y_true, y_pred, y_score):
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_score)
    rr, n_seg = range_recall(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n--- {name} ---")
    print(f"point-wise precision: {p:.4f}  recall: {r:.4f}  F1: {f1:.4f}  ROC-AUC: {auc:.4f}")
    print(f"range-based recall (of {n_seg} attack segments): {rr:.4f}")
    print(f"confusion matrix [[TN FP][FN TP]]:\n{cm}")
    return {"precision": p, "recall": r, "f1": f1, "roc_auc": auc,
            "range_recall": rr, "n_attack_segments": n_seg,
            "confusion_matrix": cm.tolist()}


print("\n=== Results ===")
results = {}
results["isolation_forest"] = evaluate("Isolation Forest (this project's approach)", y_true, y_pred, test_scores)
results["baseline_3sigma_calibrated"] = evaluate("3-sigma baseline, calibrated threshold (fair comparison)", y_true, baseline_pred, baseline_score)
results["baseline_3sigma_naive"] = evaluate("3-sigma baseline, naive fixed z=3 (shows multiple-comparisons pitfall)", y_true, baseline_pred_naive, baseline_score)

# Dual-layer combination: flag if EITHER detector fires — this is the actual
# design used elsewhere in this project (physics envelope OR ML score), so
# it's worth testing here rather than just asserting it's a good idea.
combined_pred = np.logical_or(y_pred.astype(bool), baseline_pred.astype(bool)).astype(int)
combined_score = np.maximum(
    (test_scores - test_scores.min()) / (test_scores.max() - test_scores.min()),
    (baseline_score - baseline_score.min()) / (baseline_score.max() - baseline_score.min()),
)
results["dual_layer_combined"] = evaluate("Dual-layer (Isolation Forest OR calibrated 3-sigma)", y_true, combined_pred, combined_score)

with open(f"{REPORT_DIR}/results.json", "w") as f:
    json.dump({
        "dataset": "HAI 20.07 (icsdataset/hai, CC BY-SA 4.0)",
        "train_rows_normal_used_for_fit": int(X_fit_raw.shape[0]),
        "test_rows": int(len(test_all)),
        "test_attack_rate": float(y_true.mean()),
        "if_threshold": float(threshold),
        "baseline_threshold_calibrated": float(baseline_threshold_calibrated),
        **results,
    }, f, indent=2)
print(f"\nSaved results.json to {REPORT_DIR}")

# --- Plots ---
plt.style.use("default")

# 1. Score distribution
fig, ax = plt.subplots(figsize=(7, 4.5))
ax.hist(test_scores[y_true == 0], bins=80, alpha=0.6, label="Normal", color="#3F5066", density=True)
ax.hist(test_scores[y_true == 1], bins=80, alpha=0.6, label="Attack", color="#9C4A3C", density=True)
ax.axvline(threshold, color="#B98B4E", linestyle="--", label=f"Threshold ({threshold:.2f})")
ax.set_xlabel("Isolation Forest anomaly score")
ax.set_ylabel("Density")
ax.set_title("Anomaly score distribution — normal vs. attack (HAI 20.07 test set)")
ax.legend()
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/score_distribution.png", dpi=150)
plt.close(fig)

# 2. ROC curves (threshold-independent — naive vs calibrated baseline share one curve)
fig, ax = plt.subplots(figsize=(6, 6))
for name, score, color in [("Isolation Forest", test_scores, "#3F5066"), ("3-sigma baseline (any threshold)", baseline_score, "#9C4A3C")]:
    fpr, tpr, _ = roc_curve(y_true, score)
    auc = roc_auc_score(y_true, score)
    ax.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})", color=color, linewidth=2)
ax.plot([0, 1], [0, 1], "k--", alpha=0.3, linewidth=1)
ax.set_xlabel("False positive rate")
ax.set_ylabel("True positive rate")
ax.set_title("ROC curve — Isolation Forest vs. 3-sigma baseline")
ax.legend(loc="lower right")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/roc_curve.png", dpi=150)
plt.close(fig)

# 3. Confusion matrix heatmap
fig, ax = plt.subplots(figsize=(5.5, 5))
cm = confusion_matrix(y_true, y_pred)
im = ax.imshow(cm, cmap="Blues")
for i in range(2):
    for j in range(2):
        ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=13)
ax.set_xticks([0, 1]); ax.set_xticklabels(["Normal", "Attack"])
ax.set_yticks([0, 1]); ax.set_yticklabels(["Normal", "Attack"])
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
ax.set_title("Confusion matrix — Isolation Forest\n(99th-percentile threshold)")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/confusion_matrix.png", dpi=150)
plt.close(fig)

# 4. Point-wise vs range-based recall comparison
fig, ax = plt.subplots(figsize=(7.5, 4.8))
labels = ["Isolation\nForest", "3-sigma\n(calibrated)", "3-sigma\n(naive z=3)", "Dual-layer\n(OR combined)"]
point_r = [results[k]["recall"] for k in ["isolation_forest", "baseline_3sigma_calibrated", "baseline_3sigma_naive", "dual_layer_combined"]]
range_r = [results[k]["range_recall"] for k in ["isolation_forest", "baseline_3sigma_calibrated", "baseline_3sigma_naive", "dual_layer_combined"]]
x = np.arange(len(labels))
w = 0.35
ax.bar(x - w / 2, point_r, w, label="Point-wise recall", color="#3F5066")
ax.bar(x + w / 2, range_r, w, label="Range-based recall", color="#B98B4E")
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
ax.set_ylim(0, 1.05)
ax.set_ylabel("Recall")
ax.set_title("Point-wise vs. range-based recall\n(why the metric choice matters for time-series)")
ax.legend()
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/recall_comparison.png", dpi=150)
plt.close(fig)

print(f"Saved 4 plots to {OUT_DIR}")
print("\nDONE")

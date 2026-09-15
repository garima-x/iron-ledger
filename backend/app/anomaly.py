import logging
import numpy as np

logger = logging.getLogger("ironledger.anomaly")

THRESHOLDS = {"pressure": 9.5, "temp": 95.0, "vibration": 5.5}

_model = None
_model_error: str | None = None


def _baseline_sample(n: int = 300, seed: int = 7) -> np.ndarray:
    """Synthetic baseline telemetry the model is trained on — stands in for
    the plant's normal operating envelope (see the simulator/README note on
    what a real deployment would train against instead)."""
    rng = np.random.default_rng(seed)
    pressure = rng.normal(6.2, 0.35, n)
    temp = rng.normal(71, 2.2, n)
    vibration = rng.normal(2.2, 0.3, n)
    return np.column_stack([pressure, temp, vibration])


def _get_model():
    global _model, _model_error
    if _model is not None or _model_error is not None:
        return _model
    try:
        from sklearn.ensemble import IsolationForest

        model = IsolationForest(n_estimators=150, contamination=0.05, random_state=7)
        model.fit(_baseline_sample())
        _model = model
    except Exception as exc:  # noqa: BLE001
        _model_error = f"scikit-learn unavailable, falling back to z-score heuristic: {exc}"
        logger.warning(_model_error)
    return _model


def physics_breach(pressure: float, temp: float, vibration: float) -> list[str]:
    breaches = []
    if pressure > THRESHOLDS["pressure"]:
        breaches.append(f"pressure {pressure} bar exceeds {THRESHOLDS['pressure']} bar envelope")
    if temp > THRESHOLDS["temp"]:
        breaches.append(f"temperature {temp} °C exceeds {THRESHOLDS['temp']} °C envelope")
    if vibration > THRESHOLDS["vibration"]:
        breaches.append(f"vibration {vibration} mm/s exceeds {THRESHOLDS['vibration']} mm/s envelope")
    return breaches


def ml_score(pressure: float, temp: float, vibration: float) -> float:
    """Returns an anomaly score in [0, 1] — higher is more anomalous."""
    model = _get_model()
    if model is not None:
        raw = model.decision_function([[pressure, temp, vibration]])[0]
        # decision_function: higher = more normal. Squash to [0,1], invert.
        return float(max(0.0, min(1.0, 0.5 - raw)))

    # Fallback: simple multivariate z-score heuristic.
    baseline = _baseline_sample()
    mean = baseline.mean(axis=0)
    std = baseline.std(axis=0)
    z = np.abs((np.array([pressure, temp, vibration]) - mean) / std)
    return float(max(0.0, min(1.0, z.mean() / 5)))


def evaluate(pressure: float, temp: float, vibration: float) -> dict:
    breaches = physics_breach(pressure, temp, vibration)
    score = ml_score(pressure, temp, vibration)
    return {
        "physics_breach": breaches,
        "ml_score": round(score, 3),
        "is_anomaly": bool(breaches) or score > 0.6,
    }

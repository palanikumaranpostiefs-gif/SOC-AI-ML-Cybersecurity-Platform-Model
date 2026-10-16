from typing import List, Dict, Any
import pandas as pd
from xgboost import XGBClassifier
import json
from pathlib import Path
import joblib

class XGBoostService:
    _latest_model: Any = None
    _latest_metadata: Dict[str, Any] = {}
    """Service to train an XGBoost classifier on numeric features with labels.

    The service validates that a labeled dataset is provided, that all feature
    vectors are numeric and share the same schema, and that the label column is
    present and non‑empty. The model is trained deterministically (fixed random
    seed) and is **not** persisted – it lives only for the duration of the API
    call.
    """

    def __init__(
        self,
        random_state: int = 42,
        n_estimators: int = 100,
        max_depth: int = 6,
        min_child_weight: int = 0,
    ):
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_child_weight = min_child_weight
        if self.__class__._latest_model is not None:
            self.model = self.__class__._latest_model
        else:
            self.model = XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                min_child_weight=self.min_child_weight,
                eval_metric="logloss",
                random_state=self.random_state,
            )
        # Initialize artifact directory (same convention as IsolationForestService)
        self.artifact_dir = Path(__file__).resolve().parents[3] / "model-artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def _validate_features(self, features: List[Dict[str, Any]]) -> pd.DataFrame:
        if not features:
            raise ValueError("Feature list is empty.")
        # Ensure consistent feature keys and numeric values
        first_keys = set(features[0].keys())
        for idx, feat in enumerate(features):
            if set(feat.keys()) != first_keys:
                raise ValueError(
                    f"Inconsistent feature keys at index {idx}. Expected {first_keys}, got {set(feat.keys())}."
                )
            for k, v in feat.items():
                if not isinstance(v, (int, float)):
                    raise ValueError(
                        f"Non‑numeric value for feature '{k}' in record {idx}: {v!r}."
                    )
        return pd.DataFrame(features)

    def _validate(self, features: List[Dict[str, Any]], labels: List[Any]) -> pd.DataFrame:
        if len(features) != len(labels):
            raise ValueError("Number of feature vectors does not match number of labels.")
        df = self._validate_features(features)
        # Convert known string labels to deterministic integer IDs
        # Mapping follows project labeling policy: benign -> 0, malicious -> 1
        label_mapping = {"benign": 0, "malicious": 1}
        if any(isinstance(l, str) for l in labels):
            converted = []
            for l in labels:
                if isinstance(l, str):
                    if l not in label_mapping:
                        raise ValueError(f"Unsupported label value: {l}")
                    converted.append(label_mapping[l])
                else:
                    converted.append(l)
            labels = converted
        # Validate that all labels are now integers (or already ints)
        for idx, lbl in enumerate(labels):
            if not isinstance(lbl, int):
                raise ValueError(f"Invalid label type at index {idx}: {type(lbl)}.")
        return df, pd.Series(labels)

    def train(self, features: List[Dict[str, Any]], labels: List[Any]) -> Dict[str, Any]:
        """Train the XGBoost classifier.

        Parameters
        ----------
        features: List[Dict[str, Any]]
            Feature dictionaries for each record.
        labels: List[Any]
            Corresponding labels (e.g., "benign"/"malicious" or class IDs).

        Returns
        -------
        Dict with training summary.
        """
        df, lbl = self._validate(features, labels)
        self.model.fit(df, lbl)
        # Cache the trained model for later save/load requests
        self.__class__._latest_model = self.model
        classes = self.model.get_booster().feature_names
        result = {
            "status": "success",
            "model_type": "XGBoost",
            "records_used": len(df),
            "num_features": len(df.columns),
            "num_classes": int(self.model.n_classes_) if hasattr(self.model, "n_classes_") else None,
            "params": {
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "min_child_weight": self.min_child_weight,
                "random_state": self.random_state,
            },
            "label_mapping": {"benign": 0, "malicious": 1},
        }
        # Cache metadata for saving
        self.__class__._latest_metadata = result
        return result

    # ---------------------------------------------------------------------
    # Persistence helpers (Phase 8)
    # ---------------------------------------------------------------------
    def _model_path(self, name: str) -> Path:
        """Return filesystem path for a saved XGBoost model."""
        return self.artifact_dir / f"{name}_xgboost.pkl"

    def _meta_path(self, name: str) -> Path:
        """Return path for model metadata JSON file."""
        return self.artifact_dir / f"{name}_xgboost_meta.json"

    def save_model(self, name: str, metadata: Dict[str, Any]) -> None:
        """Persist the trained model and its metadata.

        Model is saved with joblib; metadata (including label mapping) is stored as JSON.
        """
        model_file = self._model_path(name)
        meta_file = self._meta_path(name)
        joblib.dump(self.model, model_file)
        meta = {
            "label_mapping": {"benign": 0, "malicious": 1},
            "features": metadata.get("num_features"),
            **metadata,
        }
        meta_file.write_text(json.dumps(meta, indent=2))

    def load_model(self, name: str) -> Dict[str, Any]:
        """Load a persisted model and its metadata.

        Returns dict with keys 'model' and 'metadata'. Raises FileNotFoundError if missing.
        """
        model_file = self._model_path(name)
        meta_file = self._meta_path(name)
        if not model_file.is_file():
            raise FileNotFoundError(f"Model file '{model_file.name}' not found.")
        if not meta_file.is_file():
            raise FileNotFoundError(f"Metadata file '{meta_file.name}' not found.")
        model = joblib.load(model_file)
        metadata = json.loads(meta_file.read_text())
        self.model = model
        self.__class__._latest_model = model
        self.__class__._latest_metadata = metadata
        return {"model": model, "metadata": metadata}

    def predict(self, features: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate predictions and class probabilities for the given features.

        Parameters
        ----------
        features : List[Dict[str, Any]]
            Feature dictionaries for each record.

        Returns
        -------
        Dict with status, model_type, records_count, predictions, predicted_labels, and probabilities.
        """
        if self.model is None or not hasattr(self.model, "n_classes_"):
            raise ValueError("No trained XGBoost model is available.")

        df = self._validate_features(features)

        # Check feature count and alignment against trained booster/model
        expected_features = None
        try:
            expected_features = self.model.get_booster().feature_names
        except Exception:
            expected_features = getattr(self.model, "feature_names_in_", None)

        if expected_features is not None:
            if len(df.columns) != len(expected_features):
                raise ValueError(
                    f"Feature count mismatch: expected {len(expected_features)}, got {len(df.columns)}."
                )
            missing = set(expected_features) - set(df.columns)
            if missing:
                raise ValueError(f"Missing expected features: {sorted(list(missing))}.")
            df = df[list(expected_features)]

        preds = self.model.predict(df)
        preds_list = preds.tolist()

        probs = None
        if hasattr(self.model, "predict_proba"):
            try:
                probs = self.model.predict_proba(df).tolist()
            except Exception:
                probs = None

        label_mapping = {"benign": 0, "malicious": 1}
        inv_mapping = {v: k for k, v in label_mapping.items()}
        predicted_labels = [inv_mapping.get(p, str(p)) for p in preds_list]

        result = {
            "status": "success",
            "model_type": "XGBoost",
            "records_count": len(df),
            "predictions": preds_list,
            "prediction": preds_list,
            "predicted_labels": predicted_labels,
        }
        if probs is not None:
            result["probabilities"] = probs
            result["class_probabilities"] = probs
        return result


from typing import List, Dict, Any
import pandas as pd
from sklearn.ensemble import IsolationForest
import json
from pathlib import Path
import joblib

class IsolationForestService:
    _latest_model: Any = None
    _latest_metadata: Dict[str, Any] = {}
    """Service to train an Isolation Forest model on numeric features.

    The service validates input, trains a deterministic Isolation Forest, and
    returns a summary of the training run. The model is **not** persisted – it
    exists only for the duration of the request.
    """

    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.n_estimators = n_estimators
        self.random_state = random_state
        if self.__class__._latest_model is not None:
            self.model = self.__class__._latest_model
        else:
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                contamination="auto",
            )
        # Directory for persisted models (project root /model-artifacts)
        self.artifact_dir = Path(__file__).resolve().parents[3] / "model-artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def _validate_features(self, features: List[Dict[str, Any]]) -> pd.DataFrame:
        if not features:
            raise ValueError("Feature list is empty.")
        # Ensure all feature dicts have the same keys and contain only numeric values
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

    def train(self, features: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the Isolation Forest model.

        Parameters
        ----------
        features: List[Dict[str, Any]]
            A list where each dict represents a numeric feature vector.

        Returns
        -------
        Dict containing training summary information.
        """
        # Validation: require at least 2 records for training
        if len(features) < 2:
            raise ValueError(f"Isolation Forest training requires at least 2 records; received {len(features)}.")
        df = self._validate_features(features)
        self.model.fit(df)
        # Cache the trained model for later save/load requests
        self.__class__._latest_model = self.model
        # The model does not expose a meaningful training metric; we report basic stats
        result = {
            "status": "success",
            "model_type": "IsolationForest",
            "records_used": len(df),
            "num_features": len(df.columns),
            "params": {
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
            },
        }
        # Cache metadata for saving
        self.__class__._latest_metadata = result
        return result

    # ---------------------------------------------------------------------
    # Persistence helpers (Phase 8)
    # ---------------------------------------------------------------------
    def _model_path(self, name: str) -> Path:
        """Return filesystem path for a saved Isolation Forest model."""
        return self.artifact_dir / f"{name}_isolation_forest.pkl"

    def _meta_path(self, name: str) -> Path:
        """Return path for model metadata JSON file."""
        return self.artifact_dir / f"{name}_isolation_forest_meta.json"

    def save_model(self, name: str, metadata: Dict[str, Any]) -> None:
        """Persist the trained Isolation Forest model and its metadata.

        The model is serialized with ``joblib``; metadata is stored as JSON.
        """
        model_file = self._model_path(name)
        meta_file = self._meta_path(name)
        joblib.dump(self.model, model_file)
        meta = {
            "features": metadata.get("num_features"),
            **metadata,
        }
        meta_file.write_text(json.dumps(meta, indent=2))

    def load_model(self, name: str) -> Dict[str, Any]:
        """Load a persisted Isolation Forest model and its metadata.

        Returns dict with keys ``model`` and ``metadata``.
        Raises ``FileNotFoundError`` if missing.
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
        """Generate predictions and anomaly scores for the given features.

        Parameters
        ----------
        features : List[Dict[str, Any]]
            A list where each dict represents a numeric feature vector.

        Returns
        -------
        Dict with status, model_type, records_count, predictions, and anomaly_scores.
        """
        if self.model is None or not hasattr(self.model, "estimators_"):
            raise ValueError("No trained Isolation Forest model is available.")

        df = self._validate_features(features)

        # Validate feature counts and names if model recorded them during training
        if hasattr(self.model, "n_features_in_") and df.shape[1] != self.model.n_features_in_:
            raise ValueError(
                f"Feature count mismatch: expected {self.model.n_features_in_}, got {df.shape[1]}."
            )
        if hasattr(self.model, "feature_names_in_"):
            missing = set(self.model.feature_names_in_) - set(df.columns)
            if missing:
                raise ValueError(f"Missing expected features: {sorted(list(missing))}.")
            df = df[list(self.model.feature_names_in_)]

        preds = self.model.predict(df)
        scores = self.model.decision_function(df)

        return {
            "status": "success",
            "model_type": "IsolationForest",
            "records_count": len(df),
            "predictions": preds.tolist(),
            "anomaly_scores": scores.tolist(),
        }


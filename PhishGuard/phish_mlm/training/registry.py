"""
Versioned model registry with champion pointer and O(1) rollback.

Layout on disk:
    models/registry/
        v1/  model.pkl  meta.json
        v2/  model.pkl  meta.json
        ...
        CHAMPION            # text file containing the active version dir name

Why a registry (vs. overwriting one .pkl):
    - Auditability: every trained candidate is kept with its metrics + the hash
      of the data it was trained on. You can answer "why did accuracy change?"
    - Safe promotion: the champion pointer only moves after the gate passes.
    - Instant rollback: revert the pointer to the previous version — no retrain.

Complexity:
    promote / rollback / current : O(1) (single small file write/read)
    save_candidate               : O(artifact_size) IO
"""
import json
import pickle
import shutil
import time
from pathlib import Path
from typing import Optional, List, Tuple

_REGISTRY_DIRNAME = "registry"
_CHAMPION_FILE = "CHAMPION"
_MODEL_FILE = "model.pkl"
_META_FILE = "meta.json"


class ModelRegistry:
    def __init__(self, models_dir: Path):
        self.root = Path(models_dir) / _REGISTRY_DIRNAME
        self.root.mkdir(parents=True, exist_ok=True)
        self._champion_path = self.root / _CHAMPION_FILE

    # ------------------------------------------------------------------ list
    def list_versions(self) -> List[str]:
        """Version dir names sorted by their numeric suffix (v1, v2, …)."""
        dirs = [p.name for p in self.root.iterdir()
                if p.is_dir() and p.name.startswith("v")]
        return sorted(dirs, key=lambda n: int(n[1:]) if n[1:].isdigit() else 0)

    def _next_version(self) -> str:
        versions = self.list_versions()
        n = max((int(v[1:]) for v in versions if v[1:].isdigit()), default=0)
        return f"v{n + 1}"

    # ------------------------------------------------------------------ save
    def save_candidate(self, artifact: dict, metrics: dict, extra_meta: dict = None) -> str:
        """
        Persist a trained artifact as a new immutable version. Does NOT promote.
        Returns the new version name (e.g. 'v3').
        """
        version = self._next_version()
        vdir = self.root / version
        vdir.mkdir(parents=True, exist_ok=True)
        with open(vdir / _MODEL_FILE, "wb") as f:
            pickle.dump(artifact, f)
        meta = {
            "version": version,
            "created_at": time.time(),
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "feature_version": artifact.get("feature_version"),
            "calibrated": artifact.get("platt") is not None,
            "metrics": metrics,
            **(extra_meta or {}),
        }
        with open(vdir / _META_FILE, "w") as f:
            json.dump(meta, f, indent=2)
        return version

    # -------------------------------------------------------------- champion
    def current_version(self) -> Optional[str]:
        if not self._champion_path.exists():
            return None
        v = self._champion_path.read_text().strip()
        return v if (self.root / v).exists() else None

    def promote(self, version: str) -> None:
        """Atomically point the champion at `version` (O(1))."""
        if not (self.root / version).exists():
            raise ValueError(f"unknown version: {version}")
        tmp = self._champion_path.with_suffix(".tmp")
        tmp.write_text(version)
        tmp.replace(self._champion_path)  # atomic on POSIX

    def rollback(self) -> Optional[str]:
        """
        Revert the champion pointer to the previous version. Returns the version
        rolled back to, or None if there is no prior version.
        """
        versions = self.list_versions()
        cur = self.current_version()
        if cur is None or cur not in versions:
            return None
        idx = versions.index(cur)
        if idx == 0:
            return None
        prev = versions[idx - 1]
        self.promote(prev)
        return prev

    # ------------------------------------------------------------------ load
    def load(self, version: str) -> Tuple[dict, dict]:
        """Return (artifact, meta) for a specific version."""
        vdir = self.root / version
        with open(vdir / _MODEL_FILE, "rb") as f:
            artifact = pickle.load(f)
        meta = json.loads((vdir / _META_FILE).read_text())
        return artifact, meta

    def load_champion(self) -> Optional[Tuple[dict, dict]]:
        cur = self.current_version()
        return self.load(cur) if cur else None

    def champion_metrics(self) -> dict:
        cur = self.current_version()
        if not cur:
            return {}
        meta = json.loads((self.root / cur / _META_FILE).read_text())
        return meta.get("metrics", {})

    def prune(self, keep: int = 10) -> int:
        """Delete oldest versions beyond `keep`, never deleting the champion."""
        versions = self.list_versions()
        champion = self.current_version()
        removed = 0
        for v in versions[:-keep] if len(versions) > keep else []:
            if v == champion:
                continue
            shutil.rmtree(self.root / v, ignore_errors=True)
            removed += 1
        return removed

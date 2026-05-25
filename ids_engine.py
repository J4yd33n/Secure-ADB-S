#!/usr/bin/env python3
import json
import time
import random
import threading
import logging
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
from typing import Deque, Dict, Any, List, Optional, Tuple, Callable

import numpy as np
import psutil
from sklearn.ensemble import IsolationForest

ALERT_FILE = "alerts.json"
BUS_FILE = "attack_bus.json"


# ──────────────────────────────────────────────────────────────────
# Helpers & Utilities
# ──────────────────────────────────────────────────────────────────

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def load_json(path: str, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: str, data) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def severity(score: float) -> str:
    if score > 0.90:
        return "CRITICAL"
    elif score > 0.80:
        return "HIGH"
    elif score > 0.65:
        return "MEDIUM"
    else:
        return "LOW"


# ──────────────────────────────────────────────────────────────────
# Isolation Forest Detector
# ──────────────────────────────────────────────────────────────────

class ForestDetector:
    """
    Wraps IsolationForest with:
      - A warm-up phase that collects baseline (assumed-normal) traffic.
      - Periodic model retraining on a sliding window of recent samples.
      - Score normalization: raw decision_function output → [0, 1].

    Parameters
    ----------
    name          : human-readable label (used in logs)
    warmup_size   : number of samples to collect before the first fit
    window_size   : max samples kept for retraining
    retrain_every : retrain the forest after this many new samples
    contamination : expected fraction of anomalies (IsolationForest param)
    n_estimators  : number of trees in the forest
    """

    def __init__(
        self,
        name: str,
        warmup_size: int = 60,
        window_size: int = 500,
        retrain_every: int = 50,
        contamination: float = 0.05,
        n_estimators: int = 100,
    ) -> None:
        self.name = name
        self.warmup_size = warmup_size
        self.window_size = window_size
        self.retrain_every = retrain_every
        self.contamination = contamination
        self.n_estimators = n_estimators

        self._buffer: deque = deque(maxlen=window_size)
        self._model: Optional[IsolationForest] = None
        self._samples_since_retrain: int = 0
        self._score_min: float = -0.5   # tracked for normalisation
        self._score_max: float = 0.5
        self._logger = logging.getLogger(f"ForestDetector[{name}]")

    # ── public API ────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        """True once the model has been trained at least once."""
        return self._model is not None

    def observe(self, features: List[float]) -> Optional[float]:
        """
        Feed one feature vector.

        Returns
        -------
        float in [0, 1] if the model is ready and considers the sample
        anomalous (score > 0.5); None otherwise.
        """
        vec = np.array(features, dtype=float).reshape(1, -1)
        self._buffer.append(features)
        self._samples_since_retrain += 1

        # Warm-up: just collect samples
        if len(self._buffer) < self.warmup_size:
            return None

        # Retrain periodically
        if self._samples_since_retrain >= self.retrain_every or self._model is None:
            self._fit()

        if self._model is None:
            return None

        raw = float(self._model.decision_function(vec)[0])
        score = self._normalize(raw)
        return score if score > 0.5 else None

    # ── internal ──────────────────────────────────────────────────

    def _fit(self) -> None:
        X = np.array(list(self._buffer), dtype=float)
        if X.ndim == 1:
            X = X.reshape(-1, 1)
        try:
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42,
                n_jobs=1,
            )
            model.fit(X)
            scores = model.decision_function(X)
            self._score_min = float(scores.min())
            self._score_max = float(scores.max())
            self._model = model
            self._samples_since_retrain = 0
            self._logger.debug(
                "Retrained on %d samples | score range [%.3f, %.3f]",
                len(X), self._score_min, self._score_max,
            )
        except Exception as exc:
            self._logger.warning("Fit failed: %s", exc)

    def _normalize(self, raw: float) -> float:
        """
        Map decision_function output to [0, 1].

        IsolationForest: negative raw → anomalous, positive → normal.
        We invert so that 1 = most anomalous.
        """
        lo, hi = self._score_min, self._score_max
        if hi == lo:
            return 0.5
        # Clamp to tracked range
        raw = max(lo, min(hi, raw))
        # Invert: lower raw score → higher anomaly score
        normalized = 1.0 - (raw - lo) / (hi - lo)
        return round(normalized, 4)


# ──────────────────────────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    attack_type: str
    score: float          # anomaly score from IsolationForest [0, 1]
    details: Dict[str, Any]


# ──────────────────────────────────────────────────────────────────
# IDS Engine
# ──────────────────────────────────────────────────────────────────

class ATCIDS:
    def __init__(self, airport: str = "ADS-B", scan_interval: float = 2.0) -> None:
        self.airport = airport
        self.scan_interval = scan_interval
        self.logger = logging.getLogger(f"ATC_IDS[{airport}]")

        # ── Traffic buffers ───────────────────────────────────────
        self.adsb_1090:   Deque[Tuple[str, float]] = deque(maxlen=10000)
        self.acars_vhf:   Deque[Tuple[str, float]] = deque(maxlen=5000)
        self.cpdlc_port:  Deque[Tuple[str, float]] = deque(maxlen=2000)
        self.atis_port:   Deque[Tuple[str, float]] = deque(maxlen=1000)
        self.vdl2_port:   Deque[Tuple[str, float]] = deque(maxlen=5000)
        self.radar_10900: Deque[Tuple[str, float]] = deque(maxlen=2000)

        # ── Runtime state ─────────────────────────────────────────
        self.detection_active: bool = True
        self.last_scan_ts: float = 0.0
        self.alerts: List[Dict[str, Any]] = []

        # Clean start
        self.alerts.clear()
        save_json(ALERT_FILE, self.alerts)

        # ── One ForestDetector per detection rule ─────────────────
        # Shared settings; tweak contamination per rule if needed.
        _fd = lambda name, contamination=0.05: ForestDetector(
            name=name,
            warmup_size=20,
            window_size=500,
            retrain_every=20,
            contamination=contamination,
        )
        self._forests: Dict[str, ForestDetector] = {
            "ADS_B_SPOOFING":   _fd("ADS_B_SPOOFING",  0.04),
            "ACARS_FLOOD":      _fd("ACARS_FLOOD",      0.05),
            "CPDLC_JAMMING":    _fd("CPDLC_JAMMING",   0.04),
            "ATIS_DISRUPTION":  _fd("ATIS_DISRUPTION", 0.05),
            "VDL2_OVERLOAD":    _fd("VDL2_OVERLOAD",   0.05),
            "RADAR_SPOOFING":   _fd("RADAR_SPOOFING",  0.04),
            "ICAO_COLLISION":   _fd("ICAO_COLLISION",  0.03),
            "ATC_BAND_NOISE":   _fd("ATC_BAND_NOISE",  0.05),
            "MLAT_JAMMING":     _fd("MLAT_JAMMING",    0.04),
            "FMS_INJECTION":    _fd("FMS_INJECTION",   0.04),
            "GPS_SPOOFING":     _fd("GPS_SPOOFING",    0.03),
        }

        # ── Detection rules (ordered list) ───────────────────────
        self.detection_rules: List[Callable[[float], Optional[DetectionResult]]] = [
            self.detect_adsb_spoofing,
            self.detect_acars_flood,
            self.detect_cpdlc_jamming,
            self.detect_atis_disruption,
            self.detect_vdl2_overload,
            self.detect_radar_spoof,
            self.detect_icao_collision,
            self.detect_atc_band_noise,
            self.detect_mlat_jamming,
            self.detect_fms_injection,
            self.detect_gps_spoofing,
        ]

    # ── Simulation ────────────────────────────────────────────────

    def _simulate_aviation_traffic(self) -> None:
        ports: Dict[str, Deque[Tuple[str, float]]] = {
            "adsb":  self.adsb_1090,
            "acars": self.acars_vhf,
            "atis":  self.atis_port,
            "radar": self.radar_10900,
            "vdl2":  self.vdl2_port,
            "cpdlc": self.cpdlc_port,
        }
        while self.detection_active:
            port_name, buffer = random.choice(list(ports.items()))
            ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            buffer.append((ip, time.time()))
            time.sleep(random.uniform(0.001, 0.05))

    def _start_traffic_simulator(self) -> None:
        t = threading.Thread(target=self._simulate_aviation_traffic, daemon=True)
        t.start()

    # ── Detection helpers ─────────────────────────────────────────

    @staticmethod
    def _recent(
        buffer: Deque[Tuple[str, float]], now: float, window: float
    ) -> List[Tuple[str, float]]:
        return [item for item in buffer if now - item[1] < window]

    def _score(self, rule_name: str, features: List[float]) -> Optional[float]:
        """
        Delegate to the per-rule IsolationForest.
        Returns an anomaly score in (0.5, 1.0] or None.
        """
        return self._forests[rule_name].observe(features)

    # ── Detection rules ───────────────────────────────────────────

    def detect_adsb_spoofing(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.adsb_1090, now, window=5.0)
        count = len(recent)
        icaos = len({ip for ip, _ in recent}) if recent else 0
        ratio = icaos / count if count else 0.0

        # Features: [message_count, unique_icao_count, unique_ratio]
        score = self._score("ADS_B_SPOOFING", [count, icaos, ratio])
        if score is None:
            return None
        return DetectionResult(
            attack_type="ADS_B_SPOOFING",
            score=score,
            details={"msgs": count, "ghost_aircraft": icaos, "unique_ratio": round(ratio, 3)},
        )

    def detect_acars_flood(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.acars_vhf, now, window=10.0)
        count = len(recent)

        score = self._score("ACARS_FLOOD", [count])
        if score is None:
            return None
        return DetectionResult(
            attack_type="ACARS_FLOOD",
            score=score,
            details={"msgs": count},
        )

    def detect_cpdlc_jamming(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.cpdlc_port, now, window=30.0)
        count = len(recent)

        score = self._score("CPDLC_JAMMING", [count])
        if score is None:
            return None
        return DetectionResult(
            attack_type="CPDLC_JAMMING",
            score=score,
            details={"connections": count},
        )

    def detect_atis_disruption(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.atis_port, now, window=60.0)
        count = len(recent)

        score = self._score("ATIS_DISRUPTION", [count])
        if score is None:
            return None
        return DetectionResult(
            attack_type="ATIS_DISRUPTION",
            score=score,
            details={"broadcasts": count},
        )

    def detect_vdl2_overload(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.vdl2_port, now, window=20.0)
        count = len(recent)

        score = self._score("VDL2_OVERLOAD", [count])
        if score is None:
            return None
        return DetectionResult(
            attack_type="VDL2_OVERLOAD",
            score=score,
            details={"datagrams": count},
        )

    def detect_radar_spoof(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.radar_10900, now, window=10.0)
        count = len(recent)

        score = self._score("RADAR_SPOOFING", [count])
        if score is None:
            return None
        return DetectionResult(
            attack_type="RADAR_SPOOFING",
            score=score,
            details={"returns": count},
        )

    def detect_icao_collision(self, now: float) -> Optional[DetectionResult]:
        """
        Features: ratio of adsb messages from duplicate IPs within a 1-second window.
        """
        recent = self._recent(self.adsb_1090, now, window=1.0)
        count = len(recent)
        from collections import Counter
        if count == 0:
            dup_ratio = 0.0
            max_dup = 0
        else:
            c = Counter(ip for ip, _ in recent)
            max_dup = max(c.values())
            dup_ratio = sum(v for v in c.values() if v > 1) / count

        score = self._score("ICAO_COLLISION", [count, max_dup, dup_ratio])
        if score is None:
            return None
        return DetectionResult(
            attack_type="ICAO_COLLISION",
            score=score,
            details={"window_msgs": count, "max_dup": max_dup, "dup_ratio": round(dup_ratio, 3)},
        )

    def detect_atc_band_noise(self, _: float) -> Optional[DetectionResult]:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent

        score = self._score("ATC_BAND_NOISE", [cpu, mem])
        if score is None:
            return None
        return DetectionResult(
            attack_type="ATC_BAND_NOISE",
            score=score,
            details={"cpu_impact": cpu, "mem_pct": mem},
        )

    def detect_mlat_jamming(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.adsb_1090, now, window=2.0)
        count = len(recent)
        # Inter-arrival rate: msgs/sec
        rate = count / 2.0

        score = self._score("MLAT_JAMMING", [count, rate])
        if score is None:
            return None
        return DetectionResult(
            attack_type="MLAT_JAMMING",
            score=score,
            details={"spike": count, "rate_per_sec": round(rate, 2)},
        )

    def detect_fms_injection(self, now: float) -> Optional[DetectionResult]:
        recent = self._recent(self.acars_vhf, now, window=5.0)
        count = len(recent)
        total = len(self.acars_vhf)

        score = self._score("FMS_INJECTION", [count, total])
        if score is None:
            return None
        return DetectionResult(
            attack_type="FMS_INJECTION",
            score=score,
            details={"pos_msgs": total, "recent_5s": count},
        )

    def detect_gps_spoofing(self, now: float) -> Optional[DetectionResult]:
        adsb_total = len(self.adsb_1090)
        recent = self._recent(self.adsb_1090, now, window=10.0)
        count = len(recent)
        unique = len({ip for ip, _ in recent})
        anomaly_ratio = (unique / count) if count else 0.0

        score = self._score("GPS_SPOOFING", [adsb_total, count, anomaly_ratio])
        if score is None:
            return None
        return DetectionResult(
            attack_type="GPS_SPOOFING",
            score=score,
            details={"adsb_total": adsb_total, "anomalies": count, "unique_ratio": round(anomaly_ratio, 3)},
        )

    # ── Alert handling ────────────────────────────────────────────

    def _emit_alert(self, alert: Dict[str, Any]) -> None:
        self.alerts.append(alert)
        save_json(ALERT_FILE, self.alerts)

    def _process_bus_attacks(self) -> None:
        queue = load_json(BUS_FILE, [])
        if not queue:
            return

        attack = queue.pop(0)
        # Bus attacks bypass the forest (external injection); use a fixed score.
        score = 0.78
        sev = severity(score)

        alert = {
            "timestamp": current_timestamp(),
            "airport": self.airport,
            "attack": attack.get("type", "ATC_UNKNOWN"),
            "icao": attack.get("icao", "N/A"),
            "source": "BUS",
            "details": attack,
            "ml_score": score,
            "severity": sev,
        }

        self._emit_alert(alert)
        save_json(BUS_FILE, queue)

        self.logger.warning(
            "[ATC-BUS] %s → %s | %s | %.2f",
            alert["attack"], alert["icao"], alert["severity"], alert["ml_score"],
        )

    def _run_detection_cycle(self, now: float) -> None:
        for rule in self.detection_rules:
            result = rule(now)
            if result is None:
                continue

            sev = severity(result.score)
            alert = {
                "timestamp": current_timestamp(),
                "airport": self.airport,
                "attack": result.attack_type,
                "icao": "AUTO_DETECTED",
                "source": "ISOLATION_FOREST",
                "details": result.details,
                "ml_score": result.score,
                "severity": sev,
            }

            self._emit_alert(alert)

            self.logger.warning(
                "[IF-AUTO] %s | %s | score=%.4f",
                alert["attack"], alert["severity"], alert["ml_score"],
            )

    # ── Main loop ─────────────────────────────────────────────────

    def run(self) -> None:
        self.logger.info("ADS-B ATC IDS Engine — Isolation Forest Edition")
        self.logger.info("Detecting %d attack types (warm-up: 20 samples each)", len(self.detection_rules))
        self.logger.info("Protocols: ADS-B, ACARS, CPDLC, ATIS, VDL2, Radar")
        self.logger.info("Waiting for aviation attacks...\n")

        self._start_traffic_simulator()
        self.logger.info("Traffic simulator started. IDS active...\n")

        try:
            while self.detection_active:
                time.sleep(1.0)

                # 1) Process externally injected attacks
                self._process_bus_attacks()

                # 2) Run detection rules every scan_interval
                now = time.time()
                if now - self.last_scan_ts >= self.scan_interval:
                    self._run_detection_cycle(now)
                    self.last_scan_ts = now

        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt received, stopping IDS...")
            self.detection_active = False


# ── Entry point ───────────────────────────────────────────────────

def main() -> None:
    setup_logging()
    ids = ATCIDS(airport="ADS-B", scan_interval=0.5)
    ids.run()


if __name__ == "__main__":
    main()

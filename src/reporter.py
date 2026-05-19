from __future__ import annotations

import csv
import statistics
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.decision import ThreatAssessment, Decision

logger = logging.getLogger(__name__)


@dataclass
class RunMetrics:
    total_ips_analyzed: int
    blocked_count: int
    monitored_count: int
    ignored_count: int
    avg_response_time_ms: float
    p95_response_time_ms: float
    api_cache_hits: int
    api_cache_misses: int
    # Ground truth metrics (None when no ground truth provided)
    true_positives: Optional[int] = None
    false_positives: Optional[int] = None
    true_negatives: Optional[int] = None
    false_negatives: Optional[int] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None


class Reporter:
    def __init__(self, report_path: Path) -> None:
        self._report_path = report_path
        self._assessments: list[ThreatAssessment] = []

    def record(self, assessment: ThreatAssessment) -> None:
        """Append a ThreatAssessment to the internal list."""
        self._assessments.append(assessment)

    def compute_metrics(
        self,
        ground_truth: Optional[dict[str, bool]] = None,
        api_cache_hits: int = 0,
        api_cache_misses: int = 0,
    ) -> RunMetrics:
        """Compute and return RunMetrics from the recorded assessments."""
        total = len(self._assessments)
        blocked_count = sum(1 for a in self._assessments if a.decision == Decision.BLOCK)
        monitored_count = sum(1 for a in self._assessments if a.decision == Decision.MONITOR)
        ignored_count = sum(1 for a in self._assessments if a.decision == Decision.IGNORE)

        times = [a.response_time_ms for a in self._assessments]
        if len(times) == 0:
            avg_response_time_ms = 0.0
            p95_response_time_ms = 0.0
        elif len(times) == 1:
            avg_response_time_ms = times[0]
            p95_response_time_ms = times[0]
        else:
            avg_response_time_ms = statistics.mean(times)
            # statistics.quantiles with n=20 gives the 5th percentile boundary at index 18 (95th percentile)
            quantile_list = statistics.quantiles(times, n=20)
            p95_response_time_ms = quantile_list[18]

        # Ground truth metrics
        true_positives: Optional[int] = None
        false_positives: Optional[int] = None
        true_negatives: Optional[int] = None
        false_negatives: Optional[int] = None
        precision: Optional[float] = None
        recall: Optional[float] = None
        f1_score: Optional[float] = None

        if ground_truth is not None:
            true_positives = 0
            false_positives = 0
            true_negatives = 0
            false_negatives = 0

            for assessment in self._assessments:
                ip = assessment.ip_address
                if ip not in ground_truth:
                    continue
                is_malicious = ground_truth[ip]
                is_blocked = assessment.decision == Decision.BLOCK

                if is_blocked and is_malicious:
                    true_positives += 1
                elif is_blocked and not is_malicious:
                    false_positives += 1
                elif not is_blocked and not is_malicious:
                    true_negatives += 1
                elif not is_blocked and is_malicious:
                    false_negatives += 1

            precision = (
                true_positives / (true_positives + false_positives)
                if (true_positives + false_positives) > 0
                else None
            )
            recall = (
                true_positives / (true_positives + false_negatives)
                if (true_positives + false_negatives) > 0
                else None
            )
            if precision is not None and recall is not None and (precision + recall) > 0:
                f1_score = 2 * precision * recall / (precision + recall)
            else:
                f1_score = None

        return RunMetrics(
            total_ips_analyzed=total,
            blocked_count=blocked_count,
            monitored_count=monitored_count,
            ignored_count=ignored_count,
            avg_response_time_ms=avg_response_time_ms,
            p95_response_time_ms=p95_response_time_ms,
            api_cache_hits=api_cache_hits,
            api_cache_misses=api_cache_misses,
            true_positives=true_positives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            false_negatives=false_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
        )

    def write_csv(self) -> None:
        """Write all recorded assessments to a CSV file at the configured report path."""
        self._report_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "timestamp",
            "ip_address",
            "decision",
            "fail_count",
            "window_seconds",
            "abuse_score",
            "country_code",
            "reason",
            "response_time_ms",
            "api_error",
            "dry_run_blocked",
        ]

        with self._report_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for assessment in self._assessments:
                writer.writerow({
                    "timestamp": assessment.timestamp.isoformat(),
                    "ip_address": assessment.ip_address,
                    "decision": assessment.decision.value,
                    "fail_count": assessment.detection_event.fail_count,
                    "window_seconds": assessment.detection_event.window_seconds,
                    "abuse_score": assessment.reputation.abuse_confidence_score,
                    "country_code": assessment.reputation.country_code,
                    "reason": assessment.reason,
                    "response_time_ms": assessment.response_time_ms,
                    "api_error": assessment.reputation.api_error,
                    "dry_run_blocked": assessment.decision == Decision.BLOCK,
                })

        logger.info("CSV report written to %s (%d rows)", self._report_path, len(self._assessments))

    def print_summary(self, metrics: RunMetrics) -> None:
        """Print a formatted summary table to stdout."""
        width = 38  # inner width between the border characters

        def row(label: str, value: str) -> str:
            inner = f" {label}{value} "
            # Pad to fill the box width exactly
            padding = width - len(inner)
            return f"\u2551{inner}{' ' * padding}\u2551"

        lines: list[str] = []
        lines.append("\u2554" + "\u2550" * width + "\u2557")
        lines.append(f"\u2551{'    Threat Detection Run Summary      '}\u2551")
        lines.append("\u2560" + "\u2550" * width + "\u2563")

        lines.append(row(
            f"{'IPs analyzed:':25s}",
            f"{metrics.total_ips_analyzed:>5d}          ",
        ))
        lines.append(row(
            f"{'Blocked:':25s}",
            f"{metrics.blocked_count:>5d}  (BLOCK) ",
        ))
        lines.append(row(
            f"{'Monitored:':25s}",
            f"{metrics.monitored_count:>5d} (MONITOR)",
        ))
        lines.append(row(
            f"{'Ignored:':25s}",
            f"{metrics.ignored_count:>5d}  (IGNORE)",
        ))
        lines.append(row(
            f"{'Avg response time:':25s}",
            f"{metrics.avg_response_time_ms:>5.0f}ms        ",
        ))
        lines.append(row(
            f"{'P95 response time:':25s}",
            f"{metrics.p95_response_time_ms:>5.0f}ms        ",
        ))
        lines.append(row(
            f"{'API cache hits:':25s}",
            f"{metrics.api_cache_hits:>5d}          ",
        ))
        lines.append(row(
            f"{'API cache misses:':25s}",
            f"{metrics.api_cache_misses:>5d}          ",
        ))

        if metrics.precision is not None or metrics.recall is not None or metrics.f1_score is not None:
            lines.append("\u2560" + "\u2550" * width + "\u2563")

            precision_str = f"{metrics.precision:.3f}" if metrics.precision is not None else "N/A"
            recall_str = f"{metrics.recall:.3f}" if metrics.recall is not None else "N/A"
            f1_str = f"{metrics.f1_score:.3f}" if metrics.f1_score is not None else "N/A"

            lines.append(row(f"{'Precision:':25s}", f"{precision_str:>10s}     "))
            lines.append(row(f"{'Recall:':25s}", f"{recall_str:>10s}     "))
            lines.append(row(f"{'F1 Score:':25s}", f"{f1_str:>10s}     "))

        lines.append("\u255a" + "\u2550" * width + "\u255d")

        print("\n".join(lines))

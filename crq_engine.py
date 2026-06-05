"""
CRQ Engine — Quantitative Risk Engine based on Monte Carlo simulation.

No external dependencies required (stdlib only).
"""

import math
import random
from typing import Optional


class CRQEngine:
    """Monte Carlo Cyber Risk Quantification Engine."""

    def simulate(
        self,
        asset_value: float,
        threat_freq_per_year: float,
        vuln_factor: float,
        impact_min_pct: float,
        impact_max_pct: float,
        iterations: int = 10_000,
        seed: Optional[int] = None,
    ) -> dict:
        """
        Run a Monte Carlo simulation to quantify cyber risk.

        Parameters
        ----------
        asset_value : float
            Dollar value of the asset at risk.
        threat_freq_per_year : float
            Expected number of threat events per year (e.g. 0.5 = once every 2 yrs).
        vuln_factor : float
            Probability (0–1) that the threat succeeds when it occurs.
        impact_min_pct : float
            Minimum loss as a fraction of asset_value (0–1).
        impact_max_pct : float
            Maximum loss as a fraction of asset_value (0–1).
        iterations : int
            Number of Monte Carlo iterations (default 10 000).
        seed : int | None
            Optional RNG seed for reproducibility.

        Returns
        -------
        dict with keys:
            ale               – Annual Loss Expectancy (mean annual loss, $)
            var_95            – Value at Risk at 95th percentile (annual, $)
            var_99            – Value at Risk at 99th percentile (annual, $)
            expected_loss     – Mean single-event loss ($)
            max_loss          – Maximum simulated annual loss ($)
            loss_exceedance   – 20-point list [{threshold, probability}] for the LEC curve
            iterations        – Number of simulations run
        """
        if seed is not None:
            random.seed(seed)

        # Clamp inputs to safe ranges
        vuln_factor = max(0.0, min(1.0, vuln_factor))
        impact_min_pct = max(0.0, min(1.0, impact_min_pct))
        impact_max_pct = max(impact_min_pct, min(1.0, impact_max_pct))
        threat_freq_per_year = max(1e-9, threat_freq_per_year)

        annual_losses: list[float] = []
        event_losses: list[float] = []  # individual event losses (non-zero only)

        for _ in range(iterations):
            annual_loss = 0.0
            # Simulate time until all events in the year using Poisson process.
            # Exponential inter-arrival times: sum until > 1.0 year.
            time_elapsed = 0.0
            while True:
                inter_arrival = random.expovariate(threat_freq_per_year)
                time_elapsed += inter_arrival
                if time_elapsed > 1.0:
                    break
                # Threat occurred — did it succeed?
                if random.random() < vuln_factor:
                    # Sample impact uniformly between min and max pct of asset value
                    impact_pct = random.uniform(impact_min_pct, impact_max_pct)
                    loss = asset_value * impact_pct
                    annual_loss += loss
                    event_losses.append(loss)

            annual_losses.append(annual_loss)

        # Sort for percentile calculations
        annual_losses.sort()

        ale = sum(annual_losses) / iterations
        var_95 = _percentile(annual_losses, 0.95)
        var_99 = _percentile(annual_losses, 0.99)
        max_loss = annual_losses[-1] if annual_losses else 0.0
        expected_loss = (sum(event_losses) / len(event_losses)) if event_losses else 0.0

        loss_exceedance = _build_loss_exceedance_curve(annual_losses, points=20)

        return {
            "ale": round(ale, 2),
            "var_95": round(var_95, 2),
            "var_99": round(var_99, 2),
            "expected_loss": round(expected_loss, 2),
            "max_loss": round(max_loss, 2),
            "loss_exceedance": loss_exceedance,
            "iterations": iterations,
        }

    def portfolio_var(
        self,
        risks: list[dict],
        confidence: float = 0.95,
        iterations: int = 10_000,
        seed: Optional[int] = None,
    ) -> dict:
        """
        Aggregate multiple risks and return portfolio-level VaR.

        Each risk dict must contain:
            asset_value, threat_freq_per_year, vuln_factor,
            impact_min_pct, impact_max_pct
        Optional: id, name, iterations (per-risk override)

        Returns
        -------
        dict with:
            portfolio_ale     – Sum of individual ALEs
            portfolio_var     – Portfolio VaR at requested confidence level
            portfolio_var_99  – Portfolio VaR at 99%
            portfolio_max_loss
            confidence        – Confidence level used
            risk_count        – Number of risks in portfolio
            individual        – List of per-risk simulation summaries
        """
        if seed is not None:
            random.seed(seed)

        individual_results: list[dict] = []
        combined_annual_losses: list[float] = [0.0] * iterations

        for risk in risks:
            risk_iters = risk.get("iterations", iterations)
            result = self.simulate(
                asset_value=float(risk["asset_value"]),
                threat_freq_per_year=float(risk["threat_freq_per_year"]),
                vuln_factor=float(risk["vuln_factor"]),
                impact_min_pct=float(risk["impact_min_pct"]),
                impact_max_pct=float(risk["impact_max_pct"]),
                iterations=risk_iters,
            )
            individual_results.append(
                {
                    "id": risk.get("id", ""),
                    "name": risk.get("name", ""),
                    "ale": result["ale"],
                    "var_95": result["var_95"],
                    "var_99": result["var_99"],
                    "expected_loss": result["expected_loss"],
                    "max_loss": result["max_loss"],
                }
            )
            # Re-simulate to collect correlated annual losses for portfolio aggregation
            risk_losses = _simulate_annual_losses(
                asset_value=float(risk["asset_value"]),
                threat_freq_per_year=float(risk["threat_freq_per_year"]),
                vuln_factor=float(risk["vuln_factor"]),
                impact_min_pct=float(risk["impact_min_pct"]),
                impact_max_pct=float(risk["impact_max_pct"]),
                iterations=iterations,
            )
            for i, loss in enumerate(risk_losses):
                combined_annual_losses[i] += loss

        combined_annual_losses.sort()
        portfolio_ale = sum(r["ale"] for r in individual_results)
        portfolio_var = _percentile(combined_annual_losses, confidence)
        portfolio_var_99 = _percentile(combined_annual_losses, 0.99)
        portfolio_max_loss = combined_annual_losses[-1] if combined_annual_losses else 0.0

        return {
            "portfolio_ale": round(portfolio_ale, 2),
            "portfolio_var": round(portfolio_var, 2),
            "portfolio_var_99": round(portfolio_var_99, 2),
            "portfolio_max_loss": round(portfolio_max_loss, 2),
            "confidence": confidence,
            "risk_count": len(risks),
            "individual": individual_results,
        }


# ── Private helpers ────────────────────────────────────────────────────────────

def _simulate_annual_losses(
    asset_value: float,
    threat_freq_per_year: float,
    vuln_factor: float,
    impact_min_pct: float,
    impact_max_pct: float,
    iterations: int,
) -> list[float]:
    """Return a list of annual loss values (one per iteration) without sorting."""
    annual_losses: list[float] = []
    for _ in range(iterations):
        annual_loss = 0.0
        time_elapsed = 0.0
        while True:
            inter_arrival = random.expovariate(threat_freq_per_year)
            time_elapsed += inter_arrival
            if time_elapsed > 1.0:
                break
            if random.random() < vuln_factor:
                impact_pct = random.uniform(impact_min_pct, impact_max_pct)
                annual_loss += asset_value * impact_pct
        annual_losses.append(annual_loss)
    return annual_losses


def _percentile(sorted_values: list[float], p: float) -> float:
    """Return the p-th percentile (0<p<1) of a pre-sorted list."""
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    idx = p * (n - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_values[lo]
    # Linear interpolation
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def _build_loss_exceedance_curve(
    sorted_annual_losses: list[float],
    points: int = 20,
) -> list[dict]:
    """
    Build a Loss Exceedance Curve with `points` evenly-spaced threshold samples.

    Returns a list of dicts: [{threshold: float, probability: float}, ...]
    where probability is the fraction of simulations that exceed the threshold.
    """
    if not sorted_annual_losses:
        return [{"threshold": 0.0, "probability": 0.0}]

    n = len(sorted_annual_losses)
    min_loss = sorted_annual_losses[0]
    max_loss = sorted_annual_losses[-1]

    # Use max_loss * 1.1 as upper bound so curve reaches near-zero probability
    upper = max_loss * 1.1 if max_loss > 0 else 1.0
    lower = 0.0

    result: list[dict] = []
    for i in range(points):
        t = lower + (upper - lower) * i / (points - 1)
        # Fraction of losses that EXCEED threshold (1 - CDF)
        # Binary search for first index >= t
        lo_idx, hi_idx = 0, n
        while lo_idx < hi_idx:
            mid = (lo_idx + hi_idx) // 2
            if sorted_annual_losses[mid] <= t:
                lo_idx = mid + 1
            else:
                hi_idx = mid
        exceed_count = n - lo_idx
        probability = exceed_count / n
        result.append(
            {
                "threshold": round(t, 2),
                "probability": round(probability, 4),
            }
        )

    return result

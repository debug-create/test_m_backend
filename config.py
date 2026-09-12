"""Fable configuration and manually-set fusion weights.

These weights are NOT learned. They were chosen by the team for interpretability
and can be defended / adjusted directly during demos and judge Q&A.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'fable.db'}"

# ---------------------------------------------------------------------------
# Evidence fusion weights (manually set — not learned)
# R_t = σ(w_s·S_t + w_p·P_t + w_q·Q_t + w_a·A_t + w_i·I_t − w_c·C_t)
#
# Inputs S/P/Q/A/I/C are normalized to roughly [0, 1] before weighting.
# W_C is intentionally large so adding legitimate context visibly lowers
# residual_risk (required for live judge demos that edit the ledger).
# ---------------------------------------------------------------------------
W_S = 0.20  # self-baseline deviation
W_P = 0.12  # peer/cohort deviation
W_Q = 0.22  # sequence-risk strength
W_A = 0.28  # asset sensitivity
W_I = 0.18  # identity/privilege risk
W_C = 0.75  # matched legitimate context (subtractive)

# Suspicious sequence window (hours)
SUSPICIOUS_SEQUENCE_WINDOW_HOURS = 48

# Page-Hinkley detector defaults
PH_DELTA = 0.05
PH_LAMBDA = 2.5
PH_ALPHA = 0.01  # forgetting factor for running mean

# History / cohort thresholds
MIN_PERSONAL_HISTORY_DAYS = 14
ROLE_CHANGE_BLEND_DAYS = 30
MIN_COHORT_SIZE = 3

# Baseline mixing defaults
ALPHA_ESTABLISHED = 0.65
BETA_ESTABLISHED = 0.25
GAMMA_ESTABLISHED = 0.10

ALPHA_NEW = 0.10
BETA_NEW = 0.70
GAMMA_NEW = 0.20

# Feature windows (seconds)
WINDOW_15M = 15 * 60
WINDOW_24H = 24 * 3600
WINDOW_7D = 7 * 24 * 3600
WINDOW_30D = 30 * 24 * 3600

SENSITIVE_CLASSIFICATIONS = {"restricted", "critical"}
DOWNLOAD_ACTIONS = {"file_download", "external_upload"}

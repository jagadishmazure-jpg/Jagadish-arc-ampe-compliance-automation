"""ARC-AMPE compliance automation for a fictional state health exchange (offline, synthetic data)."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
TODAY = "2026-10-31"  # fixed "as of" date so every run is repeatable
ENTITY = "Lakehaven Health Connector"  # fictional state-based exchange of the fictional State of Lakehaven
__version__ = "0.1.0"

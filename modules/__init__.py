# modules/__init__.py
#
# Package initializer for the CyberSentinel modules package.
# Exports all public classes and functions used by the entry points
# (CyberSentinel.py, gui.py, dashboard.py, eval_harness.py).

from . import utils
from .analysis_manager  import ScannerLogic
from .scanner_api       import VirusTotalAPI, AlienVaultAPI, MetaDefenderAPI, MalwareBazaarAPI
from .live_edr          import get_target_process_path
from .daemon_monitor    import start_daemon
from . import network_isolation
from . import feedback
from . import colors
from . import intel_updater
from .lolbas_detector   import LolbasDetector
from .byovd_detector    import ByovdDetector
from .c2_fingerprint    import FeodoMonitor, DgaMonitor, Ja3Monitor
from .chain_correlator  import ChainCorrelator
from .baseline_engine   import BaselineEngine
from .amsi_monitor      import AmsiMonitor
from .adaptive_learner  import AdaptiveLearner, get_learner
from .explainability    import SHAPExplainer, get_explainer
from .risk_scorer       import DynamicRiskScorer, get_risk_scorer
from .drift_detector    import DriftDetector, get_drift_detector

# Additional module exports
from .loading          import Spinner
from .ml_engine         import LocalScanner
from .quarantine        import quarantine_file

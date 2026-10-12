"""detection-validation-lab: validate Sigma detections on real Windows telemetry.

The package does not detect anything by itself: Chainsaw runs the Sigma rules on EVTX
files. dvl normalises Chainsaw's output, evaluates the one correlation rule, and checks
the hits against written expectations (which test must fire which rule, and what must
stay silent).
"""

__version__ = "1.0.0"

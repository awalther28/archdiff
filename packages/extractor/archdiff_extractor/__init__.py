"""OpenTofu plan JSON -> Permission Graph v1 extractor."""
__version__ = "0.1.0"

from .extract import extract_plan
from .merge import merge
from .plan import Plan

__all__ = ["Plan", "extract_plan", "merge", "__version__"]

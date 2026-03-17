"""Portcullis exposure-lattice defense for AgentDojo benchmark."""

from .exposure import ExposureLabel, ExposureSet, classify_tool, should_deny, apply_record
from .defense import PortcullisDefense

__all__ = [
    "ExposureLabel",
    "ExposureSet",
    "classify_tool",
    "should_deny",
    "apply_record",
    "PortcullisDefense",
]

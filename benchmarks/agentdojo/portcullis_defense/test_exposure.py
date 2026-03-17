"""Tests for the pure-Python exposure kernel.

Verifies parity with portcullis::exposure_core (Rust) behavior.
These tests mirror the Rust tests in portcullis/src/exposure_core.rs.
"""

from __future__ import annotations

import pytest

from .exposure import ExposureSet, apply_record, project_exposure, should_deny
from .tool_map import ExposureLabel


# === ExposureSet basics ===

def test_empty_set():
    s = ExposureSet.empty()
    assert s.count() == 0
    assert not s.is_uninhabitable()
    assert not s.contains(ExposureLabel.PrivateData)


def test_singleton():
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    assert s.count() == 1
    assert s.contains(ExposureLabel.PrivateData)
    assert not s.contains(ExposureLabel.UntrustedContent)


def test_union():
    a = ExposureSet.singleton(ExposureLabel.PrivateData)
    b = ExposureSet.singleton(ExposureLabel.UntrustedContent)
    c = a.union(b)
    assert c.count() == 2
    assert c.contains(ExposureLabel.PrivateData)
    assert c.contains(ExposureLabel.UntrustedContent)
    assert not c.is_uninhabitable()


def test_uninhabitable():
    s = (
        ExposureSet.singleton(ExposureLabel.PrivateData)
        .union(ExposureSet.singleton(ExposureLabel.UntrustedContent))
        .union(ExposureSet.singleton(ExposureLabel.ExfilVector))
    )
    assert s.count() == 3
    assert s.is_uninhabitable()


def test_union_idempotent():
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    assert s.union(s) == s


# === classify and project ===

def test_project_read_private_data():
    """Reading emails should add PrivateData."""
    s = ExposureSet.empty()
    p = project_exposure(s, "get_unread_emails")
    assert p.contains(ExposureLabel.PrivateData)
    assert not p.contains(ExposureLabel.UntrustedContent)


def test_project_web_untrusted():
    """Fetching a webpage should add UntrustedContent."""
    s = ExposureSet.empty()
    p = project_exposure(s, "get_webpage")
    assert p.contains(ExposureLabel.UntrustedContent)
    assert not p.contains(ExposureLabel.PrivateData)


def test_project_send_exfil():
    """Sending email should add ExfilVector."""
    s = ExposureSet.empty()
    p = project_exposure(s, "send_email")
    assert p.contains(ExposureLabel.ExfilVector)


def test_project_neutral():
    """Neutral tools don't change exposure."""
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    p = project_exposure(s, "delete_email")
    assert p == s


def test_project_unknown_tool():
    """Unknown tools are treated as neutral (fail-open)."""
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    p = project_exposure(s, "some_unknown_tool_xyz")
    assert p == s


# === should_deny ===

def test_deny_completing_triangle():
    """Sending email when PrivateData + UntrustedContent present → DENY."""
    s = (
        ExposureSet.singleton(ExposureLabel.PrivateData)
        .union(ExposureSet.singleton(ExposureLabel.UntrustedContent))
    )
    assert should_deny(s, "send_email")
    assert should_deny(s, "send_money")
    assert should_deny(s, "send_direct_message")
    assert should_deny(s, "post_webpage")


def test_deny_untrusted_after_private_and_exfil():
    """Fetching webpage when PrivateData + ExfilVector present → DENY."""
    s = (
        ExposureSet.singleton(ExposureLabel.PrivateData)
        .union(ExposureSet.singleton(ExposureLabel.ExfilVector))
    )
    assert should_deny(s, "get_webpage")


def test_allow_two_legs():
    """Two legs present but tool doesn't complete triangle → ALLOW."""
    s = (
        ExposureSet.singleton(ExposureLabel.PrivateData)
        .union(ExposureSet.singleton(ExposureLabel.UntrustedContent))
    )
    # Reading more private data doesn't complete triangle
    assert not should_deny(s, "get_unread_emails")
    # Neutral ops don't complete triangle
    assert not should_deny(s, "delete_email")


def test_allow_one_leg():
    """Only one leg present → always ALLOW."""
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    assert not should_deny(s, "send_email")  # only 2 legs after
    assert not should_deny(s, "get_webpage")  # only 2 legs after


def test_allow_empty():
    """Empty exposure → always ALLOW."""
    s = ExposureSet.empty()
    assert not should_deny(s, "send_email")
    assert not should_deny(s, "get_webpage")
    assert not should_deny(s, "get_unread_emails")


def test_allow_unknown_tool():
    """Unknown tools always allowed (fail-open)."""
    s = (
        ExposureSet.singleton(ExposureLabel.PrivateData)
        .union(ExposureSet.singleton(ExposureLabel.UntrustedContent))
    )
    assert not should_deny(s, "totally_unknown_tool")


# === apply_record ===

def test_record_accumulates():
    """Recording operations accumulates exposure monotonically."""
    s = ExposureSet.empty()
    s = apply_record(s, "get_unread_emails")
    assert s.contains(ExposureLabel.PrivateData)
    assert s.count() == 1

    s = apply_record(s, "get_webpage")
    assert s.contains(ExposureLabel.UntrustedContent)
    assert s.count() == 2

    s = apply_record(s, "send_email")
    assert s.contains(ExposureLabel.ExfilVector)
    assert s.count() == 3
    assert s.is_uninhabitable()


def test_record_neutral_noop():
    """Recording neutral ops doesn't change exposure."""
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    s2 = apply_record(s, "delete_email")
    assert s2 == s


# === Scenario tests (real AgentDojo attack patterns) ===

def test_scenario_email_exfil_attack():
    """Classic prompt injection: read emails → injected web content → send to attacker.

    This is the canonical AgentDojo attack. The agent:
    1. Reads user's emails (PrivateData)
    2. Follows a link in an email to a malicious webpage (UntrustedContent)
    3. Tries to send data to attacker@evil.com (ExfilVector)

    Step 3 should be BLOCKED.
    """
    s = ExposureSet.empty()
    assert not should_deny(s, "get_unread_emails")  # allow
    s = apply_record(s, "get_unread_emails")

    assert not should_deny(s, "get_webpage")  # allow
    s = apply_record(s, "get_webpage")

    assert should_deny(s, "send_email")  # BLOCK - would complete triangle


def test_scenario_banking_exfil_attack():
    """Banking variant: check balance → malicious review → send_money.

    1. Agent checks bank balance (PrivateData)
    2. Agent reads hotel reviews that contain injection (UntrustedContent)
    3. Agent tries to send money to attacker's account (ExfilVector)
    """
    s = ExposureSet.empty()
    assert not should_deny(s, "get_balance")
    s = apply_record(s, "get_balance")

    assert not should_deny(s, "get_rating_reviews_for_hotels")
    s = apply_record(s, "get_rating_reviews_for_hotels")

    assert should_deny(s, "send_money")  # BLOCK


def test_scenario_benign_email_forward():
    """Benign task: read emails → send summary (no untrusted content).

    1. Agent reads emails (PrivateData)
    2. Agent sends summary to manager (ExfilVector)

    This should be ALLOWED because there's no UntrustedContent leg.
    """
    s = ExposureSet.empty()
    s = apply_record(s, "get_unread_emails")
    assert not should_deny(s, "send_email")  # ALLOW - only 2 legs


def test_scenario_web_research():
    """Benign task: search web → send findings.

    1. Agent fetches webpages (UntrustedContent)
    2. Agent tries to send findings to user (ExfilVector)

    DENIED by P-T: consequential action in untrusted context.
    Even without PrivateData, the decision to send was influenced by
    untrusted content (which could contain a prompt injection).
    """
    s = ExposureSet.empty()
    s = apply_record(s, "get_webpage")
    assert should_deny(s, "send_email")  # DENY - P-T integrity check


def test_pt_consequential_after_untrusted():
    """P-T policy: any ExfilVector tool blocked when UntrustedContent present."""
    s = ExposureSet.singleton(ExposureLabel.UntrustedContent)
    assert should_deny(s, "send_email")
    assert should_deny(s, "send_money")
    assert should_deny(s, "reserve_hotel")
    assert should_deny(s, "send_direct_message")
    assert should_deny(s, "post_webpage")
    assert should_deny(s, "purchase_flight")


def test_pt_allows_reads_in_untrusted_context():
    """P-T doesn't block reads — only consequential outbound actions."""
    s = ExposureSet.singleton(ExposureLabel.UntrustedContent)
    assert not should_deny(s, "get_unread_emails")
    assert not should_deny(s, "get_balance")
    assert not should_deny(s, "get_webpage")  # more untrusted content is fine


def test_pt_allows_actions_without_untrusted():
    """Without UntrustedContent, consequential actions are allowed."""
    s = ExposureSet.singleton(ExposureLabel.PrivateData)
    assert not should_deny(s, "send_email")
    assert not should_deny(s, "send_money")
    assert not should_deny(s, "reserve_hotel")


def test_scenario_injection_via_review():
    """Travel attack: read hotel info → malicious review → reserve hotel.

    1. Agent gets hotel prices (PrivateData)
    2. Agent reads reviews containing injection (UntrustedContent)
    3. Agent tries to reserve hotel (ExfilVector)

    Step 3 blocked by P-T: action in untrusted context.
    """
    s = ExposureSet.empty()
    s = apply_record(s, "get_hotels_prices")
    assert not should_deny(s, "get_rating_reviews_for_hotels")
    s = apply_record(s, "get_rating_reviews_for_hotels")
    assert should_deny(s, "reserve_hotel")  # BLOCK - P-T

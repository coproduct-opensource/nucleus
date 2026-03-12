"""Tests for the Python SDK profile registry."""

from __future__ import annotations

import pytest

from nucleus_sdk.profiles import (
    BudgetSpec,
    Capabilities,
    CapabilityLevel,
    ProfileRegistry,
    ProfileSpec,
    TimeSpec,
    SAFE_PR_FIXER,
    DOC_EDITOR,
    TEST_RUNNER,
    TRIAGE_BOT,
    CODE_REVIEW,
    CODEGEN,
    RELEASE,
    RESEARCH_WEB,
    READ_ONLY,
    LOCAL_DEV,
    _CANONICAL_PROFILES,
)


class TestCapabilityLevel:
    def test_values(self):
        assert CapabilityLevel.NEVER.value == "never"
        assert CapabilityLevel.LOW_RISK.value == "low_risk"
        assert CapabilityLevel.ALWAYS.value == "always"

    def test_string_identity(self):
        assert CapabilityLevel.NEVER == "never"
        assert CapabilityLevel.ALWAYS == "always"


class TestCapabilities:
    def test_defaults_match_rust(self):
        caps = Capabilities()
        assert caps.read_files == CapabilityLevel.ALWAYS
        assert caps.write_files == CapabilityLevel.LOW_RISK
        assert caps.run_bash == CapabilityLevel.NEVER
        assert caps.git_push == CapabilityLevel.NEVER
        assert caps.manage_pods == CapabilityLevel.NEVER

    def test_allowed_operations(self):
        caps = Capabilities(
            read_files=CapabilityLevel.ALWAYS,
            write_files=CapabilityLevel.NEVER,
            edit_files=CapabilityLevel.NEVER,
            run_bash=CapabilityLevel.NEVER,
            glob_search=CapabilityLevel.ALWAYS,
            grep_search=CapabilityLevel.ALWAYS,
            web_search=CapabilityLevel.NEVER,
            web_fetch=CapabilityLevel.NEVER,
            git_commit=CapabilityLevel.NEVER,
            git_push=CapabilityLevel.NEVER,
            create_pr=CapabilityLevel.NEVER,
            manage_pods=CapabilityLevel.NEVER,
        )
        allowed = caps.allowed_operations()
        assert allowed == ["read_files", "glob_search", "grep_search"]

    def test_denied_operations(self):
        caps = READ_ONLY.capabilities
        denied = caps.denied_operations()
        assert "write_files" in denied
        assert "run_bash" in denied
        assert "git_push" in denied
        assert "read_files" not in denied

    def test_frozen(self):
        caps = Capabilities()
        with pytest.raises(AttributeError):
            caps.read_files = CapabilityLevel.NEVER  # type: ignore[misc]


class TestProfileSpec:
    def test_frozen(self):
        with pytest.raises(AttributeError):
            CODEGEN.name = "something-else"  # type: ignore[misc]

    def test_trifecta_components_one(self):
        # read-only: only private_data (read_files=always)
        assert READ_ONLY.trifecta_components == 1
        assert READ_ONLY.trifecta_safe is True

    def test_trifecta_components_two(self):
        # triage-bot: private_data + untrusted_content (web_fetch=low_risk)
        assert TRIAGE_BOT.trifecta_components == 2
        assert TRIAGE_BOT.trifecta_safe is True

    def test_trifecta_components_three(self):
        # release: all three (read + web + push)
        assert RELEASE.trifecta_components == 3
        assert RELEASE.trifecta_safe is False

    def test_safe_pr_fixer_trifecta(self):
        # safe-pr-fixer: private_data + untrusted (web_fetch) + exfil (run_bash)
        assert SAFE_PR_FIXER.trifecta_components == 3
        assert SAFE_PR_FIXER.trifecta_safe is False

    def test_codegen_trifecta(self):
        # codegen: private_data + exfil (run_bash), no untrusted
        assert CODEGEN.trifecta_components == 2
        assert CODEGEN.trifecta_safe is True

    def test_doc_editor_trifecta(self):
        # doc-editor: only private_data
        assert DOC_EDITOR.trifecta_components == 1
        assert DOC_EDITOR.trifecta_safe is True


class TestCanonicalProfiles:
    def test_exactly_10_canonical(self):
        assert len(_CANONICAL_PROFILES) == 10

    def test_all_have_names(self):
        names = {p.name for p in _CANONICAL_PROFILES}
        expected = {
            "safe-pr-fixer",
            "doc-editor",
            "test-runner",
            "triage-bot",
            "code-review",
            "codegen",
            "release",
            "research-web",
            "read-only",
            "local-dev",
        }
        assert names == expected

    def test_all_have_descriptions(self):
        for p in _CANONICAL_PROFILES:
            assert p.description, f"{p.name} has no description"

    def test_all_have_budgets(self):
        for p in _CANONICAL_PROFILES:
            assert p.budget is not None, f"{p.name} has no budget"

    def test_all_have_time_bounds(self):
        for p in _CANONICAL_PROFILES:
            assert p.time is not None, f"{p.name} has no time bounds"
            assert (
                p.time.duration_minutes is not None or p.time.duration_hours is not None
            ), f"{p.name} has no duration"

    def test_all_block_sensitive_paths(self):
        for p in _CANONICAL_PROFILES:
            assert "**/.ssh/**" in p.blocked_paths, f"{p.name} doesn't block .ssh"
            assert "**/.aws/**" in p.blocked_paths, f"{p.name} doesn't block .aws"
            assert "**/.env" in p.blocked_paths, f"{p.name} doesn't block .env"

    def test_no_profile_allows_manage_pods(self):
        for p in _CANONICAL_PROFILES:
            assert (
                p.capabilities.manage_pods == CapabilityLevel.NEVER
            ), f"{p.name} allows manage_pods"

    def test_release_has_obligations(self):
        assert "git_push" in RELEASE.obligations
        assert "create_pr" in RELEASE.obligations

    def test_code_review_has_obligations(self):
        assert "web_search" in CODE_REVIEW.obligations


class TestProfileRegistry:
    def test_canonical_has_10(self):
        registry = ProfileRegistry.canonical()
        assert len(registry) == 10

    def test_canonical_names(self):
        registry = ProfileRegistry.canonical()
        names = set(registry.names())
        assert "safe-pr-fixer" in names
        assert "codegen" in names
        assert "release" in names

    def test_resolve_exact(self):
        registry = ProfileRegistry.canonical()
        spec = registry.resolve("codegen")
        assert spec.name == "codegen"
        assert spec is CODEGEN

    def test_resolve_case_insensitive(self):
        registry = ProfileRegistry.canonical()
        spec = registry.resolve("CODEGEN")
        assert spec.name == "codegen"

    def test_resolve_underscore_normalization(self):
        registry = ProfileRegistry.canonical()
        spec = registry.resolve("safe_pr_fixer")
        assert spec.name == "safe-pr-fixer"

    def test_resolve_mixed_normalization(self):
        registry = ProfileRegistry.canonical()
        spec = registry.resolve("Code_Review")
        assert spec.name == "code-review"

    def test_resolve_unknown_raises(self):
        registry = ProfileRegistry.canonical()
        with pytest.raises(KeyError, match="unknown profile"):
            registry.resolve("nonexistent")

    def test_get_returns_none(self):
        registry = ProfileRegistry.canonical()
        assert registry.get("nonexistent") is None

    def test_get_returns_spec(self):
        registry = ProfileRegistry.canonical()
        spec = registry.get("release")
        assert spec is RELEASE

    def test_contains(self):
        registry = ProfileRegistry.canonical()
        assert "codegen" in registry
        assert "Code_Review" in registry
        assert "nonexistent" not in registry

    def test_register_custom(self):
        registry = ProfileRegistry.canonical()
        custom = ProfileSpec(
            name="custom-profile",
            description="A custom profile",
            capabilities=Capabilities(),
        )
        registry.register(custom)
        assert len(registry) == 11
        assert registry.resolve("custom-profile") is custom

    def test_register_overrides_existing(self):
        registry = ProfileRegistry.canonical()
        replacement = ProfileSpec(
            name="codegen",
            description="Replaced codegen",
            capabilities=Capabilities(),
        )
        registry.register(replacement)
        assert len(registry) == 10
        assert registry.resolve("codegen").description == "Replaced codegen"


class TestSessionProfileValidation:
    """Test Session integration with profile registry."""

    def test_session_accepts_canonical_profile(self):
        from nucleus_sdk.session import Session

        s = Session(profile="codegen", validate_profile=True)
        assert s.profile_spec is not None
        assert s.profile_spec.name == "codegen"

    def test_session_accepts_normalized_name(self):
        from nucleus_sdk.session import Session

        s = Session(profile="safe_pr_fixer", validate_profile=True)
        assert s.profile_spec is not None
        assert s.profile_spec.name == "safe-pr-fixer"

    def test_session_rejects_unknown_when_validating(self):
        from nucleus_sdk.session import Session

        with pytest.raises(KeyError, match="unknown profile"):
            Session(profile="nonexistent", validate_profile=True)

    def test_session_allows_unknown_without_validation(self):
        from nucleus_sdk.session import Session

        s = Session(profile="custom-thing", validate_profile=False)
        assert s.profile_spec is None

    def test_session_default_no_validation(self):
        from nucleus_sdk.session import Session

        # Default validate_profile=False, so arbitrary names are allowed
        s = Session(profile="anything-goes")
        assert s.profile_spec is None


class TestBudgetSpec:
    def test_frozen(self):
        b = BudgetSpec()
        with pytest.raises(AttributeError):
            b.max_cost_usd = "99.99"  # type: ignore[misc]

    def test_defaults(self):
        b = BudgetSpec()
        assert b.max_cost_usd == "5.00"
        assert b.max_input_tokens == 100000
        assert b.max_output_tokens == 10000


class TestTimeSpec:
    def test_minutes(self):
        t = TimeSpec(duration_minutes=30)
        assert t.duration_minutes == 30
        assert t.duration_hours is None

    def test_hours(self):
        t = TimeSpec(duration_hours=2)
        assert t.duration_hours == 2
        assert t.duration_minutes is None

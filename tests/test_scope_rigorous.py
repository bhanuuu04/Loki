import pytest
from loki.security.scope_manager import ScopeManager, ScopeConfig, METADATA_IPS


def test_scope_versioning_and_audit_history():
    scope = ScopeManager.create_explicit_scope(
        assessment_name="Audit-Corp",
        targets=["example.com"],
        excluded_targets=["secret.example.com"],
        author="lead_auditor",
    )
    assert scope.config.version == 1
    assert len(scope.get_version_history()) >= 1

    scope.update_targets(
        add_targets=["app.example.com"],
        add_exclusions=["db.example.com"],
        author="sec_ops",
        reason="Added new staging app and excluded database",
    )
    assert scope.config.version == 2
    history = scope.get_version_history()
    assert len(history) == 2
    assert history[1].author == "sec_ops"
    assert "app.example.com" in history[1].targets
    assert "db.example.com" in history[1].excluded_targets


def test_strict_exclusion_precedence():
    scope = ScopeManager(
        ScopeConfig(
            assessment_name="Exclusion Precedence Test",
            targets=["corp.local", "192.168.1.0/24"],
            excluded_targets=["admin.corp.local", "192.168.1.50"],
            allow_subdomains=True,
            allow_private_ips=True,
        )
    )

    # Subdomain excluded despite parent domain being authorized
    allowed_sub, reason_sub = scope.is_in_scope("admin.corp.local")
    assert not allowed_sub
    assert "explicitly excluded" in reason_sub

    # Normal subdomain allowed
    allowed_api, _ = scope.is_in_scope("api.corp.local")
    assert allowed_api

    # Excluded IP inside authorized CIDR
    allowed_ip, reason_ip = scope.is_in_scope("192.168.1.50")
    assert not allowed_ip
    assert "excluded network" in reason_ip

    # Other IP in CIDR allowed
    allowed_other, _ = scope.is_in_scope("192.168.1.99")
    assert allowed_other


def test_domain_normalization_comprehensive():
    norm = ScopeManager.normalize_target

    assert norm("https://example.com/api/v1/users?query=1#frag") == "example.com"
    assert norm("http://user:pass@sub.example.com:8443/test") == "sub.example.com"
    assert norm("FQDN.EXAMPLE.COM.") == "fqdn.example.com"
    assert norm("http://[2001:db8::1]:8080/path") == "2001:db8::1"
    # CIDR preserved
    assert norm("10.0.0.0/16") == "10.0.0.0/16"
    assert norm("2001:db8::/32") == "2001:db8::/32"


def test_ipv4_ipv6_and_mapped_ipv4():
    scope = ScopeManager(
        ScopeConfig(
            assessment_name="IP Test",
            targets=["2001:db8::/32", "203.0.113.0/24"],
            allow_subdomains=False,
        )
    )

    # IPv6 in scope
    in_v6, _ = scope.is_in_scope("2001:db8::42")
    assert in_v6

    # IPv6 out of scope
    out_v6, _ = scope.is_in_scope("2001:db9::1")
    assert not out_v6

    # IPv4 in scope
    in_v4, _ = scope.is_in_scope("203.0.113.10")
    assert in_v4

    # IPv4-mapped IPv6 representation
    in_mapped, _ = scope.is_in_scope("::ffff:203.0.113.10")
    assert in_mapped


def test_dns_rebinding_and_cloud_metadata_protection():
    scope = ScopeManager(
        ScopeConfig(
            assessment_name="Rebinding Protection",
            targets=["public-target.com"],
            allow_loopback=False,
            allow_private_ips=False,
        )
    )

    # Directly targeting AWS/GCP/Azure link-local metadata IP
    for meta_ip in ["169.254.169.254", "169.254.0.1", "fe80::1", "metadata.google.internal"]:
        allowed, reason = scope.is_in_scope(meta_ip)
        assert not allowed
        assert "cloud-metadata" in reason.lower() or "forbidden" in reason.lower() or "not in authorized scope" in reason.lower()


def test_redirect_destination_validation():
    scope = ScopeManager(
        ScopeConfig(
            assessment_name="Redirect Test",
            targets=["authorized.org"],
            allow_subdomains=True,
        )
    )

    # Safe relative redirect
    ok1, _ = scope.validate_redirect("https://authorized.org/login", "/dashboard")
    assert ok1

    # Safe same-origin redirect
    ok2, _ = scope.validate_redirect("https://authorized.org/login", "https://api.authorized.org/v2")
    assert ok2

    # Malicious open redirect to external asset
    ok_ext, reason_ext = scope.validate_redirect("https://authorized.org/login", "https://malicious-external-site.com/steal")
    assert not ok_ext
    assert "blocked" in reason_ext.lower()


def test_model_self_authorization_is_blocked():
    from loki.tools.security_tools import authorize_target

    # Attempting to self-authorize an unauthorized target without operator token
    res = authorize_target("unauthorized-domain.com")
    assert "Authorization Denied" in res
    assert "Autonomous self-authorization by the model is disabled" in res

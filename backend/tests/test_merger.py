"""Tests for the multi-source merger."""
import unittest
from app.services.merger import normalize_value, merge_results, compute_source_agreement


def _make_result(source, finding_type, value, confidence=0.85):
    return {
        "source": source, "finding_type": finding_type, "value": value,
        "confidence": confidence, "observation_type": "observed",
        "evidence": f"Test evidence from {source}", "title": f"{finding_type}: {value}",
        "description": f"Test {finding_type}", "category": "test", "tags": "test",
        "discovered_at": "2026-07-01T00:00:00+00:00",
        "raw_data": {"source": source}, "external_url": None,
        "first_seen": None, "last_seen": None,
    }


class TestNormalizeValue(unittest.TestCase):
    def test_subdomain_strips_trailing_dot(self):
        assert normalize_value("subdomain", "dev.example.com.") == "dev.example.com"

    def test_ip_strips_brackets(self):
        assert normalize_value("ip", "[2001:db8::1]") == "2001:db8::1"

    def test_technology_strips_version(self):
        result = normalize_value("technology", "nginx 1.24.0")
        assert "1.24.0" not in result

    def test_email_lowercases(self):
        assert normalize_value("email", "John@Example.COM") == "john@example.com"

    def test_asn_normalizes(self):
        result = normalize_value("asn", "AS12345 (Some ISP)")
        assert result == "as12345"


class TestMergeResults(unittest.TestCase):
    def test_single_source_no_merge(self):
        results = [_make_result("crt.sh", "subdomain", "dev.example.com")]
        merged = merge_results(results)
        assert len(merged) == 1
        assert merged[0]["source_count"] == 1
        assert merged[0]["sources"] == ["crt.sh"]

    def test_two_sources_merge(self):
        results = [
            _make_result("crt.sh", "subdomain", "dev.example.com", 0.92),
            _make_result("virustotal", "subdomain", "dev.example.com", 0.90),
        ]
        merged = merge_results(results)
        assert len(merged) == 1
        m = merged[0]
        assert m["source_count"] == 2
        assert "crt.sh" in m["sources"]
        assert "virustotal" in m["sources"]
        assert m["confidence"] > 0.92  # bonus applied

    def test_three_sources_higher_confidence(self):
        results = [
            _make_result("crt.sh", "subdomain", "api.example.com", 0.92),
            _make_result("virustotal", "subdomain", "api.example.com", 0.90),
            _make_result("hackertarget", "subdomain", "api.example.com", 0.85),
        ]
        merged = merge_results(results)
        assert len(merged) == 1
        assert merged[0]["source_count"] == 3
        assert merged[0]["confidence"] >= 0.90

    def test_different_types_not_merged(self):
        results = [
            _make_result("crt.sh", "subdomain", "dev.example.com"),
            _make_result("shodan", "ip", "1.2.3.4"),
        ]
        merged = merge_results(results)
        assert len(merged) == 2

    def test_evidence_per_source_populated(self):
        results = [
            _make_result("crt.sh", "subdomain", "dev.example.com"),
            _make_result("virustotal", "subdomain", "dev.example.com"),
        ]
        merged = merge_results(results)
        eps = merged[0]["evidence_per_source"]
        assert len(eps) == 2
        sources_in_eps = [e["source"] for e in eps]
        assert "crt.sh" in sources_in_eps
        assert "virustotal" in sources_in_eps


class TestComputeSourceAgreement(unittest.TestCase):
    def test_agreement_calculation(self):
        merged = [
            {"finding_type": "subdomain", "source_count": 3, "sources": ["a", "b", "c"],
             "confidence": 0.9, "value": "dev.ex.com", "source_agreement": 1.0, "total_queried": 1},
        ]
        result = compute_source_agreement(merged, {"subdomain": 4})
        assert result[0]["source_agreement"] == 0.75  # 3/4
        assert result[0]["total_queried"] == 4


if __name__ == "__main__":
    unittest.main()

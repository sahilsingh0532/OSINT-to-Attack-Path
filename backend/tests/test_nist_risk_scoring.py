"""
Unit tests validating NIST SP 800-30 Rev. 1 Risk Scoring Method across:
1. Target Domain Findings Risk Engine (RiskScore model & risk_engine service)
2. Email Intelligence Security Posture & Breach Analytics
3. Username OSINT Threat Index & Posture Assessment
"""
import unittest
from app.models.risk_score import RiskScore
from app.services.risk_engine import calculate_risk_scores_for_findings
from app.services.email_lookup import _compute_security_posture
from app.services.username_lookup import _compute_username_security_posture


class TestNistRiskScoreModel(unittest.TestCase):
    def test_nist_likelihood_calculation(self):
        # Exposure 8.0, Exploitability 7.0, Confidence 0.90
        # Avg = 7.5, Conf factor = 0.70 + 0.30 * 0.9 = 0.97 => 7.5 * 0.97 = 7.275 -> 7.3
        likelihood = RiskScore.calculate_likelihood(8.0, 0.90, 7.0)
        self.assertAlmostEqual(likelihood, 7.3, delta=0.1)

    def test_nist_composite_score(self):
        # L ~ 7.3, Impact 8.0 -> Score ~ 58.4 (out of 100)
        score = RiskScore.calculate_composite(8.0, 0.90, 7.0, 8.0)
        self.assertGreater(score, 50.0)
        self.assertLessEqual(score, 100.0)

    def test_nist_risk_levels(self):
        self.assertEqual(RiskScore.get_risk_level(15.0), "LOW")
        self.assertEqual(RiskScore.get_risk_level(35.0), "LOW")
        self.assertEqual(RiskScore.get_risk_level(55.0), "MEDIUM")
        self.assertEqual(RiskScore.get_risk_level(75.0), "HIGH")
        self.assertEqual(RiskScore.get_risk_level(90.0), "CRITICAL")

    def test_nist_risk_breakdown_dict(self):
        breakdown = RiskScore.calculate_nist_risk(8.0, 0.85, 8.0, 8.0)
        self.assertEqual(breakdown["standard"], "NIST SP 800-30 Rev. 1")
        self.assertIn("likelihood", breakdown)
        self.assertIn("impact", breakdown)
        self.assertIn("risk_score", breakdown)
        self.assertIn("risk_level", breakdown)


class TestNistRiskEngine(unittest.TestCase):
    def test_findings_risk_scoring(self):
        mock_findings = [
            {"id": "1", "finding_type": "exposure", "confidence": 0.90},
            {"id": "2", "finding_type": "domain", "confidence": 0.80},
        ]
        results = calculate_risk_scores_for_findings(mock_findings)
        self.assertEqual(len(results), 2)
        # Check first finding
        f1 = results[0]
        self.assertIn("composite_score", f1)
        self.assertIn("[NIST SP 800-30 Rev. 1]", f1["rationale"])
        self.assertGreater(f1["composite_score"], 0)


class TestNistEmailPosture(unittest.TestCase):
    def test_email_posture_nist_scoring(self):
        reputation = {"credentials_leaked": True, "deliverable": True, "suspicious": False}
        dns_data = {"spf_status": "Strict Reject (-all)", "dmarc_policy": "REJECT", "mail_provider": "Google Workspace"}
        xon_data = {"breached": True, "breach_count": 2, "pastes_count": 0, "exposed_data_types": ["Passwords", "Emails"]}

        posture = _compute_security_posture(
            email="test.user@company.com",
            reputation=reputation,
            dns_data=dns_data,
            xon_data=xon_data,
        )

        self.assertIn("nist_assessment", posture)
        nist = posture["nist_assessment"]
        self.assertEqual(nist["standard"], "NIST SP 800-30 Rev. 1")
        self.assertGreaterEqual(nist["threat_likelihood"], 1.0)
        self.assertGreaterEqual(nist["threat_impact"], 1.0)
        self.assertEqual(nist["risk_score"], posture["composite_score"])
        self.assertIn(posture["risk_level"], ["CRITICAL THREAT", "HIGH RISK", "MODERATE RISK", "LOW RISK", "CLEAN / SECURE"])


class TestNistUsernamePosture(unittest.TestCase):
    def test_username_posture_nist_scoring(self):
        gh_profile = {"found": True, "public_repos": 15, "company": "ApexNova", "followers": 20}
        gh_events = {"uncovered_emails": ["dev@apexnova.com"]}
        gh_repos = {"repos": [{"name": "backend"}], "total_stars": 50}
        gh_keys = {"has_ssh_keys": True, "uncovered_key_comments": ["dev-macbook-pro"]}
        gh_gists = {"gists": []}
        probes = [{"platform": "GitHub", "exists": True}, {"platform": "Docker Hub", "exists": True}]
        breached_emails = [{"email": "dev@apexnova.com", "breached": True, "breach_count": 1}]

        posture = _compute_username_security_posture(
            username="alexdev",
            gh_profile=gh_profile,
            gh_events=gh_events,
            gh_repos=gh_repos,
            gh_keys=gh_keys,
            gh_gists=gh_gists,
            probes=probes,
            breached_emails=breached_emails,
        )

        self.assertIn("nist_assessment", posture)
        nist = posture["nist_assessment"]
        self.assertEqual(nist["standard"], "NIST SP 800-30 Rev. 1")
        self.assertGreaterEqual(nist["threat_likelihood"], 1.0)
        self.assertGreaterEqual(nist["threat_impact"], 1.0)
        self.assertEqual(nist["risk_score"], posture["composite_score"])


if __name__ == "__main__":
    unittest.main()

"""
Standalone Email OSINT Lookup & Export Service.

Aggregates intelligence from multiple free OSINT sources for a given email address:
  - XposedOrNot         -> breach exposure, breach catalog details, risk scores & password risks
  - EmailRep.io         -> reputation, suspicious flags, profiles, deliverability, breach flags
  - GitHub Search API   -> public commits, code references, matching user profiles
  - Gravatar            -> avatar, display name, public bio & profile link
  - DNS MX Analysis     -> domain mail infrastructure, mail provider, SPF & DMARC policies
  - Public Web Mentions -> search engine harvesting for public webpages where email appears
  - Hunter.io           -> optional verification if API key is provided
  - Excel Export        -> multi-sheet formatted workbook (.xlsx) generation via openpyxl
"""

import io
import re
import hashlib
import httpx
import dns.resolver
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.config import settings

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_valid_email(email: str) -> bool:
    """Basic email format validation."""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email.strip()))


# ═══════════════════════════════ OSINT SOURCES ═══════════════════════════════

async def _query_emailrep(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """EmailRep.io — free, no key needed (100 req/day), or with API key."""
    try:
        headers = {"User-Agent": "OSINT-Academic-Research/2.0"}
        if settings.emailrep_api_key:
            headers["Key"] = settings.emailrep_api_key

        r = await client.get(f"https://emailrep.io/{email}", headers=headers)
        if r.status_code == 200:
            data = r.json()
            details = data.get("details", {})
            return {
                "source": "emailrep.io",
                "success": True,
                "reputation": data.get("reputation", "unknown"),
                "suspicious": data.get("suspicious", False),
                "references": data.get("references", 0),
                "profiles": details.get("profiles", []),
                "deliverable": details.get("deliverable"),
                "domain_exists": details.get("domain_exists"),
                "free_provider": details.get("free_provider", False),
                "disposable": details.get("disposable", False),
                "spam": details.get("spam", False),
                "malicious_activity": details.get("malicious_activity", False),
                "credentials_leaked": details.get("credentials_leaked", False),
                "data_breach": details.get("data_breach", False),
                "first_seen": details.get("first_seen"),
                "last_seen": details.get("last_seen"),
                "days_since_domain_creation": details.get("days_since_domain_creation"),
                "spoofable": details.get("spoofable"),
                "spf_strict": details.get("spf_strict"),
                "dmarc_enforced": details.get("dmarc_enforced"),
                "accepted_all": details.get("accepted_all"),
            }
        return {"source": "emailrep.io", "success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "emailrep.io", "success": False, "error": str(e)}


def _get_github_headers() -> Dict[str, str]:
    headers = {
        "User-Agent": "OSINT-to-Attack-Path",
        "Accept": "application/vnd.github+json",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


async def _query_github_commits(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """GitHub commit search — find public commits by author email."""
    try:
        headers = _get_github_headers()
        headers["Accept"] = "application/vnd.github.cloak-preview"
        r = await client.get(
            f"https://api.github.com/search/commits?q=author-email:{email}&per_page=15",
            headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            total = data.get("total_count", 0)
            items = data.get("items", [])
            commits = []
            seen_repos = set()
            for item in items[:15]:
                commit = item.get("commit", {})
                author = commit.get("author", {})
                repo = item.get("repository", {})
                repo_full = repo.get("full_name", "")
                commits.append({
                    "repo": repo_full,
                    "repo_url": repo.get("html_url", ""),
                    "message": commit.get("message", "")[:140],
                    "author_name": author.get("name", ""),
                    "date": author.get("date", ""),
                    "commit_url": item.get("html_url", ""),
                })
                if repo_full:
                    seen_repos.add(repo_full)
            return {
                "source": "github_commits",
                "success": True,
                "total_commits": total,
                "commits": commits,
                "unique_repos": list(seen_repos),
            }
        return {"source": "github_commits", "success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "github_commits", "success": False, "error": str(e)}


async def _query_github_code(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """GitHub code search — find public repositories and files referencing this email."""
    try:
        headers = _get_github_headers()
        r = await client.get(
            f'https://api.github.com/search/code?q="{email}"&per_page=15',
            headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            total = data.get("total_count", 0)
            items = data.get("items", [])
            references = []
            for item in items[:15]:
                repo = item.get("repository", {})
                references.append({
                    "file": item.get("name", ""),
                    "path": item.get("path", ""),
                    "repo": repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "file_url": item.get("html_url", ""),
                })
            return {
                "source": "github_code",
                "success": True,
                "total_references": total,
                "references": references,
            }
        return {"source": "github_code", "success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "github_code", "success": False, "error": str(e)}


async def _query_github_users(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """GitHub user search — find user profiles associated with this email."""
    try:
        headers = _get_github_headers()
        r = await client.get(
            f"https://api.github.com/search/users?q={email}+in:email&per_page=5",
            headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            users = []
            for u in data.get("items", [])[:5]:
                profile_r = await client.get(u.get("url", ""), headers=headers)
                if profile_r.status_code == 200:
                    p = profile_r.json()
                    users.append({
                        "login": p.get("login", ""),
                        "name": p.get("name", ""),
                        "avatar_url": p.get("avatar_url", ""),
                        "profile_url": p.get("html_url", ""),
                        "bio": p.get("bio", ""),
                        "company": p.get("company", ""),
                        "location": p.get("location", ""),
                        "blog": p.get("blog", ""),
                        "twitter_username": p.get("twitter_username", ""),
                        "public_repos": p.get("public_repos", 0),
                        "followers": p.get("followers", 0),
                        "created_at": p.get("created_at", ""),
                    })
            return {
                "source": "github_users",
                "success": True,
                "users": users,
            }
        return {"source": "github_users", "success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "github_users", "success": False, "error": str(e)}


async def _query_gravatar(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Gravatar profile & avatar metadata via email MD5 hash."""
    email_clean = email.strip().lower()
    email_hash = hashlib.md5(email_clean.encode()).hexdigest()
    profile_url = f"https://gravatar.com/{email_hash}"
    avatar_url = f"https://gravatar.com/avatar/{email_hash}?d=404"

    res = {
        "source": "gravatar",
        "success": False,
        "hash": email_hash,
        "profile_url": profile_url,
        "avatar_url": avatar_url,
        "has_avatar": False,
        "display_name": None,
        "bio": None,
        "location": None,
    }

    try:
        # Check avatar existence
        avatar_r = await client.head(avatar_url)
        if avatar_r.status_code == 200:
            res["success"] = True
            res["has_avatar"] = True

        # Check public JSON profile
        json_r = await client.get(
            f"https://gravatar.com/{email_hash}.json",
            headers={"User-Agent": "OSINT-to-Attack-Path"}
        )
        if json_r.status_code == 200:
            p_data = json_r.json()
            entry = p_data.get("entry", [{}])[0]
            res["success"] = True
            res["display_name"] = entry.get("displayName") or entry.get("preferredUsername")
            res["bio"] = entry.get("aboutMe")
            res["location"] = entry.get("currentLocation")
            if entry.get("profileUrl"):
                res["profile_url"] = entry.get("profileUrl")
    except Exception as e:
        res["error"] = str(e)

    return res


def _identify_mail_provider(mx_records: List[Dict]) -> Optional[str]:
    """Identify corporate / cloud mail provider from MX records."""
    if not mx_records:
        return None
    exchange = mx_records[0].get("exchange", "").lower()
    providers = {
        "google": "Google Workspace",
        "gmail": "Google Workspace",
        "outlook": "Microsoft 365",
        "microsoft": "Microsoft 365",
        "protection.outlook": "Microsoft 365",
        "zoho": "Zoho Mail",
        "protonmail": "ProtonMail",
        "proton": "ProtonMail",
        "yahoodns": "Yahoo Mail",
        "icloud": "Apple iCloud Mail",
        "mimecast": "Mimecast",
        "barracuda": "Barracuda",
        "pphosted": "Proofpoint",
        "sendgrid": "SendGrid",
        "mailgun": "Mailgun",
        "amazonses": "Amazon SES",
        "cloudflare": "Cloudflare Email Routing",
    }
    for key, name in providers.items():
        if key in exchange:
            return name
    return exchange.split(".")[-2].title() if "." in exchange else exchange


def _query_dns_mx(email: str) -> Dict[str, Any]:
    """DNS MX record, SPF and DMARC lookup for email domain."""
    domain = email.split("@")[1] if "@" in email else email
    try:
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_records.append({
                    "priority": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip("."),
                })
            mx_records.sort(key=lambda x: x["priority"])
        except Exception:
            pass

        # SPF TXT check
        spf_record = None
        spf_status = "Not Found"
        try:
            txt_answers = dns.resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    if "-all" in txt:
                        spf_status = "Strict Reject (-all)"
                    elif "~all" in txt:
                        spf_status = "SoftFail (~all)"
                    elif "?all" in txt:
                        spf_status = "Neutral (?all)"
                    else:
                        spf_status = "Configured"
                    break
        except Exception:
            pass

        # DMARC TXT check
        dmarc_record = None
        dmarc_policy = "Not Found"
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in dmarc_answers:
                txt = rdata.to_text().strip('"')
                if "v=DMARC1" in txt:
                    dmarc_record = txt
                    p_match = re.search(r'p=(\w+)', txt)
                    if p_match:
                        dmarc_policy = f"Policy: {p_match.group(1).upper()}"
                    else:
                        dmarc_policy = "Configured"
                    break
        except Exception:
            pass

        return {
            "source": "dns_mx",
            "success": bool(mx_records or spf_record),
            "domain": domain,
            "mx_records": mx_records,
            "spf_record": spf_record,
            "spf_status": spf_status,
            "dmarc_record": dmarc_record,
            "dmarc_policy": dmarc_policy,
            "mail_provider": _identify_mail_provider(mx_records),
        }
    except Exception as e:
        return {"source": "dns_mx", "success": False, "domain": domain, "error": str(e), "mx_records": []}


async def _query_public_web_pages(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Search DuckDuckGo HTML for public webpages and documentation where the email appears.
    100% free OSINT without API keys or browser automation.
    """
    try:
        r = await client.post(
            "https://html.duckduckgo.com/html/",
            data={"q": f'"{email}"'},
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        if r.status_code == 200:
            # Parse result snippets and urls
            pattern = re.compile(
                r'<h2 class="result__title">.*?<a class="result__url"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?<a class="result__snippet[^"]*"[^>]*>(.*?)</a>',
                re.DOTALL
            )
            matches = pattern.findall(r.text)
            pages = []
            seen_urls = set()

            for href, title_html, snippet_html in matches[:10]:
                url = href.strip()
                if "duckduckgo.com" in url or url in seen_urls:
                    continue
                seen_urls.add(url)
                title = re.sub(r'<[^>]+>', '', title_html).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet_html).strip()
                pages.append({
                    "title": title or url,
                    "url": url,
                    "snippet": snippet,
                    "source": "DuckDuckGo Web Index",
                })

            # Fallback regex if layout differed slightly
            if not pages:
                snippet_pattern = re.compile(
                    r'<a class="result__snippet[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                    re.DOTALL
                )
                for href, snippet_html in snippet_pattern.findall(r.text)[:8]:
                    url = href.strip()
                    if url and url not in seen_urls and "duckduckgo.com" not in url:
                        seen_urls.add(url)
                        snippet = re.sub(r'<[^>]+>', '', snippet_html).strip()
                        pages.append({
                            "title": url.split("//")[-1].split("/")[0],
                            "url": url,
                            "snippet": snippet,
                            "source": "DuckDuckGo Web Index",
                        })

            return {
                "source": "public_web_search",
                "success": len(pages) > 0,
                "total_pages": len(pages),
                "pages": pages,
            }
        return {"source": "public_web_search", "success": False, "error": f"HTTP {r.status_code}", "pages": []}
    except Exception as e:
        return {"source": "public_web_search", "success": False, "error": str(e), "pages": []}


async def _query_hunter_verifier(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Hunter.io email verifier API (if API key is configured)."""
    if not settings.hunter_api_key:
        return {"source": "hunter.io", "success": False, "configured": False}
    try:
        r = await client.get(
            f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={settings.hunter_api_key}"
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "source": "hunter.io",
                "success": True,
                "configured": True,
                "status": data.get("status"),
                "result": data.get("result"),
                "score": data.get("score"),
                "sources": [s.get("uri") for s in data.get("sources", [])[:5] if s.get("uri")],
            }
        return {"source": "hunter.io", "success": False, "configured": True, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "hunter.io", "success": False, "configured": True, "error": str(e)}


async def _query_xposedornot(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    XposedOrNot (XON) — free, keyless breach intelligence lookup.
    Checks if email has been exposed in data breaches, and returns breach details:
    risk score, exposure metrics, breach descriptions, exposed data types, and password risk.
    """
    res = {
        "source": "xposedornot",
        "success": False,
        "breached": False,
        "breach_count": 0,
        "breaches": [],
        "pastes_count": 0,
        "risk_score": 0.0,
        "risk_label": "Clean",
        "exposed_data_types": [],
        "summary_sites": [],
    }
    try:
        headers = {
            "User-Agent": "OSINT-to-Attack-Path/2.0",
        }
        if settings.xposedornot_api_key:
            headers["x-api-key"] = settings.xposedornot_api_key

        # 1. Primary: Detailed breach analytics
        r = await client.get(
            f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
            headers=headers,
        )

        if r.status_code == 200:
            data = r.json()
            exposed = data.get("ExposedBreaches") or {}
            breaches_details = exposed.get("breaches_details") if isinstance(exposed, dict) else []
            summary = data.get("BreachesSummary") or {}
            site_str = summary.get("site", "") if isinstance(summary, dict) else ""

            pastes_summary = data.get("PastesSummary") or {}
            pastes_cnt = pastes_summary.get("cnt", 0) if isinstance(pastes_summary, dict) else 0

            if breaches_details:
                res["success"] = True
                res["breached"] = True
                res["breach_count"] = len(breaches_details)
                res["pastes_count"] = pastes_cnt

                parsed_breaches = []
                all_data_types = set()
                max_risk = 0.0
                for b in breaches_details:
                    b_name = b.get("breach", "Unknown")
                    x_data = b.get("xposed_data", "")
                    data_list = [d.strip() for d in x_data.split(";") if d.strip()] if isinstance(x_data, str) else []
                    for dt in data_list:
                        all_data_types.add(dt)

                    p_risk = str(b.get("password_risk") or "unknown").lower()
                    b_risk = float(b.get("risk_score") or 0.0) if b.get("risk_score") else 0.0
                    if b_risk > max_risk:
                        max_risk = b_risk

                    parsed_breaches.append({
                        "breach": b_name,
                        "domain": b.get("domain", ""),
                        "industry": b.get("industry", ""),
                        "logo": b.get("logo", ""),
                        "details": b.get("details", ""),
                        "password_risk": p_risk,
                        "risk_score": b.get("risk_score"),
                        "xposed_data": data_list,
                        "xposed_date": str(b.get("xposed_date") or ""),
                        "xposed_records": b.get("xposed_records", 0),
                        "references": b.get("references", ""),
                        "searchable": b.get("searchable", "Yes"),
                        "verified": b.get("verified", "Yes"),
                    })

                res["breaches"] = parsed_breaches
                res["exposed_data_types"] = sorted(list(all_data_types))
                res["summary_sites"] = [b["breach"] for b in parsed_breaches]
                # NIST SP 800-30 Breach Risk Scoring (Likelihood x Impact / 10):
                b_likelihood = min(10.0, 3.0 + len(breaches_details) * 1.2 + (pastes_cnt * 0.8))
                has_pw = any("password" in dt.lower() or "credential" in dt.lower() for dt in all_data_types)
                has_plain = any("plaintext" in str(b.get("password_risk", "")).lower() for b in breaches_details)
                b_impact = 4.0 + (3.5 if has_pw else 0.0) + (2.5 if has_plain else 0.0)
                nist_breach_score = min(10.0, max(0.0, round((b_likelihood * b_impact) / 10.0, 1)))

                res["risk_score"] = max_risk if (max_risk and max_risk > 0) else nist_breach_score
                res["risk_label"] = "High Risk (NIST)" if res["risk_score"] >= 7.0 else "Moderate Risk (NIST)" if res["risk_score"] >= 4.0 else "Low Risk (NIST)"
                return res

            elif site_str:
                site_list = [s.strip() for s in site_str.split(";") if s.strip()]
                res["success"] = True
                res["breached"] = True
                res["breach_count"] = len(site_list)
                res["summary_sites"] = site_list
                res["breaches"] = [
                    {
                        "breach": name,
                        "domain": "",
                        "industry": "",
                        "logo": "",
                        "details": f"Exposed in {name} breach dump",
                        "password_risk": "unknown",
                        "xposed_data": ["Credentials", "Email addresses"],
                        "xposed_date": "",
                        "xposed_records": 0,
                    }
                    for name in site_list
                ]
                res["exposed_data_types"] = ["Credentials", "Email addresses"]
                site_l = min(10.0, 3.5 + len(site_list) * 1.2)
                site_i = 7.0
                res["risk_score"] = min(10.0, round((site_l * site_i) / 10.0, 1))
                res["risk_label"] = "High Risk (NIST)" if res["risk_score"] >= 7.0 else "Moderate Risk (NIST)"
                return res

            else:
                # Clean result (ExposedBreaches is null and site is empty)
                res["success"] = True
                res["breached"] = False
                res["breach_count"] = 0
                res["risk_score"] = 0.0
                res["risk_label"] = "Clean / No Exposure"
                return res

        elif r.status_code == 404:
            res["success"] = True
            res["breached"] = False
            res["breach_count"] = 0
            res["risk_score"] = 0.0
            res["risk_label"] = "Clean / No Exposure"
            return res

        # 2. Fallback to check-email if breach-analytics returned an unexpected status code
        fb_r = await client.get(f"https://api.xposedornot.com/v1/check-email/{email}", headers=headers)
        if fb_r.status_code == 200:
            fb_data = fb_r.json()
            raw_breaches = fb_data.get("breaches", [])
            flat_breaches = []
            if raw_breaches and isinstance(raw_breaches, list):
                if isinstance(raw_breaches[0], list):
                    flat_breaches = raw_breaches[0]
                else:
                    flat_breaches = raw_breaches
            if flat_breaches:
                res["success"] = True
                res["breached"] = True
                res["breach_count"] = len(flat_breaches)
                res["summary_sites"] = flat_breaches
                res["breaches"] = [
                    {
                        "breach": name,
                        "domain": "",
                        "industry": "",
                        "logo": "",
                        "details": f"Exposed in {name} breach dump",
                        "password_risk": "unknown",
                        "xposed_data": ["Credentials", "Email addresses"],
                        "xposed_date": "",
                        "xposed_records": 0,
                    }
                    for name in flat_breaches
                ]
                fb_l = min(10.0, 3.5 + len(flat_breaches) * 1.2)
                fb_i = 7.0
                res["risk_score"] = min(10.0, round((fb_l * fb_i) / 10.0, 1))
                res["risk_label"] = "High Risk (NIST)" if res["risk_score"] >= 7.0 else "Moderate Risk (NIST)"
                return res
            elif fb_data.get("Error") == "Not found":
                res["success"] = True
                res["breached"] = False
                res["breach_count"] = 0
                res["risk_score"] = 0.0
                res["risk_label"] = "Clean / No Exposure"
                return res

        elif fb_r.status_code == 404:
            res["success"] = True
            res["breached"] = False
            res["breach_count"] = 0
            res["risk_score"] = 0.0
            res["risk_label"] = "Clean / No Exposure"
            return res

        res["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        res["error"] = str(e)
    return res


# ═══════════════════════ REPUTATION & SECURITY POSTURE ═══════════════════════

def _compute_security_posture(
    email: str,
    reputation: Dict[str, Any],
    dns_data: Dict[str, Any],
    xon_data: Dict[str, Any],
    hunter_data: Optional[Dict[str, Any]] = None,
    github_commits: Optional[Dict[str, Any]] = None,
    github_code: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compute a multi-dimensional Security Posture and Threat Risk Index for an email address.
    Evaluates:
      1. Credential & Identity Exposure (breaches, leaked creds, plaintext passwords, pastes)
      2. Domain Spoofability & Email Authentication (SPF, DMARC, spoofable status, MX provider)
      3. Account & Domain Authenticity (deliverability, disposable, free webmail, domain existence)
      4. Threat Intelligence & Blacklist Signals (EmailRep reputation, spam/malicious flags, public references)
    Produces an overall composite risk score (0-100), health score, letter grade (A-F),
    threat level, attack path exploitation scenarios, and actionable defensive playbook.
    """
    domain = email.split("@")[1] if "@" in email else ""
    local_part = email.split("@")[0] if "@" in email else email

    # 1. Credential & Identity Exposure Vector
    breaches = xon_data.get("breaches", []) if isinstance(xon_data, dict) else []
    breach_count = len(breaches) or (xon_data.get("breach_count", 0) if isinstance(xon_data, dict) else 0)
    pastes_count = xon_data.get("pastes_count", 0) if isinstance(xon_data, dict) else 0
    creds_leaked = bool(reputation.get("credentials_leaked")) if isinstance(reputation, dict) else False
    data_breach = bool(reputation.get("data_breach")) if isinstance(reputation, dict) else bool(breach_count > 0)
    exposed_types = xon_data.get("exposed_data_types", []) if isinstance(xon_data, dict) else []

    pw_risk_levels = [str(b.get("password_risk", "")).lower() for b in breaches if isinstance(b, dict)]
    has_plaintext = any("plaintext" in pr or "easy" in pr for pr in pw_risk_levels)
    has_passwords = has_plaintext or any("password" in str(t).lower() or "credential" in str(t).lower() for t in exposed_types)

    cred_score = 0.0
    if creds_leaked:
        cred_score += 35.0
    if data_breach or breach_count > 0:
        cred_score += 25.0
    cred_score += min(25.0, breach_count * 8.0)
    if pastes_count > 0:
        cred_score += 10.0
    if has_plaintext:
        cred_score += 15.0
    elif has_passwords:
        cred_score += 8.0
    cred_score = min(100.0, max(0.0, round(cred_score, 1)))

    if cred_score >= 75.0:
        cred_status = "CRITICAL"
    elif cred_score >= 50.0:
        cred_status = "HIGH RISK"
    elif cred_score >= 25.0:
        cred_status = "ELEVATED"
    elif cred_score > 0.0:
        cred_status = "LOW RISK"
    else:
        cred_status = "CLEAN"

    # 2. Domain Spoofability & Email Auth Vector
    spf_status = (dns_data.get("spf_status") or "Not Found") if isinstance(dns_data, dict) else "Not Found"
    dmarc_policy = (dns_data.get("dmarc_policy") or "Not Found") if isinstance(dns_data, dict) else "Not Found"
    spoofable = reputation.get("spoofable") if isinstance(reputation, dict) else None
    mx_records = dns_data.get("mx_records", []) if isinstance(dns_data, dict) else []

    if "Strict Reject" in spf_status or "-all" in spf_status:
        spf_risk = 5.0
    elif "SoftFail" in spf_status or "~all" in spf_status:
        spf_risk = 35.0
    elif "Neutral" in spf_status or "?all" in spf_status:
        spf_risk = 55.0
    elif "Configured" in spf_status:
        spf_risk = 30.0
    else:
        spf_risk = 75.0

    if "REJECT" in dmarc_policy.upper():
        dmarc_risk = 5.0
    elif "QUARANTINE" in dmarc_policy.upper():
        dmarc_risk = 25.0
    elif "NONE" in dmarc_policy.upper():
        dmarc_risk = 60.0
    elif "CONFIGURED" in dmarc_policy.upper():
        dmarc_risk = 35.0
    else:
        dmarc_risk = 80.0

    spoof_score = round(spf_risk * 0.45 + dmarc_risk * 0.55, 1)
    if spoofable is True:
        spoof_score = max(spoof_score, 75.0)
    elif spoofable is False:
        spoof_score = min(spoof_score, 30.0)
    if not mx_records:
        spoof_score = min(100.0, spoof_score + 15.0)
    spoof_score = min(100.0, max(0.0, round(spoof_score, 1)))

    if spoof_score >= 70.0:
        spoof_status = "HIGHLY SPOOFABLE"
    elif spoof_score >= 45.0:
        spoof_status = "VULNERABLE"
    elif spoof_score >= 25.0:
        spoof_status = "MODERATE"
    else:
        spoof_status = "PROTECTED"

    # 3. Account & Domain Authenticity Vector
    deliverable = reputation.get("deliverable") if isinstance(reputation, dict) else None
    disposable = bool(reputation.get("disposable")) if isinstance(reputation, dict) else False
    free_provider = bool(reputation.get("free_provider")) if isinstance(reputation, dict) else False
    domain_exists = reputation.get("domain_exists", True) if isinstance(reputation, dict) else True

    auth_score = 5.0
    if disposable:
        auth_score += 65.0
    if domain_exists is False:
        auth_score += 50.0
    if deliverable is False:
        auth_score += 35.0
    elif deliverable is None:
        auth_score += 10.0
    if free_provider:
        auth_score += 15.0
    auth_score = min(100.0, max(0.0, round(auth_score, 1)))

    if disposable:
        auth_status = "DISPOSABLE / BURNER"
    elif auth_score >= 60.0:
        auth_status = "SUSPICIOUS / RISKY"
    elif auth_score >= 35.0:
        auth_status = "UNVERIFIED"
    else:
        auth_status = "VERIFIED"

    # 4. Threat Intelligence & Blacklist Vector
    rep_val = str(reputation.get("reputation", "unknown")).lower() if isinstance(reputation, dict) else "unknown"
    suspicious = bool(reputation.get("suspicious")) if isinstance(reputation, dict) else False
    spam = bool(reputation.get("spam")) if isinstance(reputation, dict) else False
    malicious = bool(reputation.get("malicious_activity")) if isinstance(reputation, dict) else False
    references = int(reputation.get("references") or 0) if isinstance(reputation, dict) else 0

    threat_score = 10.0
    if rep_val == "high":
        threat_score = 5.0
    elif rep_val == "medium":
        threat_score = 25.0
    elif rep_val in ("low", "none"):
        threat_score = 55.0
    elif rep_val == "unknown":
        threat_score = 20.0
    if suspicious:
        threat_score += 35.0
    if spam:
        threat_score += 25.0
    if malicious:
        threat_score += 45.0
    if references >= 10:
        threat_score = max(0.0, threat_score - 10.0)
    threat_score = min(100.0, max(0.0, round(threat_score, 1)))

    if malicious:
        threat_status = "MALICIOUS"
    elif suspicious or threat_score >= 70.0:
        threat_status = "SUSPICIOUS"
    elif threat_score >= 45.0:
        threat_status = "ELEVATED RISK"
    elif threat_score >= 25.0:
        threat_status = "NEUTRAL"
    else:
        threat_status = "HIGH TRUST"

    # NIST SP 800-30 Rev. 1 Risk Scoring Method:
    # Risk = Threat Event Likelihood (0-10) × Threat Event Impact (0-10) -> (0-100)
    
    # Threat Event Likelihood (0-10): Combines spoofability pre-disposition, mailbox authenticity, and external threat signals
    spoof_l = min(4.0, spoof_score / 25.0)
    auth_l = min(3.0, auth_score / 33.3)
    threat_l = min(3.0, threat_score / 33.3)
    nist_likelihood = min(10.0, max(1.0, round(spoof_l + auth_l + threat_l, 1)))

    # Threat Event Impact (0-10): Combines credential compromise severity and organizational/asset blast radius
    cred_i = min(6.0, cred_score / 16.7)
    blast_radius = 1.5 + (1.5 if not free_provider and not disposable else 0.5) + (1.0 if (has_plaintext or creds_leaked) else 0.0)
    nist_impact = min(10.0, max(1.0, round(cred_i + blast_radius, 1)))

    # Overall NIST Risk Score & Health Resilience:
    composite_score = min(100.0, max(0.0, round(nist_likelihood * nist_impact, 1)))
    health_score = round(max(0.0, 100.0 - composite_score), 1)

    if composite_score > 80.0:
        grade = "F"
        risk_level = "CRITICAL THREAT"
        badge_color = "#ef4444"
    elif composite_score > 60.0:
        grade = "D"
        risk_level = "HIGH RISK"
        badge_color = "#ea580c"
    elif composite_score > 40.0:
        grade = "C"
        risk_level = "MODERATE RISK"
        badge_color = "#f59e0b"
    elif composite_score > 20.0:
        grade = "B"
        risk_level = "LOW RISK"
        badge_color = "#38bdf8"
    else:
        grade = "A"
        risk_level = "CLEAN / SECURE"
        badge_color = "#22c55e"

    # Verdict synthesis
    verdict_parts = []
    if creds_leaked or breach_count > 0:
        verdict_parts.append(f"compromised credentials detected across {breach_count or 1} public breach incident(s)")
    if spoof_score >= 45.0:
        verdict_parts.append("weak email authentication policy allowing spoofing")
    if suspicious or malicious:
        verdict_parts.append("active threat intelligence risk flags")
    if disposable:
        verdict_parts.append("burner/disposable mailbox domain")

    if verdict_parts:
        verdict = f"{risk_level.title()} Posture: Detected {', and '.join(verdict_parts)}. Adversary weaponization requires priority defensive intervention."
    else:
        verdict = "Secure Posture: No compromised credentials, active threat flags, or critical email authentication vulnerabilities detected for this address."

    # Attack Scenarios
    attack_scenarios = []
    commits_list = github_commits.get("commits", []) if isinstance(github_commits, dict) else []
    code_list = github_code.get("references", []) if isinstance(github_code, dict) else []

    if cred_score >= 25.0 or creds_leaked or breach_count > 0:
        attack_scenarios.append({
            "id": "scenario_credential_stuffing",
            "title": "Credential Stuffing & Lateral SSO Account Takeover",
            "mitre_technique": "T1110.004",
            "mitre_name": "Credential Stuffing",
            "probability": "HIGH" if has_plaintext else "MEDIUM",
            "impact": "CRITICAL",
            "description": f"Adversary correlates {email} with public breach records and utilizes recovered password hashes to spray corporate single sign-on (SSO), VPN gateways, and cloud console endpoints.",
            "attack_steps": [
                f"1. OSINT Harvest: Query breach indexing databases for {email} to retrieve historical credentials.",
                "2. Hash Cracking: Execute GPU-accelerated wordlist cracking on retrieved salted hashes or use leaked plaintext passwords directly.",
                "3. Credential Spraying: Replay credentials against corporate Okta/Azure AD portals, GitHub, and remote access endpoints.",
                "4. Persistence & Privilege Escalation: Bypass un-enforced MFA or exploit MFA fatigue to establish persistence inside corporate infrastructure."
            ],
            "mitigation": "Enforce mandatory FIDO2/WebAuthn hardware MFA across all IdP providers, invalidate all past passwords, and monitor active session tokens."
        })

    if spoof_score >= 35.0 or spoofable:
        attack_scenarios.append({
            "id": "scenario_domain_spoofing",
            "title": "Domain Spoofing & Business Email Compromise (BEC)",
            "mitre_technique": "T1566.002",
            "mitre_name": "Spearphishing Link / Email Impersonation",
            "probability": "HIGH" if spoof_score >= 60.0 else "MEDIUM",
            "impact": "HIGH",
            "description": f"Because {domain or 'the domain'} lacks strict DMARC reject enforcement, attackers can forge emails appearing to originate directly from this address to deceive employees, partners, or customers.",
            "attack_steps": [
                f"1. DNS Reconnaissance: Identify that {domain or 'domain'} uses permissive SPF ({spf_status}) and missing/non-enforced DMARC ({dmarc_policy}).",
                "2. Mail Forgery: Use an open mail relay or bulletproof SMTP server with a forged `From: " + email + "` header.",
                "3. Infiltration: Recipient MTAs accept the message into the primary inbox due to absence of strict rejection rules.",
                "4. Social Engineering: Deceive finance or operations personnel into executing unauthorized wire transfers, divulging API secrets, or clicking credential-stealing lures."
            ],
            "mitigation": f"Publish strict DMARC policy `v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@{domain}` and update SPF to `-all`."
        })

    if len(commits_list) > 0 or len(code_list) > 0:
        attack_scenarios.append({
            "id": "scenario_developer_spearphishing",
            "title": "Developer Targeted Spear-Phishing & Supply Chain Infiltration",
            "mitre_technique": "T1566.001",
            "mitre_name": "Spearphishing Attachment / Code Tampering",
            "probability": "HIGH" if len(commits_list) >= 2 else "MEDIUM",
            "impact": "CRITICAL",
            "description": f"Public commit records disclose developer role and repository involvement. Attackers craft hyper-targeted lures targeting software dependencies, CI/CD pull requests, or code review notifications.",
            "attack_steps": [
                f"1. Code Footprint Analysis: Adversary maps developer's commit activity across public repositories ({', '.join([c.get('repo', '') for c in commits_list[:2]]) or 'repositories'}).",
                "2. Contextual Pretexting: Craft a weaponized pull request issue or fake security alert referencing developer's active projects.",
                "3. Malicious Code Execution: Developer installs a malicious package containing post-install command execution hooks.",
                "4. CI/CD & Production Tampering: Attacker extracts developer AWS/GCP tokens or SSH keys to tamper with production deployment pipelines."
            ],
            "mitigation": "Enforce GPG commit signing, mandate branch protection rules requiring multiple independent reviews, and deploy developer workstation EDR."
        })

    if disposable or auth_score >= 45.0 or free_provider:
        attack_scenarios.append({
            "id": "scenario_shadow_identity",
            "title": "Shadow Account Hijack & Orphaned SaaS Access",
            "mitre_technique": "T1586.002",
            "mitre_name": "Compromise Accounts: Email Accounts",
            "probability": "MEDIUM",
            "impact": "MEDIUM",
            "description": "Unmanaged or consumer/burner email addresses used for corporate cloud services evade central IAM governance and offboarding controls, creating persistent backdoors.",
            "attack_steps": [
                "1. SaaS Account Enumeration: Attacker identifies corporate test environments or third-party SaaS accounts registered using this address.",
                "2. Password Reset Hijack: Exploit unmonitored or expired mailbox access to trigger automated password reset links.",
                "3. Corporate Data Exfiltration: Download proprietary source code, tickets, or infrastructure configurations stored in shadow tools."
            ],
            "mitigation": "Enforce Single Sign-On (SSO) federation and block non-corporate / burner email registrations across enterprise cloud assets."
        })

    # Defensive Playbook Checklist
    defensive_playbook = []
    if cred_score >= 25.0 or creds_leaked or breach_count > 0:
        defensive_playbook.append({
            "priority": "P1 - Critical",
            "category": "Credential Hygiene",
            "title": "Enforce Hardware MFA & Trigger Enterprise Password Reset",
            "description": f"Exposures detected across public breach sets for {email}. Force an immediate password expiration and mandate hardware-backed FIDO2 / WebAuthn MFA.",
            "effort": "LOW",
            "remediation_cmd": "Revoke active SSO sessions & trigger password reset in identity provider",
        })

    if spoof_score >= 35.0:
        defensive_playbook.append({
            "priority": "P1 - Critical" if spoof_score >= 60.0 else "P2 - High",
            "category": "Email Authentication",
            "title": "Enforce Strict DMARC Policy (p=reject) & SPF HardFail (-all)",
            "description": f"Protect {domain or 'domain'} against email spoofing and BEC attacks by publishing a strict DMARC rejection rule and updating SPF to hard-fail.",
            "effort": "LOW",
            "remediation_cmd": f'DNS TXT: _dmarc.{domain or "domain.com"} -> "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@{domain or "domain.com"}"',
        })

    if len(commits_list) > 0 or len(code_list) > 0:
        defensive_playbook.append({
            "priority": "P2 - High",
            "category": "Source Code Security",
            "title": "Mandate GPG Commit Signing & Run Secret Scanning",
            "description": "Public commit history links this email to repository commits. Enable GitHub secret scanning and enforce signed commits to prevent unauthorized commit spoofing.",
            "effort": "MEDIUM",
            "remediation_cmd": "git config --global commit.gpgsign true; git config --global user.signingkey <KEY_ID>",
        })

    defensive_playbook.append({
        "priority": "P3 - Moderate",
        "category": "Threat Intelligence",
        "title": "Continuous Dark Web & Threat Intel Monitoring",
        "description": f"Subscribe {email} to real-time breach alerting feeds to receive instant notifications if new dump archives or credential pastes emerge.",
        "effort": "LOW",
        "remediation_cmd": "Configure automated XposedOrNot / HIBP domain alerting webhook",
    })

    # Posture Matrix (Controls Assessment Table)
    posture_matrix = [
        {
            "category": "Authentication",
            "control": "SPF Record HardFail (-all)",
            "value": spf_status,
            "status": "PASS" if ("Strict" in spf_status or "-all" in spf_status) else "WARNING" if ("SoftFail" in spf_status or "~all" in spf_status) else "FAIL",
            "detail": "Strict HardFail explicitly instructs mail servers to drop forged mail.",
            "recommendation": "Update SPF TXT record to end with `-all` instead of `~all`."
        },
        {
            "category": "Authentication",
            "control": "DMARC Policy Enforcement",
            "value": dmarc_policy,
            "status": "PASS" if "REJECT" in dmarc_policy.upper() else "WARNING" if "QUARANTINE" in dmarc_policy.upper() else "FAIL",
            "detail": "DMARC p=reject protects domain reputation by discarding unauthenticated messages.",
            "recommendation": "Set `p=reject; sp=reject` with RUA reporting destination."
        },
        {
            "category": "Breach Exposure",
            "control": "Public Data Breach Exposure",
            "value": f"{breach_count} Incident(s) Detected" if breach_count > 0 else "Clean (0 Breaches)",
            "status": "FAIL" if breach_count >= 2 else "WARNING" if breach_count == 1 else "PASS",
            "detail": "Accounts found in breach dumps are targeted with automated credential stuffing.",
            "recommendation": "Audit exposed services and verify unique, complex passwords."
        },
        {
            "category": "Breach Exposure",
            "control": "Leaked Credentials & Password Hashes",
            "value": "Plaintext / Crackable" if has_plaintext else "Detected in Leaks" if creds_leaked else "None Detected",
            "status": "FAIL" if (creds_leaked or has_passwords) else "PASS",
            "detail": "Plaintext or cracked password leaks enable immediate unauthorized access.",
            "recommendation": "Enforce enterprise MFA to render leaked passwords ineffective."
        },
        {
            "category": "Domain Posture",
            "control": "Mail Infrastructure Security Tier",
            "value": dns_data.get("mail_provider") or "Standard DNS Mail Exchange",
            "status": "PASS" if dns_data.get("mail_provider") in ("Google Workspace", "Microsoft 365", "ProtonMail", "Mimecast") else "NEUTRAL",
            "detail": "Enterprise cloud mail providers offer built-in anti-phishing and spam filtering.",
            "recommendation": "Ensure provider anti-spoofing and DKIM signing keys are activated."
        },
        {
            "category": "Account Integrity",
            "control": "Burner / Disposable Address Check",
            "value": "Disposable Mailbox" if disposable else "Legitimate Domain",
            "status": "FAIL" if disposable else "PASS",
            "detail": "Disposable mailboxes are frequently utilized for anonymous malicious registrations.",
            "recommendation": "Block disposable domains on corporate registration forms."
        },
        {
            "category": "Account Integrity",
            "control": "Mailbox Deliverability Verification",
            "value": "Deliverable" if deliverable else "Undeliverable / Unknown",
            "status": "PASS" if deliverable else "WARNING",
            "detail": "Active deliverability confirms real recipient inbox presence.",
            "recommendation": "Ensure MX routing targets operational mail servers."
        },
        {
            "category": "Threat Intelligence",
            "control": "EmailRep Threat Reputation Score",
            "value": str(rep_val).upper(),
            "status": "PASS" if rep_val == "high" else "WARNING" if rep_val == "medium" else "FAIL" if rep_val in ("low", "none") else "NEUTRAL",
            "detail": "Reputation aggregates sender trust, internet age, and abuse reports.",
            "recommendation": "Maintain positive sending reputation by preventing outbound spam."
        },
        {
            "category": "Threat Intelligence",
            "control": "Suspicious / Malicious Behavior Flag",
            "value": "FLAGGED (Suspicious)" if (suspicious or malicious) else "Clean (No Flags)",
            "status": "FAIL" if (suspicious or malicious) else "PASS",
            "detail": "Indicates whether this email has been observed in abuse feeds or malicious campaigns.",
            "recommendation": "Quarantine email and audit sending logs if flagged."
        },
        {
            "category": "OSINT Footprint",
            "control": "Public Code & Developer Footprint",
            "value": f"{len(commits_list)} Commits, {len(code_list)} Code Refs" if (commits_list or code_list) else "Minimal Code Footprint",
            "status": "WARNING" if (commits_list or code_list) else "PASS",
            "detail": "Public code references expose developer roles, tech stacks, and internal naming conventions.",
            "recommendation": "Ensure commit email is set to anonymous noreply address for public repos."
        },
    ]

    return {
        "composite_score": composite_score,
        "health_score": health_score,
        "grade": grade,
        "risk_level": risk_level,
        "badge_color": badge_color,
        "verdict": verdict,
        "nist_assessment": {
            "standard": "NIST SP 800-30 Rev. 1",
            "threat_likelihood": nist_likelihood,
            "threat_impact": nist_impact,
            "risk_formula": "Risk = Likelihood (0-10) × Impact (0-10)",
            "risk_score": composite_score,
            "risk_level": risk_level,
            "likelihood_tier": "Very High" if nist_likelihood >= 8.0 else "High" if nist_likelihood >= 6.0 else "Moderate" if nist_likelihood >= 4.0 else "Low" if nist_likelihood >= 2.0 else "Very Low",
            "impact_tier": "Very High" if nist_impact >= 8.0 else "High" if nist_impact >= 6.0 else "Moderate" if nist_impact >= 4.0 else "Low" if nist_impact >= 2.0 else "Very Low",
        },
        "pillars": {
            "credential_exposure": {
                "name": "Credential & Identity Exposure",
                "score": cred_score,
                "status": cred_status,
                "description": f"{breach_count} breach incident(s); {'plaintext / easy-to-crack password risks detected' if has_plaintext else 'creds detected in leak records' if creds_leaked else 'clean record'}.",
                "metrics": {
                    "breaches_count": breach_count,
                    "pastes_count": pastes_count,
                    "credentials_leaked": creds_leaked,
                    "data_breach": data_breach,
                    "password_risk": "Plaintext / Crackable" if has_plaintext else "Crackable Hashes" if has_passwords else "None Recorded",
                    "exposed_types_count": len(exposed_types),
                }
            },
            "spoofing_vulnerability": {
                "name": "Domain Spoofability & Email Auth",
                "score": spoof_score,
                "status": spoof_status,
                "description": f"SPF: {spf_status}; DMARC: {dmarc_policy}; Domain is {'spoofable' if spoofable else 'partially protected' if spoof_score < 45 else 'at risk of impersonation'}.",
                "metrics": {
                    "spf_status": spf_status,
                    "dmarc_policy": dmarc_policy,
                    "spoofable": bool(spoofable) if spoofable is not None else (spoof_score >= 50),
                    "has_mx": bool(mx_records),
                    "mail_provider": dns_data.get("mail_provider") or "Unknown",
                }
            },
            "domain_authenticity": {
                "name": "Account & Domain Authenticity",
                "score": auth_score,
                "status": auth_status,
                "description": f"{'Burner/disposable email address' if disposable else 'Legitimate domain'}. Deliverable: {deliverable if deliverable is not None else 'Unknown'}.",
                "metrics": {
                    "deliverable": deliverable,
                    "disposable": disposable,
                    "free_provider": free_provider,
                    "domain_exists": domain_exists,
                }
            },
            "threat_intelligence": {
                "name": "Threat Intel & Blacklist Signals",
                "score": threat_score,
                "status": threat_status,
                "description": f"Reputation: {rep_val.upper()}. Suspicious: {'YES' if suspicious else 'NO'}. References: {references}.",
                "metrics": {
                    "reputation": rep_val,
                    "suspicious": suspicious,
                    "spam": spam,
                    "malicious_activity": malicious,
                    "references": references,
                }
            }
        },
        "attack_scenarios": attack_scenarios,
        "defensive_playbook": defensive_playbook,
        "posture_matrix": posture_matrix,
    }


# ══════════════════════════ SIMULATION / DEMO DATA ══════════════════════════

def _generate_demo_email_intel(email: str) -> Dict[str, Any]:
    """
    Realistic demo simulation for demonstration domains (e.g. *.apexnova.example)
    or offline demonstration environments.
    """
    local = email.split("@")[0].lower()
    domain = email.split("@")[1].lower() if "@" in email else "example.com"
    name = local.replace(".", " ").title()

    demo_webpages = [
        {
            "title": f"ApexNova Engineering Directory — {name}",
            "url": f"https://docs.{domain}/team/{local}",
            "snippet": f"Contact author: {email}. Core contributor to ApexNova cloud services infrastructure.",
            "source": "Internal Documentation Index",
        },
        {
            "title": f"ApexNova Staging API Changelog — v2.4.0",
            "url": f"https://staging.{domain}/changelog",
            "snippet": f"Release signed off by {name} <{email}>. Deployed Kubernetes staging cluster.",
            "source": "Public Staging Endpoint",
        },
        {
            "title": "GitHub Advisory: Leaked Staging Environment Config",
            "url": f"https://github.com/apexnova-demo/core-api/blob/main/.env.staging",
            "snippet": f"Commit references maintainer email {email}. Contains staging AWS secret tokens.",
            "source": "GitHub Public Code",
        },
    ]

    demo_commits = [
        {
            "repo": "apexnova-demo/core-api",
            "repo_url": "https://github.com/apexnova-demo/core-api",
            "message": "feat(auth): add OAuth2 token validation and staging webhook callback",
            "author_name": name,
            "date": "2026-09-14T10:32:00Z",
            "commit_url": "https://github.com/apexnova-demo/core-api/commit/7f4a21b",
        },
        {
            "repo": "apexnova-demo/infra-deploy",
            "repo_url": "https://github.com/apexnova-demo/infra-deploy",
            "message": "fix: update k8s cluster ingress controller rules for staging.apexnova.example",
            "author_name": name,
            "date": "2026-08-28T14:15:22Z",
            "commit_url": "https://github.com/apexnova-demo/infra-deploy/commit/b8391ca",
        },
    ]

    demo_code = [
        {
            "file": ".env.staging",
            "path": "config/.env.staging",
            "repo": "apexnova-demo/core-api",
            "repo_url": "https://github.com/apexnova-demo/core-api",
            "file_url": "https://github.com/apexnova-demo/core-api/blob/main/config/.env.staging",
        },
        {
            "file": "CODEOWNERS",
            "path": ".github/CODEOWNERS",
            "repo": "apexnova-demo/infra-deploy",
            "repo_url": "https://github.com/apexnova-demo/infra-deploy",
            "file_url": "https://github.com/apexnova-demo/infra-deploy/blob/main/.github/CODEOWNERS",
        },
    ]

    demo_xposedornot = {
        "source": "xposedornot",
        "success": True,
        "breached": True,
        "breach_count": 3,
        "pastes_count": 1,
        "risk_score": 7.8,
        "risk_label": "High Risk",
        "exposed_data_types": [
            "Email addresses",
            "Passwords",
            "Usernames",
            "IP addresses",
            "Authentication tokens",
            "Geographic locations"
        ],
        "summary_sites": ["CloudStagingLeak-2024", "DevOpsCommunity-Dump", "TechForum-CredentialSet"],
        "breaches": [
            {
                "breach": "CloudStagingLeak-2024",
                "domain": f"staging.{domain}",
                "industry": "Information Technology",
                "logo": "https://xposedornot.com/static/logos/Dropbox.png",
                "details": f"In March 2024, an unsecured staging cluster configuration exposed developer records, maintainer email {email}, server IP addresses, and authentication tokens.",
                "password_risk": "plaintext",
                "risk_score": 8.5,
                "xposed_data": ["Email addresses", "Usernames", "IP addresses", "Authentication tokens"],
                "xposed_date": "2024",
                "xposed_records": 3200000,
                "references": f"https://staging.{domain}/changelog",
                "searchable": "Yes",
                "verified": "Yes",
            },
            {
                "breach": "DevOpsCommunity-Dump",
                "domain": "devops-portal.org",
                "industry": "Software Engineering",
                "logo": "https://xposedornot.com/static/logos/Canva.png",
                "details": "A community forum breach compromised account credentials, salted SHA-256 password hashes, and profile metadata for 850,000 infrastructure engineers.",
                "password_risk": "easytocrack",
                "risk_score": 7.2,
                "xposed_data": ["Email addresses", "Passwords", "Usernames"],
                "xposed_date": "2023",
                "xposed_records": 850000,
                "references": "",
                "searchable": "Yes",
                "verified": "Yes",
            },
            {
                "breach": "TechForum-CredentialSet",
                "domain": "techdiscussions.io",
                "industry": "Telecommunications",
                "logo": "https://xposedornot.com/static/logos/Adobe.png",
                "details": "Credential stuffing dump containing combined tech forum user records and geographic location tags.",
                "password_risk": "unknown",
                "risk_score": 5.4,
                "xposed_data": ["Email addresses", "Geographic locations"],
                "xposed_date": "2022",
                "xposed_records": 412000,
                "references": "",
                "searchable": "Yes",
                "verified": "Yes",
            },
        ],
    }

    res_dict = {
        "email": email,
        "domain": domain,
        "local_part": local,
        "lookup_timestamp": _now_iso(),
        "is_demo": True,
        "sources_queried": ["xposedornot", "emailrep.io", "github_commits", "github_code", "github_users", "gravatar", "dns_mx", "public_web_search"],
        "sources_successful": ["xposedornot", "emailrep.io", "github_commits", "github_code", "github_users", "gravatar", "dns_mx", "public_web_search"],
        "xposedornot": demo_xposedornot,
        "breaches": demo_xposedornot["breaches"],
        "identity": {
            "name": name,
            "email": email,
            "domain": domain,
            "username": local.replace(".", ""),
            "avatar_url": f"https://avatars.githubusercontent.com/u/10293847?v=4",
            "company": "ApexNova Technologies",
            "location": "San Francisco, CA / Remote",
            "bio": f"Lead Infrastructure & Cloud Security Engineer @ ApexNova. Kubernetes, Python & Go enthusiast.",
            "mail_provider": "Google Workspace",
            "social_profiles": [
                {"platform": "GitHub", "username": local.replace(".", ""), "url": f"https://github.com/{local.replace('.', '')}"},
                {"platform": "Twitter/X", "username": f"{local.replace('.', '')}_sec", "url": f"https://x.com/{local.replace('.', '')}_sec"},
                {"platform": "LinkedIn", "username": local, "url": f"https://linkedin.com/in/{local}"},
            ],
            "public_webpages": demo_webpages,
        },
        "reputation": {
            "source": "emailrep.io",
            "success": True,
            "reputation": "high",
            "suspicious": False,
            "references": 12,
            "profiles": ["github", "twitter", "linkedin", "spotify"],
            "deliverable": True,
            "domain_exists": True,
            "free_provider": False,
            "disposable": False,
            "spam": False,
            "malicious_activity": False,
            "credentials_leaked": True,
            "data_breach": True,
            "first_seen": "2021-03-15",
            "last_seen": "2026-09-20",
            "spf_strict": True,
            "dmarc_enforced": True,
        },
        "github_commits": {
            "source": "github_commits",
            "success": True,
            "total_commits": len(demo_commits),
            "commits": demo_commits,
            "unique_repos": ["apexnova-demo/core-api", "apexnova-demo/infra-deploy"],
        },
        "github_code": {
            "source": "github_code",
            "success": True,
            "total_references": len(demo_code),
            "references": demo_code,
        },
        "github_users": {
            "source": "github_users",
            "success": True,
            "users": [{
                "login": local.replace(".", ""),
                "name": name,
                "avatar_url": "https://avatars.githubusercontent.com/u/10293847?v=4",
                "profile_url": f"https://github.com/{local.replace('.', '')}",
                "bio": "Lead Infrastructure Engineer @ ApexNova",
                "company": "ApexNova Technologies",
                "location": "San Francisco, CA",
                "public_repos": 14,
                "followers": 86,
            }],
        },
        "gravatar": {
            "source": "gravatar",
            "success": True,
            "has_avatar": True,
            "avatar_url": "https://gravatar.com/avatar/sample?d=identicon",
            "profile_url": "https://gravatar.com/apexnova_dev",
            "display_name": name,
        },
        "dns": {
            "source": "dns_mx",
            "success": True,
            "domain": domain,
            "mail_provider": "Google Workspace",
            "mx_records": [
                {"priority": 1, "exchange": "aspmx.l.google.com"},
                {"priority": 5, "exchange": "alt1.aspmx.l.google.com"},
                {"priority": 5, "exchange": "alt2.aspmx.l.google.com"},
            ],
            "spf_record": "v=spf1 include:_spf.google.com ~all",
            "spf_status": "SoftFail (~all)",
            "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@apexnova.example",
            "dmarc_policy": "Policy: REJECT",
        },
        "public_web_pages": {
            "source": "public_web_search",
            "success": True,
            "total_pages": len(demo_webpages),
            "pages": demo_webpages,
        },
    }

    demo_reputation = {
        "source": "emailrep.io",
        "success": True,
        "reputation": "high",
        "suspicious": False,
        "references": 12,
        "profiles": ["github", "twitter", "linkedin", "spotify"],
        "deliverable": True,
        "domain_exists": True,
        "free_provider": False,
        "disposable": False,
        "spam": False,
        "malicious_activity": False,
        "credentials_leaked": True,
        "data_breach": True,
        "first_seen": "2021-03-15",
        "last_seen": "2026-09-20",
        "spf_strict": True,
        "dmarc_enforced": True,
    }
    demo_dns = {
        "source": "dns_mx",
        "success": True,
        "domain": domain,
        "mail_provider": "Google Workspace",
        "mx_records": [
            {"priority": 1, "exchange": "aspmx.l.google.com"},
            {"priority": 5, "exchange": "alt1.aspmx.l.google.com"},
            {"priority": 5, "exchange": "alt2.aspmx.l.google.com"},
        ],
        "spf_record": "v=spf1 include:_spf.google.com ~all",
        "spf_status": "SoftFail (~all)",
        "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@apexnova.example",
        "dmarc_policy": "Policy: REJECT",
    }

    posture = _compute_security_posture(
        email=email,
        reputation=demo_reputation,
        dns_data=demo_dns,
        xon_data=demo_xposedornot,
        github_commits={"commits": demo_commits},
        github_code={"references": demo_code},
    )
    res_dict["security_posture"] = posture
    return res_dict


# ══════════════════════════════ IDENTITY BUILDER ═════════════════════════════

def _build_identity(
    email: str,
    emailrep: Dict,
    github_users: Dict,
    github_commits: Dict,
    gravatar: Dict,
    dns_data: Dict,
    web_pages_data: Dict,
    hunter_data: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Correlate all disparate source outputs into a clean, unified identity object."""
    domain = email.split("@")[1] if "@" in email else ""
    local_part = email.split("@")[0] if "@" in email else email

    name = None
    username = None
    avatar = None
    company = None
    location = None
    bio = None
    social_profiles = []
    webpages_list = []
    seen_urls = set()

    # 1. GitHub user data
    if isinstance(github_users, dict) and github_users.get("success"):
        users = github_users.get("users", [])
        if users:
            u = users[0]
            username = u.get("login") or username
            name = u.get("name") or name
            avatar = u.get("avatar_url") or avatar
            company = u.get("company") or company
            location = u.get("location") or location
            bio = u.get("bio") or bio
            if u.get("profile_url") and u["profile_url"] not in seen_urls:
                seen_urls.add(u["profile_url"])
                social_profiles.append({"platform": "GitHub", "username": u.get("login"), "url": u["profile_url"]})
                webpages_list.append({"title": f"GitHub Profile (@{u.get('login')})", "url": u["profile_url"], "snippet": u.get("bio") or "Public GitHub user account", "source": "GitHub API"})
            if u.get("blog") and u["blog"] not in seen_urls:
                seen_urls.add(u["blog"])
                webpages_list.append({"title": f"Personal Website / Blog", "url": u["blog"], "snippet": f"Linked on developer's GitHub profile", "source": "GitHub Profile Link"})
            if u.get("twitter_username"):
                tw_url = f"https://x.com/{u['twitter_username']}"
                if tw_url not in seen_urls:
                    seen_urls.add(tw_url)
                    social_profiles.append({"platform": "Twitter/X", "username": u["twitter_username"], "url": tw_url})

    # 2. GitHub commit author name fallback
    if not name and isinstance(github_commits, dict) and github_commits.get("success"):
        commits = github_commits.get("commits", [])
        if commits:
            name = commits[0].get("author_name") or name

    # 3. Gravatar profile data
    if isinstance(gravatar, dict) and gravatar.get("success"):
        if not name and gravatar.get("display_name"):
            name = gravatar.get("display_name")
        if not avatar and gravatar.get("has_avatar"):
            avatar = gravatar.get("avatar_url")
        if not bio and gravatar.get("bio"):
            bio = gravatar.get("bio")
        if not location and gravatar.get("location"):
            location = gravatar.get("location")
        if gravatar.get("profile_url") and gravatar["profile_url"] not in seen_urls:
            seen_urls.add(gravatar["profile_url"])
            social_profiles.append({"platform": "Gravatar", "username": None, "url": gravatar["profile_url"]})
            webpages_list.append({"title": "Gravatar Public Profile", "url": gravatar["profile_url"], "snippet": "Public Gravatar profile associated with email hash", "source": "Gravatar"})

    # 4. EmailRep profiles
    if isinstance(emailrep, dict) and emailrep.get("success"):
        for prof in emailrep.get("profiles", []):
            prof_title = prof.title()
            if not any(sp["platform"].lower() == prof.lower() for sp in social_profiles):
                social_profiles.append({"platform": prof_title, "username": None, "url": None})

    # 5. Public Web Pages (DuckDuckGo Search)
    if isinstance(web_pages_data, dict) and web_pages_data.get("success"):
        for page in web_pages_data.get("pages", []):
            p_url = page.get("url")
            if p_url and p_url not in seen_urls:
                seen_urls.add(p_url)
                webpages_list.append({
                    "title": page.get("title") or p_url,
                    "url": p_url,
                    "snippet": page.get("snippet", ""),
                    "source": page.get("source", "Public Web Search"),
                })

    # 6. Hunter.io sources
    if isinstance(hunter_data, dict) and hunter_data.get("success"):
        for h_src in hunter_data.get("sources", []):
            if h_src and h_src not in seen_urls:
                seen_urls.add(h_src)
                webpages_list.append({
                    "title": f"Hunter.io Indexed Source",
                    "url": h_src,
                    "snippet": f"Public webpage indexed by Hunter.io referencing {email}",
                    "source": "Hunter.io",
                })

    # 7. Fallback name from local-part if still missing
    if not name and local_part:
        if "." in local_part or "_" in local_part or "-" in local_part:
            name = local_part.replace(".", " ").replace("_", " ").replace("-", " ").title()

    mail_provider = dns_data.get("mail_provider") if isinstance(dns_data, dict) else None

    return {
        "name": name,
        "username": username,
        "email": email,
        "domain": domain,
        "avatar_url": avatar,
        "company": company,
        "location": location,
        "bio": bio,
        "mail_provider": mail_provider,
        "social_profiles": social_profiles,
        "public_webpages": webpages_list,
    }


# ════════════════════════════ MAIN LOOKUP PIPELINE ═══════════════════════════

async def lookup_email(email: str) -> Dict[str, Any]:
    """
    Main entrypoint: run all OSINT tools concurrently against an email address
    and produce an aggregated intelligence report.
    """
    email_clean = email.strip().lower()
    if not _is_valid_email(email_clean):
        return {"error": "Invalid email address format. Expected format: user@domain.com", "email": email}

    # If demo domain (e.g. *.apexnova.example, example.com) or demo mode requested without network
    if "apexnova" in email_clean or email_clean.endswith(".example"):
        return _generate_demo_email_intel(email_clean)

    domain = email_clean.split("@")[1]
    local_part = email_clean.split("@")[0]
    started_at = _now_iso()

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
        import asyncio
        tasks = [
            _query_xposedornot(email_clean, client),
            _query_emailrep(email_clean, client),
            _query_github_commits(email_clean, client),
            _query_github_code(email_clean, client),
            _query_github_users(email_clean, client),
            _query_gravatar(email_clean, client),
            _query_public_web_pages(email_clean, client),
            _query_hunter_verifier(email_clean, client),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    xposedornot_data = results[0] if not isinstance(results[0], Exception) else {
        "source": "xposedornot", "success": False, "breached": False, "breach_count": 0, "breaches": [], "error": str(results[0])
    }
    emailrep_data = results[1] if not isinstance(results[1], Exception) else {"source": "emailrep.io", "success": False, "error": str(results[1])}
    github_commits = results[2] if not isinstance(results[2], Exception) else {"source": "github_commits", "success": False, "error": str(results[2])}
    github_code = results[3] if not isinstance(results[3], Exception) else {"source": "github_code", "success": False, "error": str(results[3])}
    github_users = results[4] if not isinstance(results[4], Exception) else {"source": "github_users", "success": False, "error": str(results[4])}
    gravatar_data = results[5] if not isinstance(results[5], Exception) else {"source": "gravatar", "success": False, "error": str(results[5])}
    web_pages_data = results[6] if not isinstance(results[6], Exception) else {"source": "public_web_search", "success": False, "error": str(results[6]), "pages": []}
    hunter_data = results[7] if not isinstance(results[7], Exception) else {"source": "hunter.io", "success": False, "configured": False}

    # Cross-correlate breach findings with reputation
    if xposedornot_data.get("breached"):
        if isinstance(emailrep_data, dict):
            emailrep_data["data_breach"] = True
            for b in xposedornot_data.get("breaches", []):
                p_risk = str(b.get("password_risk") or "").lower()
                if p_risk in ("plaintext", "easytocrack") or "passwords" in [str(x).lower() for x in b.get("xposed_data", [])]:
                    emailrep_data["credentials_leaked"] = True

    dns_data = _query_dns_mx(email_clean)

    # Build consolidated identity
    identity = _build_identity(
        email=email_clean,
        emailrep=emailrep_data,
        github_users=github_users,
        github_commits=github_commits,
        gravatar=gravatar_data,
        dns_data=dns_data,
        web_pages_data=web_pages_data,
        hunter_data=hunter_data,
    )

    sources_queried = ["xposedornot", "emailrep.io", "github_commits", "github_code", "github_users", "gravatar", "dns_mx", "public_web_search"]
    if hunter_data.get("configured"):
        sources_queried.append("hunter.io")

    sources_successful = []
    for item in [xposedornot_data, emailrep_data, github_commits, github_code, github_users, gravatar_data, dns_data, web_pages_data, hunter_data]:
        if isinstance(item, dict) and item.get("success"):
            src = item.get("source")
            if src and src not in sources_successful:
                sources_successful.append(src)

    posture = _compute_security_posture(
        email=email_clean,
        reputation=emailrep_data,
        dns_data=dns_data,
        xon_data=xposedornot_data,
        hunter_data=hunter_data,
        github_commits=github_commits,
        github_code=github_code,
    )

    return {
        "email": email_clean,
        "domain": domain,
        "local_part": local_part,
        "lookup_timestamp": started_at,
        "is_demo": False,
        "sources_queried": sources_queried,
        "sources_successful": sources_successful,
        "xposedornot": xposedornot_data,
        "breaches": xposedornot_data.get("breaches", []),
        "identity": identity,
        "reputation": emailrep_data,
        "security_posture": posture,
        "github_commits": github_commits,
        "github_code": github_code,
        "github_users": github_users,
        "gravatar": gravatar_data,
        "dns": dns_data,
        "public_web_pages": web_pages_data,
        "hunter": hunter_data,
    }


# ══════════════════════════════ EXCEL EXPORT ═════════════════════════════════

def export_email_intel_excel(data: Dict[str, Any]) -> bytes:
    """
    Generate a styled, multi-sheet Excel workbook (.xlsx) containing all
    harvested email intelligence records.
    """
    if not OPENPYXL_AVAILABLE:
        raise RuntimeError("openpyxl is not installed. Run `pip install openpyxl`.")

    wb = openpyxl.Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    # Styling palettes
    header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    header_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
    accent_fill = PatternFill(start_color="0284C7", end_color="0284C7", fill_type="solid")
    accent_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
    data_font = Font(name="Segoe UI", size=10)
    bold_font = Font(name="Segoe UI", size=10, bold=True)
    thin_border = Border(
        left=Side(style='thin', color='CBD5E1'),
        right=Side(style='thin', color='CBD5E1'),
        top=Side(style='thin', color='CBD5E1'),
        bottom=Side(style='thin', color='CBD5E1'),
    )

    email = data.get("email", "")
    identity = data.get("identity", {})
    reputation = data.get("reputation", {})
    dns_data = data.get("dns", {})
    commits_data = data.get("github_commits", {}).get("commits", [])
    code_data = data.get("github_code", {}).get("references", [])
    webpages = identity.get("public_webpages", [])
    socials = identity.get("social_profiles", [])
    xon_data = data.get("xposedornot") or {}
    breaches_list = xon_data.get("breaches") or data.get("breaches") or []

    def style_header_row(ws, row_idx):
        for cell in ws[row_idx]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="left", vertical="center")
        ws.row_dimensions[row_idx].height = 24

    def auto_fit_columns(ws):
        for col in ws.columns:
            max_len = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                val = str(cell.value or "")
                if "\n" in val:
                    val = max(val.split("\n"), key=len)
                max_len = max(max_len, len(val))
            ws.column_dimensions[col_letter].width = max(max_len + 4, 12)

    # ──────────────── SHEET 1: Identity & Summary ────────────────
    ws1 = wb.create_sheet(title="Identity Summary")
    ws1.views.sheetView[0].showGridLines = True

    # Title Banner
    ws1.merge_cells("A1:B1")
    banner = ws1["A1"]
    banner.value = f"OSINT-to-Attack-Path — Email Intelligence Report"
    banner.fill = accent_fill
    banner.font = Font(name="Segoe UI", size=13, bold=True, color="FFFFFF")
    banner.alignment = Alignment(horizontal="left", vertical="center")
    ws1.row_dimensions[1].height = 28

    ws1.append(["Target Email", email])
    ws1.append(["Investigation Timestamp", data.get("lookup_timestamp", _now_iso())])
    ws1.append(["Sources Queried", ", ".join(data.get("sources_queried", []))])
    ws1.append(["Sources Responded", ", ".join(data.get("sources_successful", []))])
    ws1.append([])

    # Table: Identity Attributes
    ws1.append(["Identity Attribute", "Value"])
    style_header_row(ws1, ws1.max_row)

    rows = [
        ("Full Name", identity.get("name") or "Not Identified"),
        ("Associated Username", identity.get("username") or "Not Identified"),
        ("Target Domain", identity.get("domain") or ""),
        ("Company / Organization", identity.get("company") or "Not Disclosed"),
        ("Location", identity.get("location") or "Not Disclosed"),
        ("Bio / Role Description", identity.get("bio") or "N/A"),
        ("Mail Provider", identity.get("mail_provider") or "Standard DNS Mail Exchange"),
        ("XposedOrNot Breach Status", f"BREACHED ({len(breaches_list)} breach incident(s))" if xon_data.get("breached") else "CLEAN (No breaches detected)"),
        ("Breach Risk Score", f"{xon_data.get('risk_score', 0.0)}/10 ({xon_data.get('risk_label', 'Clean')})"),
        ("Public Pastes Count", f"{xon_data.get('pastes_count', 0)} paste(s)"),
        ("Reputation Score", str(reputation.get("reputation", "Unknown")).upper()),
        ("Suspicious Flag", "YES (Flagged)" if reputation.get("suspicious") else "NO (Clean)"),
        ("Deliverability Status", "Deliverable" if reputation.get("deliverable") else "Undeliverable / Unknown"),
        ("Credentials Leaked Flag", "YES (Found in Leaks)" if reputation.get("credentials_leaked") else "NO"),
        ("Data Breach Exposure", "YES (Found in Breach Dumps)" if reputation.get("data_breach") else "NO"),
        ("First Seen In Public Feeds", str(reputation.get("first_seen") or "Unknown")),
        ("Last Seen In Public Feeds", str(reputation.get("last_seen") or "Unknown")),
        ("Gravatar / Profile Avatar", identity.get("avatar_url") or "None"),
    ]
    for k, v in rows:
        ws1.append([k, v])
        r_idx = ws1.max_row
        ws1[f"A{r_idx}"].font = bold_font
        ws1[f"A{r_idx}"].border = thin_border
        ws1[f"B{r_idx}"].font = data_font
        ws1[f"B{r_idx}"].border = thin_border

    auto_fit_columns(ws1)

    # ──────────────── SHEET 2: Security Posture & Risk ────────────────
    ws_posture = wb.create_sheet(title="Security Posture & Risk")
    ws_posture.views.sheetView[0].showGridLines = True

    ws_posture.merge_cells("A1:D1")
    p_banner = ws_posture["A1"]
    p_banner.value = "OSINT-to-Attack-Path — Security Posture & Threat Risk Assessment"
    p_banner.fill = accent_fill
    p_banner.font = Font(name="Segoe UI", size=13, bold=True, color="FFFFFF")
    p_banner.alignment = Alignment(horizontal="left", vertical="center")
    ws_posture.row_dimensions[1].height = 28

    posture_data = data.get("security_posture") or {}
    if not posture_data:
        posture_data = _compute_security_posture(
            email=email,
            reputation=reputation,
            dns_data=dns_data,
            xon_data=xon_data,
            github_commits=data.get("github_commits"),
            github_code=data.get("github_code"),
        )

    nist_info = posture_data.get("nist_assessment") or {}
    ws_posture.append(["Target Email", email])
    ws_posture.append(["Risk Scoring Standard", nist_info.get("standard", "NIST SP 800-30 Rev. 1")])
    ws_posture.append(["Threat Event Likelihood", f"{nist_info.get('threat_likelihood', 'N/A')} / 10 ({nist_info.get('likelihood_tier', '')})"])
    ws_posture.append(["Threat Event Impact", f"{nist_info.get('threat_impact', 'N/A')} / 10 ({nist_info.get('impact_tier', '')})"])
    ws_posture.append(["Composite Risk Score", f"{posture_data.get('composite_score', 0)} / 100 (Grade {posture_data.get('grade', 'C')})"])
    ws_posture.append(["Security Health Rating", f"{posture_data.get('health_score', 100)} / 100"])
    ws_posture.append(["Evaluated Threat Level", posture_data.get("risk_level", "UNKNOWN")])
    ws_posture.append(["Defensive Verdict", posture_data.get("verdict", "N/A")])
    ws_posture.append([])

    # Table: 4-Pillar Vector Evaluation
    ws_posture.append(["Security Dimension", "Risk Score (0-100)", "Dimension Status", "Summary Analysis"])
    style_header_row(ws_posture, ws_posture.max_row)

    pillars = posture_data.get("pillars", {})
    for p_key, p_info in pillars.items():
        ws_posture.append([
            p_info.get("name", p_key.title()),
            f"{p_info.get('score', 0)}/100",
            p_info.get("status", "N/A"),
            p_info.get("description", ""),
        ])
        r = ws_posture.max_row
        for col_l in ["A", "B", "C", "D"]:
            ws_posture[f"{col_l}{r}"].border = thin_border
            ws_posture[f"{col_l}{r}"].font = data_font

    ws_posture.append([])

    # Table: Posture Matrix (Controls)
    ws_posture.append(["Category", "Security Control Evaluated", "Observed Value", "Status", "Technical Details", "Mitigation Guidance"])
    style_header_row(ws_posture, ws_posture.max_row)

    for c in posture_data.get("posture_matrix", []):
        ws_posture.append([
            c.get("category", ""),
            c.get("control", ""),
            str(c.get("value", "")),
            c.get("status", "PASS"),
            c.get("detail", ""),
            c.get("recommendation", ""),
        ])
        r = ws_posture.max_row
        for col_l in ["A", "B", "C", "D", "E", "F"]:
            ws_posture[f"{col_l}{r}"].border = thin_border
            ws_posture[f"{col_l}{r}"].font = data_font

    ws_posture.append([])

    # Table: OSINT Attack Path Scenarios
    ws_posture.append(["Attack Scenario", "MITRE ATT&CK", "Probability", "Impact", "Attack Kill Chain Summary", "Mitigation"])
    style_header_row(ws_posture, ws_posture.max_row)

    for sc in posture_data.get("attack_scenarios", []):
        chain_summary = " -> ".join(sc.get("attack_steps", []))
        ws_posture.append([
            sc.get("title", ""),
            f"{sc.get('mitre_technique', '')} ({sc.get('mitre_name', '')})",
            sc.get("probability", "MEDIUM"),
            sc.get("impact", "HIGH"),
            chain_summary,
            sc.get("mitigation", ""),
        ])
        r = ws_posture.max_row
        for col_l in ["A", "B", "C", "D", "E", "F"]:
            ws_posture[f"{col_l}{r}"].border = thin_border
            ws_posture[f"{col_l}{r}"].font = data_font

    ws_posture.append([])

    # Table: Defensive Playbook Checklist
    ws_posture.append(["Priority", "Category", "Hardening Objective", "Remediation Command / Record", "Effort"])
    style_header_row(ws_posture, ws_posture.max_row)

    for pb in posture_data.get("defensive_playbook", []):
        ws_posture.append([
            pb.get("priority", "P2 - High"),
            pb.get("category", "General"),
            pb.get("title", ""),
            pb.get("remediation_cmd", pb.get("description", "")),
            pb.get("effort", "LOW"),
        ])
        r = ws_posture.max_row
        for col_l in ["A", "B", "C", "D", "E"]:
            ws_posture[f"{col_l}{r}"].border = thin_border
            ws_posture[f"{col_l}{r}"].font = data_font

    auto_fit_columns(ws_posture)

    # ──────────────── SHEET 3: Data Breaches (XposedOrNot) ────────────────
    ws_breaches = wb.create_sheet(title="Data Breaches (XON)")
    ws_breaches.views.sheetView[0].showGridLines = True
    ws_breaches.append(["Breach Name", "Target Domain", "Industry Sector", "Breach Date", "Password Risk", "Exposed Records", "Exposed Data Fields", "Incident Details"])
    style_header_row(ws_breaches, 1)

    if breaches_list:
        for b in breaches_list:
            x_data = b.get("xposed_data", [])
            x_data_str = ", ".join(x_data) if isinstance(x_data, list) else str(x_data)
            ws_breaches.append([
                b.get("breach") or "Unknown Breach",
                b.get("domain") or "N/A",
                b.get("industry") or "General",
                b.get("xposed_date") or "Unknown",
                str(b.get("password_risk") or "Unknown").upper(),
                b.get("xposed_records") or 0,
                x_data_str or "Credentials",
                b.get("details") or "No details available.",
            ])
            r = ws_breaches.max_row
            for col_letter in ["A", "B", "C", "D", "E", "F", "G", "H"]:
                ws_breaches[f"{col_letter}{r}"].border = thin_border
                ws_breaches[f"{col_letter}{r}"].font = data_font
    else:
        ws_breaches.append(["No data breaches discovered for this email address in XposedOrNot.", "", "", "", "", "", "", ""])

    auto_fit_columns(ws_breaches)

    # ──────────────── SHEET 2: Public Webpages ────────────────
    ws2 = wb.create_sheet(title="Public Webpages")
    ws2.views.sheetView[0].showGridLines = True
    ws2.append(["Page Title", "Public Webpage URL", "Snippet / Context", "Source"])
    style_header_row(ws2, 1)

    if webpages:
        for p in webpages:
            ws2.append([
                p.get("title") or "Webpage",
                p.get("url") or "",
                p.get("snippet") or "",
                p.get("source") or "Web Search",
            ])
            r = ws2.max_row
            for col_letter in ["A", "B", "C", "D"]:
                ws2[f"{col_letter}{r}"].border = thin_border
                ws2[f"{col_letter}{r}"].font = data_font
    else:
        ws2.append(["No public webpages indexed directly mentioning this email address.", "", "", ""])

    auto_fit_columns(ws2)

    # ──────────────── SHEET 3: GitHub Commits ────────────────
    ws3 = wb.create_sheet(title="GitHub Commits")
    ws3.views.sheetView[0].showGridLines = True
    ws3.append(["Repository", "Author Name", "Commit Date", "Commit Message", "Commit URL"])
    style_header_row(ws3, 1)

    if commits_data:
        for c in commits_data:
            ws3.append([
                c.get("repo", ""),
                c.get("author_name", ""),
                c.get("date", ""),
                c.get("message", ""),
                c.get("commit_url", ""),
            ])
            r = ws3.max_row
            for col_letter in ["A", "B", "C", "D", "E"]:
                ws3[f"{col_letter}{r}"].border = thin_border
                ws3[f"{col_letter}{r}"].font = data_font
    else:
        ws3.append(["No public GitHub commits found with author-email matching this target.", "", "", "", ""])

    auto_fit_columns(ws3)

    # ──────────────── SHEET 4: GitHub Code References ────────────────
    ws4 = wb.create_sheet(title="Code References")
    ws4.views.sheetView[0].showGridLines = True
    ws4.append(["File Name", "Repository", "File Path", "File URL"])
    style_header_row(ws4, 1)

    if code_data:
        for cd in code_data:
            ws4.append([
                cd.get("file", ""),
                cd.get("repo", ""),
                cd.get("path", ""),
                cd.get("file_url", ""),
            ])
            r = ws4.max_row
            for col_letter in ["A", "B", "C", "D"]:
                ws4[f"{col_letter}{r}"].border = thin_border
                ws4[f"{col_letter}{r}"].font = data_font
    else:
        ws4.append(["No public code files found containing explicit text references to this email.", "", "", ""])

    auto_fit_columns(ws4)

    # ──────────────── SHEET 5: Mail Infrastructure ────────────────
    ws5 = wb.create_sheet(title="Mail Infrastructure")
    ws5.views.sheetView[0].showGridLines = True
    ws5.append(["Configuration Item", "Detail / Value"])
    style_header_row(ws5, 1)

    ws5.append(["Target Domain", dns_data.get("domain", "")])
    ws5.append(["Identified Mail Provider", dns_data.get("mail_provider") or "Unknown"])
    ws5.append(["SPF Record TXT", dns_data.get("spf_record") or "None"])
    ws5.append(["SPF Enforcement Status", dns_data.get("spf_status") or "None"])
    ws5.append(["DMARC Record TXT", dns_data.get("dmarc_record") or "None"])
    ws5.append(["DMARC Policy Enforcement", dns_data.get("dmarc_policy") or "None"])

    for r_i in range(2, ws5.max_row + 1):
        ws5[f"A{r_i}"].font = bold_font
        ws5[f"A{r_i}"].border = thin_border
        ws5[f"B{r_i}"].font = data_font
        ws5[f"B{r_i}"].border = thin_border

    ws5.append([])
    ws5.append(["Priority", "MX Exchange Server Host"])
    style_header_row(ws5, ws5.max_row)

    mx_list = dns_data.get("mx_records", [])
    if mx_list:
        for mx in mx_list:
            ws5.append([mx.get("priority", 0), mx.get("exchange", "")])
            r_idx = ws5.max_row
            ws5[f"A{r_idx}"].font = data_font
            ws5[f"A{r_idx}"].border = thin_border
            ws5[f"B{r_idx}"].font = data_font
            ws5[f"B{r_idx}"].border = thin_border
    else:
        ws5.append(["N/A", "No MX records discovered"])

    auto_fit_columns(ws5)

    # ──────────────── SHEET 6: Social & Profiles ────────────────
    ws6 = wb.create_sheet(title="Social & Profiles")
    ws6.views.sheetView[0].showGridLines = True
    ws6.append(["Platform", "Username / Handle", "Profile URL"])
    style_header_row(ws6, 1)

    if socials:
        for s in socials:
            ws6.append([
                s.get("platform", ""),
                s.get("username") or "—",
                s.get("url") or "—",
            ])
            r = ws6.max_row
            for col_letter in ["A", "B", "C"]:
                ws6[f"{col_letter}{r}"].border = thin_border
                ws6[f"{col_letter}{r}"].font = data_font
    else:
        ws6.append(["No linked social profiles detected across public intelligence sources.", "", ""])

    auto_fit_columns(ws6)

    # Save to buffer
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output.getvalue()

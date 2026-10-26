"""
Standalone Username OSINT Lookup & Export Service.

Aggregates intelligence from multiple free and passive OSINT sources for a given username/handle:
  - GitHub User Profile & Metadata  -> bio, company, location, website, public metrics
  - GitHub Events & Commit History  -> author emails, commit messages, repository links
  - GitHub Repositories & Languages -> primary tech stack, stars, forks, licenses, topics
  - GitHub Organizations & Gists    -> team affiliations, sensitive scripts/snippets
  - GitHub SSH Keys & GPG Keys      -> developer machine names, internal domain comments, key types
  - Cross-Platform Account Probing  -> Sherlock/WhatsMyName style checks across 20+ platforms (GitLab, Docker Hub, PyPI, NPM, HackerOne, Keybase, Reddit, etc.)
  - Uncovered Email Breach Check    -> XposedOrNot checks on any emails discovered in commits/SSH keys
  - Public Web Search (DuckDuckGo)  -> Web mentions, forum profiles, public references
  - Security Posture & Risk Engine  -> 4 security pillars, composite threat index, MITRE attack scenarios, controls matrix
  - Excel Export                    -> Multi-sheet formatted workbook (.xlsx) generation via openpyxl
"""

import io
import re
import asyncio
import httpx
from typing import Dict, Any, List, Optional, Set
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


def _sanitize_username(username: str) -> str:
    """Normalize and clean a username input."""
    clean = username.strip().lstrip('@')
    return clean


def _is_valid_username(username: str) -> bool:
    """Validate username syntax (alphanumeric, dashes, underscores, dots, 1-60 chars)."""
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]{1,60}$', username))


def _get_github_headers() -> Dict[str, str]:
    headers = {
        "User-Agent": "OSINT-to-Attack-Path/2.0",
        "Accept": "application/vnd.github+json",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


# ═══════════════════════════════ GITHUB OSINT ═══════════════════════════════

async def _query_github_user(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch GitHub profile metadata for the given username."""
    try:
        headers = _get_github_headers()
        r = await client.get(f"https://api.github.com/users/{username}", headers=headers)
        if r.status_code == 200:
            data = r.json()
            return {
                "source": "github_profile",
                "success": True,
                "found": True,
                "login": data.get("login"),
                "id": data.get("id"),
                "name": data.get("name"),
                "avatar_url": data.get("avatar_url"),
                "bio": data.get("bio"),
                "company": data.get("company"),
                "blog": data.get("blog"),
                "location": data.get("location"),
                "email": data.get("email"),
                "hireable": data.get("hireable"),
                "twitter_username": data.get("twitter_username"),
                "public_repos": data.get("public_repos", 0),
                "public_gists": data.get("public_gists", 0),
                "followers": data.get("followers", 0),
                "following": data.get("following", 0),
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
                "profile_url": data.get("html_url") or f"https://github.com/{username}",
                "type": data.get("type", "User"),
            }
        elif r.status_code == 404:
            return {"source": "github_profile", "success": True, "found": False}
        return {"source": "github_profile", "success": False, "found": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source": "github_profile", "success": False, "found": False, "error": str(e)}


async def _query_github_events(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Examine public commit events to discover author email addresses and recent activity.
    Author emails embedded in Git commits are often personal or corporate addresses.
    """
    try:
        headers = _get_github_headers()
        r = await client.get(
            f"https://api.github.com/users/{username}/events/public?per_page=30",
            headers=headers
        )
        if r.status_code == 200:
            events = r.json() if isinstance(r.json(), list) else []
            commits_list = []
            uncovered_emails = set()
            uncovered_names = set()

            for ev in events:
                if ev.get("type") == "PushEvent":
                    repo_name = ev.get("repo", {}).get("name", "")
                    created_at = ev.get("created_at", "")
                    payload = ev.get("payload", {})
                    for c in payload.get("commits", []):
                        author = c.get("author", {})
                        a_email = (author.get("email") or "").strip().lower()
                        a_name = (author.get("name") or "").strip()
                        c_msg = (c.get("message") or "")[:120]
                        c_sha = c.get("sha", "")[:7]

                        if a_email and "@" in a_email and "noreply" not in a_email:
                            uncovered_emails.add(a_email)
                        elif a_email and "noreply" in a_email:
                            # Flag noreply email as well for reference
                            uncovered_emails.add(a_email)

                        if a_name:
                            uncovered_names.add(a_name)

                        commits_list.append({
                            "sha": c_sha,
                            "repo": repo_name,
                            "repo_url": f"https://github.com/{repo_name}",
                            "message": c_msg,
                            "author_name": a_name,
                            "author_email": a_email,
                            "date": created_at,
                            "commit_url": f"https://github.com/{repo_name}/commit/{c.get('sha', '')}",
                        })

            return {
                "source": "github_events",
                "success": True,
                "total_events": len(events),
                "commits_found": len(commits_list),
                "commits": commits_list[:20],
                "uncovered_emails": sorted(list(uncovered_emails)),
                "uncovered_names": sorted(list(uncovered_names)),
            }
        return {"source": "github_events", "success": False, "commits": [], "uncovered_emails": []}
    except Exception as e:
        return {"source": "github_events", "success": False, "commits": [], "uncovered_emails": [], "error": str(e)}


async def _query_github_repos(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch public repositories and summarize primary technologies and stars."""
    try:
        headers = _get_github_headers()
        r = await client.get(
            f"https://api.github.com/users/{username}/repos?sort=updated&per_page=15",
            headers=headers
        )
        if r.status_code == 200:
            repos = r.json() if isinstance(r.json(), list) else []
            formatted_repos = []
            languages_count: Dict[str, int] = {}
            total_stars = 0
            total_forks = 0

            for repo in repos:
                lang = repo.get("language")
                if lang:
                    languages_count[lang] = languages_count.get(lang, 0) + 1

                stars = repo.get("stargazers_count", 0)
                forks = repo.get("forks_count", 0)
                total_stars += stars
                total_forks += forks

                formatted_repos.append({
                    "name": repo.get("name"),
                    "full_name": repo.get("full_name"),
                    "description": repo.get("description") or "",
                    "url": repo.get("html_url"),
                    "language": lang or "Other",
                    "stars": stars,
                    "forks": forks,
                    "is_fork": repo.get("fork", False),
                    "topics": repo.get("topics", []),
                    "license": repo.get("license", {}).get("name") if repo.get("license") else None,
                    "updated_at": repo.get("updated_at"),
                })

            top_languages = sorted(languages_count.items(), key=lambda x: x[1], reverse=True)

            return {
                "source": "github_repos",
                "success": True,
                "total_queried": len(formatted_repos),
                "total_stars": total_stars,
                "total_forks": total_forks,
                "top_languages": [lang for lang, _ in top_languages[:5]],
                "languages_breakdown": languages_count,
                "repos": formatted_repos,
            }
        return {"source": "github_repos", "success": False, "repos": [], "top_languages": []}
    except Exception as e:
        return {"source": "github_repos", "success": False, "repos": [], "top_languages": [], "error": str(e)}


async def _query_github_orgs(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch organizations the user is publicly a member of."""
    try:
        headers = _get_github_headers()
        r = await client.get(f"https://api.github.com/users/{username}/orgs", headers=headers)
        if r.status_code == 200:
            orgs = r.json() if isinstance(r.json(), list) else []
            return {
                "source": "github_orgs",
                "success": True,
                "total_orgs": len(orgs),
                "orgs": [
                    {
                        "login": o.get("login"),
                        "description": o.get("description") or "",
                        "avatar_url": o.get("avatar_url"),
                        "url": f"https://github.com/{o.get('login')}",
                    }
                    for o in orgs
                ]
            }
        return {"source": "github_orgs", "success": False, "orgs": []}
    except Exception as e:
        return {"source": "github_orgs", "success": False, "orgs": [], "error": str(e)}


async def _query_github_gists(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch public gists to inspect code snippets, notes, or potential config leaks."""
    try:
        headers = _get_github_headers()
        r = await client.get(f"https://api.github.com/users/{username}/gists?per_page=10", headers=headers)
        if r.status_code == 200:
            gists = r.json() if isinstance(r.json(), list) else []
            formatted_gists = []
            for g in gists:
                files = list(g.get("files", {}).keys())
                formatted_gists.append({
                    "id": g.get("id"),
                    "description": g.get("description") or "Untitled Gist",
                    "url": g.get("html_url"),
                    "files": files,
                    "created_at": g.get("created_at"),
                    "updated_at": g.get("updated_at"),
                })
            return {
                "source": "github_gists",
                "success": True,
                "total_gists": len(formatted_gists),
                "gists": formatted_gists,
            }
        return {"source": "github_gists", "success": False, "gists": []}
    except Exception as e:
        return {"source": "github_gists", "success": False, "gists": [], "error": str(e)}


async def _query_github_keys(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Fetch public SSH keys and GPG public keys.
    SSH key comments often disclose internal usernames, machine hostnames, or corporate emails!
    """
    res = {
        "source": "github_keys",
        "success": False,
        "has_ssh_keys": False,
        "ssh_keys_count": 0,
        "ssh_keys": [],
        "has_gpg_key": False,
        "gpg_key_present": False,
        "uncovered_key_comments": [],
    }
    try:
        # 1. SSH Keys
        r_keys = await client.get(f"https://github.com/{username}.keys", timeout=6.0)
        if r_keys.status_code == 200 and r_keys.text.strip():
            lines = [l.strip() for l in r_keys.text.strip().splitlines() if l.strip()]
            parsed_keys = []
            comments = []
            for line in lines:
                parts = line.split()
                key_type = parts[0] if len(parts) >= 1 else "Unknown"
                comment = " ".join(parts[2:]) if len(parts) >= 3 else ""
                if comment:
                    comments.append(comment)
                parsed_keys.append({
                    "type": key_type,
                    "comment": comment,
                    "raw": line[:60] + "..." if len(line) > 60 else line,
                })
            res["has_ssh_keys"] = len(parsed_keys) > 0
            res["ssh_keys_count"] = len(parsed_keys)
            res["ssh_keys"] = parsed_keys
            res["uncovered_key_comments"] = comments

        # 2. GPG Key
        r_gpg = await client.get(f"https://github.com/{username}.gpg", timeout=6.0)
        if r_gpg.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in r_gpg.text:
            res["has_gpg_key"] = True
            res["gpg_key_present"] = True

        res["success"] = True
    except Exception as e:
        res["error"] = str(e)
    return res


# ═════════════════════ CROSS-PLATFORM ACCOUNT PROBING ══════════════════════

PLATFORM_PROBES = [
    {
        "platform": "GitHub",
        "category": "Developer & Code",
        "url_template": "https://github.com/{username}",
        "check_url": "https://github.com/{username}",
        "exists_status": [200],
    },
    {
        "platform": "GitLab",
        "category": "Developer & Code",
        "url_template": "https://gitlab.com/{username}",
        "check_url": "https://gitlab.com/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Docker Hub",
        "category": "Container & Cloud",
        "url_template": "https://hub.docker.com/u/{username}",
        "check_url": "https://hub.docker.com/v2/users/{username}",
        "exists_status": [200],
    },
    {
        "platform": "PyPI",
        "category": "Package Registry",
        "url_template": "https://pypi.org/user/{username}/",
        "check_url": "https://pypi.org/user/{username}/",
        "exists_status": [200],
    },
    {
        "platform": "NPM",
        "category": "Package Registry",
        "url_template": "https://www.npmjs.com/~{username}",
        "check_url": "https://www.npmjs.com/~{username}",
        "exists_status": [200],
    },
    {
        "platform": "HackerOne",
        "category": "Security & Bug Bounty",
        "url_template": "https://hackerone.com/{username}",
        "check_url": "https://hackerone.com/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Bugcrowd",
        "category": "Security & Bug Bounty",
        "url_template": "https://bugcrowd.com/{username}",
        "check_url": "https://bugcrowd.com/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Keybase",
        "category": "Identity & Cryptography",
        "url_template": "https://keybase.io/{username}",
        "check_url": "https://keybase.io/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Reddit",
        "category": "Social & Community",
        "url_template": "https://www.reddit.com/user/{username}",
        "check_url": "https://www.reddit.com/user/{username}/about.json",
        "exists_status": [200],
    },
    {
        "platform": "Dev.to",
        "category": "Developer Community",
        "url_template": "https://dev.to/{username}",
        "check_url": "https://dev.to/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Medium",
        "category": "Blogging & Publication",
        "url_template": "https://medium.com/@{username}",
        "check_url": "https://medium.com/@{username}",
        "exists_status": [200],
    },
    {
        "platform": "Kaggle",
        "category": "Data Science & AI",
        "url_template": "https://www.kaggle.com/{username}",
        "check_url": "https://www.kaggle.com/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Telegram",
        "category": "Messaging",
        "url_template": "https://t.me/{username}",
        "check_url": "https://t.me/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Linktree",
        "category": "Social Bio Link",
        "url_template": "https://linktr.ee/{username}",
        "check_url": "https://linktr.ee/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Pastebin",
        "category": "Paste & Snippet",
        "url_template": "https://pastebin.com/u/{username}",
        "check_url": "https://pastebin.com/u/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Gravatar",
        "category": "Identity & Avatar",
        "url_template": "https://en.gravatar.com/{username}",
        "check_url": "https://en.gravatar.com/{username}.json",
        "exists_status": [200],
    },
    {
        "platform": "Bitbucket",
        "category": "Developer & Code",
        "url_template": "https://bitbucket.org/{username}/",
        "check_url": "https://bitbucket.org/{username}/",
        "exists_status": [200],
    },
    {
        "platform": "LeetCode",
        "category": "Developer Practice",
        "url_template": "https://leetcode.com/{username}/",
        "check_url": "https://leetcode.com/{username}/",
        "exists_status": [200],
    },
    {
        "platform": "Codeforces",
        "category": "Competitive Programming",
        "url_template": "https://codeforces.com/profile/{username}",
        "check_url": "https://codeforces.com/profile/{username}",
        "exists_status": [200],
    },
    {
        "platform": "Twitter / X",
        "category": "Social & Media",
        "url_template": "https://x.com/{username}",
        "check_url": "https://x.com/{username}",
        "exists_status": [200],
    },
]


async def _probe_single_platform(probe: Dict[str, Any], username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    url = probe["check_url"].format(username=username)
    profile_url = probe["url_template"].format(username=username)
    name = probe["platform"]
    category = probe["category"]

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
        }
        r = await client.get(url, headers=headers, timeout=5.0)

        exists = False
        # Specific platform response validation
        if name == "Reddit":
            exists = r.status_code == 200 and not r.json().get("error") and not r.json().get("is_suspended")
        elif name == "Docker Hub":
            exists = r.status_code == 200 and "id" in r.text
        elif name == "Telegram":
            exists = r.status_code == 200 and "tgme_page_extra" in r.text and "If you have Telegram" in r.text
        elif name == "Pastebin":
            exists = r.status_code == 200 and "Public Pastes" in r.text
        elif name == "Gravatar":
            exists = r.status_code == 200 and "entry" in r.text
        else:
            exists = r.status_code in probe["exists_status"]

        return {
            "platform": name,
            "category": category,
            "profile_url": profile_url,
            "status": "FOUND" if exists else "NOT FOUND",
            "exists": exists,
            "status_code": r.status_code,
        }
    except Exception:
        return {
            "platform": name,
            "category": category,
            "profile_url": profile_url,
            "status": "UNREACHABLE",
            "exists": False,
            "status_code": 0,
        }


async def _probe_all_platforms(username: str, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """Concurrently probe 20+ platforms for account presence."""
    tasks = [_probe_single_platform(probe, username, client) for probe in PLATFORM_PROBES]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    clean_results = []
    for r in results:
        if isinstance(r, dict):
            clean_results.append(r)
    return clean_results


# ════════════════════ UNCOVERED EMAIL BREACH CHECK ══════════════════════════

async def _check_email_breach(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Check an uncovered email address against XposedOrNot for breach history."""
    try:
        headers = {"User-Agent": "OSINT-to-Attack-Path/2.0"}
        if settings.xposedornot_api_key:
            headers["x-api-key"] = settings.xposedornot_api_key

        r = await client.get(f"https://api.xposedornot.com/v1/check-email/{email}", headers=headers, timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            raw_breaches = data.get("breaches", [])
            flat_breaches = raw_breaches[0] if (raw_breaches and isinstance(raw_breaches[0], list)) else raw_breaches
            return {
                "email": email,
                "breached": True,
                "breach_count": len(flat_breaches),
                "breaches": flat_breaches,
            }
        elif r.status_code == 404:
            return {"email": email, "breached": False, "breach_count": 0, "breaches": []}
    except Exception:
        pass
    return {"email": email, "breached": False, "breach_count": 0, "breaches": []}


async def _check_uncovered_emails_breaches(emails: List[str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """Check breach status for all emails uncovered from commit events & SSH comments."""
    unique_valid_emails = [e for e in set(emails) if "@" in e and "noreply" not in e][:6]
    if not unique_valid_emails:
        return []

    tasks = [_check_email_breach(email, client) for email in unique_valid_emails]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


# ══════════════════════ PUBLIC WEB SEARCH (DUCKDUCKGO) ══════════════════════

async def _query_public_web_pages(username: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Search public search engines for web pages, forum threads, and paste mentions of the username."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        query = f'"{username}" profile OR github OR developer OR security'
        r = await client.get(
            f"https://html.duckduckgo.com/html/?q={httpx.URL(query).raw_path.decode()}",
            headers=headers,
            timeout=8.0
        )
        if r.status_code == 200:
            pages = []
            seen_urls = set()
            pattern = re.compile(
                r'<h2[^>]*class="result__title"[^>]*>.*?<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?</h2>.*?<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
                re.DOTALL
            )
            for href, title_html, snippet_html in pattern.findall(r.text)[:8]:
                raw_url = href.strip()
                match = re.search(r'uddg=([^&]+)', raw_url)
                if match:
                    import urllib.parse
                    url = urllib.parse.unquote(match.group(1))
                else:
                    url = raw_url

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
            return {"source": "public_web_search", "success": len(pages) > 0, "total_pages": len(pages), "pages": pages}
        return {"source": "public_web_search", "success": False, "pages": []}
    except Exception as e:
        return {"source": "public_web_search", "success": False, "pages": [], "error": str(e)}


# ════════════════════ SECURITY POSTURE & THREAT RISK ENGINE ══════════════════

def _compute_username_security_posture(
    username: str,
    gh_profile: Dict[str, Any],
    gh_events: Dict[str, Any],
    gh_repos: Dict[str, Any],
    gh_keys: Dict[str, Any],
    gh_gists: Dict[str, Any],
    probes: List[Dict[str, Any]],
    breached_emails: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compute multi-dimensional Security Posture and Threat Risk Index for a developer/user identity.
    Evaluates 4 Pillars:
      1. Code & Developer Footprint (Public repos, gists, tech stack, forks)
      2. Identity & Secret Leakage (Uncovered author emails, SSH machine comments, breach leaks)
      3. Cross-Platform Attack Surface (Breadth of active accounts, handle squatting, takeovers)
      4. Social Engineering & Reconnaissance Risk (Public bio, company affiliation, contact vectors)
    """
    found_platforms = [p for p in probes if p.get("exists")]
    found_count = len(found_platforms)
    public_repos_count = gh_profile.get("public_repos", 0) if gh_profile.get("found") else len(gh_repos.get("repos", []))
    public_gists_count = gh_profile.get("public_gists", 0) if gh_profile.get("found") else len(gh_gists.get("gists", []))
    
    uncovered_emails = gh_events.get("uncovered_emails", [])
    real_emails = [e for e in uncovered_emails if "@" in e and "noreply" not in e]
    ssh_comments = gh_keys.get("uncovered_key_comments", [])
    has_ssh_keys = gh_keys.get("has_ssh_keys", False)
    has_gpg = gh_keys.get("has_gpg_key", False)

    total_breaches = sum(b.get("breach_count", 0) for b in breached_emails)
    is_breached = total_breaches > 0

    # ── PILLAR 1: Code & Developer Footprint (0-100) ──
    code_score = 15
    if public_repos_count > 0:
        code_score += min(35, public_repos_count * 2)
    if public_gists_count > 0:
        code_score += min(20, public_gists_count * 5)
    if gh_repos.get("total_stars", 0) > 10:
        code_score += 15
    code_score = min(100, code_score)
    code_status = "CRITICAL" if code_score >= 80 else "HIGH" if code_score >= 60 else "ELEVATED" if code_score >= 40 else "CONTROLLED"

    # ── PILLAR 2: Identity & Secret Leakage (0-100) ──
    leak_score = 10
    if real_emails:
        leak_score += 30 + min(20, len(real_emails) * 10)
    if is_breached:
        leak_score += min(35, 15 + total_breaches * 5)
    if ssh_comments:
        leak_score += 15
    leak_score = min(100, leak_score)
    leak_status = "CRITICAL" if leak_score >= 75 else "HIGH" if leak_score >= 50 else "MODERATE" if leak_score >= 25 else "LOW"

    # ── PILLAR 3: Cross-Platform Attack Surface (0-100) ──
    surface_score = 15
    if found_count > 0:
        surface_score += min(60, found_count * 7)
    # Check if high-value registries are present (NPM, PyPI, Docker Hub)
    high_value_found = [p["platform"] for p in found_platforms if p["platform"] in ("PyPI", "NPM", "Docker Hub")]
    if high_value_found:
        surface_score += 20
    surface_score = min(100, surface_score)
    surface_status = "EXTENSIVE" if surface_score >= 70 else "EXPANDED" if surface_score >= 45 else "MINIMAL"

    # ── PILLAR 4: Reconnaissance & Social Engineering (0-100) ──
    recon_score = 15
    if gh_profile.get("company"):
        recon_score += 25
    if gh_profile.get("location"):
        recon_score += 15
    if gh_profile.get("bio"):
        recon_score += 15
    if gh_profile.get("blog") or gh_profile.get("twitter_username"):
        recon_score += 15
    recon_score = min(100, recon_score)
    recon_status = "HIGH" if recon_score >= 70 else "MEDIUM" if recon_score >= 40 else "LOW"

    # ── NIST SP 800-30 Rev. 1 RISK SCORING METHOD ──
    # Threat Event Likelihood (0-10): Surface exposure, public code footprint, and discoverability
    surface_l = min(4.5, round(surface_score / 22.2, 2))
    code_l = min(3.5, round(code_score / 28.6, 2))
    recon_l = min(2.0, round(recon_score / 50.0, 2))
    nist_likelihood = min(10.0, max(1.0, round(surface_l + code_l + recon_l, 1)))

    # Threat Event Impact (0-10): Identity/secret leakage and organizational blast radius
    leak_i = min(6.0, round(leak_score / 16.7, 2))
    blast_i = 1.5 + (2.0 if high_value_found else 0.5) + (1.0 if gh_profile.get("company") else 0.0)
    nist_impact = min(10.0, max(1.0, round(leak_i + blast_i, 1)))

    # NIST Composite Risk Score (Likelihood x Impact) & Resilience Health:
    composite_score = min(100.0, max(0.0, round(nist_likelihood * nist_impact, 1)))
    health_score = round(max(0.0, 100.0 - composite_score), 1)

    if composite_score > 80.0:
        grade = "F"
        badge_color = "#ef4444"
        risk_level = "CRITICAL RISK"
        verdict = f"High-risk profile exposure. Real email addresses ({len(real_emails)}) uncovered with {total_breaches} known breach associations across public developer events and {found_count} online accounts."
    elif composite_score > 60.0:
        grade = "D"
        badge_color = "#ea580c"
        risk_level = "HIGH RISK"
        verdict = f"Significant attack surface detected. Public code and commit metadata leak personal contact info and corporate affiliations across {found_count} public platforms."
    elif composite_score > 40.0:
        grade = "C"
        badge_color = "#f59e0b"
        risk_level = "MODERATE RISK"
        verdict = f"Moderate identity footprint. Public accounts discovered across {found_count} platforms with public code artifacts, but no severe active credential breaches."
    elif composite_score > 20.0:
        grade = "B"
        badge_color = "#38bdf8"
        risk_level = "LOW RISK"
        verdict = "Controlled attack surface. Limited public exposure, minimal unverified cross-platform footprint, and good identity hygiene."
    else:
        grade = "A"
        badge_color = "#22c55e"
        risk_level = "MINIMAL RISK"
        verdict = "Hardened identity posture. Low public reconnaissance exposure and clean developer privacy hygiene."

    # ── ATTACK SCENARIOS (MITRE ATT&CK KILL CHAINS) ──
    attack_scenarios = []

    # Scenario 1: Commit Author Email Harvesting & Spearphishing
    if real_emails:
        attack_scenarios.append({
            "title": "Developer Email Harvesting & Targeted Spear-Phishing",
            "mitre_technique": "T1589.002 / T1566.002",
            "severity": "CRITICAL" if is_breached else "HIGH",
            "likelihood": "Very High",
            "impact": "High",
            "description": f"Adversaries passively extract verified email addresses ({', '.join(real_emails[:2])}) from Git PushEvent commit metadata to bypass privacy settings and launch spear-phishing campaigns.",
            "kill_chain_steps": [
                f"Adversary queries public GitHub Events API for @{username}.",
                f"Extracts author email metadata: {real_emails[0]}.",
                "Correlates email with leaked password hashes from credential breach dumps.",
                "Crafts authentic, context-rich phishing email referencing recent repository commits."
            ],
            "mitigation": "Configure GitHub commit email privacy ('Keep my email address private') and configure local git client with your users.noreply.github.com email."
        })

    # Scenario 2: Supply Chain Registry Account Takeover
    if high_value_found:
        attack_scenarios.append({
            "title": f"Supply Chain Package Registry Hijacking ({', '.join(high_value_found)})",
            "mitre_technique": "T1195.002 / T1586.002",
            "severity": "CRITICAL",
            "likelihood": "Medium",
            "impact": "Severe (Supply Chain)",
            "description": f"The handle '{username}' is active on package registries ({', '.join(high_value_found)}). If these accounts lack hardware 2FA or re-use passwords from exposed breaches, attackers can hijack packages to poison downstream dependencies.",
            "kill_chain_steps": [
                f"Adversary confirms handle registration on {', '.join(high_value_found)}.",
                "Executes credential stuffing against package registry login using breach dumps.",
                "If successful, publishes poisoned semantic version patch containing remote access payloads.",
                "Downstream enterprise CI/CD pipelines pull compromised dependencies automatically."
            ],
            "mitigation": "Enforce mandatory WebAuthn/FIDO2 2FA across all package registries and use scoped publishing access tokens with strict expiry."
        })

    # Scenario 3: Cross-Platform Handle Squatting & Impersonation
    unregistered_top = [p["platform"] for p in probes if not p.get("exists") and p["platform"] in ("GitLab", "Keybase", "Docker Hub", "HackerOne")]
    if unregistered_top:
        attack_scenarios.append({
            "title": f"Cross-Platform Impersonation & Handle Squatting ({', '.join(unregistered_top[:3])})",
            "mitre_technique": "T1585.001 / T1586.002",
            "severity": "MEDIUM",
            "likelihood": "High",
            "impact": "Moderate",
            "description": f"Handle '{username}' is unregistered on prominent developer portals ({', '.join(unregistered_top[:3])}). Adversaries can register these handles to impersonate the developer, host malicious forks, or socially engineer colleagues.",
            "kill_chain_steps": [
                f"Adversary scans presence and spots unclaimed handle on {unregistered_top[0]}.",
                "Registers the handle, cloning public avatars and bio details.",
                "Forks popular repositories, injecting subtle backdoors into pull requests.",
                "Targets developer teammates via trusted platform messages."
            ],
            "mitigation": "Proactively claim executive and developer handles across key ecosystems or implement cryptographic PGP signature verification for all code commits."
        })

    # Scenario 4: SSH Key Comment Internal Reconnaissance
    if ssh_comments:
        attack_scenarios.append({
            "title": "Internal Hostname & Machine Architecture Reconnaissance",
            "mitre_technique": "T1592.004 Reconnaissance: Gather Victim Host Info",
            "severity": "LOW",
            "likelihood": "Very High",
            "impact": "Low-Moderate",
            "description": f"Public SSH key comments disclose machine hostnames and internal naming conventions ({', '.join(ssh_comments[:2])}), aiding internal lateral movement planning.",
            "kill_chain_steps": [
                f"Attacker fetches https://github.com/{username}.keys.",
                f"Extracts internal host comments: {ssh_comments[0]}.",
                "Maps corporate naming scheme (e.g. corp-laptop-mac, staging-bastion) for target profiling."
            ],
            "mitigation": "Generate SSH keys with non-identifying generic comments (e.g. ssh-keygen -C 'id_ed25519_auth')."
        })

    # ── CONTROLS ASSESSMENT MATRIX ──
    posture_matrix = [
        {
            "category": "Email & Identity Privacy",
            "control": "Commit Author Email Redaction",
            "value": f"{len(real_emails)} Real Email(s) Exposed" if real_emails else "Protected (No Leaked Personal Emails)",
            "status": "FAIL" if real_emails else "PASS",
            "detail": f"Public Git commit headers reveal: {', '.join(real_emails[:2])}." if real_emails else "Commit events utilize noreply addresses or contain no public leaks.",
            "recommendation": "Enable GitHub 'Block command line pushes that expose my email' in Account Email settings."
        },
        {
            "category": "Credential Integrity",
            "control": "Breach Dump Exposure Status",
            "value": f"{total_breaches} Breach(es) Found" if is_breached else "Clean (0 Breaches Found)",
            "status": "FAIL" if is_breached else "PASS",
            "detail": f"Associated developer email(s) found in {total_breaches} credential leaks." if is_breached else "No associated email addresses detected in known breach databases.",
            "recommendation": "Rotate compromised passwords, invalidate active sessions, and mandate hardware security keys."
        },
        {
            "category": "Code Cryptography",
            "control": "PGP Commit Signing Verification",
            "value": "PGP Key Published" if has_gpg else "No Public PGP Key",
            "status": "PASS" if has_gpg else "WARNING",
            "detail": "Verified commit signatures prevent impersonation and commit spoofing." if has_gpg else "Unsigned commits can be easily spoofed by anyone with git author flags.",
            "recommendation": "Generate a GPG key, upload to GitHub, and enforce signing on all repository branches."
        },
        {
            "category": "SSH Authentication",
            "control": "SSH Public Key Architecture & Hygiene",
            "value": f"{gh_keys.get('ssh_keys_count', 0)} Public Key(s) Configured" if has_ssh_keys else "No Public Keys Listed",
            "status": "PASS" if has_ssh_keys else "WARNING",
            "detail": f"Keys found: {', '.join([k['type'] for k in gh_keys.get('ssh_keys', [])[:2]])}. Comments: {', '.join(ssh_comments) if ssh_comments else 'None (Clean)'}.",
            "recommendation": "Audit old SSH keys and remove keys containing sensitive internal machine names or outdated algorithms."
        },
        {
            "category": "Cross-Platform Exposure",
            "control": "Account Footprint & Squatting Surface",
            "value": f"{found_count} Active Platform Profiles",
            "status": "FAIL" if found_count >= 10 else "WARNING" if found_count >= 5 else "PASS",
            "detail": f"Presence verified across {found_count} of 20 analyzed online services.",
            "recommendation": "Conduct periodic shadow account reviews and delete unused accounts on legacy platforms."
        },
        {
            "category": "Code Leakage Audit",
            "control": "Public Gist & Secret Exposure",
            "value": f"{public_gists_count} Public Gist(s)",
            "status": "WARNING" if public_gists_count > 5 else "PASS",
            "detail": f"{public_gists_count} public code snippets and notes published on GitHub.",
            "recommendation": "Audit all public gists to ensure no embedded API keys, internal endpoints, or credentials exist."
        },
    ]

    return {
        "composite_score": composite_score,
        "health_score": health_score,
        "grade": grade,
        "badge_color": badge_color,
        "risk_level": risk_level,
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
            "code_footprint": {
                "name": "Code & Developer Footprint",
                "score": code_score,
                "status": code_status,
                "description": f"{public_repos_count} public repos, {public_gists_count} gists, {gh_repos.get('total_stars', 0)} stars.",
                "metrics": {
                    "public_repos": public_repos_count,
                    "public_gists": public_gists_count,
                    "total_stars": gh_repos.get("total_stars", 0),
                    "total_forks": gh_repos.get("total_forks", 0),
                    "top_languages": gh_repos.get("top_languages", []),
                }
            },
            "identity_leakage": {
                "name": "Identity & Secret Leakage",
                "score": leak_score,
                "status": leak_status,
                "description": f"{len(real_emails)} real emails uncovered; {total_breaches} breach records found.",
                "metrics": {
                    "uncovered_emails_count": len(real_emails),
                    "uncovered_emails": real_emails,
                    "breaches_detected": total_breaches,
                    "ssh_comments_leaked": len(ssh_comments),
                }
            },
            "account_surface": {
                "name": "Cross-Platform Account Surface",
                "score": surface_score,
                "status": surface_status,
                "description": f"Identified on {found_count} of 20 monitored platforms ({', '.join([p['platform'] for p in found_platforms[:3]])}).",
                "metrics": {
                    "found_count": found_count,
                    "probed_count": len(probes),
                    "package_registries": high_value_found,
                }
            },
            "recon_vulnerability": {
                "name": "Reconnaissance & Threat Vulnerability",
                "score": recon_score,
                "status": recon_status,
                "description": f"Company: {gh_profile.get('company') or 'Unlisted'}; Location: {gh_profile.get('location') or 'Unlisted'}.",
                "metrics": {
                    "company": gh_profile.get("company"),
                    "location": gh_profile.get("location"),
                    "has_bio": bool(gh_profile.get("bio")),
                    "has_website": bool(gh_profile.get("blog")),
                    "twitter": gh_profile.get("twitter_username"),
                }
            }
        },
        "attack_scenarios": attack_scenarios,
        "posture_matrix": posture_matrix,
    }


# ══════════════════════════ DEMO SIMULATION DATA ═════════════════════════════

def _generate_demo_username_intel(username: str) -> Dict[str, Any]:
    """Provide realistic simulation intelligence for demo handles."""
    clean = _sanitize_username(username)
    name = clean.replace("_", " ").replace(".", " ").title()

    demo_repos = [
        {
            "name": "cloud-sec-toolkit",
            "full_name": f"{clean}/cloud-sec-toolkit",
            "description": "Automated AWS & GCP IAM posture scanning and privilege escalation auditor.",
            "url": f"https://github.com/{clean}/cloud-sec-toolkit",
            "language": "Python",
            "stars": 142,
            "forks": 38,
            "is_fork": False,
            "topics": ["security", "aws", "gcp", "iam", "cloud-security"],
            "license": "MIT License",
            "updated_at": "2026-10-12T14:22:00Z",
        },
        {
            "name": "k8s-pod-hardener",
            "full_name": f"{clean}/k8s-pod-hardener",
            "description": "Admission controller webhook enforcing non-root container execution and seccomp profiles.",
            "url": f"https://github.com/{clean}/k8s-pod-hardener",
            "language": "Go",
            "stars": 89,
            "forks": 14,
            "is_fork": False,
            "topics": ["kubernetes", "security", "golang"],
            "license": "Apache-2.0",
            "updated_at": "2026-09-28T09:15:00Z",
        },
        {
            "name": "dotfiles",
            "full_name": f"{clean}/dotfiles",
            "description": "Zsh, Neovim, Tmux, and developer workstation configurations.",
            "url": f"https://github.com/{clean}/dotfiles",
            "language": "Shell",
            "stars": 24,
            "forks": 5,
            "is_fork": False,
            "topics": ["dotfiles", "zsh", "macos"],
            "license": None,
            "updated_at": "2026-10-15T18:40:00Z",
        },
    ]

    demo_commits = [
        {
            "sha": "7f8b21c",
            "repo": f"{clean}/cloud-sec-toolkit",
            "repo_url": f"https://github.com/{clean}/cloud-sec-toolkit",
            "message": "fix(iam): sanitize AWS sts assume-role response and log policy ARN",
            "author_name": name,
            "author_email": f"{clean}@apexnova.example",
            "date": "2026-10-12T14:20:00Z",
            "commit_url": f"https://github.com/{clean}/cloud-sec-toolkit/commit/7f8b21c",
        },
        {
            "sha": "4c9e33a",
            "repo": f"{clean}/k8s-pod-hardener",
            "repo_url": f"https://github.com/{clean}/k8s-pod-hardener",
            "message": "feat(admission): add default deny for privileged container flag",
            "author_name": name,
            "author_email": f"{clean}@apexnova.example",
            "date": "2026-09-28T09:10:00Z",
            "commit_url": f"https://github.com/{clean}/k8s-pod-hardener/commit/4c9e33a",
        },
        {
            "sha": "1a2b3c4",
            "repo": f"{clean}/dotfiles",
            "repo_url": f"https://github.com/{clean}/dotfiles",
            "message": "chore: update zsh prompt and gpg commit signing key",
            "author_name": name,
            "author_email": f"{clean}.dev@gmail.com",
            "date": "2026-09-02T11:45:00Z",
            "commit_url": f"https://github.com/{clean}/dotfiles/commit/1a2b3c4",
        },
    ]

    demo_gists = [
        {
            "id": "e912f716283",
            "description": "terraform-staging-vpc-security-groups.tf",
            "url": f"https://gist.github.com/{clean}/e912f716283",
            "files": ["vpc-security-groups.tf", "variables.tf"],
            "created_at": "2026-08-14T10:00:00Z",
            "updated_at": "2026-08-14T10:00:00Z",
        }
    ]

    demo_ssh_keys = [
        {
            "type": "ssh-ed25519",
            "comment": f"{clean}@macbook-pro.corp.apexnova.example",
            "raw": f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... {clean}@macbook-pro.corp.apexnova.example",
        }
    ]

    demo_probes = [
        {"platform": "GitHub", "category": "Developer & Code", "profile_url": f"https://github.com/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "GitLab", "category": "Developer & Code", "profile_url": f"https://gitlab.com/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Docker Hub", "category": "Container & Cloud", "profile_url": f"https://hub.docker.com/u/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "PyPI", "category": "Package Registry", "profile_url": f"https://pypi.org/user/{clean}/", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "NPM", "category": "Package Registry", "profile_url": f"https://www.npmjs.com/~{clean}", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "HackerOne", "category": "Security & Bug Bounty", "profile_url": f"https://hackerone.com/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Bugcrowd", "category": "Security & Bug Bounty", "profile_url": f"https://bugcrowd.com/{clean}", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "Keybase", "category": "Identity & Cryptography", "profile_url": f"https://keybase.io/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Reddit", "category": "Social & Community", "profile_url": f"https://www.reddit.com/user/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Dev.to", "category": "Developer Community", "profile_url": f"https://dev.to/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Medium", "category": "Blogging & Publication", "profile_url": f"https://medium.com/@{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Kaggle", "category": "Data Science & AI", "profile_url": f"https://www.kaggle.com/{clean}", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "Telegram", "category": "Messaging", "profile_url": f"https://t.me/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Linktree", "category": "Social Bio Link", "profile_url": f"https://linktr.ee/{clean}", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "Pastebin", "category": "Paste & Snippet", "profile_url": f"https://pastebin.com/u/{clean}", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "Gravatar", "category": "Identity & Avatar", "profile_url": f"https://en.gravatar.com/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Bitbucket", "category": "Developer & Code", "profile_url": f"https://bitbucket.org/{clean}/", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "LeetCode", "category": "Developer Practice", "profile_url": f"https://leetcode.com/{clean}/", "status": "FOUND", "exists": True, "status_code": 200},
        {"platform": "Codeforces", "category": "Competitive Programming", "profile_url": f"https://codeforces.com/profile/{clean}", "status": "NOT FOUND", "exists": False, "status_code": 404},
        {"platform": "Twitter / X", "category": "Social & Media", "profile_url": f"https://x.com/{clean}", "status": "FOUND", "exists": True, "status_code": 200},
    ]

    demo_breached_emails = [
        {
            "email": f"{clean}.dev@gmail.com",
            "breached": True,
            "breach_count": 2,
            "breaches": ["LinkedIn-Dump", "Dropbox-CredentialDrop"],
        }
    ]

    demo_webpages = [
        {
            "title": f"{name} (@{clean}) — Cloud Infrastructure Security Lead",
            "url": f"https://github.com/{clean}",
            "snippet": f"Open source contributor and cloud security researcher. Author of cloud-sec-toolkit and k8s-pod-hardener.",
            "source": "GitHub Profile",
        },
        {
            "title": f"ApexNova Engineering Blog: Securing Kubernetes Pods with eBPF",
            "url": f"https://blog.apexnova.example/authors/{clean}",
            "snippet": f"Technical article by {name} discussing seccomp profile enforcement and admission webhook architectures.",
            "source": "Technical Publication",
        },
        {
            "title": f"HackerOne Bug Bounty Profile — {clean}",
            "url": f"https://hackerone.com/{clean}",
            "snippet": f"Public security research profile. Acknowledgements in responsible disclosure programs.",
            "source": "HackerOne Public Profile",
        },
    ]

    gh_profile = {
        "source": "github_profile",
        "success": True,
        "found": True,
        "login": clean,
        "id": 10492831,
        "name": name,
        "avatar_url": "https://avatars.githubusercontent.com/u/10492831?v=4",
        "bio": "Lead Cloud Security & Infrastructure Engineer @ ApexNova. Kubernetes, Python & Go enthusiast.",
        "company": "ApexNova Technologies",
        "blog": f"https://{clean}.dev",
        "location": "San Francisco, CA / Remote",
        "email": f"{clean}@apexnova.example",
        "hireable": False,
        "twitter_username": f"{clean}_sec",
        "public_repos": len(demo_repos),
        "public_gists": len(demo_gists),
        "followers": 128,
        "following": 42,
        "created_at": "2020-04-12T10:14:00Z",
        "updated_at": "2026-10-18T12:00:00Z",
        "profile_url": f"https://github.com/{clean}",
        "type": "User",
    }

    gh_events = {
        "source": "github_events",
        "success": True,
        "total_events": 28,
        "commits_found": len(demo_commits),
        "commits": demo_commits,
        "uncovered_emails": [f"{clean}@apexnova.example", f"{clean}.dev@gmail.com"],
        "uncovered_names": [name],
    }

    gh_repos = {
        "source": "github_repos",
        "success": True,
        "total_queried": len(demo_repos),
        "total_stars": sum(r["stars"] for r in demo_repos),
        "total_forks": sum(r["forks"] for r in demo_repos),
        "top_languages": ["Python", "Go", "Shell"],
        "languages_breakdown": {"Python": 1, "Go": 1, "Shell": 1},
        "repos": demo_repos,
    }

    gh_keys = {
        "source": "github_keys",
        "success": True,
        "has_ssh_keys": True,
        "ssh_keys_count": 1,
        "ssh_keys": demo_ssh_keys,
        "has_gpg_key": True,
        "gpg_key_present": True,
        "uncovered_key_comments": [f"{clean}@macbook-pro.corp.apexnova.example"],
    }

    gh_gists = {
        "source": "github_gists",
        "success": True,
        "total_gists": len(demo_gists),
        "gists": demo_gists,
    }

    posture = _compute_username_security_posture(
        username=clean,
        gh_profile=gh_profile,
        gh_events=gh_events,
        gh_repos=gh_repos,
        gh_keys=gh_keys,
        gh_gists=gh_gists,
        probes=demo_probes,
        breached_emails=demo_breached_emails,
    )

    return {
        "username": clean,
        "lookup_timestamp": _now_iso(),
        "is_demo": True,
        "sources_queried": [
            "github_profile", "github_events", "github_repos", "github_keys",
            "github_gists", "platform_probes", "email_breaches", "public_web_search"
        ],
        "sources_successful": [
            "github_profile", "github_events", "github_repos", "github_keys",
            "github_gists", "platform_probes", "email_breaches", "public_web_search"
        ],
        "profile": gh_profile,
        "events": gh_events,
        "repos": gh_repos,
        "keys": gh_keys,
        "gists": gh_gists,
        "orgs": {"source": "github_orgs", "success": True, "total_orgs": 1, "orgs": [{"login": "apexnova-demo", "description": "Cloud security research group", "avatar_url": "https://avatars.githubusercontent.com/u/10492831?v=4", "url": "https://github.com/apexnova-demo"}]},
        "platform_probes": demo_probes,
        "platforms_found_count": len([p for p in demo_probes if p.get("exists")]),
        "uncovered_emails": [f"{clean}@apexnova.example", f"{clean}.dev@gmail.com"],
        "breached_emails": demo_breached_emails,
        "web_pages": {"source": "public_web_search", "success": True, "total_pages": len(demo_webpages), "pages": demo_webpages},
        "security_posture": posture,
    }


# ════════════════════════════ MAIN LOOKUP PIPELINE ═══════════════════════════

async def lookup_username(username: str) -> Dict[str, Any]:
    """
    Main entrypoint: run comprehensive passive OSINT investigation against a username
    and return an aggregated intelligence dossier.
    """
    clean = _sanitize_username(username)
    if not _is_valid_username(clean):
        return {
            "error": "Invalid username format. Expected alphanumeric characters, hyphens, underscores, or dots (1-60 characters).",
            "username": username
        }

    # If demo handle requested or apexnova simulation
    if clean.lower() in ("apexnova_dev", "apexnova", "demo_user", "test_user"):
        return _generate_demo_username_intel(clean)

    started_at = _now_iso()

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        # 1. Primary concurrent probes
        tasks = [
            _query_github_user(clean, client),
            _query_github_events(clean, client),
            _query_github_repos(clean, client),
            _query_github_orgs(clean, client),
            _query_github_gists(clean, client),
            _query_github_keys(clean, client),
            _probe_all_platforms(clean, client),
            _query_public_web_pages(clean, client),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        gh_profile = results[0] if not isinstance(results[0], Exception) else {"source": "github_profile", "success": False, "found": False}
        gh_events = results[1] if not isinstance(results[1], Exception) else {"source": "github_events", "success": False, "commits": [], "uncovered_emails": []}
        gh_repos = results[2] if not isinstance(results[2], Exception) else {"source": "github_repos", "success": False, "repos": [], "top_languages": []}
        gh_orgs = results[3] if not isinstance(results[3], Exception) else {"source": "github_orgs", "success": False, "orgs": []}
        gh_gists = results[4] if not isinstance(results[4], Exception) else {"source": "github_gists", "success": False, "gists": []}
        gh_keys = results[5] if not isinstance(results[5], Exception) else {"source": "github_keys", "success": False, "has_ssh_keys": False, "has_gpg_key": False}
        probes = results[6] if not isinstance(results[6], Exception) else []
        web_pages = results[7] if not isinstance(results[7], Exception) else {"source": "public_web_search", "success": False, "pages": []}

        # 2. Extract all discovered emails (from commits + SSH comments) and check breach exposure
        uncovered_emails = list(gh_events.get("uncovered_emails", []))
        if gh_profile.get("email"):
            uncovered_emails.append(gh_profile.get("email"))
        for comment in gh_keys.get("uncovered_key_comments", []):
            match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', comment)
            if match:
                uncovered_emails.append(match.group(0))

        breached_emails = await _check_uncovered_emails_breaches(uncovered_emails, client)

    # 3. Compute security posture & attack paths
    posture = _compute_username_security_posture(
        username=clean,
        gh_profile=gh_profile,
        gh_events=gh_events,
        gh_repos=gh_repos,
        gh_keys=gh_keys,
        gh_gists=gh_gists,
        probes=probes,
        breached_emails=breached_emails,
    )

    sources_queried = [
        "github_profile", "github_events", "github_repos", "github_orgs",
        "github_gists", "github_keys", "platform_probes", "public_web_search"
    ]
    if uncovered_emails:
        sources_queried.append("email_breaches")

    sources_successful = []
    for s_name, item in [
        ("github_profile", gh_profile),
        ("github_events", gh_events),
        ("github_repos", gh_repos),
        ("github_orgs", gh_orgs),
        ("github_gists", gh_gists),
        ("github_keys", gh_keys),
        ("public_web_search", web_pages),
    ]:
        if isinstance(item, dict) and item.get("success"):
            sources_successful.append(s_name)
    if probes:
        sources_successful.append("platform_probes")
    if breached_emails:
        sources_successful.append("email_breaches")

    return {
        "username": clean,
        "lookup_timestamp": started_at,
        "is_demo": False,
        "sources_queried": sources_queried,
        "sources_successful": sources_successful,
        "profile": gh_profile,
        "events": gh_events,
        "repos": gh_repos,
        "orgs": gh_orgs,
        "gists": gh_gists,
        "keys": gh_keys,
        "platform_probes": probes,
        "platforms_found_count": len([p for p in probes if p.get("exists")]),
        "uncovered_emails": sorted(list(set(uncovered_emails))),
        "breached_emails": breached_emails,
        "web_pages": web_pages,
        "security_posture": posture,
    }


# ══════════════════════════════ EXCEL EXPORT ═════════════════════════════════

def export_username_intel_excel(data: Dict[str, Any]) -> bytes:
    """
    Generate a styled, multi-sheet Excel workbook (.xlsx) containing all
    harvested username intelligence records.
    """
    if not OPENPYXL_AVAILABLE:
        raise RuntimeError("openpyxl is not installed in python environment.")

    wb = openpyxl.Workbook()
    # Remove default sheet
    default_sheet = wb.active
    wb.remove(default_sheet)

    username = data.get("username", "identity")
    profile = data.get("profile", {})
    posture = data.get("security_posture", {})
    repos = data.get("repos", {}).get("repos", [])
    probes = data.get("platform_probes", [])
    commits = data.get("events", {}).get("commits", [])
    uncovered_emails = data.get("uncovered_emails", [])
    breached_emails = data.get("breached_emails", [])
    webpages = data.get("web_pages", {}).get("pages", [])

    # Color Palette
    DARK_NAVY = "0A0E1A"
    CARD_BG = "141A29"
    CYBER_BLUE = "00D4FF"
    TEXT_WHITE = "FFFFFF"
    BORDER_CLR = "2A3347"

    title_font = Font(name="Calibri", size=14, bold=True, color=TEXT_WHITE)
    title_fill = PatternFill(start_color=DARK_NAVY, end_color=DARK_NAVY, fill_type="solid")

    header_font = Font(name="Calibri", size=10, bold=True, color=TEXT_WHITE)
    header_fill = PatternFill(start_color=CARD_BG, end_color=CARD_BG, fill_type="solid")

    thin_border = Border(
        left=Side(style="thin", color=BORDER_CLR),
        right=Side(style="thin", color=BORDER_CLR),
        top=Side(style="thin", color=BORDER_CLR),
        bottom=Side(style="thin", color=BORDER_CLR)
    )

    def style_header_row(ws, row_idx: int, col_count: int):
        for col in range(1, col_count + 1):
            cell = ws.cell(row=row_idx, column=col)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = thin_border

    def auto_fit_columns(ws, max_cols=8, min_width=12, max_width=50):
        for col in range(1, max_cols + 1):
            max_len = 0
            col_letter = get_column_letter(col)
            for row in range(1, ws.max_row + 1):
                val = ws.cell(row=row, column=col).value
                if val:
                    max_len = max(max_len, len(str(val)))
            ws.column_dimensions[col_letter].width = max(min_width, min(max_len + 3, max_width))

    # ── SHEET 1: Identity Summary ──
    ws1 = wb.create_sheet(title="Identity Summary")
    ws1.cell(row=1, column=1, value="OSINT-to-Attack-Path — Username Intelligence Dossier").font = title_font
    ws1.cell(row=1, column=1).fill = title_fill
    ws1.merge_cells("A1:B1")

    summary_fields = [
        ("Target Handle", f"@{username}"),
        ("Investigation Date", data.get("lookup_timestamp", _now_iso())),
        ("Full Name", profile.get("name") or "Not Identified"),
        ("Bio / Description", profile.get("bio") or "N/A"),
        ("Company / Affiliation", profile.get("company") or "Not Disclosed"),
        ("Location", profile.get("location") or "Not Disclosed"),
        ("Website / Blog", profile.get("blog") or "None"),
        ("Twitter / X", f"@{profile.get('twitter_username')}" if profile.get("twitter_username") else "None"),
        ("GitHub Profile", profile.get("profile_url") or f"https://github.com/{username}"),
        ("Public Repositories", profile.get("public_repos", 0)),
        ("Public Gists", profile.get("public_gists", 0)),
        ("Followers / Following", f"{profile.get('followers', 0)} / {profile.get('following', 0)}"),
        ("Platforms Discovered", f"{data.get('platforms_found_count', 0)} Online Platforms"),
        ("Uncovered Commit Emails", ", ".join(uncovered_emails) if uncovered_emails else "None Discovered"),
        ("Breach Associations", f"{sum(b.get('breach_count', 0) for b in breached_emails)} known breaches across uncovered emails"),
        ("Risk Scoring Standard", posture.get("nist_assessment", {}).get("standard", "NIST SP 800-30 Rev. 1")),
        ("Threat Event Likelihood", f"{posture.get('nist_assessment', {}).get('threat_likelihood', 'N/A')} / 10 ({posture.get('nist_assessment', {}).get('likelihood_tier', '')})"),
        ("Threat Event Impact", f"{posture.get('nist_assessment', {}).get('threat_impact', 'N/A')} / 10 ({posture.get('nist_assessment', {}).get('impact_tier', '')})"),
        ("Security Posture Grade", f"Grade {posture.get('grade', 'C')} ({posture.get('risk_level', 'MODERATE')})"),
        ("Composite Threat Score", f"{posture.get('composite_score', 0)} / 100"),
        ("Resilience Health Score", f"{posture.get('health_score', 0)} %"),
    ]

    for idx, (lbl, val) in enumerate(summary_fields, start=3):
        c1 = ws1.cell(row=idx, column=1, value=lbl)
        c1.font = Font(name="Calibri", size=10, bold=True, color="334155")
        c1.border = thin_border
        c2 = ws1.cell(row=idx, column=2, value=str(val))
        c2.font = Font(name="Calibri", size=10)
        c2.border = thin_border
    auto_fit_columns(ws1, max_cols=2, min_width=24, max_width=70)

    # ── SHEET 2: Security Posture & Matrix ──
    ws2 = wb.create_sheet(title="Security Posture")
    ws2.cell(row=1, column=1, value=f"Security Posture & Controls Matrix: @{username}").font = title_font
    ws2.cell(row=1, column=1).fill = title_fill
    ws2.merge_cells("A1:E1")

    headers2 = ["Category", "Security Control", "Observed Value", "Status", "Hardening Recommendation"]
    for c_idx, h in enumerate(headers2, start=1):
        ws2.cell(row=3, column=c_idx, value=h)
    style_header_row(ws2, 3, len(headers2))

    for r_idx, ctrl in enumerate(posture.get("posture_matrix", []), start=4):
        ws2.cell(row=r_idx, column=1, value=ctrl.get("category", "")).border = thin_border
        ws2.cell(row=r_idx, column=2, value=ctrl.get("control", "")).border = thin_border
        ws2.cell(row=r_idx, column=3, value=ctrl.get("value", "")).border = thin_border
        c_stat = ws2.cell(row=r_idx, column=4, value=ctrl.get("status", ""))
        c_stat.border = thin_border
        c_stat.alignment = Alignment(horizontal="center")
        ws2.cell(row=r_idx, column=5, value=ctrl.get("recommendation", "")).border = thin_border
    auto_fit_columns(ws2, max_cols=5, min_width=16, max_width=60)

    # ── SHEET 3: Attack Scenarios ──
    ws3 = wb.create_sheet(title="Attack Scenarios")
    ws3.cell(row=1, column=1, value=f"Exploitation Scenarios & Kill Chains: @{username}").font = title_font
    ws3.cell(row=1, column=1).fill = title_fill
    ws3.merge_cells("A1:E1")

    headers3 = ["Scenario Title", "MITRE Technique", "Severity", "Impact", "Defensive Mitigation"]
    for c_idx, h in enumerate(headers3, start=1):
        ws3.cell(row=3, column=c_idx, value=h)
    style_header_row(ws3, 3, len(headers3))

    for r_idx, sc in enumerate(posture.get("attack_scenarios", []), start=4):
        ws3.cell(row=r_idx, column=1, value=sc.get("title", "")).border = thin_border
        ws3.cell(row=r_idx, column=2, value=sc.get("mitre_technique", "")).border = thin_border
        ws3.cell(row=r_idx, column=3, value=sc.get("severity", "")).border = thin_border
        ws3.cell(row=r_idx, column=4, value=sc.get("impact", "")).border = thin_border
        ws3.cell(row=r_idx, column=5, value=sc.get("mitigation", "")).border = thin_border
    auto_fit_columns(ws3, max_cols=5, min_width=18, max_width=65)

    # ── SHEET 4: Cross-Platform Accounts ──
    ws4 = wb.create_sheet(title="Platform Accounts")
    ws4.cell(row=1, column=1, value=f"Cross-Platform Presence & Reconnaissance: @{username}").font = title_font
    ws4.cell(row=1, column=1).fill = title_fill
    ws4.merge_cells("A1:E1")

    headers4 = ["Platform Name", "Category", "Status", "Profile URL", "Status Code"]
    for c_idx, h in enumerate(headers4, start=1):
        ws4.cell(row=3, column=c_idx, value=h)
    style_header_row(ws4, 3, len(headers4))

    for r_idx, probe in enumerate(probes, start=4):
        ws4.cell(row=r_idx, column=1, value=probe.get("platform", "")).border = thin_border
        ws4.cell(row=r_idx, column=2, value=probe.get("category", "")).border = thin_border
        c_st = ws4.cell(row=r_idx, column=3, value=probe.get("status", ""))
        c_st.border = thin_border
        c_st.alignment = Alignment(horizontal="center")
        ws4.cell(row=r_idx, column=4, value=probe.get("profile_url", "")).border = thin_border
        ws4.cell(row=r_idx, column=5, value=probe.get("status_code", "")).border = thin_border
    auto_fit_columns(ws4, max_cols=5, min_width=15, max_width=55)

    # ── SHEET 5: Repositories & Commits ──
    ws5 = wb.create_sheet(title="Repos & Commits")
    ws5.cell(row=1, column=1, value=f"Public Code Artifacts & Commit Logs: @{username}").font = title_font
    ws5.cell(row=1, column=1).fill = title_fill
    ws5.merge_cells("A1:E1")

    headers5 = ["Repository", "Language", "Stars / Forks", "Description", "URL"]
    for c_idx, h in enumerate(headers5, start=1):
        ws5.cell(row=3, column=c_idx, value=h)
    style_header_row(ws5, 3, len(headers5))

    curr_row = 4
    for r in repos:
        ws5.cell(row=curr_row, column=1, value=r.get("name", "")).border = thin_border
        ws5.cell(row=curr_row, column=2, value=r.get("language", "")).border = thin_border
        ws5.cell(row=curr_row, column=3, value=f"{r.get('stars', 0)} stars / {r.get('forks', 0)} forks").border = thin_border
        ws5.cell(row=curr_row, column=4, value=r.get("description", "")).border = thin_border
        ws5.cell(row=curr_row, column=5, value=r.get("url", "")).border = thin_border
        curr_row += 1

    # Commits subheader
    curr_row += 2
    ws5.cell(row=curr_row, column=1, value="Recent Commit Logs & Discovered Email Metadata").font = Font(name="Calibri", size=11, bold=True, color=TEXT_WHITE)
    ws5.cell(row=curr_row, column=1).fill = header_fill
    ws5.merge_cells(f"A{curr_row}:E{curr_row}")

    curr_row += 1
    commit_headers = ["Repository", "Commit Message", "Author Name", "Author Email", "Date"]
    for c_idx, h in enumerate(commit_headers, start=1):
        ws5.cell(row=curr_row, column=c_idx, value=h)
    style_header_row(ws5, curr_row, len(commit_headers))

    curr_row += 1
    for c in commits:
        ws5.cell(row=curr_row, column=1, value=c.get("repo", "")).border = thin_border
        ws5.cell(row=curr_row, column=2, value=c.get("message", "")).border = thin_border
        ws5.cell(row=curr_row, column=3, value=c.get("author_name", "")).border = thin_border
        ws5.cell(row=curr_row, column=4, value=c.get("author_email", "")).border = thin_border
        ws5.cell(row=curr_row, column=5, value=c.get("date", "")).border = thin_border
        curr_row += 1
    auto_fit_columns(ws5, max_cols=5, min_width=18, max_width=60)

    # ── SHEET 6: Discovered Emails & Breaches ──
    ws6 = wb.create_sheet(title="Discovered Emails")
    ws6.cell(row=1, column=1, value=f"Uncovered Emails & Breach Intelligence: @{username}").font = title_font
    ws6.cell(row=1, column=1).fill = title_fill
    ws6.merge_cells("A1:D1")

    headers6 = ["Discovered Email Address", "Breach Status", "Breaches Count", "Breach Incident Names"]
    for c_idx, h in enumerate(headers6, start=1):
        ws6.cell(row=3, column=c_idx, value=h)
    style_header_row(ws6, 3, len(headers6))

    for r_idx, em in enumerate(uncovered_emails, start=4):
        ws6.cell(row=r_idx, column=1, value=em).border = thin_border
        b_info = next((b for b in breached_emails if b.get("email") == em), None)
        if b_info and b_info.get("breached"):
            c_br = ws6.cell(row=r_idx, column=2, value="BREACHED")
            c_br.font = Font(name="Calibri", bold=True, color="EF4444")
            ws6.cell(row=r_idx, column=3, value=b_info.get("breach_count", 0)).border = thin_border
            ws6.cell(row=r_idx, column=4, value=", ".join(b_info.get("breaches", []))).border = thin_border
        else:
            c_br = ws6.cell(row=r_idx, column=2, value="CLEAN / NO EXPOSURE")
            c_br.font = Font(name="Calibri", bold=True, color="22C55E")
            ws6.cell(row=r_idx, column=3, value=0).border = thin_border
            ws6.cell(row=r_idx, column=4, value="No known breaches recorded").border = thin_border
        c_br.border = thin_border
    auto_fit_columns(ws6, max_cols=4, min_width=20, max_width=65)

    # ── SHEET 7: Public Web Mentions ──
    ws7 = wb.create_sheet(title="Web Mentions")
    ws7.cell(row=1, column=1, value=f"Public Search Engine Mentions: @{username}").font = title_font
    ws7.cell(row=1, column=1).fill = title_fill
    ws7.merge_cells("A1:C1")

    headers7 = ["Page Title", "URL", "Snippet / Context"]
    for c_idx, h in enumerate(headers7, start=1):
        ws7.cell(row=3, column=c_idx, value=h)
    style_header_row(ws7, 3, len(headers7))

    for r_idx, page in enumerate(webpages, start=4):
        ws7.cell(row=r_idx, column=1, value=page.get("title", "")).border = thin_border
        ws7.cell(row=r_idx, column=2, value=page.get("url", "")).border = thin_border
        ws7.cell(row=r_idx, column=3, value=page.get("snippet", "")).border = thin_border
    auto_fit_columns(ws7, max_cols=3, min_width=20, max_width=80)

    # Save to memory buffer
    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()

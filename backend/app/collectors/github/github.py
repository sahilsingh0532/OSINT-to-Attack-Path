"""GitHub intelligence provider — repos, code search, developer discovery, potential secret exposure."""

import httpx
import re
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings

# Patterns that may indicate credential exposure — we detect but NEVER display the value
SECRET_PATTERNS = [
    r'(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth|private[_-]?key)\s*[=:]\s*["\']?[\w\-/+]{8,}',
]


class GithubIntelCollector(BaseCollector):
    name = "github"
    display_name = "GitHub (Intelligence)"
    description = "Public repositories, code references, developer identifiers, and potential secret exposure detection."
    provider_category = "github"
    requires_key = False

    def _has_api_key(self) -> bool:
        return bool(settings.github_token)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            self._record_query()
            headers = {"Accept": "application/vnd.github.v3+json"}
            if settings.github_token:
                headers["Authorization"] = f"token {settings.github_token}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Repository search
                r = await client.get(
                    f"https://api.github.com/search/repositories?q={target}&per_page=10",
                    headers=headers,
                )
                if r.status_code == 200:
                    for repo in r.json().get("items", [])[:8]:
                        full_name = repo.get("full_name", "")
                        desc = repo.get("description") or ""
                        lang = repo.get("language") or "Unknown"
                        stars = repo.get("stargazers_count", 0)
                        topics = repo.get("topics", [])
                        results.append(make_result(
                            source=self.name,
                            finding_type="repository",
                            value=full_name,
                            target=target,
                            confidence=0.85,
                            evidence=f"GitHub repository search for {target}",
                            title=f"GitHub Repo: {full_name}",
                            description=f"Public repository: {desc[:100]}. Language: {lang}. Stars: {stars}",
                            observation_type="observed",
                            category="code",
                            tags=f"github,repository,{lang.lower()}",
                            external_url=repo.get("html_url", ""),
                            raw_data={
                                "full_name": full_name,
                                "language": lang,
                                "stars": stars,
                                "topics": topics,
                                "created_at": repo.get("created_at"),
                                "pushed_at": repo.get("pushed_at"),
                            },
                            first_seen=repo.get("created_at"),
                            last_seen=repo.get("pushed_at"),
                        ))

                # 2. Code search for potential secrets (detect only, NEVER expose value)
                r2 = await client.get(
                    f"https://api.github.com/search/code?q={target}+extension:env+OR+extension:yml+OR+extension:json&per_page=5",
                    headers=headers,
                )
                if r2.status_code == 200:
                    for item in r2.json().get("items", [])[:5]:
                        path = item.get("path", "")
                        repo_name = item.get("repository", {}).get("full_name", "repo")
                        html_url = item.get("html_url", "")
                        results.append(make_result(
                            source=self.name,
                            finding_type="exposure",
                            value=f"github_code:{repo_name}:{path}",
                            target=target,
                            confidence=0.78,
                            evidence=f"GitHub code search found {target} referenced in {repo_name}/{path}",
                            title=f"Code Reference: {path}",
                            description=(
                                f"File {path} in public repository {repo_name} references target. "
                                "Review for unintentional credential or configuration exposure. "
                                "Recommendation: rotate any exposed credentials and review repository history."
                            ),
                            observation_type="inferred",
                            category="exposure",
                            tags="github,code,exposure,potential_secret",
                            external_url=html_url,
                            raw_data={
                                "repo": repo_name,
                                "path": path,
                                # Never include actual file content or credentials
                                "note": "Potential secret exposure detected. Value not displayed for security.",
                            },
                        ))

                # 3. Organization search
                r3 = await client.get(
                    f"https://api.github.com/search/users?q={target}+type:org&per_page=3",
                    headers=headers,
                )
                if r3.status_code == 200:
                    for org in r3.json().get("items", [])[:3]:
                        login = org.get("login", "")
                        results.append(make_result(
                            source=self.name,
                            finding_type="identity",
                            value=f"github_org:{login}",
                            target=target,
                            confidence=0.80,
                            evidence=f"GitHub organization search for {target}",
                            title=f"GitHub Org: {login}",
                            description=f"Public GitHub organization {login} found referencing {target}",
                            observation_type="observed",
                            category="identity",
                            tags="github,organization,identity",
                            external_url=f"https://github.com/{login}",
                            raw_data={"login": login, "type": "Organization"},
                        ))

        except Exception as e:
            self._record_error(str(e))
        return results

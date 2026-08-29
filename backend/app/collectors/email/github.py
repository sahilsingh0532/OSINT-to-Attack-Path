"""Email providers — GitHub public email references."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class GithubEmailCollector(BaseCollector):
    name = "github"
    display_name = "GitHub (Email References)"
    description = "Email addresses referenced in public GitHub commits and profiles. API key recommended."
    provider_category = "email"
    requires_key = False

    def _has_api_key(self) -> bool:
        return bool(settings.github_token)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        domain = target if "@" not in target else target.split("@")[1]
        try:
            self._record_query()
            headers = {}
            if settings.github_token:
                headers["Authorization"] = f"token {settings.github_token}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                # Search for commits mentioning the domain email
                r = await client.get(
                    f"https://api.github.com/search/commits?q={domain}&per_page=10",
                    headers={**headers, "Accept": "application/vnd.github.cloak-preview"},
                )
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    seen_emails = set()
                    for item in items[:10]:
                        commit = item.get("commit", {})
                        author = commit.get("author", {})
                        email = author.get("email", "")
                        name = author.get("name", "")
                        repo = item.get("repository", {}).get("full_name", "")

                        if email and domain in email and email not in seen_emails:
                            seen_emails.add(email)
                            results.append(make_result(
                                source=self.name,
                                finding_type="email",
                                value=email,
                                target=target,
                                confidence=0.82,
                                evidence=f"GitHub public commit by {name} in {repo}",
                                title=f"GitHub Email: {email}",
                                description=f"Email {email} found in public GitHub commit history. Author: {name}. Repo: {repo}",
                                observation_type="observed",
                                category="email",
                                tags="email,github,commit",
                                external_url=f"https://github.com/{repo}",
                                raw_data={
                                    "email": email,
                                    "name": name,
                                    "repo": repo,
                                },
                            ))
        except Exception as e:
            self._record_error(str(e))
        return results

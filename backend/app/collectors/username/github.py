"""Username providers — GitHub user/org profile intelligence."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class GithubUsernameCollector(BaseCollector):
    name = "github"
    display_name = "GitHub (Username / Profile)"
    description = "Public GitHub user and organization profiles. API key recommended."
    provider_category = "username"
    requires_key = False

    def _has_api_key(self) -> bool:
        return bool(settings.github_token)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        target: can be a username, org name, or domain.
        Searches GitHub orgs and users referencing the target.
        """
        results = []
        # Strip domain to get org candidate
        org_name = target.replace(".", "-").split("-")[0] if "." in target else target
        try:
            self._record_query()
            headers = {}
            if settings.github_token:
                headers["Authorization"] = f"token {settings.github_token}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                # Search organizations
                r = await client.get(
                    f"https://api.github.com/search/users?q={org_name}+type:org&per_page=5",
                    headers=headers,
                )
                if r.status_code == 200:
                    for user in r.json().get("items", [])[:5]:
                        login = user.get("login", "")
                        html_url = user.get("html_url", "")
                        # Fetch org details
                        r2 = await client.get(f"https://api.github.com/users/{login}", headers=headers)
                        if r2.status_code == 200:
                            detail = r2.json()
                            results.append(make_result(
                                source=self.name,
                                finding_type="identity",
                                value=f"github_org:{login}",
                                target=target,
                                confidence=0.80,
                                evidence=f"GitHub organization search for {org_name}",
                                title=f"GitHub Org: {login}",
                                description=(
                                    f"Public GitHub organization: {detail.get('name', login)}. "
                                    f"Repos: {detail.get('public_repos', 0)}. "
                                    f"Location: {detail.get('location', 'N/A')}"
                                ),
                                observation_type="observed",
                                category="identity",
                                tags="username,github,organization",
                                external_url=html_url,
                                raw_data={
                                    "login": login,
                                    "type": "Organization",
                                    "public_repos": detail.get("public_repos", 0),
                                    "followers": detail.get("followers", 0),
                                    "location": detail.get("location", ""),
                                    "blog": detail.get("blog", ""),
                                    "created_at": detail.get("created_at", ""),
                                },
                                first_seen=detail.get("created_at"),
                            ))

                # Search users
                r3 = await client.get(
                    f"https://api.github.com/search/users?q={org_name}&per_page=5",
                    headers=headers,
                )
                if r3.status_code == 200:
                    for user in r3.json().get("items", [])[:5]:
                        login = user.get("login", "")
                        html_url = user.get("html_url", "")
                        results.append(make_result(
                            source=self.name,
                            finding_type="identity",
                            value=f"github_user:{login}",
                            target=target,
                            confidence=0.75,
                            evidence=f"GitHub user search for {org_name}",
                            title=f"GitHub User: {login}",
                            description=f"Public GitHub user profile: {login}",
                            observation_type="observed",
                            category="identity",
                            tags="username,github,developer",
                            external_url=html_url,
                            raw_data={"login": login, "type": "User"},
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results

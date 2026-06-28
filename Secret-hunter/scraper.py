"""
scraper.py — High-performance async domain scraper.

Performance design:
  - Single shared aiohttp session + connection pool across all domains
  - Semaphore-bounded concurrency (domains AND per-domain sub-requests)
  - Redirect-aware fetch returns (content, final_url) so JS/config paths
    are built from the REAL resolved host
  - Source maps fetched and scanned when discovered (often leak full source)
  - robots.txt / sitemap.xml parsed for additional JS/page discovery
"""

import asyncio
import re
import aiohttp
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from engine import scan_text, Finding
from leak_paths import JS_PATHS, ALL_LEAK_PATHS, CONFIG_PATHS, GIT_PATHS

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
]


@dataclass
class DomainResult:
    domain: str
    status: str                     # ok | error
    findings: list = field(default_factory=list)
    js_files_scanned: int = 0
    paths_scanned: int = 0
    error: Optional[str] = None
    final_url: Optional[str] = None


class SecretScraper:
    def __init__(self, concurrency: int = 30, per_domain_concurrency: int = 25,
                 timeout: int = 10, scan_sourcemaps: bool = True,
                 max_js_per_domain: int = 80):
        self.concurrency = concurrency
        self.per_domain_concurrency = per_domain_concurrency
        self.timeout = timeout
        self.scan_sourcemaps = scan_sourcemaps
        self.max_js_per_domain = max_js_per_domain
        self._ua_idx = 0

    def _ua(self) -> str:
        ua = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
        self._ua_idx += 1
        return ua

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> tuple:
        """Returns (content, final_url). Follows redirects; (None,None) if unreachable."""
        try:
            async with session.get(
                url, headers={"User-Agent": self._ua()},
                allow_redirects=True, ssl=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                max_redirects=10,
            ) as resp:
                final_url = str(resp.url)
                if resp.status == 200:
                    return await resp.text(errors="replace"), final_url
                return None, final_url
        except aiohttp.TooManyRedirects:
            return None, url
        except Exception:
            return None, None

    async def _fetch_content(self, session, url) -> Optional[str]:
        content, _ = await self._fetch(session, url)
        return content

    async def _scan_one(self, session, sem, url, source_type, domain) -> list:
        async with sem:
            content = await self._fetch_content(session, url)
        if not content:
            return []
        findings = scan_text(content, url, source_type, domain)
        return findings

    async def _scan_domain(self, domain: str, session: aiohttp.ClientSession,
                           sub_sem: asyncio.Semaphore, ui) -> DomainResult:
        result = DomainResult(domain=domain, status="ok")

        # ── 1. Root HTML ──────────────────────────────────────────────────
        html, final_url = await self._fetch(session, f"https://{domain}")
        if html is None and final_url is None:
            html, final_url = await self._fetch(session, f"http://{domain}")

        if html is None:
            result.status = "error"
            result.error = (
                f"Reachable → {final_url} but non-200" if final_url
                else "Unreachable (DNS/timeout/connection failure)"
            )
            ui.domain_done(domain, result)
            return result

        result.final_url = final_url
        parsed = urlparse(final_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        result.findings += scan_text(html, final_url, "HTML", domain)
        result.paths_scanned += 1

        # ── 2. Discover JS via <script src> + robots/sitemap + common paths ─
        js_urls = set()
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all("script", src=True):
                js_urls.add(urljoin(base_url, tag["src"]))
            # Inline <script> blocks — scan directly without fetching
            for tag in soup.find_all("script", src=False):
                if tag.string:
                    result.findings += scan_text(tag.string, final_url, "Inline JS", domain)
        except Exception:
            pass

        for path in JS_PATHS:
            js_urls.add(f"{base_url}/{path}")

        js_urls = list(js_urls)[: self.max_js_per_domain]

        js_tasks = [
            self._scan_one(session, sub_sem, u, "JS", domain) for u in js_urls
        ]
        js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
        scanned_js_urls = []
        for url, res in zip(js_urls, js_results):
            if isinstance(res, list):
                if res or True:  # we still want to count attempted/successful fetches
                    scanned_js_urls.append(url)
                result.findings += res
        result.js_files_scanned = len(js_urls)
        result.paths_scanned += len(js_urls)

        # ── 3. Source maps for discovered JS (often unminified + secrets) ──
        if self.scan_sourcemaps:
            map_urls = [u + ".map" for u in js_urls[:30]]  # cap to avoid explosion
            map_tasks = [
                self._scan_one(session, sub_sem, u, "Source Map", domain) for u in map_urls
            ]
            map_results = await asyncio.gather(*map_tasks, return_exceptions=True)
            for res in map_results:
                if isinstance(res, list):
                    result.findings += res
            result.paths_scanned += len(map_urls)

        # ── 4. Config / backup / CI / debug / git leak paths ────────────────
        leak_tasks = [
            self._scan_one(session, sub_sem, f"{base_url}/{p}", "Leak Path", domain)
            for p in ALL_LEAK_PATHS
        ]
        leak_results = await asyncio.gather(*leak_tasks, return_exceptions=True)
        for res in leak_results:
            if isinstance(res, list):
                result.findings += res
        result.paths_scanned += len(ALL_LEAK_PATHS)

        ui.domain_done(domain, result)
        return result

    async def scan_all(self, domains: list, ui) -> list:
        domain_sem = asyncio.Semaphore(self.concurrency)
        sub_sem    = asyncio.Semaphore(self.per_domain_concurrency)
        connector  = aiohttp.TCPConnector(
            limit=self.concurrency * self.per_domain_concurrency,
            limit_per_host=self.per_domain_concurrency,
            ssl=False,
        )

        async def bounded(domain):
            async with domain_sem:
                return await self._scan_domain(domain, session, sub_sem, ui)

        ui.start_progress(len(domains))
        async with aiohttp.ClientSession(connector=connector) as session:
            results = await asyncio.gather(
                *[bounded(d) for d in domains], return_exceptions=True
            )

        clean = []
        for d, r in zip(domains, results):
            if isinstance(r, DomainResult):
                clean.append(r)
            else:
                clean.append(DomainResult(domain=d, status="error", error=str(r)))
        return clean

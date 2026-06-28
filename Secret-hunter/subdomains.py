"""
subdomains.py — Passive + active subdomain enumeration.
Sources: crt.sh certificate transparency, DNS-over-HTTPS brute force.
"""

import asyncio
import aiohttp

COMMON_SUBS = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","ftp","mail2","test","portal","ns","host","support","dev",
    "web","admin","store","mx1","cdn","api","exchange","app","static","assets",
    "img","images","media","staging","beta","alpha","demo","old","new","backup",
    "db","database","git","gitlab","ci","jenkins","jira","confluence","wiki",
    "docs","help","kb","status","monitor","grafana","prometheus","kibana",
    "elastic","api2","v1","v2","v3","gateway","proxy","internal","intranet",
    "login","auth","sso","oauth","id","identity","accounts","billing","pay",
    "checkout","mobile","webapp","dashboard","panel","manage","console",
    "cpanel","whm","phpmyadmin","upload","download","files","uat","qa","prod",
    "sandbox","preview","origin","edge","lb","ws","socket","stream","video",
    "cms","blogapi","graphql","rest","public","private","internal-api",
]


async def _crtsh(session, domain, timeout=15) -> set:
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(f".{domain}") or sub == domain:
                            subs.add(sub)
    except Exception:
        pass
    return subs


async def _dns_resolves(session, fqdn, timeout=5) -> bool:
    try:
        url = f"https://dns.google/resolve?name={fqdn}&type=A"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return data.get("Status") == 0 and bool(data.get("Answer"))
    except Exception:
        pass
    return False


async def _brute_force(session, domain, wordlist, concurrency=80) -> set:
    found = set()
    sem = asyncio.Semaphore(concurrency)

    async def check(sub):
        async with sem:
            fqdn = f"{sub}.{domain}"
            if await _dns_resolves(session, fqdn):
                found.add(fqdn)

    await asyncio.gather(*[check(s) for s in wordlist], return_exceptions=True)
    return found


async def enumerate_subdomains(domain: str, brute=True, concurrency=80, timeout=15) -> list:
    connector = aiohttp.TCPConnector(ssl=False, limit=150)
    all_subs = set()

    async with aiohttp.ClientSession(connector=connector) as session:
        crt_subs = await _crtsh(session, domain, timeout)
        all_subs.update(crt_subs)

        if brute:
            brute_subs = await _brute_force(session, domain, COMMON_SUBS, concurrency)
            all_subs.update(brute_subs)

        if crt_subs:
            sem = asyncio.Semaphore(concurrency)
            verified = set()

            async def verify(fqdn):
                async with sem:
                    if await _dns_resolves(session, fqdn):
                        verified.add(fqdn)

            await asyncio.gather(*[verify(s) for s in crt_subs], return_exceptions=True)
            all_subs = verified | (all_subs - crt_subs)

    all_subs.add(domain)
    return sorted(all_subs)


async def enumerate_all_domains(domains: list, brute=True, concurrency=80, ui=None) -> dict:
    results = {}
    for domain in domains:
        if ui:
            ui.subdomain_start(domain)
        subs = await enumerate_subdomains(domain, brute=brute, concurrency=concurrency)
        results[domain] = subs
        if ui:
            ui.subdomain_done(domain, subs)
    return results

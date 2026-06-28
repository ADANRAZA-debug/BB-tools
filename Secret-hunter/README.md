# Secret Scanner

A comprehensive secret/API key/token leak detector for domains, subdomains, and JS bundles you own or are authorized to test.

## ⚠️ Authorized use only
For domains/infrastructure you own or have explicit written permission to test.

## What makes this different from basic scanners

- **151 detection signatures** spanning cloud providers, payment processors, AI/LLM APIs, dev tools, messaging platforms, databases, and private keys — not just Google/AWS
- **Deobfuscation layer** — decodes hex escapes (`\x41\x49`), unicode escapes (`\u0041`), string concatenation (`"AIza"+"SyD"`), `atob()` base64 calls, bare base64 strings, `String.fromCharCode()`, and webpack array key/value reassembly (`n[0]="val",n[1]="KEY_NAME"`) — so secrets hidden across multiple obfuscation layers are still caught
- **Entropy-based false-positive filtering** — generic patterns require quoted string values and pass through Shannon entropy + JS-identifier detection, eliminating false hits like `requestKey:g.HEAD_REQUEST_KEY` or `accessKey:a.spaceSeparated`
- **Cross-pattern deduplication** — a secret matched by multiple overlapping patterns is reported once under its highest-confidence label
- **133 leak-path probes per domain** — `.env` variants, backup files, git exposure, CI/CD configs, debug endpoints, source maps, mobile config files
- **High concurrency** — async with independent semaphores for domain-level and per-domain request concurrency; single shared connection pool

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a list of domains
python main.py -f domains.txt

# Auto-discover subdomains first (crt.sh + DNS brute-force)
python main.py -f domains.txt --subs

# Wildcard entries in domains.txt auto-trigger subdomain discovery
echo "*.example.com" >> domains.txt
python main.py -f domains.txt

# Show/store UNMASKED secret values (handle output securely!)
python main.py -f domains.txt --raw

# Scan a flat list of JS/page URLs directly (skip domain crawling)
python main.py --js-list jsfiles.txt

# Tune performance
python main.py -f domains.txt --concurrency 50 --per-domain-concurrency 40

# Custom output directory
python main.py -f domains.txt -o ./my-reports
```

## domains.txt format

```
example.com
*.example.com        ← auto-runs subdomain discovery on this root
api.example.org
# comments ignored
```

## Output

Three formats written per scan: `.json` (full detail + summary), `.csv` (spreadsheet-friendly), `.txt` (grep-friendly one-line-per-finding).

## Detection categories (151 signatures)

Cloud (AWS/GCP/Azure/DigitalOcean/Alibaba/Tencent/IBM/Oracle), source control (GitHub/GitLab/Bitbucket/NPM/PyPI/Docker Hub), payments (Stripe/PayPal/Square/Razorpay/Plaid/Coinbase), messaging (Slack/Discord/Twilio/SendGrid/Mailgun/Mailchimp), maps, e-commerce (Shopify), CMS (Contentful/Sanity/Prismic), analytics (Algolia/Segment/Mixpanel/Datadog/Sentry/New Relic), AI/LLM (OpenAI/Anthropic/HuggingFace/Replicate/Pinecone/Groq/Mistral), infra (Vercel/Netlify/Cloudflare/Supabase/PlanetScale), identity (Auth0/Okta/Clerk), dev tools (CircleCI/Jenkins/Terraform/Notion/Airtable/Figma), private keys (RSA/EC/PGP/OpenSSH), database connection strings (Postgres/MySQL/MongoDB/Redis), JWTs, and generic high-entropy secrets.

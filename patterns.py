"""
patterns.py — Secret detection signature database.

Each entry: (name, regex, severity, group_index)
  group_index: which capture group holds the actual secret value (0 = whole match)

Design rules:
  - Specific branded formats (sk_live_, AIza, ghp_, etc) = high precision, no FP filter needed
  - Generic KEY="value" patterns = require quotes, run through entropy/FP filter
  - All patterns compiled once at import time
"""

import re

F = re.IGNORECASE

# ============================================================================
# TIER 1 — Branded, fixed-prefix tokens (near-zero false positive rate)
# ============================================================================

BRANDED_PATTERNS = {
    # ── Cloud providers ──────────────────────────────────────────────────────
    "AWS Access Key ID":        (re.compile(r'\b(AKIA|ABIA|ACCA|AROA|ASIA)[0-9A-Z]{16}\b'), "CRITICAL", 0),
    "AWS Secret Access Key":    (re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), "CRITICAL", 1),
    "AWS Session Token":        (re.compile(r'(?i)aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?'), "CRITICAL", 1),
    "AWS MWS Key":               (re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), "HIGH", 0),
    "Google API Key":           (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "CRITICAL", 0),
    "Google OAuth Access Token":(re.compile(r'ya29\.[0-9A-Za-z\-_]{20,}'), "CRITICAL", 0),
    "Google OAuth Client ID":   (re.compile(r'[0-9]{8,14}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "MEDIUM", 0),
    "Google Cloud Service Account": (re.compile(r'"type"\s*:\s*"service_account"'), "CRITICAL", 0),
    "Google Cloud Private Key": (re.compile(r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----'), "CRITICAL", 0),
    "Firebase Cloud Messaging Key": (re.compile(r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}'), "HIGH", 0),
    "Firebase Database URL":    (re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'), "LOW", 0),
    "Azure Storage Account Key":(re.compile(r'(?i)(?:DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=)([A-Za-z0-9+/=]{88})'), "CRITICAL", 1),
    "Azure SAS Token":           (re.compile(r'sv=\d{4}-\d{2}-\d{2}&[a-z]{2}=[a-zA-Z%]+&s[ek]=[A-Za-z0-9%]{20,}'), "HIGH", 0),
    "DigitalOcean Token":        (re.compile(r'\bdop_v1_[a-f0-9]{64}\b'), "CRITICAL", 0),
    "DigitalOcean OAuth Token":  (re.compile(r'\bdoo_v1_[a-f0-9]{64}\b'), "CRITICAL", 0),
    "Heroku API Key":            (re.compile(r'(?i)heroku[a-z0-9_\-]*\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?'), "HIGH", 0),
    "Alibaba AccessKey":         (re.compile(r'\bLTAI[A-Za-z0-9]{12,20}\b'), "CRITICAL", 0),
    "Tencent Cloud SecretId":    (re.compile(r'\bAKID[A-Za-z0-9]{32,36}\b'), "CRITICAL", 0),
    "IBM Cloud API Key":         (re.compile(r'(?i)ibm[_\-]?cloud[_\-]?api[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{44})["\']?'), "HIGH", 1),
    "Oracle Cloud Key":          (re.compile(r'(?i)ocid1\.[a-z]+\.oc\d\.\.[a-z0-9]{60,}'), "HIGH", 0),

    # ── Source control ───────────────────────────────────────────────────────
    "GitHub Personal Access Token (classic)": (re.compile(r'\bghp_[A-Za-z0-9]{36}\b'), "CRITICAL", 0),
    "GitHub Fine-Grained PAT":   (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b'), "CRITICAL", 0),
    "GitHub OAuth Token":        (re.compile(r'\bgho_[A-Za-z0-9]{36}\b'), "HIGH", 0),
    "GitHub App Token":          (re.compile(r'\b(ghu|ghs)_[A-Za-z0-9]{36}\b'), "HIGH", 0),
    "GitHub Refresh Token":      (re.compile(r'\bghr_[A-Za-z0-9]{76}\b'), "HIGH", 0),
    "GitLab Personal Access Token": (re.compile(r'\bglpat-[A-Za-z0-9_\-]{20}\b'), "CRITICAL", 0),
    "GitLab Pipeline Trigger Token": (re.compile(r'\bglptt-[A-Za-z0-9]{40}\b'), "HIGH", 0),
    "GitLab Runner Token":       (re.compile(r'\bGR1348941[A-Za-z0-9_\-]{20}\b'), "HIGH", 0),
    "Bitbucket App Password":    (re.compile(r'(?i)bitbucket[a-z_\-]*(?:password|token)\s*[=:]\s*["\']([A-Za-z0-9]{20,})["\']'), "HIGH", 1),
    "NPM Access Token":          (re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), "HIGH", 0),
    "PyPI API Token":            (re.compile(r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b'), "HIGH", 0),
    "Docker Hub PAT":            (re.compile(r'\bdckr_pat_[A-Za-z0-9_\-]{27}\b'), "HIGH", 0),

    # ── Payments ──────────────────────────────────────────────────────────────
    "Stripe Live Secret Key":    (re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b'), "CRITICAL", 0),
    "Stripe Test Secret Key":    (re.compile(r'\bsk_test_[0-9a-zA-Z]{24,}\b'), "MEDIUM", 0),
    "Stripe Restricted Key":     (re.compile(r'\brk_live_[0-9a-zA-Z]{24,}\b'), "HIGH", 0),
    "Stripe Live Publishable Key": (re.compile(r'\bpk_live_[0-9a-zA-Z]{24,}\b'), "HIGH", 0),
    "Stripe Webhook Secret":     (re.compile(r'\bwhsec_[A-Za-z0-9]{32,}\b'), "HIGH", 0),
    "PayPal Braintree Token":    (re.compile(r'\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b'), "CRITICAL", 0),
    "Square Access Token":       (re.compile(r'\bsq0atp-[A-Za-z0-9\-_]{22}\b'), "CRITICAL", 0),
    "Square OAuth Secret":       (re.compile(r'\bsq0csp-[A-Za-z0-9\-_]{43}\b'), "CRITICAL", 0),
    "Razorpay API Key":          (re.compile(r'\brzp_(live|test)_[A-Za-z0-9]{14}\b'), "HIGH", 0),
    "Plaid Secret Key":          (re.compile(r'(?i)plaid[_\-]?secret\s*[=:]\s*["\']([a-f0-9]{30})["\']'), "CRITICAL", 1),
    "Coinbase API Key":          (re.compile(r'(?i)coinbase[a-z_\-]*api[a-z_\-]*key\s*[=:]\s*["\']([A-Za-z0-9_\-]{32,})["\']'), "CRITICAL", 1),

    # ── Communications / messaging ───────────────────────────────────────────
    "Slack Bot Token":           (re.compile(r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b'), "HIGH", 0),
    "Slack User Token":          (re.compile(r'\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b'), "HIGH", 0),
    "Slack App-Level Token":     (re.compile(r'\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b'), "MEDIUM", 0),
    "Slack Webhook URL":         (re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}'), "MEDIUM", 0),
    "Slack Legacy Token":        (re.compile(r'\bxoxa-[0-9]+-[A-Za-z0-9]+\b'), "MEDIUM", 0),
    "Discord Bot Token":         (re.compile(r'\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b'), "HIGH", 0),
    "Discord Webhook":           (re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_\-]{60,}'), "MEDIUM", 0),
    "Twilio API Key":            (re.compile(r'\bSK[0-9a-f]{32}\b'), "HIGH", 0),
    "Twilio Account SID":        (re.compile(r'\bAC[0-9a-f]{32}\b'), "MEDIUM", 0),
    "Twilio Auth Token":         (re.compile(r'(?i)twilio[a-z_\-]*(?:auth)?[a-z_\-]*token\s*[=:]\s*["\']([0-9a-f]{32})["\']'), "CRITICAL", 1),
    "SendGrid API Key":          (re.compile(r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b'), "HIGH", 0),
    "Mailgun API Key":           (re.compile(r'\bkey-[0-9a-zA-Z]{32}\b'), "HIGH", 0),
    "Mailgun Domain Key":        (re.compile(r'\b[0-9a-zA-Z]{32}-[0-9a-zA-Z]{8}-[0-9a-zA-Z]{8}\b'), "MEDIUM", 0),
    "Mailchimp API Key":         (re.compile(r'\b[0-9a-f]{32}-us[0-9]{1,2}\b'), "HIGH", 0),
    "Postmark Server Token":     (re.compile(r'(?i)postmark[a-z_\-]*token\s*[=:]\s*["\']([a-f0-9\-]{36})["\']'), "HIGH", 1),
    "Vonage/Nexmo API Key":      (re.compile(r'(?i)nexmo[a-z_\-]*(?:api)?[a-z_\-]*key\s*[=:]\s*["\']([a-f0-9]{8})["\']'), "MEDIUM", 1),
    "Plivo Auth ID":             (re.compile(r'\bMA[A-Z0-9]{18}\b'), "MEDIUM", 0),

    # ── Maps / location ───────────────────────────────────────────────────────
    "Mapbox Access Token":       (re.compile(r'\bpk\.eyJ1Ijoi[A-Za-z0-9\-_\.]{20,}\b'), "MEDIUM", 0),
    "Mapbox Secret Token":       (re.compile(r'\bsk\.eyJ1Ijoi[A-Za-z0-9\-_\.]{20,}\b'), "HIGH", 0),

    # ── E-commerce ────────────────────────────────────────────────────────────
    "Shopify Access Token":      (re.compile(r'\bshpat_[a-f0-9]{32}\b'), "CRITICAL", 0),
    "Shopify Custom App Token":  (re.compile(r'\bshpca_[a-f0-9]{32}\b'), "CRITICAL", 0),
    "Shopify Private App Password": (re.compile(r'\bshppa_[a-f0-9]{32}\b'), "CRITICAL", 0),
    "Shopify Shared Secret":     (re.compile(r'\bshpss_[a-f0-9]{32}\b'), "CRITICAL", 0),

    # ── CMS / content ─────────────────────────────────────────────────────────
    "Contentful Token":
        (re.compile(r'(?i)contentful[_A-Za-z]*(?:access|preview|delivery|management|personal)?'
                    r'[_A-Za-z]*token\s*[:"\'=]\s*["\']([A-Za-z0-9\-_]{20,})["\']'), "HIGH", 1),
    "Sanity API Token":          (re.compile(r'\bsk[A-Za-z0-9]{40,}\b'), "MEDIUM", 0),
    "Prismic API Key":           (re.compile(r'(?i)prismic[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{30,})["\']'), "HIGH", 1),
    "WordPress.com API Key":     (re.compile(r'(?i)wpcom[_\-]?api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{32,})["\']'), "HIGH", 1),

    # ── Search / analytics ───────────────────────────────────────────────────
    "Algolia API Key":           (re.compile(r'(?i)algolia[_\-]?(?:api[_\-]?)?key\s*[=:]\s*["\']([A-Za-z0-9]{32})["\']'), "HIGH", 1),
    "Algolia Admin Key":         (re.compile(r'(?i)algolia[_\-]?admin[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{32})["\']'), "CRITICAL", 1),
    "Algolia App ID":            (re.compile(r'(?i)algolia[_\-]?app[_\-]?id\s*[=:]\s*["\']([A-Z0-9]{10})["\']'), "LOW", 1),
    "Segment Write Key":         (re.compile(r'(?i)segment[_\-]?(?:write)?[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{32})["\']'), "MEDIUM", 1),
    "Mixpanel API Secret":       (re.compile(r'(?i)mixpanel[_\-]?(?:api)?[_\-]?secret\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "HIGH", 1),
    "Amplitude API Key":         (re.compile(r'(?i)amplitude[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "MEDIUM", 1),
    "Elastic/Bonsai URL":        (re.compile(r'https://[a-z0-9]+:[A-Za-z0-9]+@[a-z0-9\-]+\.(?:bonsaisearch\.net|elastic-cloud\.com)'), "HIGH", 0),
    "New Relic License Key":     (re.compile(r'(?i)new[_\-]?relic[_\-]?(?:license)?[_\-]?key\s*[=:]\s*["\']([a-f0-9]{40})["\']'), "HIGH", 1),
    "New Relic API Key (NRAK)":  (re.compile(r'\bNRAK-[A-Z0-9]{27}\b'), "HIGH", 0),
    "Datadog API Key":           (re.compile(r'(?i)datadog[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "HIGH", 1),
    "Datadog App Key":           (re.compile(r'(?i)datadog[_\-]?app[_\-]?key\s*[=:]\s*["\']([a-f0-9]{40})["\']'), "HIGH", 1),
    "Sentry Auth Token":         (re.compile(r'\bsntrys_[A-Za-z0-9_]{50,}\b'), "HIGH", 0),
    "Sentry DSN":                (re.compile(r'https://[a-f0-9]{32}@[a-z0-9\.\-]+/[0-9]+'), "LOW", 0),
    "Bugsnag API Key":           (re.compile(r'(?i)bugsnag[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "MEDIUM", 1),
    "LaunchDarkly SDK Key":      (re.compile(r'\bsdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'), "HIGH", 0),
    "PostHog API Key":           (re.compile(r'\bphc_[A-Za-z0-9]{43}\b'), "MEDIUM", 0),

    # ── AI / LLM providers ───────────────────────────────────────────────────
    "OpenAI API Key":            (re.compile(r'\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b'), "CRITICAL", 0),
    "OpenAI Project Key":        (re.compile(r'\bsk-proj-[A-Za-z0-9_\-]{20,}\b'), "CRITICAL", 0),
    "Anthropic API Key":         (re.compile(r'\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{90,}\b'), "CRITICAL", 0),
    "Cohere API Key":            (re.compile(r'(?i)cohere[_\-]?api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{40})["\']'), "HIGH", 1),
    "HuggingFace Token":         (re.compile(r'\bhf_[A-Za-z0-9]{34,38}\b'), "HIGH", 0),
    "Replicate API Token":       (re.compile(r'\br8_[A-Za-z0-9]{37}\b'), "HIGH", 0),
    "Pinecone API Key":          (re.compile(r'(?i)pinecone[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9\-]{36})["\']'), "HIGH", 1),
    "ElevenLabs API Key":        (re.compile(r'(?i)elevenlabs[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "MEDIUM", 1),
    "Groq API Key":              (re.compile(r'\bgsk_[A-Za-z0-9]{52}\b'), "HIGH", 0),
    "Perplexity API Key":        (re.compile(r'\bpplx-[A-Za-z0-9]{48}\b'), "HIGH", 0),
    "Mistral API Key":           (re.compile(r'(?i)mistral[_\-]?api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{32})["\']'), "HIGH", 1),
    "Together AI API Key":       (re.compile(r'(?i)together[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{64})["\']'), "HIGH", 1),

    # ── Infra / hosting ───────────────────────────────────────────────────────
    "Vercel Token":              (re.compile(r'(?i)vercel[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9]{24})["\']'), "HIGH", 1),
    "Netlify Access Token":      (re.compile(r'(?i)netlify[_\-]?(?:access[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9_\-]{40,})["\']'), "HIGH", 1),
    "Cloudflare API Token":      (re.compile(r'(?i)cloudflare[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9_\-]{40})["\']'), "CRITICAL", 1),
    "Cloudflare Global API Key": (re.compile(r'(?i)cf[_\-]?global[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{37})["\']'), "CRITICAL", 1),
    "Fastly API Token":          (re.compile(r'(?i)fastly[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9_\-]{32})["\']'), "HIGH", 1),
    "Linode API Token":          (re.compile(r'(?i)linode[_\-]?token\s*[=:]\s*["\']([a-f0-9]{64})["\']'), "HIGH", 1),
    "Render API Key":            (re.compile(r'\brnd_[A-Za-z0-9]{20,}\b'), "HIGH", 0),
    "Railway API Token":         (re.compile(r'(?i)railway[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9\-]{36})["\']'), "HIGH", 1),
    "Supabase Anon/Service Key": (re.compile(r'\beyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b'), "HIGH", 0),
    "PlanetScale Password":      (re.compile(r'\bpscale_pw_[A-Za-z0-9_\-]{43}\b'), "CRITICAL", 0),
    "PlanetScale OAuth Token":   (re.compile(r'\bpscale_oauth_[A-Za-z0-9_\-]{43}\b'), "CRITICAL", 0),

    # ── Communications / video ───────────────────────────────────────────────
    "Zoom API Key":              (re.compile(r'(?i)zoom[_\-]?api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{22})["\']'), "MEDIUM", 1),
    "Agora App ID":              (re.compile(r'(?i)agora[_\-]?app[_\-]?id\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "MEDIUM", 1),
    "Daily.co API Key":          (re.compile(r'(?i)daily[_\-]?api[_\-]?key\s*[=:]\s*["\']([a-f0-9]{64})["\']'), "MEDIUM", 1),

    # ── Identity / auth ───────────────────────────────────────────────────────
    "Auth0 Client Secret":       (re.compile(r'(?i)auth0[_\-]?client[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{64})["\']'), "CRITICAL", 1),
    "Auth0 Management API Token":(re.compile(r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]*auth0[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\b', F), "CRITICAL", 0),
    "Okta API Token":            (re.compile(r'(?i)okta[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9_\-]{42})["\']'), "CRITICAL", 1),
    "Clerk Secret Key":          (re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{40,}\b'), "CRITICAL", 0),
    "WorkOS API Key":            (re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{32,}\b'), "HIGH", 0),
    "Firebase Auth Custom Token":(re.compile(r'(?i)firebase[_\-]?custom[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{100,})["\']'), "HIGH", 1),

    # ── Misc dev tools ────────────────────────────────────────────────────────
    "CircleCI Token":            (re.compile(r'(?i)circleci[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([a-f0-9]{40})["\']'), "HIGH", 1),
    "Travis CI Token":           (re.compile(r'(?i)travis[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9]{22})["\']'), "MEDIUM", 1),
    "Jenkins API Token":         (re.compile(r'(?i)jenkins[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([a-f0-9]{32})["\']'), "HIGH", 1),
    "Terraform Cloud Token":     (re.compile(r'\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b'), "CRITICAL", 0),
    "Atlassian/Jira API Token":  (re.compile(r'(?i)(?:jira|atlassian)[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9]{24})["\']'), "HIGH", 1),
    "Asana Personal Access Token": (re.compile(r'\b\d{16,17}:[a-f0-9]{32}\b'), "HIGH", 0),
    "Trello API Key + Token":    (re.compile(r'(?i)trello[_\-]?token\s*[=:]\s*["\']([a-f0-9]{64})["\']'), "MEDIUM", 1),
    "Notion API Token":          (re.compile(r'\bsecret_[A-Za-z0-9]{43}\b'), "HIGH", 0),
    "Airtable API Key":          (re.compile(r'\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b'), "HIGH", 0),
    "Figma Personal Access Token": (re.compile(r'\bfigd_[A-Za-z0-9_\-]{40,}\b'), "MEDIUM", 0),
    "Intercom Access Token":     (re.compile(r'(?i)intercom[_\-]?(?:access[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9_\-=]{50,})["\']'), "HIGH", 1),
    "Zendesk API Token":         (re.compile(r'(?i)zendesk[_\-]?(?:api[_\-]?)?token\s*[=:]\s*["\']([A-Za-z0-9]{40})["\']'), "HIGH", 1),
    "Freshdesk API Key":         (re.compile(r'(?i)freshdesk[_\-]?api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9]{20})["\']'), "MEDIUM", 1),

    # ── Private keys / certs ──────────────────────────────────────────────────
    "RSA Private Key":           (re.compile(r'-----BEGIN RSA PRIVATE KEY-----'), "CRITICAL", 0),
    "EC Private Key":            (re.compile(r'-----BEGIN EC PRIVATE KEY-----'), "CRITICAL", 0),
    "DSA Private Key":           (re.compile(r'-----BEGIN DSA PRIVATE KEY-----'), "CRITICAL", 0),
    "PGP Private Key Block":     (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "CRITICAL", 0),
    "OpenSSH Private Key":       (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "CRITICAL", 0),
    "Generic Private Key":       (re.compile(r'-----BEGIN PRIVATE KEY-----'), "CRITICAL", 0),
    "PuTTY Private Key":         (re.compile(r'PuTTY-User-Key-File-\d'), "CRITICAL", 0),

    # ── Tokens / generic structured formats ──────────────────────────────────
    "JWT (JSON Web Token)":      (re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'), "MEDIUM", 0),
    "Basic Auth in URL":         (re.compile(r'[a-zA-Z][a-zA-Z0-9+.\-]*://[A-Za-z0-9_\-\.]+:[^@\s/]{4,}@[A-Za-z0-9_\-\.]+'), "HIGH", 0),
    "Bearer Token":              (re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}'), "MEDIUM", 0),

    # ── Database connection strings ──────────────────────────────────────────
    "PostgreSQL Connection String": (re.compile(r'postgres(?:ql)?://[^:\s]+:[^@\s]{4,}@[^/\s]+'), "CRITICAL", 0),
    "MySQL Connection String":   (re.compile(r'mysql://[^:\s]+:[^@\s]{4,}@[^/\s]+'), "CRITICAL", 0),
    "MongoDB Connection String": (re.compile(r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]{4,}@[^/\s]+'), "CRITICAL", 0),
    "Redis Connection String":   (re.compile(r'redis://[^:\s]*:[^@\s]{4,}@[^/\s]+'), "CRITICAL", 0),
    "RabbitMQ/AMQP Connection String": (re.compile(r'amqps?://[^:\s]+:[^@\s]{4,}@[^/\s]+'), "HIGH", 0),
    "JDBC Connection String w/ creds": (re.compile(r'jdbc:[a-z]+://[^?]+\?[^&]*(?:user|password)=[^&\s]+'), "HIGH", 0),
}


# ============================================================================
# TIER 2 — Generic KEY="value" structural patterns (require quotes + entropy filter)
# ============================================================================

_SENSITIVE_SUFFIX = (
    "ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|CLIENT_ID|API_KEY|API_SECRET|"
    "APP_KEY|APP_SECRET|APP_ID|AUTH_TOKEN|AUTH_KEY|PRIVATE_KEY|SECRET_KEY|"
    "SECRET_ACCESS_KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|SITE_KEY|SESSION_TOKEN|"
    "TOKEN|KEY|SID|AUTH|ACCESS|PASS|PWD|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY|"
    "PRIVATE_TOKEN|WEBHOOK_SECRET"
)

GENERIC_PATTERNS = {
    # UPPER_SNAKE_CASE object key — value MUST be quoted (prevents JS var-ref FPs)
    "Generic Secret (UPPER_SNAKE key)":
        (re.compile(
            r'(?<![A-Za-z0-9_])'
            r'([A-Z][A-Z0-9_]{2,}(?:' + _SENSITIVE_SUFFIX + r'))'
            r'[A-Z0-9_]*'
            r'\s*:\s*'
            r'"([A-Za-z0-9\-_/+=.@!#]{16,})"',
            re.IGNORECASE,
        ), "MEDIUM", 2),

    # camelCase/snake_case assignment — value MUST be quoted
    "Generic Secret (assignment)":
        (re.compile(
            r'(?<![A-Za-z0-9_])'
            r'([A-Za-z_][A-Za-z0-9_]*'
            r'(?:token|key|secret|password|passwd|credential|auth|api_?key|'
            r'access_?token|client_?(?:id|secret)|private_?key|app_?(?:key|id|secret)|'
            r'signing_?key|encryption_?key|master_?key)'
            r'[A-Za-z0-9_]*)'
            r'\s*[=:]\s*'
            r'"([A-Za-z0-9\-_/+=.@!#]{16,})"',
            re.IGNORECASE,
        ), "MEDIUM", 2),

    # YAML/ENV style:  API_KEY=value  (no quotes, .env file format)
    "Generic Secret (env-file style)":
        (re.compile(
            r'(?m)^([A-Z][A-Z0-9_]{2,}(?:' + _SENSITIVE_SUFFIX + r')[A-Z0-9_]*)'
            r'\s*=\s*'
            r'["\']?([A-Za-z0-9\-_/+=.@!#]{12,})["\']?\s*$',
            re.IGNORECASE,
        ), "MEDIUM", 2),

    # High-entropy hex string assigned to a sensitive-sounding variable, length 32/40/64 (common hash/key lengths)
    "Generic High-Entropy Hex Secret":
        (re.compile(
            r'(?<![A-Za-z0-9_])'
            r'([A-Za-z_][A-Za-z0-9_]*(?:key|token|secret|hash|signature)[A-Za-z0-9_]*)'
            r'\s*[=:]\s*'
            r'"([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})"',
            re.IGNORECASE,
        ), "LOW", 2),
}


# Severity ranking for sort order
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

ALL_PATTERNS = {**BRANDED_PATTERNS, **GENERIC_PATTERNS}

GENERIC_PATTERN_NAMES = set(GENERIC_PATTERNS.keys())

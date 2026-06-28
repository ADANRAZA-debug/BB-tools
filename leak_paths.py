"""
leak_paths.py — Comprehensive list of paths where secrets commonly leak.
Organized by category for clarity and easy extension.
"""

# ── JS bundle paths (common build output locations) ─────────────────────────
JS_PATHS = [
    "main.js", "app.js", "bundle.js", "index.js", "index.bundle.js",
    "static/js/main.js", "static/js/app.js", "static/js/bundle.js",
    "static/js/chunk.js", "static/js/vendor.js", "static/js/runtime.js",
    "assets/js/app.js", "assets/app.js", "assets/main.js", "assets/index.js",
    "js/app.js", "js/main.js", "js/bundle.js", "js/vendor.js",
    "dist/main.js", "dist/bundle.js", "dist/app.js", "dist/index.js",
    "dist/assets/index.js", "dist/js/main.js",
    "build/static/js/main.js", "build/static/js/bundle.js",
    "build/static/js/runtime-main.js",
    "_next/static/chunks/main.js", "_next/static/chunks/webpack.js",
    "_next/static/chunks/pages/_app.js", "_next/static/chunks/framework.js",
    "_nuxt/app.js", "_nuxt/runtime.js", "_nuxt/commons.app.js",
    "webpack.js", "vendor.js", "runtime.js", "polyfills.js", "common.js",
    "public/js/app.js", "public/build/bundle.js", "public/assets/app.js",
    "wp-content/themes/active/assets/js/main.js",
    "wp-content/plugins/main/assets/js/app.js",
    "static/chunks/main.js",
]

# ── Source map paths (often reveal full unminified source with secrets) ─────
SOURCEMAP_PATHS_SUFFIX = [".map"]  # appended to discovered JS file URLs

# ── Config / env files ────────────────────────────────────────────────────────
CONFIG_PATHS = [
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.test", ".env.example", ".env.sample", ".env.backup", ".env.bak", ".env.old",
    "config.json", "config.yaml", "config.yml", "config.js", "config.ts",
    "app.config.js", "app.config.json", "app.config.ts",
    "settings.json", "settings.py", "settings.js", "local_settings.py",
    "secrets.json", "secrets.yaml", "secrets.yml", "credentials.json",
    "firebase.json", ".firebaserc",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.save", "wp-config.php~",
    "database.yml", "database.json", "database.php",
    "application.yml", "application.properties", "application-prod.yml",
    ".aws/credentials", "aws.json", "aws-exports.js",
    "next.config.js", "nuxt.config.js", "vite.config.js", "vite.config.ts",
    "webpack.config.js", "gatsby-config.js", "svelte.config.js",
    ".npmrc", ".yarnrc", ".pypirc",
    "docker-compose.yml", "docker-compose.yaml", "docker-compose.override.yml",
    "Dockerfile",
    "serverless.yml", "serverless.yaml",
    "appsettings.json", "appsettings.Development.json", "appsettings.Production.json",
    "web.config",
    "manifest.json", "package.json",
    "terraform.tfvars", "terraform.tfstate",
    "kubeconfig", ".kube/config",
    "id_rsa", "id_rsa.pub", "id_dsa", ".ssh/id_rsa", ".ssh/config",
]

# ── Backup / leftover files (developers forget these) ───────────────────────
BACKUP_PATHS = [
    "backup.zip", "backup.sql", "backup.tar.gz", "site-backup.zip",
    "db_backup.sql", "database_backup.sql", "dump.sql", "old.zip",
    "www.zip", "website.zip", "site.tar.gz",
    "config.json.bak", "config.bak", ".env.save", ".env~",
    "index.php.bak", "index.html.bak",
]

# ── Git / VCS exposure ─────────────────────────────────────────────────────
GIT_PATHS = [
    ".git/config",
    ".git/HEAD",
    ".git/COMMIT_EDITMSG",
    ".git/logs/HEAD",
    ".git/index",
    ".gitignore",
    ".svn/entries",
    ".hg/hgrc",
]

# ── CI/CD config (often has hardcoded secrets) ───────────────────────────────
CICD_PATHS = [
    ".github/workflows/main.yml", ".github/workflows/deploy.yml",
    ".github/workflows/ci.yml", ".gitlab-ci.yml",
    ".circleci/config.yml", "Jenkinsfile", ".travis.yml",
    "azure-pipelines.yml", "bitbucket-pipelines.yml",
    "buildspec.yml", "cloudbuild.yaml",
]

# ── API / debug / admin endpoints (config disclosure) ────────────────────────
DEBUG_PATHS = [
    "api/config", "api/env", "api/debug", "api/health",
    "actuator/env", "actuator/configprops", "actuator/health",
    "_debug", "debug.php", "phpinfo.php", "info.php", "test.php",
    ".well-known/security.txt",
    "graphql", "graphiql",
    "swagger.json", "swagger.yaml", "openapi.json", "api-docs",
    "__debug__", "console",
]

# ── Mobile app config (sometimes exposed via web mirror) ─────────────────────
MOBILE_PATHS = [
    "google-services.json",
    "GoogleService-Info.plist",
    "Info.plist",
]

ALL_LEAK_PATHS = (
    CONFIG_PATHS + BACKUP_PATHS + GIT_PATHS + CICD_PATHS +
    DEBUG_PATHS + MOBILE_PATHS
)

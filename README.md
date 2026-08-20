# Personal Access Tokens for the Redmine REST API

Solution for the TaxDome technical challenge, based on the real Redmine ticket
[#43881](https://www.redmine.org/issues/43881). Branched off tag `6.1.2`;
the MR targets the `base-6.1.2` branch of this fork.

## The problem

A Redmine API key is a single `Token` row per user
(`add_action :api, max_instances: 1, validity_time: nil` in `app/models/token.rb`):
it never expires, is stored in **plaintext**, can be re-displayed at any time,
grants the user's full permission set, and bypasses 2FA. Creating a new key
silently invalidates the old one, so key rotation breaks every other integration.

## What's done

**Personal access tokens (required core)**
- Multiple named tokens per user, each with a mandatory expiration date.
- **Hashed storage**: only `SHA256(value)` is persisted (`token_digest`,
  unique-indexed). This follows the codebase's own precedent — Doorkeeper is
  configured with `hash_token_secrets` (SHA256) in
  `config/initializers/30-redmine.rb`.
- Values are `rmpat_` + 40 hex chars and are displayed **exactly once**, at
  creation. Throttled `last_used_on` tracking.
- **Admin max-lifetime policy**: setting `personal_access_token_max_lifetime`
  (days, 0 = no limit) on Administration → Settings → API, validated at creation.
- Self-service UI at `/my/personal_access_tokens` (list / create / revoke),
  reachable from the account page sidebar and contextual links; sudo-protected
  like the other credential pages.
- **Backward compatible**: the auth chain in
  `ApplicationController#find_current_user` tries a PAT digest lookup first and
  falls back to the unchanged legacy `User.find_by_api_key`. All three
  transports work (`X-Redmine-API-Key` header, `?key=` param, HTTP Basic
  username). Legacy keys keep working untouched — the same indefinite
  coexistence Redmine chose when it added OAuth2 in 6.1.0.

**Scoped permissions (optional pillar)**
- A token can be restricted to selected permissions (space-separated names,
  like OAuth scopes; blank = full access). Enforcement **reuses the existing
  OAuth scope machinery**: the token's scopes are assigned to
  `User#oauth_scope`, so `Role#allowed_to?` intersection and the `:admin`
  pseudo-scope in `User#admin?` apply with zero new permission code. Public
  permissions are force-included, mirroring OAuth applications.

**Structured audit logging (optional pillar)**
- Setting `api_audit_logging_enabled` (default off). When on, every request
  authenticated with an API credential writes one JSON line to
  `log/api_audit.log`: timestamp, user, credential id (`pat:<id>` /
  `api_key` / `oauth:<id>`), HTTP method, path, remote IP, response status.
- Implemented with `prepend_around_action` — a plain `after_action` is skipped
  when a `before_action` halts the chain, which would have missed exactly the
  denied (401/403) requests an audit trail exists for.
- The query string is never logged, since it can carry a plaintext `?key=`.

## Deferred, and why

- **Rate limiting** — explicitly out of scope (being handled upstream via
  Rails' native `rate_limit`, see the ticket discussion).
- **Granular endpoint control** — an admin on/off matrix over the 24
  `accept_api_auth` controllers; too broad for this slice, and scopes already
  give per-operation restriction.
- **CORS** — needs the `rack-cors` dependency; a Gemfile addition is a poor
  fit for a focused MR.
- **Legacy key deprecation/backfill** — this MR is deliberately additive.
  The conversion method `PersonalAccessToken.import_legacy_api_tokens!` ships
  fully unit-tested (legacy plaintext values are hashable server-side, so keys
  keep working after conversion), but invoking it belongs to a future removal
  release as a `db/migrate` data migration — matching how Redmine ships
  mandatory credential transforms (`20110223180953_salt_user_passwords.rb`)
  and retires features (deprecate at one major, remove at the next, with a
  closing data migration).

## Assumptions and limits

- Like the legacy API key and OAuth tokens, a PAT acts as its own second
  factor: 2FA is not re-checked on API requests. Fixing that wholesale is out
  of this slice; PAT expiry + revocability + scopes narrow the exposure.
- Deterministic SHA256 without per-token salt is intentional: values are
  40-hex-char random secrets (160 bits of entropy), so rainbow/brute-force
  attacks on the digest are infeasible, and a deterministic digest allows the
  unique-index lookup. Same trade-off Doorkeeper makes.
- Scopes are permission-name scopes (plus `admin`), not per-project
  restrictions.
- The one-time value travels one redirect through the Rails session flash
  (and is removed from it before the generic flash rendering).

## How to run

```bash
git clone <fork> && cd redmine && git checkout feature/personal-access-tokens
bundle install
# config/database.yml — SQLite is enough for a dev run:
#   development: {adapter: sqlite3, database: db/redmine_development.sqlite3}
#   test:        {adapter: sqlite3, database: db/redmine_test.sqlite3}
bundle exec rake generate_secret_token db:migrate
REDMINE_LANG=en bundle exec rake redmine:load_default_data
bundle exec rails server
```

Log in as `admin`/`admin`, enable the REST API
(Administration → Settings → API), then go to
**My account → Personal access tokens**.

## How to verify

```bash
# The feature's test suites (unit, functional, API integration, audit):
bundle exec rails test \
  test/unit/personal_access_token_test.rb \
  test/functional/personal_access_tokens_controller_test.rb \
  test/integration/api_test/personal_access_token_test.rb \
  test/integration/api_test/api_audit_test.rb

# Legacy regression:
bundle exec rails test test/integration/api_test/authentication_test.rb \
  test/unit/token_test.rb test/functional/my_controller_test.rb
```

Manual check: create a token in the UI, then

```bash
curl -H "X-Redmine-API-Key: rmpat_..." http://localhost:3000/users/current.json   # 200
# expired/revoked token or forged value                                            -> 401
# admin's token scoped to view_issues on /users.json                               -> 403
```

## AI workflow

Built with Claude Code (Claude Fable 5) in an interactive TDD loop: codebase
archaeology with parallel research subagents (auth-flow trace, house-conventions
survey, migration/deprecation precedent research through git history), a design
doc, a UI mock, then red-green commits per slice. The unedited conversation
logs and a screen recording are delivered separately alongside this repository.

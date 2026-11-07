# SPEC — Challenge attendee to FreeWire membership bridge (advisory)

**Prepared:** 2026-11-06. **Status:** cross-repository planning handoff. **No PHP, live membership settings, webhook routes or auth policies changed.** Authoritative owner architecture authority remains with Verious Smith III.

**Origin:** `Startempire-Wire/the-entrepreneurs-path` → `website/challenge/SPEC-MMA-LIVE-OTP-FREEWIRE-2026-11-06.md` and `make-more-assets-event.v1.json`. This repository's task is narrow: preserve parent-account membership authority and authenticate any future approved Challenge-to-FreeWire transition. It does NOT own book-site event signup, video player, OTP session or external email marketing.

## Current code facts verified on master

- `includes/class-auth.php` validates a token against the parent WordPress `/wp/v2/users/me`, uses parent MemberPress API for tier, and issues JWT for existing Network clients. A JWT tier snapshot is not live membership proof.
- `includes/class-config.php` maps the parent MemberPress product **17268** to `freewire`, and `freewire` to tier level 1; other Wire and ExtraWire IDs/tier levels are distinct and **not** benefits conveyed by Challenge registration.
- `POST /wp-json/sewn/v1/auth/membership/current` is a server-only, dedicated credential-protected current-membership verification route; README states it re-reads parent MemberPress and returns 503 on unknown/failure. Do not expose to anonymous book-site browsers, trust stale JWT tier, or treat parent HTTP 503 as `free`.
- `includes/class-webhooks.php` presently processes MemberPress member-created/transaction events and can provision a W.I.N.S. scoreboard for FreeWire+ tier. **This may be an existing enrollment side effect**; inventory actual installed plugin and decide whether this is appropriate and disclosed before directing Challenge participants to register.
- README says plugin installed on `startempirewire.network`, parent MemberPress on `startempirewire.com`. **Public `/plans/` shows FreeWire as $0 with public profile and directory functionality, but the exact active register URL and profile/publicity semantics have not been authenticated in production.**

## Desired future integration: no shadow user table

**Scenario 1 — Book-site Challenge registrant who declines community:** remains Challenge attendee only; no call to parent account, no public profile, no MemberPress account and no Ring Leader JWT created. The Challenge website grants its own event-bound access after email OTP.

**Scenario 2 — Explicitly opt into a free community profile:** show separate, clearly worded consent and redirect to the real verified FreeWire signup at `startempirewire.com`, or use a new signed short-lived back-channel handoff **only after** evaluating parental WP account flows. Parent alone creates/verifies member. Book site receives verified status through authenticated identity federation, not merely matching an email address. The sign-up must not create a paid membership, automatically post user's asset goal, or expose their attendance.

**Scenario 3 — Already has FreeWire:** secure parent sign-in/SSO connects existing account to Challenge registrant by verified principal; avoid duplicate users and mistaken email-only joins. Challenge registration is still separate from network identity; a free member might be ineligible for a limited live session if not registered for it.

**Scenario 4 — Actual member status changes:** provider verification is authoritative; a JWT minted yesterday is not proof of a current entitlement today. Do not revoke Challenge-only event registration merely because a member's network plan changes, unless the final event policy explicitly says so.

## Proposed source-qualified identity contract

```json
{
  "schema": "sewn.challenge.member-link.v1",
  "source_event_ref": "mma:<cohort_id>:<session_id>",
  "challenge_registration_ref": "private_challenge_service_id",
  "parent_user_id": "memberpress_verified_id_or_null",
  "requested_profile": true,
  "account_created_by": "startempirewire.com-parent-only",
  "membership_observation": "verified|unknown|not_requested",
  "current_membership_tier": "freewire|wire|extrawire|other|unknown",
  "observed_at": "server_generated",
  "profile_visibility": "opt_in_separately",
  "consent_ref": "versioned_user_explicit_action",
  "correlation_id": "opaque_idempotent_ref"
}
```

This is a **proposal**, not an endpoint currently implemented by Ring Leader.

### Cross-domain security requirements

1. **No email-only account matching.** A challenge address existing in MemberPress is not proof the registrant controls or owns that profile. Use authenticated parent account grant, OAuth/OIDC or properly signed one-time code challenge bound to exact principal, audience, expiry and state/nonce. HTTPS only; secure cookies, CSRF and replay defense.
2. **No bearer secrets in public URL, JavaScript bundle, public analytics or Git**. A code exchanged back-channel with strict issuer/audience/short TTL is not a persistent JWT.
3. Ring Leader only receives minimum `user_id`, consent/version and correlation ID; no raw challenge worksheet, private asset goal or attendee list.
4. Profile fields (name/bio/avatar/business goals) **private by default** until separately approved by user; a FreeWire registration and a directory listing are distinct user choices even if the current parent theme defaults to public.
5. Rate-limit and idempotently process completion callbacks; deduplicate people by authenticated principal. Unknown parent membership service response is **unknown**, never promote to free via fail-open.
6. Audit existing FreeWire signup's **W.I.N.S. scoreboard provisioning** side effects and whether parent product 17268 remains correct in deployed configuration; do not edit tier maps from this spec alone.
7. Provide a membership unlink/delete/revocation and consent/suppression path; no book-site ownership over real MemberPress records.

## MemberPress FreeWire enrollment and profile UX

- The visitor sees a distinct, unchecked choice **Create a free Startempire Wire profile** *after* Challenge interest form or during actual event onboarding.
- Need actual current parent registration route from live WordPress, real user/profile settings, terms/privacy and product effective price. The product ID in source isn't proof its signup page works today.
- Parent site may offer FreeWire public founder/talent profile and network directory per `https://startempirewire.com/plans/`. Verify if profile publication is default; if it is, explicitly tell user and offer a private/no-directory option if feasible before promising private-by-default onboarding.
- On actual confirmed registration, independent page `/challenge/live/` access still checks the event registration and email OTP/session rather than blindly accepting FreeWire JWT.

## Responsibility and tests

**Own in parent**: registration/profile/MemberPress user lifecycle, privacy status, current actual tier, source external registration URL.  
**Own in Ring Leader**: provider-authorized membership verification, source-qualified response and optional verified profile bridge once implemented.  
**Own in book site**: challenge interest + event registration + email OTP session + live room; no member tier truth.  
**Own in Wirebot**: optional consent-respecting reminders/follow-through, never the user database or arbitrary membership creation.

Before implementation capture a *read-only* live installed WP/Ring Leader audit. Then stage: nonmember -> interest only, optional FreeWire join -> verified profile, existing member -> signed link, expired/revoked membership -> unknown/valid fallback, parent unavailable -> no new member claim, duplicate requests -> one account, private profile and unsubscribe respected. Do not make a test registration against real users or replay live webhook payments.

**Required owner decisions:** Whether Challenge signup prompts optional FreeWire immediately or after session #1, which exact profile fields may become public, whether FreeWire registration should create a W.I.N.S. scoreboard automatically, and whether the pilot can accept soft-gated YouTube viewing. No new member or plan authority is approved simply by merging this design document.

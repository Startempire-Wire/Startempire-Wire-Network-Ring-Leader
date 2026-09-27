# Startempire Wire Network Ring Leader WordPress Plugin
- Singularly Unique Plugin that acts as the messenger of The Parent Membership Website of The Network [ https://startempirewire.com ]
- Installed on the Startempire Wire Network Website [ https://startempirewire.network ]
- Handles Authentication & data between:  
--- Startempire Wire Website [https://startempirewire.com], 
--- Startempire Wire Network [https://startempirewire.network],
--- Startempire Network Connect Connect Plugin (Plugin #2) [ Located on Multiple Network Members Sites ], 
--- The Startempire Network Chrome Extension
- Holds Custom Content Types Associated With Each Network Member
- Records Statistics of Network & Offers Easy ways to Display Data on the Frontend & Dashboard
- Administers A Central List of Businesses In The Network
-- Keeps Control of Moderation
-- Sends Notification Emails of Member Status
-- Accepts New Member Registrations
- Creates API Endpoints For Data To Connect to Startempire Network Connect Plugin

## Current membership proof (source contract)

`POST /wp-json/sewn/v1/auth/membership/current` accepts a positive `user_id` from the authenticated Scoreboard service only (`Authorization: Bearer` with Ring Leader's dedicated `sewn_rl_membership_service_token`). An absent or wrong service token returns 403 without contacting MemberPress. Ring Leader re-reads `/mp/v1/members/{id}` without its parent-token transient; a valid 200 response with an exact owner and an explicit empty `active_memberships` list is verified free, while provider failure, mismatched identity, malformed data, cached responses and redirects are unknown (503). Successful responses carry `sewn.membership_current.v1`, current product IDs, the provider-derived tier, an observation timestamp and `Cache-Control: private, no-store`. The score, JWT tier and signed `membership_ids` are never current provider proof. An absent or mismatched dedicated broker token fails closed; no endpoint is active until the plugin is installed and configured on the owning Network site.

Validate source in the pinned, network-isolated OVH PHP 8.3 CLI test container by running `php -l` on the changed PHP files followed by `php tests/current-membership-bridge.php`. Synthetic tests are not installed provider or customer acceptance.

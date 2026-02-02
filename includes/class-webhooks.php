<?php
namespace SEWN\RingLeader;

defined('ABSPATH') || exit;

/**
 * Webhook handler for incoming events.
 *
 * Listens for:
 * - MemberPress subscription events (from parent site)
 * - Scoreboard provisioning callbacks
 *
 * Per bigpicture.mdx, Ring Leader:
 * - Accepts new member registrations
 * - Sends notification emails of member status
 * - Moderates new member registrations
 */
class Webhooks {

    private Config $config;
    private ParentBridge $parent;

    public function __construct(Config $config, ParentBridge $parent) {
        $this->config = $config;
        $this->parent = $parent;
    }

    public function register_routes(): void {
        if (!$this->config->webhooks_enabled()) return;

        // MemberPress webhook: member created/updated/deleted
        register_rest_route('sewn/v1', '/webhooks/memberpress', [
            'methods'  => 'POST',
            'callback' => [$this, 'handle_memberpress'],
            'permission_callback' => [$this, 'verify_webhook_signature'],
        ]);

        // Generic event webhook (for Wirebot, scoreboard, etc.)
        register_rest_route('sewn/v1', '/webhooks/event', [
            'methods'  => 'POST',
            'callback' => [$this, 'handle_event'],
            'permission_callback' => [$this, 'verify_webhook_signature'],
        ]);
    }

    /**
     * Handle MemberPress subscription events.
     * Triggers scoreboard provisioning for FreeWire+ members.
     */
    public function handle_memberpress(\WP_REST_Request $request): \WP_REST_Response {
        $body = $request->get_json_params();
        $event = $body['event'] ?? $body['action'] ?? 'unknown';
        $data  = $body['data'] ?? $body;

        $this->log("MemberPress webhook: $event", $data);

        switch ($event) {
            case 'member-added':
            case 'subscription-created':
            case 'transaction-completed':
                return $this->on_member_activated($data);

            case 'member-deleted':
            case 'subscription-expired':
            case 'subscription-paused':
                return $this->on_member_deactivated($data);

            default:
                return new \WP_REST_Response([
                    'received' => true,
                    'event'    => $event,
                    'action'   => 'ignored',
                ]);
        }
    }

    /**
     * Handle generic events (from Wirebot, scoreboard, other ecosystem components).
     */
    public function handle_event(\WP_REST_Request $request): \WP_REST_Response {
        $body = $request->get_json_params();
        $type = $body['type'] ?? 'unknown';

        $this->log("Event webhook: $type", $body);

        // Flush content cache on content-related events
        if (in_array($type, ['post_published', 'event_created', 'directory_updated'])) {
            $this->parent->flush_cache();
        }

        return new \WP_REST_Response([
            'received' => true,
            'type'     => $type,
        ]);
    }

    /**
     * Verify webhook signature (shared secret).
     */
    public function verify_webhook_signature(\WP_REST_Request $request): bool {
        // Check for webhook secret in header
        $sig = $request->get_header('x-sewn-webhook-secret');
        if ($sig && hash_equals($this->config->jwt_secret(), $sig)) {
            return true;
        }

        // Also accept MemberPress-style webhook (IP allowlist or API key)
        $api_key = $request->get_header('memberpress-api-key');
        if ($api_key && hash_equals($this->config->parent_api_key(), $api_key)) {
            return true;
        }

        // For development: allow from localhost
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (in_array($ip, ['127.0.0.1', '::1'])) {
            return true;
        }

        return false;
    }

    // ==================== EVENT HANDLERS ====================

    /**
     * Member activated — provision scoreboard if FreeWire+.
     */
    private function on_member_activated(array $data): \WP_REST_Response {
        $user_id = (int) ($data['user_id'] ?? $data['member']['id'] ?? 0);
        $membership_id = (int) ($data['membership_id'] ?? $data['membership']['id'] ?? 0);

        if (!$user_id) {
            return new \WP_REST_Response(['error' => 'No user_id'], 400);
        }

        $tier_map = $this->config->tier_map();
        $tier = $tier_map[$membership_id] ?? 'free';
        $tier_level = $this->config->tier_level($tier);

        $result = [
            'user_id'       => $user_id,
            'membership_id' => $membership_id,
            'tier'          => $tier,
            'actions'       => [],
        ];

        // Provision scoreboard for FreeWire+ (tier_level >= 1)
        if ($tier_level >= 1) {
            $scoreboard = $this->provision_scoreboard($user_id, $tier);
            $result['actions'][] = 'scoreboard_provisioned';
            $result['scoreboard'] = $scoreboard;
        }

        // Flush cache to pick up new member
        $this->parent->flush_cache();
        $result['actions'][] = 'cache_flushed';

        return new \WP_REST_Response($result);
    }

    /**
     * Member deactivated — mark scoreboard as inactive (don't delete).
     */
    private function on_member_deactivated(array $data): \WP_REST_Response {
        $user_id = (int) ($data['user_id'] ?? $data['member']['id'] ?? 0);

        if ($user_id) {
            // Don't delete — just flag as inactive
            update_user_meta($user_id, 'sewn_scoreboard_active', false);
        }

        $this->parent->flush_cache();

        return new \WP_REST_Response([
            'user_id' => $user_id,
            'actions' => ['scoreboard_deactivated', 'cache_flushed'],
        ]);
    }

    // ==================== SCOREBOARD PROVISIONING ====================

    /**
     * Provision a scoreboard for a member.
     * Creates a unique randID and calls the scoreboard API.
     */
    private function provision_scoreboard(int $user_id, string $tier): array {
        // Check if already provisioned
        $existing = get_user_meta($user_id, 'sewn_scoreboard_id', true);
        if ($existing) {
            // Re-activate
            update_user_meta($user_id, 'sewn_scoreboard_active', true);
            return [
                'id'  => $existing,
                'url' => $this->config->scoreboard_url() . '/' . $existing,
                'new' => false,
            ];
        }

        // Generate unique randID (URL-safe, 12 chars)
        $rand_id = $this->generate_rand_id();

        // Store in user meta on parent site (via API) and locally
        update_user_meta($user_id, 'sewn_scoreboard_id', $rand_id);
        update_user_meta($user_id, 'sewn_scoreboard_active', true);
        update_user_meta($user_id, 'sewn_scoreboard_tier', $tier);
        update_user_meta($user_id, 'sewn_scoreboard_created', gmdate('c'));

        // Call scoreboard API to create tenant (use internal URL for same-VPS calls)
        $scoreboard_response = wp_remote_post(
            $this->config->scoreboard_internal_url() . '/v1/tenants',
            [
                'headers' => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $this->config->scoreboard_token(),
                ],
                'body' => wp_json_encode([
                    'tenant_id'   => $rand_id,
                    'user_id'     => $user_id,
                    'tier'        => $tier,
                    'created_at'  => gmdate('c'),
                ]),
                'timeout' => 10,
            ]
        );

        $scoreboard_ok = !is_wp_error($scoreboard_response)
            && wp_remote_retrieve_response_code($scoreboard_response) < 300;

        $this->log("Scoreboard provisioned: $rand_id for user $user_id (tier: $tier, api_ok: " . ($scoreboard_ok ? 'yes' : 'no') . ")");

        return [
            'id'         => $rand_id,
            'url'        => $this->config->scoreboard_url() . '/' . $rand_id,
            'new'        => true,
            'api_synced' => $scoreboard_ok,
        ];
    }

    /**
     * Generate a URL-safe random ID for scoreboard URLs.
     */
    private function generate_rand_id(): string {
        return substr(str_replace(['+', '/', '='], '', base64_encode(random_bytes(9))), 0, 12);
    }

    // ==================== LOGGING ====================

    private function log(string $message, $context = null): void {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $entry = '[Ring Leader] ' . $message;
            if ($context !== null) {
                $entry .= ' | ' . wp_json_encode($context);
            }
            error_log($entry);
        }
    }
}

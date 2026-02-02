<?php
namespace SEWN\RingLeader;

defined('ABSPATH') || exit;

/**
 * Authentication handler.
 *
 * Validates tokens against the parent site (startempirewire.com) via
 * MemberPress REST API and issues JWT tokens for ecosystem use.
 *
 * Flow per bigpicture.mdx:
 *   Extension/Connect → Ring Leader → Parent Site (MemberPress) → Ring Leader → JWT
 */
class Auth {

    private Config $config;

    public function __construct(Config $config) {
        $this->config = $config;
    }

    /**
     * Validate a WordPress auth token against the parent site.
     * Returns user data with membership tier or WP_Error.
     *
     * @param string $token WordPress application password or cookie token
     * @return array|WP_Error  { user_id, email, tier, membership_ids[], display_name }
     */
    public function validate_parent_token(string $token): array|\WP_Error {
        $cache_key = 'sewn_rl_auth_' . md5($token);
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return $cached;
        }

        // Validate against parent site's wp/v2/users/me
        $response = wp_remote_get($this->config->parent_api() . '/wp/v2/users/me', [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
            ],
            'timeout' => 10,
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code !== 200 || empty($body['id'])) {
            return new \WP_Error('auth_failed', 'Parent site rejected token', ['status' => 401]);
        }

        $user_id = (int) $body['id'];

        // Now get membership info from MemberPress API
        $tier = $this->get_member_tier($user_id);

        $user_data = [
            'user_id'        => $user_id,
            'email'          => $body['email'] ?? '',
            'display_name'   => $body['name'] ?? '',
            'tier'           => $tier['slug'],
            'tier_level'     => $this->config->tier_level($tier['slug']),
            'membership_ids' => $tier['membership_ids'],
            'avatar_url'     => $body['avatar_urls']['96'] ?? '',
        ];

        // Cache for 5 minutes
        set_transient($cache_key, $user_data, $this->config->cache_ttl());

        return $user_data;
    }

    /**
     * Issue a JWT for a validated user. Used by Connect Plugin + Extension.
     *
     * @param array $user_data From validate_parent_token()
     * @param int $ttl Seconds until expiry (default 24h)
     * @return string JWT token
     */
    public function issue_jwt(array $user_data, int $ttl = 86400): string {
        $now = time();
        $payload = [
            'iss'  => home_url(),
            'iat'  => $now,
            'exp'  => $now + $ttl,
            'data' => [
                'user_id'   => $user_data['user_id'],
                'email'     => $user_data['email'],
                'tier'      => $user_data['tier'],
                'tier_level'=> $user_data['tier_level'],
            ],
        ];

        return $this->jwt_encode($payload);
    }

    /**
     * Verify a Ring Leader JWT.
     *
     * @param string $token
     * @return array|WP_Error Decoded payload data
     */
    public function verify_jwt(string $token): array|\WP_Error {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return new \WP_Error('invalid_jwt', 'Malformed token', ['status' => 401]);
        }

        [$header_b64, $payload_b64, $sig_b64] = $parts;

        // Verify signature
        $expected_sig = $this->base64url_encode(
            hash_hmac('sha256', "$header_b64.$payload_b64", $this->config->jwt_secret(), true)
        );

        if (!hash_equals($expected_sig, $sig_b64)) {
            return new \WP_Error('invalid_jwt', 'Signature mismatch', ['status' => 401]);
        }

        $payload = json_decode($this->base64url_decode($payload_b64), true);
        if (!$payload) {
            return new \WP_Error('invalid_jwt', 'Cannot decode payload', ['status' => 401]);
        }

        // Check expiry
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return new \WP_Error('jwt_expired', 'Token expired', ['status' => 401]);
        }

        return $payload['data'] ?? $payload;
    }

    /**
     * Extract token from request (Authorization: Bearer or X-SEWN-Token header)
     */
    public function extract_token(\WP_REST_Request $request): ?string {
        // Check Authorization header
        $auth = $request->get_header('authorization');
        if ($auth && preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
            return $m[1];
        }

        // Check custom header
        $custom = $request->get_header('x-sewn-token');
        if ($custom) return $custom;

        // Check query param (for simple GET requests)
        $param = $request->get_param('token');
        if ($param) return $param;

        return null;
    }

    /**
     * Get member's highest tier from MemberPress.
     */
    private function get_member_tier(int $user_id): array {
        $api_key = $this->config->parent_api_key();
        if (empty($api_key)) {
            return ['slug' => 'free', 'membership_ids' => []];
        }

        $response = wp_remote_get(
            $this->config->parent_api() . '/mp/v1/members/' . $user_id,
            [
                'headers' => ['MEMBERPRESS-API-KEY' => $api_key],
                'timeout' => 10,
            ]
        );

        if (is_wp_error($response)) {
            return ['slug' => 'free', 'membership_ids' => []];
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        $active_memberships = $body['active_memberships'] ?? [];

        if (empty($active_memberships)) {
            return ['slug' => 'free', 'membership_ids' => []];
        }

        // Find highest tier
        $tier_map = $this->config->tier_map();
        $best_tier = 'free';
        $best_level = 0;
        $ids = [];

        foreach ($active_memberships as $membership) {
            $mid = (int) ($membership['id'] ?? 0);
            $ids[] = $mid;
            $slug = $tier_map[$mid] ?? 'free';
            $level = $this->config->tier_level($slug);
            if ($level > $best_level) {
                $best_level = $level;
                $best_tier = $slug;
            }
        }

        return ['slug' => $best_tier, 'membership_ids' => $ids];
    }

    // --- JWT helpers (no external dependency) ---

    private function jwt_encode(array $payload): string {
        $header = $this->base64url_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
        $body   = $this->base64url_encode(json_encode($payload));
        $sig    = $this->base64url_encode(
            hash_hmac('sha256', "$header.$body", $this->config->jwt_secret(), true)
        );
        return "$header.$body.$sig";
    }

    private function base64url_encode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64url_decode(string $data): string {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}

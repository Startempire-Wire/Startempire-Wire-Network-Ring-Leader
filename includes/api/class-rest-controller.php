<?php
namespace SEWN\RingLeader\API;

use SEWN\RingLeader\Config;
use SEWN\RingLeader\Auth;
use SEWN\RingLeader\ParentBridge;

defined('ABSPATH') || exit;

/**
 * REST API Controller — Creates the `sewn/v1` namespace.
 *
 * Per bigpicture.mdx, Ring Leader creates API endpoints for:
 * - Chrome Extension (content, auth, stats)
 * - Connect Plugin (content, member data)
 * - Wirebot/Scoreboard (member provisioning)
 *
 * Authentication flow (bigpicture.mdx):
 *   Request → Auth Check:
 *     ├─ WordPress Admin? → Allow All
 *     ├─ Valid Ring Leader JWT? → Apply tier limits
 *     ├─ Valid Parent WP Token? → Issue JWT, apply tier limits
 *     └─ No Auth → Free tier limits
 */
class RestController {

    private Config $config;
    private Auth $auth;
    private ParentBridge $parent;

    private const NAMESPACE = 'sewn/v1';

    public function __construct(Config $config, Auth $auth, ParentBridge $parent) {
        $this->config = $config;
        $this->auth   = $auth;
        $this->parent = $parent;
    }

    public function register_routes(): void {
        // === AUTH ===

        // Validate token + return user data with tier
        register_rest_route(self::NAMESPACE, '/auth/validate', [
            'methods'  => 'POST',
            'callback' => [$this, 'auth_validate'],
            'permission_callback' => '__return_true',
        ]);

        // Exchange parent WP token for Ring Leader JWT
        register_rest_route(self::NAMESPACE, '/auth/token', [
            'methods'  => 'POST',
            'callback' => [$this, 'auth_token'],
            'permission_callback' => '__return_true',
        ]);

        // SSO: Issue JWT for a trusted server-to-server request (Connect Plugin → Ring Leader)
        register_rest_route(self::NAMESPACE, '/auth/issue', [
            'methods'  => 'POST',
            'callback' => [$this, 'auth_issue'],
            'permission_callback' => '__return_true',
        ]);

        // === CONTENT (tier-gated) ===

        register_rest_route(self::NAMESPACE, '/content', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_content'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/content/posts', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_posts'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/content/events', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_events'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/content/podcasts', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_podcasts'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/content/directory', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_directory'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/content/activity', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_activity'],
            'permission_callback' => '__return_true',
        ]);

        // === NETWORK ===

        register_rest_route(self::NAMESPACE, '/network/stats', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_stats'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/network/members', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_members'],
            'permission_callback' => [$this, 'check_authenticated'],
        ]);

        // === MEMBER ===

        register_rest_route(self::NAMESPACE, '/member/me', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_me'],
            'permission_callback' => [$this, 'check_authenticated'],
        ]);

        register_rest_route(self::NAMESPACE, '/member/scoreboard', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_scoreboard'],
            'permission_callback' => [$this, 'check_authenticated'],
        ]);

        // === CACHE ===

        register_rest_route(self::NAMESPACE, '/cache/flush', [
            'methods'  => 'POST',
            'callback' => [$this, 'flush_cache'],
            'permission_callback' => [$this, 'check_admin'],
        ]);
    }

    // ==================== AUTH ====================

    public function auth_validate(\WP_REST_Request $request): \WP_REST_Response {
        $token = $this->auth->extract_token($request);
        if (!$token) {
            return new \WP_REST_Response(['error' => 'No token provided'], 401);
        }

        // Try Ring Leader JWT first
        $jwt_result = $this->auth->verify_jwt($token);
        if (!is_wp_error($jwt_result)) {
            return new \WP_REST_Response([
                'valid'   => true,
                'user'    => $jwt_result,
                'source'  => 'ring_leader_jwt',
            ]);
        }

        // Fall back to parent site validation
        $parent_result = $this->auth->validate_parent_token($token);
        if (is_wp_error($parent_result)) {
            return new \WP_REST_Response([
                'valid' => false,
                'error' => $parent_result->get_error_message(),
            ], 401);
        }

        return new \WP_REST_Response([
            'valid'   => true,
            'user'    => $parent_result,
            'source'  => 'parent_site',
        ]);
    }

    public function auth_token(\WP_REST_Request $request): \WP_REST_Response {
        $token = $this->auth->extract_token($request);
        if (!$token) {
            return new \WP_REST_Response(['error' => 'No token provided'], 401);
        }

        $user_data = $this->auth->validate_parent_token($token);
        if (is_wp_error($user_data)) {
            return new \WP_REST_Response([
                'error' => $user_data->get_error_message(),
            ], 401);
        }

        $jwt = $this->auth->issue_jwt($user_data);

        return new \WP_REST_Response([
            'token'      => $jwt,
            'user'       => $user_data,
            'expires_in' => 86400,
        ]);
    }

    /**
     * SSO: Issue JWT for a trusted internal request.
     * Connect Plugin on parent site calls this with a shared secret + user data.
     * This avoids the user needing to enter credentials again.
     */
    public function auth_issue(\WP_REST_Request $request): \WP_REST_Response {
        // Verify shared secret
        $secret = $request->get_header('x-sewn-internal-key');
        $expected = get_option('sewn_rl_internal_key', '');

        if (empty($expected)) {
            // Auto-generate on first use
            $expected = wp_generate_password(48, true, false);
            update_option('sewn_rl_internal_key', $expected);
        }

        if (empty($secret) || !hash_equals($expected, $secret)) {
            return new \WP_REST_Response(['error' => 'Invalid internal key'], 403);
        }

        $body = $request->get_json_params();
        $user_id = (int) ($body['user_id'] ?? 0);
        if (!$user_id) {
            return new \WP_REST_Response(['error' => 'user_id required'], 400);
        }

        // Build user data from what Connect Plugin sends (already verified via WP cookie)
        $roles = $body['roles'] ?? [];
        $is_admin = in_array('administrator', $roles, true) || !empty($body['is_admin']);
        $tier_slug = $is_admin ? 'extrawire' : ($body['tier'] ?? 'free');
        $tier_level = $is_admin ? 3 : $this->config->tier_level($tier_slug);

        // Get membership info from MemberPress
        $mp_tier = $this->auth->get_member_tier_public($user_id);
        if ($mp_tier && $mp_tier['slug'] !== 'free') {
            $tier_slug = $mp_tier['slug'];
            $tier_level = $this->config->tier_level($tier_slug);
        }
        if ($is_admin) {
            $tier_slug = 'extrawire';
            $tier_level = 3;
        }

        $user_data = [
            'user_id'        => $user_id,
            'username'       => $body['username'] ?? '',
            'email'          => $body['email'] ?? '',
            'display_name'   => $body['display_name'] ?? '',
            'roles'          => $roles,
            'is_admin'       => $is_admin,
            'tier'           => $tier_slug,
            'tier_level'     => $tier_level,
            'membership_ids' => $mp_tier['membership_ids'] ?? [],
            'avatar_url'     => $body['avatar_url'] ?? '',
            'url'            => $body['url'] ?? '',
            'registered'     => $body['registered'] ?? '',
            'description'    => $body['description'] ?? '',
        ];

        $jwt = $this->auth->issue_jwt($user_data);

        return new \WP_REST_Response([
            'token'      => $jwt,
            'user'       => $user_data,
            'expires_in' => 86400,
        ]);
    }

    // ==================== CONTENT ====================

    public function get_content(\WP_REST_Request $request): \WP_REST_Response {
        $tier = $this->resolve_tier($request);
        $type = $request->get_param('type') ?? 'posts';
        $page = (int) ($request->get_param('page') ?? 1);
        $per_page = min((int) ($request->get_param('per_page') ?? 10), 50);

        $params = ['page' => $page, 'per_page' => $per_page];

        $result = match ($type) {
            'events'    => $this->parent->get_events($params),
            'podcasts'  => $this->parent->get_podcasts($params),
            'directory' => $this->parent->get_directory($params),
            'activity'  => $this->parent->get_activity($params, $tier),
            default     => $this->parent->get_posts($params, $tier),
        };

        if (is_wp_error($result)) {
            return new \WP_REST_Response(['error' => $result->get_error_message()], 502);
        }

        return new \WP_REST_Response([
            'data' => $result,
            'meta' => [
                'type'     => $type,
                'tier'     => $tier,
                'page'     => $page,
                'per_page' => $per_page,
            ],
        ]);
    }

    public function get_posts(\WP_REST_Request $request): \WP_REST_Response {
        $request->set_param('type', 'posts');
        return $this->get_content($request);
    }

    public function get_events(\WP_REST_Request $request): \WP_REST_Response {
        $request->set_param('type', 'events');
        return $this->get_content($request);
    }

    public function get_podcasts(\WP_REST_Request $request): \WP_REST_Response {
        $request->set_param('type', 'podcasts');
        return $this->get_content($request);
    }

    public function get_directory(\WP_REST_Request $request): \WP_REST_Response {
        $request->set_param('type', 'directory');
        return $this->get_content($request);
    }

    public function get_activity(\WP_REST_Request $request): \WP_REST_Response {
        $request->set_param('type', 'activity');
        return $this->get_content($request);
    }

    // ==================== NETWORK ====================

    public function get_stats(\WP_REST_Request $request): \WP_REST_Response {
        $stats = $this->parent->get_stats();
        return new \WP_REST_Response($stats);
    }

    public function get_members(\WP_REST_Request $request): \WP_REST_Response {
        $page = (int) ($request->get_param('page') ?? 1);
        $per_page = min((int) ($request->get_param('per_page') ?? 20), 100);

        $result = $this->parent->get_members(['page' => $page, 'per_page' => $per_page]);
        if (is_wp_error($result)) {
            return new \WP_REST_Response(['error' => $result->get_error_message()], 502);
        }

        return new \WP_REST_Response(['data' => $result]);
    }

    // ==================== MEMBER ====================

    public function get_me(\WP_REST_Request $request): \WP_REST_Response {
        $user = $request->get_attributes()['sewn_user'] ?? null;
        if (!$user) {
            return new \WP_REST_Response(['error' => 'Not authenticated'], 401);
        }

        return new \WP_REST_Response(['user' => $user]);
    }

    public function get_scoreboard(\WP_REST_Request $request): \WP_REST_Response {
        $user = $request->get_attributes()['sewn_user'] ?? null;
        if (!$user) {
            return new \WP_REST_Response(['error' => 'Not authenticated'], 401);
        }

        // Check if user has a scoreboard provisioned
        $scoreboard_id = get_user_meta($user['user_id'], 'sewn_scoreboard_id', true);
        if (empty($scoreboard_id)) {
            return new \WP_REST_Response([
                'provisioned' => false,
                'message'     => 'No scoreboard provisioned. Upgrade to FreeWire+ to get your scoreboard.',
            ]);
        }

        return new \WP_REST_Response([
            'provisioned'    => true,
            'scoreboard_url' => $this->config->scoreboard_url() . '/' . $scoreboard_id,
            'scoreboard_id'  => $scoreboard_id,
        ]);
    }

    // ==================== CACHE ====================

    public function flush_cache(\WP_REST_Request $request): \WP_REST_Response {
        $this->parent->flush_cache();
        return new \WP_REST_Response(['flushed' => true]);
    }

    // ==================== PERMISSION CALLBACKS ====================

    public function check_authenticated(\WP_REST_Request $request): bool {
        $token = $this->auth->extract_token($request);
        if (!$token) return false;

        // Try JWT first
        $result = $this->auth->verify_jwt($token);
        if (!is_wp_error($result)) {
            $request->set_attributes(['sewn_user' => $result]);
            return true;
        }

        // Try parent token
        $result = $this->auth->validate_parent_token($token);
        if (!is_wp_error($result)) {
            $request->set_attributes(['sewn_user' => $result]);
            return true;
        }

        return false;
    }

    public function check_admin(\WP_REST_Request $request): bool {
        return current_user_can('manage_options');
    }

    // ==================== HELPERS ====================

    /**
     * Resolve the requesting user's tier from token, or default to 'free'.
     */
    private function resolve_tier(\WP_REST_Request $request): string {
        $tier = $request->get_param('tier');
        if ($tier) return sanitize_text_field($tier);

        $token = $this->auth->extract_token($request);
        if (!$token) return 'free';

        $result = $this->auth->verify_jwt($token);
        if (!is_wp_error($result)) {
            return $result['tier'] ?? 'free';
        }

        $result = $this->auth->validate_parent_token($token);
        if (!is_wp_error($result)) {
            return $result['tier'] ?? 'free';
        }

        return 'free';
    }
}

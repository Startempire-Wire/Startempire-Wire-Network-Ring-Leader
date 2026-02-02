<?php
namespace SEWN\RingLeader;

defined('ABSPATH') || exit;

/**
 * Bridge to the Parent Membership Website (startempirewire.com).
 *
 * Per bigpicture.mdx, Ring Leader:
 * - Retrieves ALL data from parent via WordPress REST API
 * - Handles content distribution based on membership tier
 * - Caches responses locally to reduce parent site load
 *
 * Content types from parent:
 * - Members & membership levels
 * - Message boards (/message-boards)
 * - Articles (/articles) — regular & premium
 * - Podcasts (/audio-podcasts, /video-podcasts)
 * - Events (/events)
 * - Directory (/directory)
 */
class ParentBridge {

    private Config $config;

    public function __construct(Config $config) {
        $this->config = $config;
    }

    /**
     * Fetch content from parent site with caching.
     *
     * @param string $endpoint  WP REST path (e.g., '/wp/v2/posts')
     * @param array  $params    Query parameters
     * @param string $tier      Requesting user's tier slug
     * @return array|WP_Error
     */
    public function fetch(string $endpoint, array $params = [], string $tier = 'free'): array|\WP_Error {
        $cache_key = 'sewn_rl_' . md5($endpoint . serialize($params) . $tier);
        $cached = get_transient($cache_key);

        if ($cached !== false) {
            return $cached;
        }

        $url = $this->config->parent_api() . $endpoint;
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $headers = [];
        $api_key = $this->config->parent_api_key();
        if ($api_key) {
            $headers['MEMBERPRESS-API-KEY'] = $api_key;
        }

        $response = wp_remote_get($url, [
            'headers' => $headers,
            'timeout' => 15,
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code < 200 || $code >= 300) {
            return new \WP_Error(
                'parent_api_error',
                $body['message'] ?? "Parent API returned $code",
                ['status' => $code]
            );
        }

        // Apply tier-based content filtering
        $body = $this->filter_by_tier($body, $tier);

        set_transient($cache_key, $body, $this->config->cache_ttl());

        return $body;
    }

    /**
     * Get network members list (for directory).
     */
    public function get_members(array $params = []): array|\WP_Error {
        $defaults = ['per_page' => 20, 'page' => 1];
        return $this->fetch('/mp/v1/members', array_merge($defaults, $params));
    }

    /**
     * Get membership plans.
     */
    public function get_memberships(): array|\WP_Error {
        return $this->fetch('/mp/v1/memberships');
    }

    /**
     * Get a specific member's data.
     */
    public function get_member(int $user_id): array|\WP_Error {
        return $this->fetch('/mp/v1/members/' . $user_id);
    }

    /**
     * Get posts (articles) — filterable by category, tier-gated.
     */
    public function get_posts(array $params = [], string $tier = 'free'): array|\WP_Error {
        $defaults = ['per_page' => 10, 'page' => 1, '_embed' => 1];
        return $this->fetch('/wp/v2/posts', array_merge($defaults, $params), $tier);
    }

    /**
     * Get events from The Events Calendar.
     */
    public function get_events(array $params = []): array|\WP_Error {
        $defaults = ['per_page' => 10, 'page' => 1, 'start_date' => 'now'];
        return $this->fetch('/tribe/events/v1/events', array_merge($defaults, $params));
    }

    /**
     * Get podcast episodes (Seriously Simple Podcasting).
     */
    public function get_podcasts(array $params = []): array|\WP_Error {
        $defaults = ['per_page' => 10, 'page' => 1];
        // SSP uses the standard podcast CPT
        return $this->fetch('/wp/v2/podcast', array_merge($defaults, $params));
    }

    /**
     * Get GeoDirectory listings (business directory).
     */
    public function get_directory(array $params = []): array|\WP_Error {
        $defaults = ['per_page' => 20, 'page' => 1];
        return $this->fetch('/geodir/v2/startup', array_merge($defaults, $params));
    }

    /**
     * Get BuddyBoss activity stream.
     */
    public function get_activity(array $params = [], string $tier = 'free'): array|\WP_Error {
        $defaults = ['per_page' => 20, 'page' => 1];
        return $this->fetch('/buddyboss/v1/activity', array_merge($defaults, $params), $tier);
    }

    /**
     * Get network statistics.
     * Aggregates member count, content count, etc.
     */
    public function get_stats(): array {
        $cache_key = 'sewn_rl_network_stats';
        $cached = get_transient($cache_key);
        if ($cached !== false) return $cached;

        $stats = [
            'total_members'      => 0,
            'total_posts'        => 0,
            'total_events'       => 0,
            'total_podcasts'     => 0,
            'total_listings'     => 0,
            'membership_tiers'   => [],
            'updated_at'         => gmdate('c'),
        ];

        // Members
        $members = $this->fetch('/mp/v1/members', ['per_page' => 1]);
        if (!is_wp_error($members)) {
            // MemberPress returns all by default; count from response
            $all = $this->fetch('/mp/v1/members', ['per_page' => 100]);
            $stats['total_members'] = is_array($all) ? count($all) : 0;
        }

        // Memberships
        $memberships = $this->get_memberships();
        if (!is_wp_error($memberships) && is_array($memberships)) {
            $stats['membership_tiers'] = array_map(function ($m) {
                return [
                    'id'    => $m['id'],
                    'title' => $m['title'],
                    'price' => $m['price'],
                ];
            }, $memberships);
        }

        set_transient($cache_key, $stats, 600); // 10 min cache
        return $stats;
    }

    /**
     * Filter content array by tier.
     * Premium content (password-protected or specific categories) is removed for lower tiers.
     */
    private function filter_by_tier(array $data, string $tier): array {
        if (!is_array($data) || empty($data)) return $data;

        $level = $this->config->tier_level($tier);

        // If top-level tier (extrawire), no filtering
        if ($level >= 3) return $data;

        // Filter out premium-flagged content for lower tiers
        return array_values(array_filter($data, function ($item) use ($level) {
            // Skip non-arrays (scalar data)
            if (!is_array($item)) return true;

            // If post has a 'tier_required' meta, check it
            $required = $item['meta']['tier_required'] ?? $item['tier_required'] ?? null;
            if ($required !== null) {
                return $this->config->tier_level((string) $required) <= $level;
            }

            // Password-protected content requires Wire+
            if (isset($item['content']['protected']) && $item['content']['protected']) {
                return $level >= 2;
            }

            return true;
        }));
    }

    /**
     * Invalidate all caches (called after webhook events).
     */
    public function flush_cache(): void {
        global $wpdb;
        $wpdb->query(
            "DELETE FROM $wpdb->options WHERE option_name LIKE '_transient_sewn_rl_%' OR option_name LIKE '_transient_timeout_sewn_rl_%'"
        );
    }
}

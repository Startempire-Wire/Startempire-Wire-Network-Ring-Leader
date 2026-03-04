<?php
namespace SEWN\RingLeader;

defined('ABSPATH') || exit;

/**
 * Centralized configuration for Ring Leader.
 * Reads from wp_options (set via Admin settings page).
 */
class Config {

    private $settings;

    public function __construct() {
        $this->settings = get_option('sewn_rl_settings', []);
    }

    public function get($key, $default = null) {
        return $this->settings[$key] ?? $default;
    }

    public function parent_url(): string {
        return rtrim($this->get('parent_url', SEWN_RL_PARENT_URL), '/');
    }

    public function parent_api(): string {
        return $this->parent_url() . '/wp-json';
    }

    public function parent_api_key(): string {
        return get_option('sewn_rl_parent_api_key', '');
    }

    public function jwt_secret(): string {
        return get_option('sewn_rl_jwt_secret', '');
    }

    public function cache_ttl(): int {
        return (int) $this->get('cache_ttl', 300);
    }

    public function scoreboard_url(): string {
        return rtrim($this->get('scoreboard_url', 'https://wins.wirebot.chat'), '/');
    }

    /**
     * Internal scoreboard URL (for server-to-server calls on same VPS).
     */
    public function scoreboard_internal_url(): string {
        return rtrim($this->get('scoreboard_internal_url', 'http://127.0.0.1:8100'), '/');
    }

    /**
     * Scoreboard API token for server-to-server auth.
     */
    public function scoreboard_token(): string {
        return $this->get('scoreboard_token', '');
    }

    public function wirebot_url(): string {
        return rtrim($this->get('wirebot_url', 'https://helm.wirebot.chat'), '/');
    }

    public function webhooks_enabled(): bool {
        return (bool) $this->get('enable_webhooks', true);
    }

    /**
     * Shared secret for inbound webhook signatures.
     * Separate from JWT secret to reduce blast radius.
     */
    public function webhook_secret(): string {
        return (string) $this->get('webhook_secret', '');
    }

    /**
     * Membership tier map: MemberPress membership ID → tier slug.
     * Keep in sync with wirebot-provisioning/inc/class-tier-map.php PRODUCT_MAP.
     */
    public function tier_map(): array {
        return [
            // FreeWire
            17268 => 'freewire',        // FreeWire™ (lifetime, $0)

            // Wire
            1494  => 'wire',            // Wire™ Monthly ($35)
            41156 => 'wire',            // Wire™ Quarterly ($101.85)
            41158 => 'wire',            // Wire™ Yearly ($399)

            // ExtraWire
            1498  => 'extrawire',       // ExtraWire™ Monthly ($55)
            41155 => 'extrawire',       // ExtraWire™ Quarterly ($160.05)
            41157 => 'extrawire',       // ExtraWire™ Yearly ($627)
            48655 => 'extrawire',       // ExtraWire™ Founding Signal
            48656 => 'extrawire',       // ExtraWire™ Founding Builder
            48657 => 'extrawire',       // ExtraWire™ Founding Operator
            48658 => 'extrawire',       // ExtraWire™ Founding Network
            48659 => 'extrawire',       // ExtraWire™ Founding Wire

            // Wirebot Direct (same access level as Wire)
            48595 => 'wirebot_direct',  // Wirebot Direct Quarterly
            48596 => 'wirebot_direct',  // Wirebot Direct Yearly

            // Other
            32073 => 'advertiser',      // Advertiser (lifetime, $0)
        ];
    }

    /**
     * Map tier slug to numeric level for comparison.
     * Keep in sync with wirebot-provisioning/inc/class-tier-map.php TIER_LEVELS.
     */
    public function tier_level(string $tier): int {
        $levels = [
            'free'              => 0,
            'freewire'          => 1,
            'advertiser'        => 1,
            'wire'              => 2,
            'wirebot_direct'    => 2,
            'extrawire'         => 3,
            'sovereign'         => 4,
            'sovereign_builder' => 5,
        ];
        return $levels[$tier] ?? 0;
    }
}

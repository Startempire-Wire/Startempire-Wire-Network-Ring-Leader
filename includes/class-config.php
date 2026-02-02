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

    public function wirebot_url(): string {
        return rtrim($this->get('wirebot_url', 'https://helm.wirebot.chat'), '/');
    }

    public function webhooks_enabled(): bool {
        return (bool) $this->get('enable_webhooks', true);
    }

    /**
     * Membership tier map: MemberPress membership ID → tier slug
     */
    public function tier_map(): array {
        return [
            // From MemberPress API: id → tier
            17268 => 'freewire',    // FreeWire™ (lifetime, $0)
            1494  => 'wire',        // Wire™ Monthly ($35)
            41156 => 'wire',        // Wire™ Quarterly ($101.85)
            41158 => 'wire',        // Wire™ Yearly ($399)
            1498  => 'extrawire',   // ExtraWire™ Monthly ($55)
            41155 => 'extrawire',   // ExtraWire™ Quarterly ($160.05)
            41157 => 'extrawire',   // ExtraWire™ Yearly ($627)
            32073 => 'advertiser',  // Advertiser (lifetime, $0)
        ];
    }

    /**
     * Map tier slug to numeric level for comparison
     */
    public function tier_level(string $tier): int {
        $levels = [
            'free'       => 0,
            'freewire'   => 1,
            'wire'       => 2,
            'extrawire'  => 3,
            'advertiser' => 1, // Same access as FreeWire
        ];
        return $levels[$tier] ?? 0;
    }
}

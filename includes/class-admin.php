<?php
namespace SEWN\RingLeader;

defined('ABSPATH') || exit;

/**
 * Admin settings page for Ring Leader.
 */
class Admin {

    private Config $config;

    public function __construct(Config $config) {
        $this->config = $config;
    }

    public function init(): void {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function add_menu(): void {
        add_options_page(
            'Ring Leader Settings',
            'Ring Leader',
            'manage_options',
            'sewn-ring-leader',
            [$this, 'render_page']
        );
    }

    public function register_settings(): void {
        register_setting('sewn_rl_settings_group', 'sewn_rl_settings', [
            'sanitize_callback' => [$this, 'sanitize_settings'],
        ]);
        register_setting('sewn_rl_settings_group', 'sewn_rl_parent_api_key', [
            'sanitize_callback' => 'sanitize_text_field',
        ]);

        add_settings_section('sewn_rl_main', 'Ring Leader Configuration', null, 'sewn-ring-leader');

        add_settings_field('parent_url', 'Parent Site URL', function () {
            $settings = get_option('sewn_rl_settings', []);
            $val = $settings['parent_url'] ?? SEWN_RL_PARENT_URL;
            echo '<input type="url" name="sewn_rl_settings[parent_url]" value="' . esc_attr($val) . '" class="regular-text" />';
            echo '<p class="description">The parent membership website (startempirewire.com)</p>';
        }, 'sewn-ring-leader', 'sewn_rl_main');

        add_settings_field('parent_api_key', 'Parent MemberPress API Key', function () {
            $val = get_option('sewn_rl_parent_api_key', '');
            echo '<input type="password" name="sewn_rl_parent_api_key" value="' . esc_attr($val) . '" class="regular-text" />';
            echo '<p class="description">MemberPress Developer Tools API key from parent site</p>';
        }, 'sewn-ring-leader', 'sewn_rl_main');

        add_settings_field('cache_ttl', 'Cache TTL (seconds)', function () {
            $settings = get_option('sewn_rl_settings', []);
            $val = $settings['cache_ttl'] ?? 300;
            echo '<input type="number" name="sewn_rl_settings[cache_ttl]" value="' . esc_attr($val) . '" min="0" max="86400" />';
            echo '<p class="description">How long to cache data from parent site (0 = no cache)</p>';
        }, 'sewn-ring-leader', 'sewn_rl_main');

        add_settings_field('scoreboard_url', 'Scoreboard URL', function () {
            $settings = get_option('sewn_rl_settings', []);
            $val = $settings['scoreboard_url'] ?? 'https://wins.wirebot.chat';
            echo '<input type="url" name="sewn_rl_settings[scoreboard_url]" value="' . esc_attr($val) . '" class="regular-text" />';
        }, 'sewn-ring-leader', 'sewn_rl_main');

        add_settings_field('wirebot_url', 'Wirebot URL', function () {
            $settings = get_option('sewn_rl_settings', []);
            $val = $settings['wirebot_url'] ?? 'https://helm.wirebot.chat';
            echo '<input type="url" name="sewn_rl_settings[wirebot_url]" value="' . esc_attr($val) . '" class="regular-text" />';
        }, 'sewn-ring-leader', 'sewn_rl_main');

        add_settings_field('enable_webhooks', 'Enable Webhooks', function () {
            $settings = get_option('sewn_rl_settings', []);
            $val = $settings['enable_webhooks'] ?? true;
            echo '<label><input type="checkbox" name="sewn_rl_settings[enable_webhooks]" value="1" ' . checked($val, true, false) . ' /> Accept incoming webhooks from MemberPress and ecosystem</label>';
        }, 'sewn-ring-leader', 'sewn_rl_main');

        add_settings_field('jwt_secret_display', 'JWT Secret', function () {
            $secret = get_option('sewn_rl_jwt_secret', '');
            $masked = $secret ? substr($secret, 0, 8) . '...' . substr($secret, -4) : '(not set)';
            echo '<code>' . esc_html($masked) . '</code>';
            echo '<p class="description">Auto-generated on activation. Used to sign Ring Leader JWTs.</p>';
        }, 'sewn-ring-leader', 'sewn_rl_main');
    }

    public function sanitize_settings($input): array {
        return [
            'parent_url'      => esc_url_raw($input['parent_url'] ?? SEWN_RL_PARENT_URL),
            'cache_ttl'       => absint($input['cache_ttl'] ?? 300),
            'scoreboard_url'  => esc_url_raw($input['scoreboard_url'] ?? ''),
            'wirebot_url'     => esc_url_raw($input['wirebot_url'] ?? ''),
            'enable_webhooks' => !empty($input['enable_webhooks']),
        ];
    }

    public function render_page(): void {
        if (!current_user_can('manage_options')) return;
        ?>
        <div class="wrap">
            <h1>Ring Leader — Startempire Wire Network</h1>
            <p>The Ring Leader plugin connects the Startempire Wire Network to the parent membership site, handles authentication, and distributes content to the Chrome Extension and Connect Plugin.</p>

            <form method="post" action="options.php">
                <?php
                settings_fields('sewn_rl_settings_group');
                do_settings_sections('sewn-ring-leader');
                submit_button();
                ?>
            </form>

            <hr />
            <h2>API Endpoints</h2>
            <table class="widefat fixed striped">
                <thead>
                    <tr><th>Endpoint</th><th>Method</th><th>Auth</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <?php
                    $endpoints = [
                        ['/sewn/v1/auth/validate', 'POST', 'Token', 'Validate token & return user tier'],
                        ['/sewn/v1/auth/token', 'POST', 'WP Token', 'Exchange WP token for Ring Leader JWT'],
                        ['/sewn/v1/content', 'GET', 'Optional', 'Get content (type=posts|events|podcasts|directory|activity)'],
                        ['/sewn/v1/content/posts', 'GET', 'Optional', 'Get articles (tier-gated)'],
                        ['/sewn/v1/content/events', 'GET', 'Optional', 'Get events from The Events Calendar'],
                        ['/sewn/v1/content/podcasts', 'GET', 'Optional', 'Get podcast episodes'],
                        ['/sewn/v1/content/directory', 'GET', 'Optional', 'Get business directory listings'],
                        ['/sewn/v1/content/activity', 'GET', 'Optional', 'Get BuddyBoss activity stream'],
                        ['/sewn/v1/network/stats', 'GET', 'None', 'Network statistics'],
                        ['/sewn/v1/network/members', 'GET', 'Required', 'Network member list'],
                        ['/sewn/v1/member/me', 'GET', 'Required', 'Current user profile + tier'],
                        ['/sewn/v1/member/scoreboard', 'GET', 'Required', 'Scoreboard URL for current user'],
                        ['/sewn/v1/webhooks/memberpress', 'POST', 'Webhook', 'MemberPress event handler'],
                        ['/sewn/v1/webhooks/event', 'POST', 'Webhook', 'Generic ecosystem event handler'],
                        ['/sewn/v1/cache/flush', 'POST', 'Admin', 'Flush all Ring Leader caches'],
                    ];
                    foreach ($endpoints as $e) {
                        echo "<tr><td><code>{$e[0]}</code></td><td>{$e[1]}</td><td>{$e[2]}</td><td>{$e[3]}</td></tr>";
                    }
                    ?>
                </tbody>
            </table>

            <hr />
            <h2>Quick Test</h2>
            <p>
                <a href="<?php echo esc_url(rest_url('sewn/v1/network/stats')); ?>" target="_blank" class="button">
                    Test Network Stats →
                </a>
                <a href="<?php echo esc_url(rest_url('sewn/v1/content/posts')); ?>" target="_blank" class="button">
                    Test Content/Posts →
                </a>
            </p>
        </div>
        <?php
    }
}

<?php
/**
 * Plugin Name:     Startempire Wire Network Ring Leader
 * Plugin URI:      https://startempirewire.network
 * Description:     Ring Leader for the Startempire Wire Network. Auth relay, data distribution hub, and endpoint creator for Connect Plugin & Chrome Extension.
 * Author:          Startempire Wire
 * Author URI:      https://startempirewire.network
 * Text Domain:     startempire-wire-network-ring-leader
 * Domain Path:     /languages
 * Version:         0.2.0
 *
 * @package         Startempire_Wire_Network_Ring_Leader
 */

defined('ABSPATH') || exit;

// Plugin constants
define('SEWN_RL_VERSION', '0.2.0');
define('SEWN_RL_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SEWN_RL_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SEWN_RL_PLUGIN_FILE', __FILE__);

// Parent site (identity/auth source)
define('SEWN_RL_PARENT_URL', 'https://startempirewire.com');
define('SEWN_RL_PARENT_API', SEWN_RL_PARENT_URL . '/wp-json');

/**
 * Autoloader
 */
spl_autoload_register(function ($class) {
    $prefix = 'SEWN\\RingLeader\\';
    if (strpos($class, $prefix) !== 0) return;

    $relative = str_replace($prefix, '', $class);
    $relative = str_replace('\\', '/', $relative);

    // Convert CamelCase to kebab-case with class- prefix
    $parts = explode('/', $relative);
    $filename = array_pop($parts);
    $filename = 'class-' . strtolower(preg_replace('/([a-z])([A-Z])/', '$1-$2', $filename)) . '.php';

    $path = SEWN_RL_PLUGIN_DIR . 'includes/';
    if (!empty($parts)) {
        $path .= strtolower(implode('/', $parts)) . '/';
    }
    $path .= $filename;

    if (file_exists($path)) {
        require_once $path;
    }
});

/**
 * Boot the plugin
 */
function sewn_ring_leader_init() {
    // Load auth functions (legacy compat)
    require_once SEWN_RL_PLUGIN_DIR . 'includes/auth-functions.php';

    // Core classes
    $config  = new SEWN\RingLeader\Config();
    $auth    = new SEWN\RingLeader\Auth($config);
    $parent  = new SEWN\RingLeader\ParentBridge($config);

    // REST API
    $api = new SEWN\RingLeader\API\RestController($config, $auth, $parent);
    add_action('rest_api_init', [$api, 'register_routes']);

    // Admin settings
    if (is_admin()) {
        $admin = new SEWN\RingLeader\Admin($config);
        $admin->init();
    }

    // Webhook listener (for scoreboard provisioning)
    $webhooks = new SEWN\RingLeader\Webhooks($config, $parent);
    add_action('rest_api_init', [$webhooks, 'register_routes']);
}
add_action('plugins_loaded', 'sewn_ring_leader_init');

/**
 * Activation: set defaults, generate JWT secret if missing
 */
register_activation_hook(__FILE__, function () {
    if (!get_option('sewn_rl_jwt_secret')) {
        update_option('sewn_rl_jwt_secret', wp_generate_password(64, true, true));
    }
    if (!get_option('sewn_rl_parent_api_key')) {
        update_option('sewn_rl_parent_api_key', '');
    }
    if (!get_option('sewn_rl_settings')) {
        update_option('sewn_rl_settings', [
            'parent_url'        => SEWN_RL_PARENT_URL,
            'cache_ttl'         => 300,
            'scoreboard_url'    => 'https://wins.wirebot.chat',
            'wirebot_url'       => 'https://helm.wirebot.chat',
            'enable_webhooks'   => true,
        ]);
    }
    flush_rewrite_rules();
});

/**
 * Deactivation
 */
register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules();
});

<?php
/**
 * Handles network authentication functions
 */

function startempire_wire_network_ring_leader_verify_token($token) {
    // First check WordPress admin users
    if ($user = wp_authenticate_application_password('', '', $token)) {
        if (!is_wp_error($user) && user_can($user, 'manage_network')) {
            return $user->ID;
        }
    }
    
    // Then verify JWT for network members
    require_once plugin_dir_path(__FILE__) . 'vendor/autoload.php';
    
    try {
        $decoded = JWT::decode($token, new Key(
            get_option('startempire_jwt_secret'), 
            'HS256'
        ));
        
        return $decoded->data->user_id;
    } catch (Exception $e) {
        return false;
    }
}

// Additional auth functions would go below... 
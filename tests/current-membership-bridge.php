<?php
// Source-only contract regression: php tests/current-membership-bridge.php
namespace {
    define('ABSPATH', __DIR__);
    define('SEWN_RL_PARENT_URL', 'https://parent.example.invalid');
    $GLOBALS['memberpress_response'] = ['code' => 200, 'body' => '{"id":42,"active_memberships":[]}'];
    $GLOBALS['provider_calls'] = 0;
    $GLOBALS['routes'] = [];
    $GLOBALS['options'] = ['sewn_rl_settings' => ['scoreboard_token' => 'unused-master-token'], 'sewn_rl_membership_service_token' => 'synthetic-scoreboard-service-key', 'sewn_rl_parent_api_key' => 'synthetic-provider-key', 'sewn_rl_jwt_secret' => 'synthetic-signing-secret'];
    class WP_Error {
        public function __construct(public string $code, public string $message, public array $data = []) {}
    }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
    function get_option(string $key, mixed $fallback = null): mixed { return $GLOBALS['options'][$key] ?? $fallback; }
    function home_url(): string { return 'https://network.example.invalid'; }
    function get_user_meta(int $user_id, string $key, bool $single): string { return ''; }
    function register_rest_route(string $namespace, string $route, array $config): void { $GLOBALS['routes'][$namespace . $route] = $config; }
    function wp_remote_get(string $url, array $options): array|WP_Error {
        $GLOBALS['provider_calls']++;
        $GLOBALS['provider_request'] = [$url, $options];
        return $GLOBALS['memberpress_response'];
    }
    function wp_remote_retrieve_response_code(array $response): int { return $response['code']; }
    function wp_remote_retrieve_body(array $response): string { return $response['body']; }
    function wp_remote_retrieve_header(array $response, string $name): string { return $response['headers'][$name] ?? ''; }
    class WP_REST_Request {
        public function __construct(private string $authorization, private mixed $userID = 42) {}
        public function get_header(string $name): string { return $name === 'authorization' ? $this->authorization : ''; }
        public function get_param(string $name): mixed { return $name === 'user_id' ? $this->userID : null; }
    }
    class WP_REST_Response {
        private array $headers = [];
        public function __construct(private array $data, private int $status = 200) {}
        public function get_data(): array { return $this->data; }
        public function get_status(): int { return $this->status; }
        public function header(string $name, string $value): void { $this->headers[$name] = $value; }
        public function get_headers(): array { return $this->headers; }
    }
}
namespace SEWN\RingLeader { class ParentBridge {} }
namespace {
    require __DIR__ . '/../includes/class-config.php';
    require __DIR__ . '/../includes/class-auth.php';
    require __DIR__ . '/../includes/api/class-rest-controller.php';
    function require_true(bool $condition, string $reason): void { if (!$condition) throw new \RuntimeException($reason); }
    $config = new \SEWN\RingLeader\Config();
    $controller = new \SEWN\RingLeader\API\RestController($config, new \SEWN\RingLeader\Auth($config), new \SEWN\RingLeader\ParentBridge());
    $controller->register_routes();
    $route = $GLOBALS['routes']['sewn/v1/auth/membership/current'] ?? null;
    require_true(is_array($route) && $route['methods'] === 'POST', 'current membership route not registered as POST');
    $call = fn (string $key, mixed $id = 42) => $controller->auth_current_membership(new \WP_REST_Request($key, $id));
    $key = 'Bearer synthetic-scoreboard-service-key';
    foreach (['', 'Bearer invalid', 'Bearer unused-master-token', 'Bearer synthetic-provider-key'] as $unauthorized) {
        require_true($call($unauthorized)->get_status() === 403, 'unauthorized membership read accepted');
    }
    require_true($GLOBALS['provider_calls'] === 0, 'unauthorized request reached MemberPress');
    require_true($call($key, 0)->get_status() === 400, 'invalid member ID accepted');
    require_true($GLOBALS['provider_calls'] === 0, 'invalid member ID reached MemberPress');

    $GLOBALS['memberpress_response'] = ['code' => 200, 'body' => '{"id":42,"active_memberships":[{"id":48595},{"id":48595},{"id":48596}]}'];
    $active = $call($key);
    $data = $active->get_data();
    require_true($active->get_status() === 200 && $data['schema'] === 'sewn.membership_current.v1' && $data['id'] === 42, 'current owner/schema rejected');
    require_true($data['tier'] === 'wirebot_direct' && $data['active_memberships'] === [['id' => 48595], ['id' => 48596]], 'active Direct products not normalized');
    require_true(($active->get_headers()['Cache-Control'] ?? '') === 'private, no-store' && !empty($data['observed_at']), 'fresh result lacks bounded status');
    $jwtAuth = new \SEWN\RingLeader\Auth($config);
    $jwt = $jwtAuth->issue_jwt(['user_id' => 42, 'email' => 'fixture@example.invalid', 'tier' => 'wirebot_direct', 'tier_level' => 2, 'membership_ids' => [48595, '48595', 0, -1, 48596]]);
    $claims = $jwtAuth->verify_jwt($jwt);
    require_true(!is_wp_error($claims) && ($claims['membership_ids'] ?? null) === [48595, 48596], 'signed issuance snapshot not preserved');
    require_true($jwtAuth->validate_parent_token($jwt)['membership_ids'] === [48595, 48596], 'Ring Leader validation lost signed snapshot');
    require_true($call('Bearer ' . $jwt)->get_status() === 403, 'member JWT impersonated Scoreboard service key');
    [$url, $requestOptions] = $GLOBALS['provider_request'];
    require_true($url === 'https://parent.example.invalid/wp-json/mp/v1/members/42' && $requestOptions['headers']['MEMBERPRESS-API-KEY'] === 'synthetic-provider-key', 'provider owner/key boundary changed');
    require_true($requestOptions['redirection'] === 0 && $requestOptions['sslverify'] === true && $requestOptions['timeout'] === 10 && str_contains($requestOptions['headers']['Cache-Control'], 'no-cache'), 'fresh transport controls missing');

    // A cached signed JWT or earlier positive read never turns cancellation into a grant.
    $GLOBALS['memberpress_response'] = ['code' => 200, 'body' => '{"id":42,"active_memberships":[]}'];
    $free = $call($key);
    require_true($free->get_status() === 200 && $free->get_data()['tier'] === 'free' && $free->get_data()['active_memberships'] === [], 'verified free state confused with unknown');
    foreach ([
        ['code' => 503, 'body' => '{"id":42,"active_memberships":[]}'],
        ['code' => 302, 'body' => '{"id":42,"active_memberships":[]}'],
        ['code' => 200, 'body' => '{"id":43,"active_memberships":[{"id":48595}]}'],
        ['code' => 200, 'body' => '{"id":42}'],
        ['code' => 200, 'body' => '{"id":42,"active_memberships":[{"id":0}]}'],
        ['code' => 200, 'body' => '{"id":42,"active_memberships":[{"id":48595}]}', 'headers' => ['age' => '30']],
    ] as $bad) {
        $GLOBALS['memberpress_response'] = $bad;
        $unknown = $call($key);
        require_true($unknown->get_status() === 503 && $unknown->get_data()['status'] === 'unknown', 'provider failure was treated as verified free');
    }
    $GLOBALS['memberpress_response'] = new \WP_Error('timeout', 'synthetic outage');
    require_true($call($key)->get_status() === 503, 'provider timeout treated as membership status');
    $GLOBALS['memberpress_response'] = ['code' => 200, 'body' => '{"id":42,"active_memberships":[{"id":48595}]}'];
    require_true($call($key)->get_status() === 200, 'provider reactivation did not restore current product');
    require_true($GLOBALS['provider_calls'] === 10, 'membership calls reused a cached state');
    echo "current membership bridge: OK (source-only, synthetic provider)\n";
}

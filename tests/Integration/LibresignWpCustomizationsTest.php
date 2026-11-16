<?php
/**
 * Characterization tests for the hooks wired in the main plugin file.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Integration;

use LibreSign\WPCustomizations\Tests\Support\FakeHttp;
use LibreSign\WPCustomizations\Tests\Support\PluginSecret;
use LibreSign\WPCustomizations\Tests\Support\RegistersPluginSettings;
use WP_Error;
use WPDieException;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * The deploy dispatch and its notices, the REST version route, the noindex
 * tag, the settings page and its storage, and the My Account routing, all
 * against a real WordPress with WooCommerce.
 */
final class LibresignWpCustomizationsTest extends WP_UnitTestCase {

	use RegistersPluginSettings;

	/**
	 * GitHub, answered locally.
	 *
	 * @var FakeHttp
	 */
	private $github;

	/**
	 * @var array<string, string>
	 */
	private $rewrite_rules_before;

	public function set_up() {
		parent::set_up();

		global $wp_rewrite;
		$this->rewrite_rules_before = $wp_rewrite->extra_rules_top;

		$this->github = new FakeHttp();

		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init', $wp_rest_server );

		update_option( 'libresign_github_deploy_organization_repository', 'LibreSign/site' );
		update_option( 'libresign_github_deploy_token', PluginSecret::encrypt( 'deploy-token' ) );
	}

	public function tear_down() {
		global $wp_rest_server, $wp_rewrite;
		$wp_rest_server              = null;
		$wp_rewrite->extra_rules_top = $this->rewrite_rules_before;

		parent::tear_down();
	}

	/**
	 * The deploy notices queued for the current user.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function queued_deploy_notices() {
		$notices = get_transient( 'libresign_github_action_status_' . get_current_user_id() );

		return is_array( $notices ) ? $notices : array();
	}

	public function test_the_version_route_answers_with_the_wordpress_version() {
		global $wp_version;

		$response = rest_get_server()->dispatch( new WP_REST_Request( 'GET', '/libresign/v1/version' ) );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( array( 'version' => $wp_version ), $response->get_data() );
	}

	public function test_publishing_a_post_dispatches_the_site_deploy() {
		update_option( 'libresign_github_deploy_token', PluginSecret::encrypt( 'deploy-token' ) );
		$this->github->answer_with( FakeHttp::response( 204 ) );

		$post_id = self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$this->assertSame( array( 'https://api.github.com/repos/LibreSign/site/dispatches' ), $this->github->urls() );
		$this->assertSame( 'Bearer deploy-token', $this->github->args()['headers']['Authorization'] );
		$this->assertSame( array( 'event_type' => 'deploy-site' ), json_decode( $this->github->args()['body'], true ) );

		$notices = $this->queued_deploy_notices();

		$this->assertCount( 1, $notices );
		$this->assertSame( 'success', $notices[0]['type'] );
		$this->assertSame( $post_id, $notices[0]['post_id'] );
		$this->assertSame( 'indefinido', $notices[0]['language'] );
	}

	public function test_a_refused_dispatch_is_reported_as_an_error() {
		$this->github->answer_with( FakeHttp::response( 401, (string) wp_json_encode( array( 'message' => 'Bad credentials' ) ) ) );

		self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$notices = $this->queued_deploy_notices();

		$this->assertSame( 'error', $notices[0]['type'] );
		$this->assertStringContainsString( '401', $notices[0]['message'] );
		$this->assertStringContainsString( 'Bad credentials', $notices[0]['message'] );
	}

	public function test_an_unreachable_github_is_reported_as_an_error() {
		$this->github->answer_with( new WP_Error( 'http_request_failed', 'Connection refused' ) );

		self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$notices = $this->queued_deploy_notices();

		$this->assertSame( 'error', $notices[0]['type'] );
		$this->assertSame( 'Connection refused', $notices[0]['message'] );
	}

	public function test_a_draft_does_not_dispatch_anything() {
		$this->github->answer_with( FakeHttp::response( 204 ) );

		self::factory()->post->create( array( 'post_status' => 'draft' ) );

		$this->assertSame( array(), $this->github->urls() );
		$this->assertSame( array(), $this->queued_deploy_notices() );
	}

	public function test_publishing_a_page_does_not_dispatch_anything() {
		$this->github->answer_with( FakeHttp::response( 204 ) );

		self::factory()->post->create(
			array(
				'post_type'   => 'page',
				'post_status' => 'publish',
			)
		);

		$this->assertSame( array(), $this->github->urls() );
		$this->assertSame( array(), $this->queued_deploy_notices() );
	}

	public function test_trashing_a_published_page_does_not_dispatch_anything() {
		$this->github->answer_with( FakeHttp::response( 204 ) );

		$page_id = self::factory()->post->create(
			array(
				'post_type'   => 'page',
				'post_status' => 'publish',
			)
		);
		$this->github->forget();

		wp_trash_post( $page_id );

		$this->assertSame( array(), $this->github->urls() );
	}

	public function test_trashing_a_published_post_dispatches_the_site_deploy() {
		$this->github->answer_with( FakeHttp::response( 204 ) );

		$post_id = self::factory()->post->create( array( 'post_status' => 'publish' ) );
		$this->github->forget();

		wp_trash_post( $post_id );

		$this->assertCount( 1, $this->github->urls() );
	}

	public function test_a_token_saved_over_an_existing_one_is_stored_encrypted() {
		update_option( 'libresign_github_deploy_token', 'placeholder' );
		$this->register_plugin_settings();

		update_option( 'libresign_github_deploy_token', 'a-personal-access-token' );

		$this->assertNotSame( 'a-personal-access-token', get_option( 'libresign_github_deploy_token' ) );

		$this->github->answer_with( FakeHttp::response( 204 ) );
		self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$this->assertSame( 'Bearer a-personal-access-token', $this->github->args()['headers']['Authorization'] );
	}

	/**
	 * A token saved on a site that never had one goes through add_option(),
	 * which sanitizes the already sanitized value a second time, so it is only
	 * stored encrypted once because the encryption is idempotent.
	 */
	public function test_a_token_saved_for_the_first_time_is_stored_encrypted() {
		delete_option( 'libresign_github_deploy_token' );
		$this->register_plugin_settings();

		update_option( 'libresign_github_deploy_token', 'a-personal-access-token' );

		$this->assertNotSame( 'a-personal-access-token', get_option( 'libresign_github_deploy_token' ) );

		$this->github->answer_with( FakeHttp::response( 204 ) );
		self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$this->assertSame( 'Bearer a-personal-access-token', $this->github->args()['headers']['Authorization'] );
	}

	public function test_a_deploy_token_that_cannot_be_decrypted_is_not_sent_to_github() {
		update_option( 'libresign_github_deploy_token', PluginSecret::encrypt_with_other_salts( 'a-personal-access-token' ) );
		$this->github->answer_with( FakeHttp::response( 204 ) );

		self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$this->assertSame( array(), $this->github->urls() );
	}

	public function test_a_setting_of_zero_is_stored_instead_of_being_taken_for_a_blank_field() {
		$this->register_plugin_settings();

		update_option( 'libresign_github_deploy_token', 'the-previous-token' );
		update_option( 'libresign_github_deploy_token', '0' );

		$this->assertSame( '0', libresign_plugin_secret()->decrypt_or_discard( get_option( 'libresign_github_deploy_token' ) ) );
	}

	public function test_saving_an_empty_deploy_token_keeps_the_previous_one() {
		update_option( 'libresign_github_deploy_token', 'placeholder' );
		$this->register_plugin_settings();

		update_option( 'libresign_github_deploy_token', 'a-personal-access-token' );
		$stored = get_option( 'libresign_github_deploy_token' );

		update_option( 'libresign_github_deploy_token', '' );

		$this->assertSame( $stored, get_option( 'libresign_github_deploy_token' ) );
	}

	public function test_an_internal_article_is_not_indexed() {
		$this->github->answer_with( FakeHttp::response( 204 ) );
		$post_id = self::factory()->post->create( array( 'post_status' => 'publish' ) );
		wp_set_post_categories( $post_id, array( self::factory()->category->create( array( 'slug' => 'article' ) ) ) );
		$this->go_to( get_permalink( $post_id ) );

		ob_start();
		libresign_wp_add_noindex_meta_tag();
		$html = ob_get_clean();

		$this->assertSame( '<meta name="robots" content="noindex, nofollow">' . PHP_EOL, $html );
	}

	public function test_a_regular_post_is_indexed() {
		$this->github->answer_with( FakeHttp::response( 204 ) );
		$post_id = self::factory()->post->create( array( 'post_status' => 'publish' ) );
		$this->go_to( get_permalink( $post_id ) );

		ob_start();
		libresign_wp_add_noindex_meta_tag();

		$this->assertSame( '', ob_get_clean() );
	}

	public function test_the_home_page_is_indexed() {
		$this->go_to( home_url( '/' ) );

		ob_start();
		libresign_wp_add_noindex_meta_tag();

		$this->assertSame( '', ob_get_clean() );
	}

	/**
	 * @dataProvider provide_nextcloud_hosts
	 *
	 * @param string $public_host Value of nextcloud_public_host.
	 * @param string $api_host    Value of nextcloud_api_host.
	 * @param string $expected    Host used for the customer facing link.
	 */
	public function test_the_customer_link_prefers_the_public_host( $public_host, $api_host, $expected ) {
		update_option( 'nextcloud_public_host', $public_host );
		update_option( 'nextcloud_api_host', $api_host );

		$this->assertSame( $expected, libresign_get_nextcloud_public_host() );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string, 2: string}>
	 */
	public static function provide_nextcloud_hosts() {
		yield 'the public host wins'              => array( 'https://cloud.libresign.coop', 'http://host.docker.internal:8082', 'https://cloud.libresign.coop' );
		yield 'without it the api host is used'   => array( '', 'https://cloud.libresign.coop', 'https://cloud.libresign.coop' );
		yield 'a blank public host is ignored'    => array( '   ', 'https://cloud.libresign.coop', 'https://cloud.libresign.coop' );
		yield 'both are trimmed'                  => array( '', '  https://cloud.libresign.coop  ', 'https://cloud.libresign.coop' );
		yield 'nothing configured, nothing shown' => array( '', '', '' );
	}

	public function test_a_page_without_polylang_is_its_own_translation() {
		$page_id = self::factory()->post->create( array( 'post_type' => 'page' ) );

		$this->assertSame( $page_id, libresign_get_translated_page_id( $page_id, 'pt' ) );
		$this->assertSame( $page_id, libresign_get_translated_page_id( $page_id ) );
	}

	/**
	 * @dataProvider provide_missing_pages
	 *
	 * @param mixed $page_id Page identifier.
	 */
	public function test_a_missing_page_has_no_translation( $page_id ) {
		$this->assertSame( 0, libresign_get_translated_page_id( $page_id, 'pt' ) );
	}

	/**
	 * @return iterable<string, array{0: mixed}>
	 */
	public static function provide_missing_pages() {
		yield 'no page'       => array( 0 );
		yield 'a negative id' => array( -1 );
		yield 'an empty id'   => array( '' );
	}

	public function test_the_rewrite_rules_are_flushed_once_per_version() {
		update_option( 'libresign_root_my_account_rewrite_version', 'stale' );

		libresign_maybe_flush_root_my_account_endpoints();

		$this->assertSame( LIBRESIGN_WP_REWRITE_VERSION, get_option( 'libresign_root_my_account_rewrite_version' ) );
	}

	public function test_the_settings_link_comes_first_on_the_plugins_screen() {
		$links = libresign_add_settings_link( array( '<a href="#">Deactivate</a>' ) );

		$this->assertCount( 2, $links );
		$this->assertStringContainsString( 'options-general.php?page=libresign-config', $links[0] );
		$this->assertSame( '<a href="#">Deactivate</a>', $links[1] );
	}

	public function test_the_settings_are_registered_on_admin_init() {
		$this->assertSame( 10, has_action( 'admin_init', 'libresign_register_settings' ) );
	}

	public function test_the_post_author_is_exposed_with_a_gravatar_hash() {
		$user_id = (int) self::factory()->user->create(
			array(
				'user_email'   => ' Ana@Example.ORG ',
				'display_name' => 'Ana Lima',
			)
		);
		$post    = get_post( self::factory()->post->create( array( 'post_author' => $user_id ) ) );

		$response = new WP_REST_Response( array( 'author' => $user_id ) );
		$filtered = apply_filters( 'rest_prepare_post', $response, $post, new WP_REST_Request( 'GET', '/wp/v2/posts' ) );

		$this->assertInstanceOf( WP_REST_Response::class, $filtered );
		$this->assertSame(
			array(
				// The author identifier is whatever post_author holds, a string.
				'id'            => (string) $user_id,
				'name'          => 'Ana Lima',
				'gravatar_hash' => md5( 'ana@example.org' ),
			),
			$filtered->get_data()['author']
		);
	}

	/**
	 * @param bool $as_front_page Whether the site opens on it.
	 * @return int
	 */
	private function create_the_account_page( $as_front_page ) {
		$account_page_id = (int) self::factory()->post->create(
			array(
				'post_type' => 'page',
				'post_name' => 'my-account',
			)
		);
		update_option( 'woocommerce_myaccount_page_id', $account_page_id );

		if ( $as_front_page ) {
			update_option( 'show_on_front', 'page' );
			update_option( 'page_on_front', $account_page_id );
		}

		return $account_page_id;
	}

	/**
	 * @param string $pattern Rewrite pattern.
	 * @return string|null
	 */
	private function rewrite_target( $pattern ) {
		global $wp_rewrite;

		return $wp_rewrite->extra_rules_top[ $pattern ] ?? null;
	}

	/**
	 * @return string
	 */
	private function render_deploy_notices() {
		ob_start();
		libresign_show_github_action_status_notice();

		return (string) ob_get_clean();
	}

	/**
	 * @return string
	 */
	private function render_settings_page() {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		ob_start();
		libresign_config_page();

		return (string) ob_get_clean();
	}

	/**
	 * @return string
	 */
	private function render_nextcloud_link() {
		ob_start();
		libresign_render_nextcloud_account_button();

		return (string) ob_get_clean();
	}

	public function test_a_successful_deploy_is_shown_once_on_the_next_admin_screen() {
		$this->github->answer_with( FakeHttp::response( 204 ) );
		$post_id = self::factory()->post->create(
			array(
				'post_status' => 'publish',
				'post_title'  => 'Release notes',
			)
		);

		$html = $this->render_deploy_notices();

		$this->assertStringContainsString( 'class="notice notice-success is-dismissible"', $html );
		$this->assertStringContainsString( 'Post: <strong>Release notes</strong>', $html );
		$this->assertStringContainsString( 'ID: ' . $post_id, $html );
		$this->assertStringContainsString( 'Idioma: <strong>indefinido</strong>', $html );
		$this->assertSame( '', $this->render_deploy_notices() );
	}

	public function test_a_refused_deploy_is_shown_as_an_error() {
		$this->github->answer_with( FakeHttp::response( 401, (string) wp_json_encode( array( 'message' => 'Bad credentials' ) ) ) );
		self::factory()->post->create( array( 'post_status' => 'publish' ) );

		$html = $this->render_deploy_notices();

		$this->assertStringContainsString( 'class="notice notice-error is-dismissible"', $html );
		$this->assertStringContainsString( 'Bad credentials', $html );
	}

	public function test_an_admin_screen_without_a_deploy_shows_no_notice() {
		$this->assertSame( '', $this->render_deploy_notices() );
	}

	public function test_the_settings_page_never_shows_the_stored_token() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		update_option( 'libresign_github_deploy_organization_repository', 'LibreSign/site"><script>' );

		$html = $this->render_settings_page();

		$this->assertStringNotContainsString( 'deploy-token', $html );
		$this->assertStringNotContainsString( (string) get_option( 'libresign_github_deploy_token' ), $html );
		$this->assertStringContainsString( 'placeholder="•••••••••• (altere aqui)"', $html );
		$this->assertStringContainsString( 'value="LibreSign/site&quot;&gt;&lt;script&gt;"', $html );
		$this->assertStringContainsString( "name='option_page' value='libresign_settings_group'", $html );
	}

	public function test_the_settings_page_has_no_placeholder_before_a_token_is_saved() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		delete_option( 'libresign_github_deploy_token' );

		$this->assertStringContainsString( 'placeholder=""', $this->render_settings_page() );
	}

	public function test_the_settings_page_is_refused_to_who_cannot_manage_options() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );

		$this->expectException( WPDieException::class );

		libresign_config_page();
	}

	public function test_the_account_endpoints_are_served_at_the_root_when_the_account_page_is_the_front_page() {
		$account_page_id = $this->create_the_account_page( true );

		libresign_register_root_my_account_endpoints();
		libresign_register_my_account_page_aliases();

		$this->assertSame(
			'index.php?page_id=' . $account_page_id . '&payment-methods=$matches[1]',
			$this->rewrite_target( '^payment\-methods(?:/(.*))?/?$' )
		);
		$this->assertSame(
			'index.php?page_id=' . $account_page_id . '&lost-password=$matches[1]',
			$this->rewrite_target( '^lost\-password(?:/(.*))?/?$' )
		);
		$this->assertSame( 'index.php?page_id=' . $account_page_id, $this->rewrite_target( '^my-account/?$' ) );
	}

	public function test_the_account_endpoints_stay_under_the_account_page_when_it_is_not_the_front_page() {
		$this->create_the_account_page( false );

		libresign_register_root_my_account_endpoints();
		libresign_register_my_account_page_aliases();

		$this->assertNull( $this->rewrite_target( '^payment\-methods(?:/(.*))?/?$' ) );
		$this->assertNull( $this->rewrite_target( '^my-account/?$' ) );
	}

	public function test_the_order_payment_and_receipt_screens_are_routed_to_the_checkout_page() {
		$checkout_page_id = (int) self::factory()->post->create(
			array(
				'post_type' => 'page',
				'post_name' => 'finalizar-compra',
			)
		);
		update_option( 'woocommerce_checkout_page_id', $checkout_page_id );

		libresign_register_checkout_endpoints();

		$this->assertSame(
			'index.php?page_id=' . $checkout_page_id . '&order-pay=$matches[1]',
			$this->rewrite_target( '^finalizar\-compra/order\-pay(?:/(.*))?/?$' )
		);
		$this->assertSame(
			'index.php?page_id=' . $checkout_page_id . '&order-received=$matches[1]',
			$this->rewrite_target( '^finalizar\-compra/order\-received(?:/(.*))?/?$' )
		);
	}

	public function test_no_checkout_route_is_registered_without_a_checkout_page() {
		update_option( 'woocommerce_checkout_page_id', '' );
		global $wp_rewrite;
		$rules_before = $wp_rewrite->extra_rules_top;

		libresign_register_checkout_endpoints();

		$this->assertSame( $rules_before, $wp_rewrite->extra_rules_top );
	}

	public function test_an_account_endpoint_at_the_root_is_not_redirected_to_the_front_page() {
		$this->create_the_account_page( true );
		$this->go_to( home_url( '/payment-methods/' ) );

		$this->assertFalse( libresign_disable_canonical_redirect_for_root_my_account_endpoints( home_url( '/' ), home_url( '/payment-methods/' ) ) );

		libresign_prevent_root_my_account_endpoint_redirects();

		$this->assertFalse( has_action( 'template_redirect', 'redirect_canonical' ) );
		$this->assertFalse( has_action( 'template_redirect', 'wp_old_slug_redirect' ) );
	}

	public function test_any_other_page_keeps_its_canonical_redirect() {
		$this->create_the_account_page( true );
		$this->go_to( home_url( '/hello-world/' ) );

		$this->assertSame( home_url( '/?p=1' ), libresign_disable_canonical_redirect_for_root_my_account_endpoints( home_url( '/?p=1' ), home_url( '/hello-world/' ) ) );

		libresign_prevent_root_my_account_endpoint_redirects();

		$this->assertSame( 10, has_action( 'template_redirect', 'redirect_canonical' ) );
	}

	public function test_an_account_endpoint_is_redirected_as_usual_when_the_account_page_is_not_the_front_page() {
		$this->create_the_account_page( false );
		$this->go_to( home_url( '/payment-methods/' ) );

		$this->assertSame( home_url( '/' ), libresign_disable_canonical_redirect_for_root_my_account_endpoints( home_url( '/' ), home_url( '/payment-methods/' ) ) );
	}

	public function test_a_signed_in_customer_is_sent_to_nextcloud_from_the_account_screen() {
		update_option( 'nextcloud_public_host', 'https://cloud.libresign.coop' );
		$this->go_to( get_permalink( $this->create_the_account_page( false ) ) );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'customer' ) ) );

		$html = $this->render_nextcloud_link();

		$this->assertStringContainsString( 'href="https://cloud.libresign.coop"', $html );
		$this->assertStringContainsString( 'href="' . LIBRESIGN_FAQ_URL . '"', $html );
	}

	public function test_a_visitor_is_not_sent_to_nextcloud() {
		update_option( 'nextcloud_public_host', 'https://cloud.libresign.coop' );
		$this->go_to( get_permalink( $this->create_the_account_page( false ) ) );
		wp_set_current_user( 0 );

		$this->assertSame( '', $this->render_nextcloud_link() );
	}

	public function test_the_nextcloud_link_is_only_on_the_account_screen() {
		update_option( 'nextcloud_public_host', 'https://cloud.libresign.coop' );
		$this->create_the_account_page( false );
		$this->go_to( get_permalink( self::factory()->post->create( array( 'post_type' => 'page' ) ) ) );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'customer' ) ) );

		$this->assertSame( '', $this->render_nextcloud_link() );
	}

	public function test_no_nextcloud_link_without_a_nextcloud_host() {
		update_option( 'nextcloud_public_host', '' );
		update_option( 'nextcloud_api_host', '' );
		$this->go_to( get_permalink( $this->create_the_account_page( false ) ) );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'customer' ) ) );

		$this->assertSame( '', $this->render_nextcloud_link() );
	}

	public function test_the_plugin_requires_the_wordpress_version_the_suite_runs_against() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$data = get_plugin_data( dirname( __DIR__, 2 ) . '/libresign-wp-customizations.php', false, false );

		$this->assertSame( '7.0', $data['RequiresWP'] );
	}
}

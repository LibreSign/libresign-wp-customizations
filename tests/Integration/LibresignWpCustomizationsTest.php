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
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * The deploy dispatch, the REST version route, the noindex tag and the
 * settings storage, all against a real WordPress.
 */
final class LibresignWpCustomizationsTest extends WP_UnitTestCase {

	use RegistersPluginSettings;

	/**
	 * GitHub, answered locally.
	 *
	 * @var FakeHttp
	 */
	private $github;

	public function set_up() {
		parent::set_up();

		$this->github = new FakeHttp();

		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init', $wp_rest_server );

		update_option( 'libresign_github_deploy_organization_repository', 'LibreSign/site' );
	}

	public function tear_down() {
		global $wp_rest_server;
		$wp_rest_server = null;

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

		$this->assertSame( 'Bearer ', $this->github->args()['headers']['Authorization'] );
	}

	public function test_a_setting_of_zero_is_stored_instead_of_being_taken_for_a_blank_field() {
		$this->register_plugin_settings();

		update_option( 'libresign_github_webhook_secret', 'the-previous-secret' );
		update_option( 'libresign_github_webhook_secret', '0' );

		$this->assertSame( '0', libresign_github_webhook_secret() );
	}

	public function test_saving_an_empty_deploy_token_keeps_the_previous_one() {
		update_option( 'libresign_github_deploy_token', 'placeholder' );
		$this->register_plugin_settings();

		update_option( 'libresign_github_deploy_token', 'a-personal-access-token' );
		$stored = get_option( 'libresign_github_deploy_token' );

		update_option( 'libresign_github_deploy_token', '' );

		$this->assertSame( $stored, get_option( 'libresign_github_deploy_token' ) );
	}

	/**
	 * @dataProvider provide_settings
	 *
	 * @param string $option   Option name.
	 * @param string $saved    Value submitted on the settings screen.
	 * @param string $expected Value actually stored.
	 */
	public function test_the_settings_fall_back_to_the_production_defaults( $option, $saved, $expected ) {
		$this->register_plugin_settings();

		update_option( $option, $saved );

		$this->assertSame( $expected, get_option( $option ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string, 2: string}>
	 */
	public static function provide_settings() {
		yield 'an empty origin falls back'   => array( 'libresign_site_origin', '   ', 'https://libresign.coop' );
		yield 'the origin loses its slash'   => array( 'libresign_site_origin', 'https://staging.libresign.coop/', 'https://staging.libresign.coop' );
		yield 'an empty workflow falls back' => array( 'libresign_site_deploy_workflow_name', '', 'pages build and deployment' );
		yield 'the workflow is trimmed'      => array( 'libresign_site_deploy_workflow_name', '  deploy  ', 'deploy' );
		yield 'an empty branch falls back'   => array( 'libresign_site_deploy_branch_name', '', 'gh-pages' );
		yield 'the branch is kept'           => array( 'libresign_site_deploy_branch_name', 'main', 'main' );
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
}

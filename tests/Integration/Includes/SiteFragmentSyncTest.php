<?php
/**
 * Characterization tests for the static site fragment synchronization.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Integration\Includes;

use LibreSign\WPCustomizations\Tests\Support\FakeHttp;
use WP_Error;
use WP_UnitTestCase;

/**
 * The outgoing requests are answered by the pre_http_request filter, so the
 * fetching, storing and error paths run exactly as they do in production.
 */
final class SiteFragmentSyncTest extends WP_UnitTestCase {

	private const ORIGIN = 'https://libresign.coop';

	/**
	 * The static site origin, answered locally.
	 *
	 * @var FakeHttp
	 */
	private $origin;

	public function set_up() {
		parent::set_up();

		$this->origin = new FakeHttp();
	}

	/**
	 * @dataProvider provide_origins
	 *
	 * @param string $origin   Raw origin value.
	 * @param string $expected Normalized origin.
	 */
	public function test_normalize_site_origin( $origin, $expected ) {
		$this->assertSame( $expected, libresign_site_fragment_normalize_site_origin( $origin ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string}>
	 */
	public static function provide_origins() {
		yield 'an origin already normalized' => array( 'https://libresign.coop', 'https://libresign.coop' );
		yield 'the trailing slash goes away' => array( 'https://libresign.coop/', 'https://libresign.coop' );
		yield 'whitespace goes away'         => array( "  https://libresign.coop/  \n", 'https://libresign.coop' );
		yield 'a path is preserved'          => array( 'https://libresign.coop/site/', 'https://libresign.coop/site' );
		yield 'a port is preserved'          => array( 'http://localhost:8081/', 'http://localhost:8081' );
		yield 'a javascript url is dropped'  => array( 'javascript:alert(1)', '' );
		yield 'an empty origin stays empty'  => array( '', '' );
	}

	public function test_a_fragment_is_fetched_from_the_origin() {
		$this->origin->answer_with( FakeHttp::response( 200, '<header>site</header>' ) );

		$this->assertSame( '<header>site</header>', libresign_fetch_site_fragment( self::ORIGIN, 'header' ) );
		$this->assertSame( array( self::ORIGIN . '/fragments/header/' ), $this->origin->urls() );
	}

	public function test_a_failing_status_becomes_an_error() {
		$this->origin->answer_with( FakeHttp::response( 404, 'Not Found' ) );

		$result = libresign_fetch_site_fragment( self::ORIGIN, 'header' );

		$this->assertWPError( $result );
		$this->assertSame( 'libresign_fragment_fetch_failed', $result->get_error_code() );
	}

	public function test_an_empty_body_becomes_an_error() {
		$this->origin->answer_with( FakeHttp::response( 200, "  \n" ) );

		$result = libresign_fetch_site_fragment( self::ORIGIN, 'header' );

		$this->assertWPError( $result );
		$this->assertSame( 'libresign_fragment_empty', $result->get_error_code() );
	}

	public function test_a_transport_error_is_passed_through() {
		$this->origin->answer_with( new WP_Error( 'http_request_failed', 'Connection refused' ) );

		$result = libresign_fetch_site_fragment( self::ORIGIN, 'header' );

		$this->assertWPError( $result );
		$this->assertSame( 'http_request_failed', $result->get_error_code() );
	}

	public function test_synchronizing_stores_every_fragment_with_its_metadata() {
		$this->origin->answer_each(
			array(
				self::ORIGIN . '/fragments/header/' => FakeHttp::response( 200, '<header>site</header>' ),
				self::ORIGIN . '/fragments/footer/' => FakeHttp::response( 200, '<footer>site</footer>' ),
			)
		);

		$result = libresign_sync_site_fragments_from_origin(
			self::ORIGIN . '/',
			array( 'header', 'footer' ),
			array(
				'generated_at' => '2026-09-14T12:00:00Z',
				'source_sha'   => '0f1e2d3',
				'source_url'   => 'https://github.com/LibreSign/site/actions/runs/1',
			)
		);

		$this->assertSame(
			array(
				'synced' => array( 'header', 'footer' ),
				'origin' => self::ORIGIN,
			),
			$result
		);

		$header = get_option( 'libresign_site_fragment_header' );

		$this->assertSame( '<header>site</header>', $header['html'] );
		$this->assertSame( self::ORIGIN, $header['origin'] );
		$this->assertSame( '2026-09-14T12:00:00Z', $header['generated_at'] );
		$this->assertSame( '0f1e2d3', $header['source_sha'] );
		$this->assertSame( 'https://github.com/LibreSign/site/actions/runs/1', $header['source_url'] );
		$this->assertMatchesRegularExpression( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $header['synced_at'] );
		$this->assertSame( '<footer>site</footer>', libresign_get_site_fragment_html( 'footer' ) );
	}

	public function test_missing_metadata_is_stored_as_empty_strings() {
		$this->origin->answer_with( FakeHttp::response( 200, '<header>site</header>' ) );

		libresign_sync_site_fragments_from_origin( self::ORIGIN, array( 'header' ) );

		$header = get_option( 'libresign_site_fragment_header' );

		$this->assertSame( '', $header['generated_at'] );
		$this->assertSame( '', $header['source_sha'] );
		$this->assertSame( '', $header['source_url'] );
	}

	public function test_one_broken_fragment_does_not_stop_the_other() {
		$this->origin->answer_each(
			array(
				self::ORIGIN . '/fragments/header/' => FakeHttp::response( 500, 'Server Error' ),
				self::ORIGIN . '/fragments/footer/' => FakeHttp::response( 200, '<footer>site</footer>' ),
			)
		);

		$result = libresign_sync_site_fragments_from_origin( self::ORIGIN, array( 'header', 'footer' ) );

		$this->assertSame( array( 'footer' ), $result['synced'] );
		$this->assertSame( '', libresign_get_site_fragment_html( 'header' ) );
		$this->assertSame( '<footer>site</footer>', libresign_get_site_fragment_html( 'footer' ) );
	}

	public function test_an_origin_that_is_entirely_down_returns_the_last_error() {
		$this->origin->answer_with( FakeHttp::response( 500, 'Server Error' ) );

		$result = libresign_sync_site_fragments_from_origin( self::ORIGIN, array( 'header', 'footer' ) );

		$this->assertWPError( $result );
		$this->assertSame( 'libresign_fragment_fetch_failed', $result->get_error_code() );
	}

	public function test_blank_fragment_names_are_skipped() {
		$this->origin->answer_with( FakeHttp::response( 200, '<header>site</header>' ) );

		$result = libresign_sync_site_fragments_from_origin( self::ORIGIN, array( '', '   ', 'header' ) );

		$this->assertSame( array( 'header' ), $result['synced'] );
		$this->assertSame( array( self::ORIGIN . '/fragments/header/' ), $this->origin->urls() );
	}

	public function test_syncing_nothing_reports_no_fragments() {
		$result = libresign_sync_site_fragments_from_origin( self::ORIGIN, array() );

		$this->assertSame(
			array(
				'synced' => array(),
				'origin' => self::ORIGIN,
			),
			$result
		);
	}

	public function test_a_fragment_that_was_never_synced_has_no_html() {
		$this->assertSame( '', libresign_get_site_fragment_html( 'header' ) );
		$this->assertSame( '', libresign_get_site_fragment_html( 'does-not-exist' ) );
	}

	public function test_a_fragment_stored_without_html_has_no_html() {
		update_option( 'libresign_site_fragment_header', array( 'origin' => self::ORIGIN ) );

		$this->assertSame( '', libresign_get_site_fragment_html( 'header' ) );
	}
}

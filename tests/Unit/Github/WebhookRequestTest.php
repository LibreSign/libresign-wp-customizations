<?php
/**
 * Tests for the delivery received on the webhook endpoint.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\WebhookRequest;
use PHPUnit\Framework\TestCase;

/**
 * What the endpoint reads out of the headers and the body.
 */
final class WebhookRequestTest extends TestCase {

	/**
	 * A delivery with only the header under test filled in.
	 *
	 * @param array<string, string> $headers Values replacing the empty defaults.
	 * @return WebhookRequest
	 */
	private static function delivery( array $headers = array() ) {
		$headers = array_merge(
			array(
				'user_agent'  => 'GitHub-Hookshot/044aadd',
				'event'       => 'workflow_run',
				'signature'   => '',
				'delivery_id' => 'delivery-1',
				'body'        => '{}',
			),
			$headers
		);

		return new WebhookRequest(
			$headers['user_agent'],
			$headers['event'],
			$headers['signature'],
			$headers['delivery_id'],
			$headers['body']
		);
	}

	/**
	 * @dataProvider provide_user_agents
	 *
	 * @param string $user_agent User agent header.
	 * @param bool   $expected   Expected result.
	 */
	public function test_is_from_github( $user_agent, $expected ) {
		$this->assertSame( $expected, self::delivery( array( 'user_agent' => $user_agent ) )->is_from_github() );
	}

	/**
	 * @return iterable<string, array{0: string, 1: bool}>
	 */
	public static function provide_user_agents() {
		yield 'the agent GitHub sends'       => array( 'GitHub-Hookshot/044aadd', true );
		yield 'surrounding whitespace'       => array( "  GitHub-Hookshot/044aadd\n", true );
		yield 'the match is case sensitive'  => array( 'github-hookshot/044aadd', false );
		yield 'the prefix has to come first' => array( 'curl/8.7.1 GitHub-Hookshot/044aadd', false );
		yield 'another client'               => array( 'curl/8.7.1', false );
		yield 'no user agent at all'         => array( '', false );
	}

	/**
	 * @dataProvider provide_events
	 *
	 * @param string $event    X-GitHub-Event header.
	 * @param string $expected Normalized event name.
	 */
	public function test_event( $event, $expected ) {
		$this->assertSame( $expected, self::delivery( array( 'event' => $event ) )->event() );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string}>
	 */
	public static function provide_events() {
		yield 'as GitHub sends it' => array( 'workflow_run', 'workflow_run' );
		yield 'uppercase'          => array( 'Workflow_Run', 'workflow_run' );
		yield 'padded'             => array( "  ping \n", 'ping' );
		yield 'absent'             => array( '', '' );
	}

	public function test_the_delivery_identifier_is_kept_as_received() {
		$this->assertSame( '  delivery-1 ', self::delivery( array( 'delivery_id' => '  delivery-1 ' ) )->delivery_id() );
	}

	public function test_the_signature_is_checked_against_the_body() {
		$delivery = self::delivery(
			array(
				'body'      => '{"action":"completed"}',
				'signature' => 'sha256=' . hash_hmac( 'sha256', '{"action":"completed"}', 'the-secret' ),
			)
		);

		$this->assertTrue( $delivery->has_valid_signature( 'the-secret' ) );
		$this->assertFalse( $delivery->has_valid_signature( 'another-secret' ) );
	}

	/**
	 * @dataProvider provide_bodies
	 *
	 * @param string             $body     Raw request body.
	 * @param array<mixed>|null  $expected Expected payload.
	 */
	public function test_payload( $body, $expected ) {
		$this->assertSame( $expected, self::delivery( array( 'body' => $body ) )->payload() );
	}

	/**
	 * @return iterable<string, array{0: string, 1: array<mixed>|null}>
	 */
	public static function provide_bodies() {
		yield 'a json object'        => array( '{"action":"completed"}', array( 'action' => 'completed' ) );
		yield 'an empty object'      => array( '{}', array() );
		yield 'a json array'         => array( '[1,2]', array( 1, 2 ) );
		yield 'not json at all'      => array( 'not json', null );
		yield 'a json scalar'        => array( '"completed"', null );
		yield 'an empty body'        => array( '', null );
	}
}

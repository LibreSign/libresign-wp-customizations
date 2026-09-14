<?php
/**
 * Characterization tests for the pure helpers of includes/github-site-webhook.php.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Includes;

use PHPUnit\Framework\TestCase;

/**
 * Signature, user agent and payload parsing, none of which touch WordPress.
 */
final class GithubSiteWebhookTest extends TestCase {

	private const BODY   = '{"action":"completed"}';
	private const SECRET = 'a-shared-secret';

	/**
	 * Signature of self::BODY under self::SECRET.
	 */
	private static function digest() {
		return hash_hmac( 'sha256', self::BODY, self::SECRET );
	}

	/**
	 * @dataProvider provide_signatures
	 *
	 * @param string $body      Raw request body.
	 * @param string $signature Signature header value.
	 * @param string $secret    Shared secret.
	 * @param bool   $expected  Expected verification result.
	 */
	public function test_verify_github_webhook_signature( $body, $signature, $secret, $expected ) {
		$this->assertSame( $expected, libresign_verify_github_webhook_signature( $body, $signature, $secret ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string, 2: string, 3: bool}>
	 */
	public static function provide_signatures() {
		yield 'signature sent the way GitHub sends it' => array( self::BODY, 'sha256=' . self::digest(), self::SECRET, true );
		yield 'prefix is optional'                     => array( self::BODY, self::digest(), self::SECRET, true );
		yield 'prefix is case insensitive'             => array( self::BODY, 'SHA256=' . self::digest(), self::SECRET, true );
		yield 'hexadecimal is case insensitive'        => array( self::BODY, strtoupper( self::digest() ), self::SECRET, true );
		yield 'surrounding whitespace is trimmed'      => array( self::BODY, '  sha256=' . self::digest() . "\n", '  ' . self::SECRET . ' ', true );
		yield 'another secret does not match'          => array( self::BODY, 'sha256=' . self::digest(), 'another-secret', false );
		yield 'a tampered body does not match'         => array( self::BODY . ' ', 'sha256=' . self::digest(), self::SECRET, false );
		yield 'an empty body is never valid'           => array( '', 'sha256=' . self::digest(), self::SECRET, false );
		yield 'an empty secret is never valid'         => array( self::BODY, 'sha256=' . self::digest(), '', false );
		yield 'an empty signature is never valid'      => array( self::BODY, '', self::SECRET, false );
		yield 'a non hexadecimal signature is refused' => array( self::BODY, 'sha256=not-a-digest', self::SECRET, false );
		yield 'a truncated signature is refused'       => array( self::BODY, 'sha256=' . substr( self::digest(), 0, 32 ), self::SECRET, false );
	}

	/**
	 * @dataProvider provide_user_agents
	 *
	 * @param string $user_agent User agent header.
	 * @param bool   $expected   Expected result.
	 */
	public function test_is_github_hookshot_user_agent( $user_agent, $expected ) {
		$this->assertSame( $expected, libresign_is_github_hookshot_user_agent( $user_agent ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: bool}>
	 */
	public static function provide_user_agents() {
		yield 'the agent GitHub sends'          => array( 'GitHub-Hookshot/044aadd', true );
		yield 'surrounding whitespace'          => array( "  GitHub-Hookshot/044aadd\n", true );
		yield 'the match is case sensitive'     => array( 'github-hookshot/044aadd', false );
		yield 'the prefix has to come first'    => array( 'curl/8.7.1 GitHub-Hookshot/044aadd', false );
		yield 'another client'                  => array( 'curl/8.7.1', false );
		yield 'no user agent at all'            => array( '', false );
	}

	/**
	 * @dataProvider provide_payloads
	 *
	 * @param array<string, mixed> $payload  Parsed webhook payload.
	 * @param string               $expected Expected workflow name.
	 */
	public function test_site_deploy_workflow_name_from_payload( $payload, $expected ) {
		$this->assertSame( $expected, libresign_site_deploy_workflow_name_from_payload( $payload ) );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>, 1: string}>
	 */
	public static function provide_payloads() {
		yield 'the run name wins' => array(
			array(
				'workflow_run' => array( 'name' => 'pages build and deployment' ),
				'workflow'     => array( 'name' => 'deploy' ),
			),
			'pages build and deployment',
		);
		yield 'falls back to the workflow name' => array(
			array( 'workflow' => array( 'name' => 'deploy' ) ),
			'deploy',
		);
		yield 'a blank run name falls back too' => array(
			array(
				'workflow_run' => array( 'name' => '   ' ),
				'workflow'     => array( 'name' => 'deploy' ),
			),
			'deploy',
		);
		yield 'names are trimmed' => array(
			array( 'workflow_run' => array( 'name' => "  deploy \n" ) ),
			'deploy',
		);
		yield 'neither is present' => array( array( 'action' => 'completed' ), '' );
		yield 'an empty payload'   => array( array(), '' );
	}
}

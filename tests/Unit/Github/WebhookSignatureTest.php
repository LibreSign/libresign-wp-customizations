<?php
/**
 * Tests for the signature of a webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\WebhookSignature;
use PHPUnit\Framework\TestCase;

/**
 * The HMAC GitHub sends, checked against the shared secret.
 */
final class WebhookSignatureTest extends TestCase {

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
	public function test_matches( $body, $signature, $secret, $expected ) {
		$this->assertSame( $expected, WebhookSignature::matches( $body, $signature, $secret ) );
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
}

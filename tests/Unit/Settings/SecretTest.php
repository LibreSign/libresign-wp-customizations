<?php
/**
 * Tests for the settings stored encrypted.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Settings;

use LibreSign\WPCustomizations\Settings\Secret;
use PHPUnit\Framework\TestCase;

/**
 * The cipher protecting the deploy token and the webhook secret.
 */
final class SecretTest extends TestCase {

	/**
	 * @return Secret
	 */
	private static function secret() {
		return Secret::from_salts( 'an-auth-key', 'a-secure-auth-salt', 'a-nonce-salt' );
	}

	/**
	 * @dataProvider provide_values
	 *
	 * @param string $value Value to store.
	 */
	public function test_a_stored_value_is_read_back( $value ) {
		$secret = self::secret();

		$this->assertSame( $value, $secret->decrypt( $secret->encrypt( $value ) ) );
	}

	/**
	 * @return iterable<string, array{0: string}>
	 */
	public static function provide_values() {
		yield 'a personal access token' => array( 'ghp_0123456789abcdefghijklmnopqrstuvwxyz' );
		yield 'a webhook secret'        => array( 'a-shared-secret' );
		yield 'punctuation'             => array( '{"not":"json"} + / = %' );
		yield 'accents'                 => array( 'segredo com acentuação' );
		yield 'a single character'      => array( 'x' );
	}

	/**
	 * @dataProvider provide_values
	 *
	 * @param string $value Value to store.
	 */
	public function test_a_stored_value_is_read_back_for_sending( $value ) {
		$secret = self::secret();

		$this->assertSame( $value, $secret->decrypt_or_discard( $secret->encrypt( $value ) ) );
	}

	public function test_a_value_encrypted_elsewhere_is_discarded_instead_of_sent() {
		$stored_value = Secret::from_salts( 'another-auth-key', 'another-secure-auth-salt', 'another-nonce-salt' )
			->encrypt( 'ghp_0123456789abcdefghijklmnopqrstuvwxyz' );

		$this->assertSame( $stored_value, self::secret()->decrypt( $stored_value ) );
		$this->assertSame( '', self::secret()->decrypt_or_discard( $stored_value ) );
	}

	/**
	 * @dataProvider provide_plain_tokens
	 *
	 * @param string $stored_value Value found in the database.
	 */
	public function test_a_token_saved_by_hand_is_still_sent( $stored_value ) {
		$this->assertSame( $stored_value, self::secret()->decrypt_or_discard( $stored_value ) );
	}

	/**
	 * A GitHub token carries an underscore, which base64 does not.
	 *
	 * @return iterable<string, array{0: string}>
	 */
	public static function provide_plain_tokens() {
		yield 'a classic personal access token' => array( 'ghp_0123456789abcdefghijklmnopqrstuvwxyz' );
		yield 'a fine grained token'            => array( 'github_pat_11ABCDEFG0abcdefghijklmn' );
		yield 'nothing saved yet'               => array( '' );
	}

	public function test_the_stored_value_is_not_the_value() {
		$this->assertNotSame( 'a-shared-secret', self::secret()->encrypt( 'a-shared-secret' ) );
	}

	public function test_another_installation_cannot_read_the_value() {
		$stored_value         = self::secret()->encrypt( 'a-shared-secret' );
		$another_installation = Secret::from_salts( 'another-auth-key', 'another-secure-auth-salt', 'another-nonce-salt' );

		$this->assertNotSame( 'a-shared-secret', $another_installation->decrypt( $stored_value ) );
	}

	/**
	 * @dataProvider provide_stored_values
	 *
	 * @param string $stored_value   Value found in the database.
	 * @param string $expected Value the plugin uses.
	 */
	public function test_a_value_that_is_not_encrypted_is_used_as_it_is( $stored_value, $expected ) {
		$this->assertSame( $expected, self::secret()->decrypt( $stored_value ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string}>
	 */
	public static function provide_stored_values() {
		yield 'a secret saved by hand'        => array( 'plain-secret', 'plain-secret' );
		yield 'surrounding whitespace'        => array( "  plain-secret \n", 'plain-secret' );
		yield 'nothing saved yet'             => array( '', '' );
		yield 'blanks only'                   => array( '   ', '' );
		yield 'base64 that is not a secret'   => array( 'cGxhaW4tc2VjcmV0', 'cGxhaW4tc2VjcmV0' );
	}
}

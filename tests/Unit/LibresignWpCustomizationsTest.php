<?php
/**
 * Characterization tests for the value-in/value-out helpers of the main plugin file.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Subscription confirmation strings and the plugins screen action link.
 */
final class LibresignWpCustomizationsTest extends TestCase {

	/**
	 * @dataProvider provide_statuses
	 *
	 * @param string $new_status Status the customer asked for.
	 * @param bool   $confirmed  Whether the status requires a confirmation step.
	 */
	public function test_get_subscription_confirmation_strings( $new_status, $confirmed ) {
		$strings = libresign_get_subscription_confirmation_strings( $new_status );

		if ( ! $confirmed ) {
			$this->assertNull( $strings );

			return;
		}

		$this->assertSame( array( 'question', 'confirm', 'dismiss' ), array_keys( $strings ) );
		$this->assertNotSame( '', trim( $strings['question'] ) );
		$this->assertNotSame( '', trim( $strings['confirm'] ) );
		$this->assertNotSame( '', trim( $strings['dismiss'] ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: bool}>
	 */
	public static function provide_statuses() {
		yield 'cancelling asks for confirmation'    => array( 'cancelled', true );
		yield 'reactivating asks for confirmation'  => array( 'active', true );
		yield 'on hold goes straight through'       => array( 'on-hold', false );
		yield 'pending cancel goes straight through' => array( 'pending-cancel', false );
		yield 'an unknown status goes through'      => array( 'whatever', false );
		yield 'no status at all goes through'       => array( '', false );
	}

	public function test_cancelling_and_reactivating_do_not_share_strings() {
		$cancel     = libresign_get_subscription_confirmation_strings( 'cancelled' );
		$reactivate = libresign_get_subscription_confirmation_strings( 'active' );

		$this->assertNotSame( $cancel['question'], $reactivate['question'] );
		$this->assertNotSame( $cancel['confirm'], $reactivate['confirm'] );
	}

	public function test_settings_link_comes_first_on_the_plugins_screen() {
		$links = libresign_add_settings_link( array( '<a href="#">Deactivate</a>' ) );

		$this->assertCount( 2, $links );
		$this->assertStringContainsString( 'options-general.php?page=libresign-config', $links[0] );
		$this->assertSame( '<a href="#">Deactivate</a>', $links[1] );
	}
}

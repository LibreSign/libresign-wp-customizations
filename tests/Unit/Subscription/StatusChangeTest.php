<?php
/**
 * Tests for the subscription status changes that ask for a confirmation.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Subscription;

use LibreSign\WPCustomizations\Subscription\StatusChange;
use PHPUnit\Framework\TestCase;

/**
 * What the customer is asked before a status change goes through.
 */
final class StatusChangeTest extends TestCase {

	/**
	 * @dataProvider provide_statuses
	 *
	 * @param string $new_status Status the customer asked for.
	 * @param bool   $confirmed  Whether the status requires a confirmation step.
	 */
	public function test_confirmation_strings( $new_status, $confirmed ) {
		$strings = StatusChange::confirmation_strings( $new_status );

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
		yield 'cancelling asks for confirmation'     => array( 'cancelled', true );
		yield 'reactivating asks for confirmation'   => array( 'active', true );
		yield 'on hold goes straight through'        => array( 'on-hold', false );
		yield 'pending cancel goes straight through' => array( 'pending-cancel', false );
		yield 'an unknown status goes through'       => array( 'whatever', false );
		yield 'no status at all goes through'        => array( '', false );
	}

	public function test_cancelling_and_reactivating_do_not_share_strings() {
		$cancel     = StatusChange::confirmation_strings( 'cancelled' );
		$reactivate = StatusChange::confirmation_strings( 'active' );

		$this->assertNotSame( $cancel['question'], $reactivate['question'] );
		$this->assertNotSame( $cancel['confirm'], $reactivate['confirm'] );
	}
}

<?php
/**
 * Tests for the deploy requested from the editor.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\DeployDispatch;
use PHPUnit\Framework\TestCase;

/**
 * Which post status transitions ask GitHub for a deploy, and what is reported back.
 */
final class DeployDispatchTest extends TestCase {

	/**
	 * @dataProvider provide_transitions
	 *
	 * @param string $new_status Status the post moved to.
	 * @param string $old_status Status the post came from.
	 * @param string $post_type  Post type.
	 * @param bool   $expected   Whether a deploy is requested.
	 */
	public function test_triggers_deploy( $new_status, $old_status, $post_type, $expected ) {
		$this->assertSame( $expected, DeployDispatch::triggers_deploy( $new_status, $old_status, $post_type ) );
	}

	/**
	 * The post type only weighs in on the second half of the condition, which is
	 * the current behaviour and a bug: publishing a page deploys the site too.
	 *
	 * @return iterable<string, array{0: string, 1: string, 2: string, 3: bool}>
	 */
	public static function provide_transitions() {
		yield 'publishing a post'            => array( 'publish', 'draft', 'post', true );
		yield 'publishing a page'            => array( 'publish', 'draft', 'page', true );
		yield 'publishing a product'         => array( 'publish', 'draft', 'product', true );
		yield 'updating a published post'    => array( 'publish', 'publish', 'post', true );
		yield 'trashing a published post'    => array( 'trash', 'publish', 'post', true );
		yield 'trashing a published page'    => array( 'trash', 'publish', 'page', false );
		yield 'trashing a published product' => array( 'trash', 'publish', 'product', false );
		yield 'saving a draft'               => array( 'draft', 'draft', 'post', false );
		yield 'scheduling a post'            => array( 'future', 'draft', 'post', false );
		yield 'restoring a post from trash'  => array( 'draft', 'trash', 'post', false );
	}

	public function test_the_success_notice_links_to_the_actions_of_the_repository() {
		$this->assertStringContainsString(
			'https://github.com/LibreSign/site/actions',
			DeployDispatch::success_message( 'LibreSign/site' )
		);
	}

	public function test_the_failure_notice_carries_the_status_and_the_message() {
		$message = DeployDispatch::failure_message( 401, 'Bad credentials' );

		$this->assertStringContainsString( '401', $message );
		$this->assertStringContainsString( 'Bad credentials', $message );
	}

	public function test_the_failure_notice_survives_a_response_without_a_message() {
		$this->assertStringContainsString( '500', DeployDispatch::failure_message( 500, '' ) );
	}
}

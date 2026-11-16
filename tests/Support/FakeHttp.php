<?php
/**
 * Test double for the WordPress HTTP API.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Support;

use WP_Error;

/**
 * Answers outgoing requests through the pre_http_request filter and records them.
 *
 * This is not a mock object: it is the extension point WordPress itself offers,
 * so the code under test runs its real request building and response handling.
 */
final class FakeHttp {

	/**
	 * Requests made while this double was installed.
	 *
	 * @var array<int, array{url: string, args: array<string, mixed>}>
	 */
	private $requests = array();

	/**
	 * Answer every request with the same response.
	 *
	 * @param array<string, mixed>|WP_Error $response Canned response.
	 * @return void
	 */
	public function answer_with( $response ) {
		$this->answer_each( array( '*' => $response ) );
	}

	/**
	 * Answer each URL with its own response, falling back to the '*' entry.
	 *
	 * A URL with neither an entry of its own nor a '*' fallback is answered with
	 * an error naming it, so a request that drifts fails as an assertion instead
	 * of as an undefined array key.
	 *
	 * @param array<string, array<string, mixed>|WP_Error> $responses Response per URL.
	 * @return void
	 */
	public function answer_each( $responses ) {
		add_filter(
			'pre_http_request',
			function ( $preempt, $args, $url ) use ( $responses ) {
				$this->requests[] = array(
					'url'  => (string) $url,
					'args' => (array) $args,
				);

				if ( isset( $responses[ $url ] ) ) {
					return $responses[ $url ];
				}

				if ( isset( $responses['*'] ) ) {
					return $responses['*'];
				}

				return new WP_Error(
					'libresign_tests_http_unstubbed',
					sprintf( 'No response was stubbed for %s.', $url )
				);
			},
			10,
			3
		);
	}

	/**
	 * Requests recorded so far.
	 *
	 * @return array<int, array{url: string, args: array<string, mixed>}>
	 */
	public function requests() {
		return $this->requests;
	}

	/**
	 * URLs requested so far.
	 *
	 * @return string[]
	 */
	public function urls() {
		return array_column( $this->requests, 'url' );
	}

	/**
	 * Arguments of a recorded request.
	 *
	 * @param int $index Position of the request.
	 * @return array<string, mixed>
	 */
	public function args( $index = 0 ) {
		return isset( $this->requests[ $index ] ) ? $this->requests[ $index ]['args'] : array();
	}

	/**
	 * Drop the recorded requests, keeping the responses in place.
	 *
	 * @return void
	 */
	public function forget() {
		$this->requests = array();
	}

	/**
	 * Build a response in the shape the HTTP API returns.
	 *
	 * @param int    $code HTTP status code.
	 * @param string $body Response body.
	 * @return array<string, mixed>
	 */
	public static function response( $code, $body = '' ) {
		return array(
			'headers'  => array(),
			'body'     => $body,
			'response' => array(
				'code'    => $code,
				'message' => get_status_header_desc( $code ),
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}
}

<?php
/**
 * Site fragment synchronization from the static origin.
 *
 * Fetches the header and footer HTML fragments published by the static site
 * (libresign.coop) and stores them as WordPress options so the active theme
 * can include up-to-date navigation without rebuilding WordPress.
 *
 * PR status comments are intentionally absent from this file.
 * The deploy.yml GitHub Actions workflow posts those comments via
 * GITHUB_TOKEN (github-actions[bot]) so no personal access token is needed.
 *
 * @package LibreSign_WP_Customizations
 */

defined( 'ABSPATH' ) || exit;

/**
 * Normalize a site origin URL: trim whitespace and remove trailing slash.
 *
 * @param string $origin Raw origin value.
 * @return string
 */
function libresign_site_fragment_normalize_site_origin( $origin ) {
	return rtrim( esc_url_raw( trim( (string) $origin ) ), '/' );
}

/**
 * Fetch the HTML of a single fragment from the static site origin.
 *
 * @param string $origin   Base URL with no trailing slash, e.g. 'https://libresign.coop'.
 * @param string $fragment Fragment name, e.g. 'header' or 'footer'.
 * @return string|WP_Error HTML string, or WP_Error on failure.
 */
function libresign_fetch_site_fragment( $origin, $fragment ) {
	$url = $origin . '/fragments/' . rawurlencode( (string) $fragment ) . '/';

	$response = wp_remote_get(
		$url,
		array(
			'timeout'    => 30,
			'user-agent' => 'WordPress/LibreSign-Fragment-Sync',
			'sslverify'  => true,
		)
	);

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$code = (int) wp_remote_retrieve_response_code( $response );
	if ( 200 !== $code ) {
		return new WP_Error(
			'libresign_fragment_fetch_failed',
			sprintf(
				/* translators: 1: HTTP status code, 2: fragment name, 3: URL */
				__( 'HTTP %1$s fetching fragment \u201c%2$s\u201d from %3$s.', 'libresign-wp-customizations' ),
				$code,
				$fragment,
				$url
			)
		);
	}

	$body = wp_remote_retrieve_body( $response );
	if ( '' === trim( $body ) ) {
		return new WP_Error(
			'libresign_fragment_empty',
			sprintf(
				/* translators: fragment name */
				__( 'Empty body received for fragment \u201c%s\u201d.', 'libresign-wp-customizations' ),
				$fragment
			)
		);
	}

	return $body;
}

/**
 * Fetch and store site fragments from the static origin.
 *
 * Each fragment is persisted as a WordPress option named
 * `libresign_site_fragment_{name}` containing the raw HTML and metadata.
 *
 * @param string               $origin    Base URL of the static site (no trailing slash).
 * @param string[]             $fragments Fragment names to sync, e.g. ['header', 'footer'].
 * @param array<string, mixed> $metadata  Optional metadata: generated_at, source_sha, source_url.
 * @return array{synced: string[], origin: string}|WP_Error
 */
function libresign_sync_site_fragments_from_origin( $origin, $fragments, $metadata = array() ) {
	$origin     = libresign_site_fragment_normalize_site_origin( $origin );
	$synced     = array();
	$last_error = null;

	foreach ( $fragments as $fragment ) {
		$fragment = sanitize_key( (string) $fragment );
		if ( '' === $fragment ) {
			continue;
		}

		$html = libresign_fetch_site_fragment( $origin, $fragment );
		if ( is_wp_error( $html ) ) {
			$last_error = $html;
			continue;
		}

		update_option(
			'libresign_site_fragment_' . $fragment,
			array(
				'html'         => $html,
				'origin'       => $origin,
				'generated_at' => isset( $metadata['generated_at'] ) ? (string) $metadata['generated_at'] : '',
				'source_sha'   => isset( $metadata['source_sha'] ) ? (string) $metadata['source_sha'] : '',
				'source_url'   => isset( $metadata['source_url'] ) ? (string) $metadata['source_url'] : '',
				'synced_at'    => gmdate( 'Y-m-d\\TH:i:s\\Z' ),
			),
			false
		);

		$synced[] = $fragment;
	}

	if ( empty( $synced ) && null !== $last_error ) {
		return $last_error;
	}

	return array(
		'synced' => $synced,
		'origin' => $origin,
	);
}

/**
 * Retrieve the stored HTML for a site fragment.
 *
 * Returns an empty string when the fragment has not been synced yet.
 *
 * @param string $fragment Fragment name, e.g. 'header' or 'footer'.
 * @return string
 */
function libresign_get_site_fragment_html( $fragment ) {
	$fragment = sanitize_key( (string) $fragment );
	$data     = get_option( 'libresign_site_fragment_' . $fragment, array() );

	return is_array( $data ) && isset( $data['html'] ) ? (string) $data['html'] : '';
}

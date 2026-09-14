<?php
/**
 * Configuration consumed by the WordPress test suite.
 *
 * Every value can be overridden through the environment, so the same file
 * serves the local Docker stack and CI.
 *
 * @package LibreSign_WP_Customizations
 */

/**
 * Read an environment variable, falling back to a default.
 *
 * @param string $name    Variable name.
 * @param string $default Value used when the variable is not set.
 * @return string
 */
function libresign_tests_env( $name, $default ) {
	$value = getenv( $name );

	return false === $value || '' === $value ? $default : $value;
}

define( 'ABSPATH', rtrim( libresign_tests_env( 'WP_CORE_DIR', dirname( __DIR__ ) . '/vendor/wordpress' ), '/' ) . '/' );

define( 'DB_NAME', libresign_tests_env( 'WP_TESTS_DB_NAME', 'wordpress_test' ) );
define( 'DB_USER', libresign_tests_env( 'WP_TESTS_DB_USER', 'root' ) );
define( 'DB_PASSWORD', libresign_tests_env( 'WP_TESTS_DB_PASSWORD', 'root' ) );
define( 'DB_HOST', libresign_tests_env( 'WP_TESTS_DB_HOST', 'mariadb' ) );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- the WordPress test suite reads this global.
$table_prefix = libresign_tests_env( 'WP_TESTS_TABLE_PREFIX', 'wptests_' );

define( 'WP_TESTS_DOMAIN', 'example.org' );
define( 'WP_TESTS_EMAIL', 'admin@example.org' );
define( 'WP_TESTS_TITLE', 'LibreSign Test Site' );
define( 'WP_PHP_BINARY', 'php' );
define( 'WPLANG', '' );

define( 'WP_DEBUG', true );

/*
 * The plugin derives the deploy token and the webhook secret encryption key
 * from these salts, so they have to be defined and stable across the suite.
 */
define( 'AUTH_KEY', 'libresign-tests-auth-key' );
define( 'SECURE_AUTH_KEY', 'libresign-tests-secure-auth-key' );
define( 'LOGGED_IN_KEY', 'libresign-tests-logged-in-key' );
define( 'NONCE_KEY', 'libresign-tests-nonce-key' );
define( 'AUTH_SALT', 'libresign-tests-auth-salt' );
define( 'SECURE_AUTH_SALT', 'libresign-tests-secure-auth-salt' );
define( 'LOGGED_IN_SALT', 'libresign-tests-logged-in-salt' );
define( 'NONCE_SALT', 'libresign-tests-nonce-salt' );

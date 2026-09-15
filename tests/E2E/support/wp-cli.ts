import { execFileSync } from 'node:child_process';

const WP_CLI_ON_THE_LOCAL_STACK =
	'docker exec -i -u www-data wordpress-docker-wordpress-1 wp --path=/var/www/html';

export function runWpCli( args: readonly string[], stdin = '' ): string {
	const [ command, ...prefix ] = (
		process.env.WP_CLI ?? WP_CLI_ON_THE_LOCAL_STACK
	).split( /\s+/ );

	return execFileSync( command, [ ...prefix, ...args ], {
		input: stdin,
		encoding: 'utf8',
		maxBuffer: 16 * 1024 * 1024,
	} );
}

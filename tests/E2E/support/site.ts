import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { runWpCli } from './wp-cli';

const SEED_SCRIPT = join( __dirname, 'seed.php' );
const STATE_DIR = join( __dirname, '..', '.state' );
const SITE_STATE = join( STATE_DIR, 'site.json' );

export const CUSTOMER_STATE = join( STATE_DIR, 'customer.json' );

export const CUSTOMER_PASSWORD =
	process.env.WP_E2E_CUSTOMER_PASSWORD ?? 'libresign-e2e';

export interface SeededSite {
	customerId: number;
	customerLogin: string;
	customerEmail: string;
	productId: number;
	subscriptionId: number;
	accountPageId: number;
	nextcloudHost: string;
}

export function seedSite(): SeededSite {
	const output = runWpCli(
		[ 'eval-file', '-', CUSTOMER_PASSWORD ],
		readFileSync( SEED_SCRIPT, 'utf8' )
	);

	runWpCli( [ 'rewrite', 'flush', '--hard' ] );

	const description = output
		.split( '\n' )
		.reverse()
		.find( ( line ) => line.startsWith( '{' ) );

	if ( ! description ) {
		throw new Error( `The seed printed no site description:\n${ output }` );
	}

	const site = JSON.parse( description ) as SeededSite;

	mkdirSync( dirname( SITE_STATE ), { recursive: true } );
	writeFileSync( SITE_STATE, JSON.stringify( site, null, '\t' ) );

	return site;
}

export function seededSite(): SeededSite {
	return JSON.parse( readFileSync( SITE_STATE, 'utf8' ) ) as SeededSite;
}

export function subscriptionStatus( subscriptionId: number ): string {
	const output = runWpCli( [
		'eval',
		`echo 'status:' . wcs_get_subscription( ${ subscriptionId } )->get_status();`,
	] );

	const status = output.match( /status:(\S+)/ );

	if ( ! status ) {
		throw new Error( `WP-CLI reported no status:\n${ output }` );
	}

	return status[ 1 ];
}

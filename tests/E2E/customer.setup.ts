import { expect, test as setup } from '@playwright/test';

import { CUSTOMER_PASSWORD, CUSTOMER_STATE, seedSite } from './support/site';

setup( 'seed the site and sign the customer in', async ( { page } ) => {
	const site = seedSite();

	await page.goto( '/wp-login.php?redirect_to=%2F' );
	await page.locator( '#user_login' ).fill( site.customerLogin );
	await page.locator( '#user_pass' ).fill( CUSTOMER_PASSWORD );
	await page.locator( '#wp-submit' ).click();

	await expect(
		page.locator( '.woocommerce-MyAccount-navigation' )
	).toBeVisible();

	await page.context().storageState( { path: CUSTOMER_STATE } );
} );

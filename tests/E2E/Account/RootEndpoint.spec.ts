import { expect, test } from '@playwright/test';

test.describe( 'Account screens served from the site root', () => {
	test( 'serves the invoices screen at /orders/', async ( { page } ) => {
		await page.goto( '/orders/' );

		await expect( page ).toHaveURL( '/orders/' );
		await expect(
			page.locator( '.woocommerce-MyAccount-navigation-link--orders' )
		).toHaveClass( /is-active/ );
	} );

	test( 'serves the billing screen at /payment-methods/', async ( {
		page,
	} ) => {
		await page.goto( '/payment-methods/' );

		await expect( page ).toHaveURL( '/payment-methods/' );
		await expect(
			page.locator(
				'.woocommerce-MyAccount-navigation-link--payment-methods'
			)
		).toHaveClass( /is-active/ );
	} );

	test( 'keeps the /my-account/ permalink working as an alias', async ( {
		page,
	} ) => {
		await page.goto( '/my-account/' );

		await expect( page ).toHaveURL( '/my-account/' );
		await expect(
			page.locator( '.woocommerce-MyAccount-navigation' )
		).toBeVisible();
	} );

	test.describe( 'signed out', () => {
		test.use( { storageState: { cookies: [], origins: [] } } );

		test( 'serves the lost password screen at /lost-password/', async ( {
			page,
		} ) => {
			await page.goto( '/lost-password/' );

			await expect( page ).toHaveURL( '/lost-password/' );
			await expect(
				page.locator( 'form.lost_reset_password' )
			).toBeVisible();
		} );
	} );
} );

import { expect, test } from '@playwright/test';

import { seededSite } from '../support/site';

const ENTRY = '.woocommerce-MyAccount-navigation-link';

test.describe( 'My Account navigation', () => {
	test( 'keeps five entries, in the order the plugin sets', async ( {
		page,
	} ) => {
		await page.goto( '/' );

		const entries = page.locator( ENTRY );
		await expect( entries ).toHaveCount( 5 );

		const order = [
			'subscriptions',
			'orders',
			'payment-methods',
			'edit-account',
			'customer-logout',
		];

		for ( const [ position, endpoint ] of order.entries() ) {
			await expect( entries.nth( position ) ).toHaveClass(
				new RegExp( `${ ENTRY.slice( 1 ) }--${ endpoint }(\\s|$)` )
			);
		}
	} );

	test( 'renames the three entries it relabels', async ( { page } ) => {
		await page.goto( '/' );

		await expect( page.locator( `${ ENTRY }--subscriptions a` ) ).toHaveText(
			'My subscription'
		);
		await expect( page.locator( `${ ENTRY }--orders a` ) ).toHaveText(
			'Invoices'
		);
		await expect(
			page.locator( `${ ENTRY }--payment-methods a` )
		).toHaveText( 'Billing' );
	} );

	test( 'titles a screen with the label its entry carries', async ( {
		page,
	} ) => {
		await page.goto( '/orders/' );

		await expect(
			page.getByRole( 'heading', { name: 'Invoices' } )
		).toBeVisible();
	} );

	test( 'shows the payment methods and the addresses on the billing screen', async ( {
		page,
	} ) => {
		await page.goto( '/payment-methods/' );

		await expect(
			page.locator( '.libresign-account-section-title' )
		).toHaveText( [ 'Payment methods', 'Addresses' ] );

		await expect(
			page.getByText(
				'These addresses are used on your invoices and subscription charges.'
			)
		).toBeVisible();
	} );

	test( 'sends the standalone addresses list to the billing screen', async ( {
		page,
	} ) => {
		await page.goto( '/edit-address/' );

		await expect( page ).toHaveURL( '/payment-methods/' );
	} );

	test( 'keeps billing highlighted while an address is being edited', async ( {
		page,
	} ) => {
		await page.goto( '/edit-address/billing/' );

		await expect(
			page.locator( `${ ENTRY }--payment-methods` )
		).toHaveClass( /is-active/ );
	} );

	test( 'points the account screens at the signature system', async ( {
		page,
	} ) => {
		await page.goto( '/' );

		const callToAction = page.locator( '.libresign-nextcloud-account-cta' );

		await expect( callToAction ).toBeVisible();
		await expect(
			callToAction.getByRole( 'link', {
				name: 'Ir para o sistema de assinaturas',
			} )
		).toHaveAttribute( 'href', seededSite().nextcloudHost );
	} );
} );

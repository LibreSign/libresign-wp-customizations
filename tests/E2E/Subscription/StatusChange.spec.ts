import { expect, Page, test } from '@playwright/test';

import { SeededSite, seedSite, subscriptionStatus } from '../support/site';

const CANCELLATION_QUESTION =
	'Are you sure you want to cancel your subscription? This action cannot be undone.';

const cancelAction = ( page: Page ) =>
	page.getByRole( 'button', { name: 'Cancel', exact: true } );

test.describe( 'Confirming a subscription status change', () => {
	let site: SeededSite;

	test.beforeEach( () => {
		site = seedSite();
	} );

	test( 'asks before cancelling instead of cancelling right away', async ( {
		page,
	} ) => {
		await page.goto( `/view-subscription/${ site.subscriptionId }/` );
		await cancelAction( page ).click();

		await expect( page.getByText( CANCELLATION_QUESTION ) ).toBeVisible();
		await expect(
			page.getByRole( 'link', { name: 'Yes, cancel subscription' } )
		).toBeVisible();
		await expect(
			page.getByRole( 'link', { name: 'No, keep subscription' } )
		).toBeVisible();

		expect( subscriptionStatus( site.subscriptionId ) ).toBe( 'active' );
	} );

	test( 'leaves the subscription active when the customer backs out', async ( {
		page,
	} ) => {
		await page.goto( `/view-subscription/${ site.subscriptionId }/` );
		await cancelAction( page ).click();
		await page
			.getByRole( 'link', { name: 'No, keep subscription' } )
			.click();

		await expect( page.getByText( CANCELLATION_QUESTION ) ).toBeHidden();

		expect( subscriptionStatus( site.subscriptionId ) ).toBe( 'active' );
	} );

	test( 'stops the renewals once the customer confirms', async ( {
		page,
	} ) => {
		await page.goto( `/view-subscription/${ site.subscriptionId }/` );
		await cancelAction( page ).click();
		await page
			.getByRole( 'link', { name: 'Yes, cancel subscription' } )
			.click();

		await expect( cancelAction( page ) ).toBeHidden();

		expect( subscriptionStatus( site.subscriptionId ) ).toBe(
			'pending-cancel'
		);
	} );
} );

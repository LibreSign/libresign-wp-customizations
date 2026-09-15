import { defineConfig, devices } from '@playwright/test';

import { CUSTOMER_STATE } from './tests/E2E/support/site';

export default defineConfig( {
	testDir: 'tests/E2E',
	outputDir: 'tests/E2E/.results',
	workers: 1,
	fullyParallel: false,
	forbidOnly: Boolean( process.env.CI ),
	retries: process.env.CI ? 1 : 0,
	reporter: process.env.CI
		? [
				[ 'github' ],
				[
					'html',
					{ open: 'never', outputFolder: 'tests/E2E/.report' },
				],
		  ]
		: [ [ 'list' ] ],
	use: {
		baseURL: process.env.WP_BASE_URL ?? 'http://localhost',
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
	},
	projects: [
		{
			name: 'setup',
			testMatch: /.*\.setup\.ts/,
			use: { ...devices[ 'Desktop Chrome' ] },
		},
		{
			name: 'customer',
			dependencies: [ 'setup' ],
			use: {
				...devices[ 'Desktop Chrome' ],
				storageState: CUSTOMER_STATE,
			},
		},
	],
} );

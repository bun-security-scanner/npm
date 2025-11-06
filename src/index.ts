/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

/// <reference types="bun-types" />
import "./types.js";
import { NpmAuditClient } from "./client.js";
import { AdvisoryProcessor } from "./processor.js";
import { logger } from "./logger.js";

/**
 * Bun Security Scanner using npm audit API
 * Integrates with npm registry's GitHub Advisory Database to detect vulnerabilities
 */
export const scanner: Bun.Security.Scanner = {
	version: "1", // This is the version of Bun security scanner implementation. You should keep this set as '1'

	async scan({ packages }) {
		try {
			logger.info(`Starting npm audit scan for ${packages.length} packages`);

			// Initialize components
			const client = new NpmAuditClient();
			const processor = new AdvisoryProcessor();

			// Fetch advisories from npm registry
			const advisories = await client.queryVulnerabilities(packages);

			// Process advisories into Bun security advisories
			const bunAdvisories = processor.processAdvisories(advisories, packages);

			logger.info(
				`npm audit scan completed: ${bunAdvisories.length} advisories found for ${packages.length} packages`,
			);

			return bunAdvisories;
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			logger.error("npm audit scanner encountered an unexpected error", {
				error: message,
			});

			// Fail-safe: allow installation to proceed on scanner errors
			return [];
		}
	},
};

// CLI entry point
if (import.meta.main) {
	const { runCli } = await import("./cli.js");
	await runCli();
}

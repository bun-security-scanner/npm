/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { beforeEach, describe, expect, test } from "bun:test";
import {
	ENV,
	HTTP,
	NPM_AUDIT_API,
	PERFORMANCE,
	SECURITY,
	getConfig,
} from "../src/constants.js";

describe("Constants", () => {
	// Store original env values
	const originalEnv: Record<string, string | undefined> = {};

	beforeEach(() => {
		// Clear test env vars
		for (const key of Object.values(ENV)) {
			originalEnv[key] = Bun.env[key];
			delete Bun.env[key];
		}
	});

	describe("NPM_AUDIT_API Constants", () => {
		test("has correct registry URL", () => {
			expect(NPM_AUDIT_API.REGISTRY_URL).toBe("https://registry.npmjs.org");
		});

		test("has correct bulk advisory path", () => {
			expect(NPM_AUDIT_API.BULK_ADVISORY_PATH).toBe(
				"/-/npm/v1/security/advisories/bulk",
			);
		});

		test("has reasonable timeout", () => {
			expect(NPM_AUDIT_API.TIMEOUT_MS).toBe(30000);
			expect(NPM_AUDIT_API.TIMEOUT_MS).toBeGreaterThan(0);
		});

		test("has valid max packages per request limit", () => {
			expect(NPM_AUDIT_API.MAX_PACKAGES_PER_REQUEST).toBe(1000);
			expect(NPM_AUDIT_API.MAX_PACKAGES_PER_REQUEST).toBeGreaterThan(0);
		});

		test("has retry configuration", () => {
			expect(NPM_AUDIT_API.MAX_RETRY_ATTEMPTS).toBe(2);
			expect(NPM_AUDIT_API.RETRY_DELAY_MS).toBe(1000);
		});
	});

	describe("HTTP Constants", () => {
		test("has correct content type", () => {
			expect(HTTP.CONTENT_TYPE).toBe("application/json");
		});

		test("has gzip content encoding", () => {
			expect(HTTP.CONTENT_ENCODING).toBe("gzip");
		});

		test("has user agent", () => {
			expect(HTTP.USER_AGENT).toMatch(/@bun-security-scanner\/npm/);
		});
	});

	describe("SECURITY Constants", () => {
		test("has CVSS fatal threshold", () => {
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBe(7.0);
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeGreaterThanOrEqual(0);
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeLessThanOrEqual(10);
		});

		test("has fatal severities list", () => {
			expect(SECURITY.FATAL_SEVERITIES).toContain("critical");
			expect(SECURITY.FATAL_SEVERITIES).toContain("high");
			expect(SECURITY.FATAL_SEVERITIES.length).toBe(2);
		});

		test("has max vulnerabilities per package", () => {
			expect(SECURITY.MAX_VULNERABILITIES_PER_PACKAGE).toBe(100);
			expect(SECURITY.MAX_VULNERABILITIES_PER_PACKAGE).toBeGreaterThan(0);
		});

		test("has max description length", () => {
			expect(SECURITY.MAX_DESCRIPTION_LENGTH).toBe(200);
			expect(SECURITY.MAX_DESCRIPTION_LENGTH).toBeGreaterThan(0);
		});
	});

	describe("PERFORMANCE Constants", () => {
		test("has max concurrent requests limit", () => {
			expect(PERFORMANCE.MAX_CONCURRENT_REQUESTS).toBe(10);
			expect(PERFORMANCE.MAX_CONCURRENT_REQUESTS).toBeGreaterThan(0);
		});

		test("has max response size", () => {
			expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBe(32 * 1024 * 1024);
			expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBeGreaterThan(0);
		});
	});

	describe("ENV Constants", () => {
		test("has correct environment variable names", () => {
			expect(ENV.LOG_LEVEL).toBe("NPM_SCANNER_LOG_LEVEL");
			expect(ENV.REGISTRY_URL).toBe("NPM_SCANNER_REGISTRY_URL");
			expect(ENV.TIMEOUT_MS).toBe("NPM_SCANNER_TIMEOUT_MS");
		});
	});

	describe("getConfig Function", () => {
		test("returns default value when env var not set", () => {
			const result = getConfig("TEST_VAR", "default");
			expect(result).toBe("default");
		});

		test("returns env value for string default", () => {
			Bun.env.TEST_VAR = "custom";
			const result = getConfig("TEST_VAR", "default");
			expect(result).toBe("custom");
		});

		test("parses number from env var", () => {
			Bun.env.TEST_VAR = "42";
			const result = getConfig("TEST_VAR", 0);
			expect(result).toBe(42);
		});

		test("returns default for invalid number", () => {
			Bun.env.TEST_VAR = "not-a-number";
			const result = getConfig("TEST_VAR", 10);
			expect(result).toBe(10);
		});

		test("parses boolean from env var", () => {
			Bun.env.TEST_VAR = "true";
			const result = getConfig("TEST_VAR", false);
			expect(result).toBe(true);
		});

		test("parses false from env var", () => {
			Bun.env.TEST_VAR = "false";
			const result = getConfig("TEST_VAR", true);
			expect(result).toBe(false);
		});

		test("handles case-insensitive boolean parsing", () => {
			Bun.env.TEST_VAR = "TRUE";
			const result = getConfig("TEST_VAR", false);
			expect(result).toBe(true);
		});

		test("uses custom parser when provided", () => {
			Bun.env.TEST_VAR = "100";
			const parser = (val: string) => Number.parseInt(val, 10) * 2;
			const result = getConfig("TEST_VAR", 0, parser);
			expect(result).toBe(200);
		});

		test("returns default when custom parser throws", () => {
			Bun.env.TEST_VAR = "invalid";
			const parser = (_val: string) => {
				throw new Error("Parse error");
			};
			const result = getConfig("TEST_VAR", 42, parser);
			expect(result).toBe(42);
		});

		test("handles empty string env var", () => {
			Bun.env.TEST_VAR = "";
			const result = getConfig("TEST_VAR", "default");
			expect(result).toBe("default");
		});

		test("parses negative numbers", () => {
			Bun.env.TEST_VAR = "-42";
			const result = getConfig("TEST_VAR", 0);
			expect(result).toBe(-42);
		});

		test("parses floating point numbers", () => {
			Bun.env.TEST_VAR = "3.14";
			const result = getConfig("TEST_VAR", 0.0);
			expect(result).toBe(3.14);
		});
	});

	describe("Real-World Configuration", () => {
		test("gets registry URL from environment", () => {
			Bun.env.NPM_SCANNER_REGISTRY_URL = "https://custom.registry.test";
			const result: string = getConfig(
				ENV.REGISTRY_URL,
				NPM_AUDIT_API.REGISTRY_URL,
			);
			expect(result).toEqual("https://custom.registry.test");
		});

		test("gets timeout from environment", () => {
			Bun.env.NPM_SCANNER_TIMEOUT_MS = "60000";
			const result: number = getConfig(
				ENV.TIMEOUT_MS,
				NPM_AUDIT_API.TIMEOUT_MS,
			);
			expect(result).toEqual(60000);
		});

		test("uses defaults when no env vars set", () => {
			const registryUrl = getConfig(
				ENV.REGISTRY_URL,
				NPM_AUDIT_API.REGISTRY_URL,
			);
			const timeout = getConfig(ENV.TIMEOUT_MS, NPM_AUDIT_API.TIMEOUT_MS);

			expect(registryUrl).toBe(NPM_AUDIT_API.REGISTRY_URL);
			expect(timeout).toBe(NPM_AUDIT_API.TIMEOUT_MS);
		});
	});

	describe("Type Safety", () => {
		test("NPM_AUDIT_API is readonly", () => {
			const constants = NPM_AUDIT_API;
			expect(Object.isFrozen(constants)).toBe(false); // Not frozen, but readonly in TS
			expect(constants.REGISTRY_URL).toBeTruthy();
		});

		test("FATAL_SEVERITIES is readonly array", () => {
			const severities = SECURITY.FATAL_SEVERITIES;
			expect(Array.isArray(severities)).toBe(true);
			expect(severities.length).toBe(2);
		});
	});

	describe("Validation", () => {
		test("timeout is positive", () => {
			expect(NPM_AUDIT_API.TIMEOUT_MS).toBeGreaterThan(0);
		});

		test("max packages per request is reasonable", () => {
			expect(NPM_AUDIT_API.MAX_PACKAGES_PER_REQUEST).toBeGreaterThan(0);
			expect(NPM_AUDIT_API.MAX_PACKAGES_PER_REQUEST).toBeLessThanOrEqual(10000);
		});

		test("retry attempts is non-negative", () => {
			expect(NPM_AUDIT_API.MAX_RETRY_ATTEMPTS).toBeGreaterThanOrEqual(0);
		});

		test("retry delay is positive", () => {
			expect(NPM_AUDIT_API.RETRY_DELAY_MS).toBeGreaterThan(0);
		});

		test("CVSS threshold is in valid range", () => {
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeGreaterThanOrEqual(0);
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeLessThanOrEqual(10);
		});

		test("max response size is reasonable", () => {
			expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBeGreaterThan(0);
			expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBeLessThan(100 * 1024 * 1024);
		});
	});
});

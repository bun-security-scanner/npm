/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { beforeEach, describe, expect, test } from "bun:test";
import { AdvisoryProcessor } from "../src/processor.js";
import type { NpmAdvisory } from "../src/schema.js";

describe("Advisory Processor", () => {
	let processor: AdvisoryProcessor;

	beforeEach(() => {
		// Set log level to error to reduce test output
		Bun.env.NPM_SCANNER_LOG_LEVEL = "error";
		processor = new AdvisoryProcessor();
	});

	describe("Basic Processing", () => {
		test("returns empty array when no advisories", () => {
			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			];

			const result = processor.processAdvisories([], packages);

			expect(result).toEqual([]);
		});

		test("returns empty array when no packages", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1065,
					title: "Prototype Pollution",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.21",
					url: "https://github.com/advisories/GHSA-xxxx",
				},
			];

			const result = processor.processAdvisories(advisories, []);

			expect(result).toEqual([]);
		});

		test("creates advisory for matching vulnerability", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: "GHSA-test-1234",
					title: "Test vulnerability",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.20",
					url: "https://github.com/advisories/GHSA-test-1234",
					overview: "This is a test vulnerability",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.19",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
			expect(result[0]).toMatchObject({
				id: "GHSA-test-1234",
				message: "Test vulnerability",
				level: "fatal",
				package: "lodash",
				url: "https://github.com/advisories/GHSA-test-1234",
				description: "This is a test vulnerability",
			});
		});

		test("returns empty array when package not affected", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1065,
					title: "Prototype Pollution",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.20",
					url: "https://github.com/advisories/GHSA-xxxx",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.21", // Not affected
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result).toEqual([]);
		});
	});

	describe("Multiple Advisories", () => {
		test("processes multiple advisories for same package", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1065,
					title: "First vulnerability",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.20",
					url: "https://github.com/advisories/GHSA-1111",
					overview: "First issue",
				},
				{
					id: 1066,
					title: "Second vulnerability",
					name: "lodash",
					severity: "moderate",
					vulnerable_versions: "<4.17.19",
					url: "https://github.com/advisories/GHSA-2222",
					overview: "Second issue",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.15",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(2);
			expect(result[0]?.description).toBe("First issue");
			expect(result[1]?.description).toBe("Second issue");
		});

		test("processes multiple packages with different advisories", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1001,
					title: "Lodash vulnerability",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.21",
					url: "https://github.com/advisories/GHSA-lodash",
				},
				{
					id: 1002,
					title: "Axios vulnerability",
					name: "axios",
					severity: "moderate",
					vulnerable_versions: "<0.21.1",
					url: "https://github.com/advisories/GHSA-axios",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.20",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
				},
				{
					name: "axios",
					version: "0.21.0",
					requestedRange: "^0.21.0",
					tarball: "https://registry.npmjs.org/axios/-/axios-0.21.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(2);
			expect(result.find((a) => a.package === "lodash")).toBeDefined();
			expect(result.find((a) => a.package === "axios")).toBeDefined();
		});
	});

	describe("Version Matching", () => {
		test("matches exact version", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "event-stream",
					severity: "critical",
					vulnerable_versions: "=3.3.6",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "event-stream",
					version: "3.3.6",
					requestedRange: "^3.3.0",
					tarball:
						"https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});

		test("matches version range", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "lodash",
					severity: "high",
					vulnerable_versions: ">=4.0.0 <4.17.21",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.20",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});

		test("does not match version outside range", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.20",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result).toEqual([]);
		});

		test("handles complex version ranges", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "axios",
					severity: "moderate",
					vulnerable_versions: ">=0.8.1 <0.21.1",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "axios",
					version: "0.21.0",
					requestedRange: "^0.21.0",
					tarball: "https://registry.npmjs.org/axios/-/axios-0.21.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});

		test("handles wildcard versions", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "package",
					severity: "low",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});
	});

	describe("Severity Mapping", () => {
		test("maps critical severity to fatal level", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Critical Issue",
					name: "package",
					severity: "critical",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.level).toBe("fatal");
		});

		test("maps high severity to fatal level", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "High Issue",
					name: "package",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.level).toBe("fatal");
		});

		test("maps moderate severity to warn level", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Moderate Issue",
					name: "package",
					severity: "moderate",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.level).toBe("warn");
		});

		test("maps low severity to warn level", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Low Issue",
					name: "package",
					severity: "low",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.level).toBe("warn");
		});

		test("maps info severity to warn level", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Info Issue",
					name: "package",
					severity: "info",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.level).toBe("warn");
		});
	});

	describe("Package Name Matching", () => {
		test("matches package by name field", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});

		test("falls back to module_name field", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					module_name: "lodash",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});

		test("does not match different package name", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "express",
					version: "4.18.0",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result).toEqual([]);
		});

		test("handles scoped packages", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "@babel/core",
					severity: "high",
					vulnerable_versions: "<7.20.0",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "@babel/core",
					version: "7.19.0",
					requestedRange: "^7.0.0",
					tarball: "https://registry.npmjs.org/@babel/core/-/core-7.19.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
		});
	});

	describe("Deduplication", () => {
		test("prevents duplicate advisories for same package", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.20",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
				},
				{
					name: "lodash",
					version: "4.17.20",
					requestedRange: "^4.17.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			// Should only create one advisory even though same package appears twice
			expect(result.length).toBe(1);
		});

		test("creates separate advisories for different versions", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.21",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.19",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
				},
				{
					name: "lodash",
					version: "4.17.20",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			// Should create two advisories for different affected versions
			expect(result.length).toBe(2);
		});
	});

	describe("Advisory Field Extraction", () => {
		test("extracts advisory ID", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: "GHSA-1234-5678-9012",
					title: "Test",
					name: "package",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.id).toBe("GHSA-1234-5678-9012");
		});

		test("extracts advisory URL", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "package",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://github.com/advisories/GHSA-xxxx",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.url).toBe("https://github.com/advisories/GHSA-xxxx");
		});

		test("uses overview as description", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "package",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
					overview: "This is the vulnerability overview",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result[0]?.description).toBe("This is the vulnerability overview");
		});

		test("truncates long descriptions", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "package",
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
					overview: "A".repeat(300), // Very long overview
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			// Should be truncated to MAX_DESCRIPTION_LENGTH (200)
			expect(result[0]?.description?.length).toBeLessThanOrEqual(203); // 200 + "..."
		});
	});

	describe("Edge Cases", () => {
		test("handles advisory with no package name", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					// no name or module_name
					severity: "high",
					vulnerable_versions: "*",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result).toEqual([]);
		});

		test("handles invalid version range gracefully", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "package",
					severity: "high",
					vulnerable_versions: "invalid-range",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball: "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
				},
			];

			// Should not throw, should handle gracefully
			const result = processor.processAdvisories(advisories, packages);

			expect(Array.isArray(result)).toBe(true);
		});

		test("handles pre-release versions", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1,
					title: "Test",
					name: "package",
					severity: "high",
					vulnerable_versions: "<1.0.0",
					url: "https://example.com",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "package",
					version: "1.0.0-beta.1",
					requestedRange: "^1.0.0-beta",
					tarball:
						"https://registry.npmjs.org/package/-/package-1.0.0-beta.1.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(Array.isArray(result)).toBe(true);
		});
	});

	describe("Real-World Scenarios", () => {
		test("processes lodash prototype pollution advisory", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1065,
					title: "Prototype Pollution in lodash",
					name: "lodash",
					severity: "high",
					vulnerable_versions: "<4.17.21",
					url: "https://github.com/advisories/GHSA-p6mc-m468-83gw",
					overview:
						"Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution.",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "lodash",
					version: "4.17.20",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
			expect(result[0]?.level).toBe("fatal");
			expect(result[0]?.package).toBe("lodash");
		});

		test("processes event-stream malicious code advisory", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: "GHSA-4xcv-9jjx-gfj3",
					title: "Malicious Package",
					name: "event-stream",
					severity: "critical",
					vulnerable_versions: "=3.3.6",
					url: "https://github.com/advisories/GHSA-4xcv-9jjx-gfj3",
					overview: "Malicious code injected into event-stream package",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "event-stream",
					version: "3.3.6",
					requestedRange: "^3.3.0",
					tarball:
						"https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
			expect(result[0]?.level).toBe("fatal");
		});

		test("processes axios SSRF advisory", () => {
			const advisories: NpmAdvisory[] = [
				{
					id: 1594,
					title: "Server-Side Request Forgery in axios",
					name: "axios",
					severity: "moderate",
					vulnerable_versions: ">=0.8.1 <0.21.1",
					url: "https://github.com/advisories/GHSA-4w2v-q235-vp99",
				},
			];

			const packages: Bun.Security.Package[] = [
				{
					name: "axios",
					version: "0.21.0",
					requestedRange: "^0.21.0",
					tarball: "https://registry.npmjs.org/axios/-/axios-0.21.0.tgz",
				},
			];

			const result = processor.processAdvisories(advisories, packages);

			expect(result.length).toBe(1);
			expect(result[0]?.level).toBe("warn");
		});
	});
});

/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { describe, expect, test } from "bun:test";
import {
	NpmAdvisorySchema,
	NpmAuditRequestSchema,
	NpmAuditResponseAltSchema,
	NpmAuditResponseSchema,
	type NpmAdvisory,
	type NpmAuditRequest,
} from "../src/schema.js";

describe("npm Audit Schemas", () => {
	describe("NpmAuditRequestSchema", () => {
		test("validates valid request", () => {
			const request: NpmAuditRequest = {
				lodash: ["4.17.20", "4.17.21"],
				express: ["4.17.1"],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("validates empty request", () => {
			const request: NpmAuditRequest = {};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("validates single package", () => {
			const request: NpmAuditRequest = {
				"event-stream": ["3.3.4"],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("validates scoped package names", () => {
			const request: NpmAuditRequest = {
				"@babel/core": ["7.0.0"],
				"@types/node": ["18.0.0"],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("validates multiple versions", () => {
			const request: NpmAuditRequest = {
				axios: ["0.21.0", "0.21.1", "0.21.2", "0.21.3"],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("accepts numeric keys (coerced to strings)", () => {
			const request = {
				123: ["1.0.0"],
			};

			// Zod z.record() coerces numeric keys to strings
			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("rejects non-array versions", () => {
			const request = {
				lodash: "4.17.20",
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(false);
		});

		test("rejects non-string versions in array", () => {
			const request = {
				lodash: ["4.17.20", 123],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(false);
		});
	});

	describe("NpmAdvisorySchema", () => {
		test("validates minimal advisory", () => {
			const advisory: NpmAdvisory = {
				id: 1065,
				title: "Prototype Pollution",
				severity: "high",
				vulnerable_versions: "<4.17.21",
				url: "https://github.com/advisories/GHSA-xxxx",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates complete advisory", () => {
			const advisory: NpmAdvisory = {
				id: "GHSA-xxxx-yyyy-zzzz",
				title: "Remote Code Execution",
				name: "lodash",
				module_name: "lodash",
				severity: "critical",
				vulnerable_versions: ">=1.0.0 <4.17.21",
				patched_versions: ">=4.17.21",
				url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
				overview: "Detailed description of the vulnerability",
				recommendation: "Update to version 4.17.21 or higher",
				references: "https://example.com/advisory",
				access: "public",
				cwe: "CWE-94",
				cves: ["CVE-2021-12345"],
				cvss: {
					score: 9.8,
					vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
				findings: [
					{
						version: "4.17.20",
						paths: ["lodash", "lodash>4.17.20"],
					},
				],
				created: "2021-01-01T00:00:00Z",
				updated: "2021-01-02T00:00:00Z",
				deleted: false,
				github_advisory_id: "GHSA-xxxx-yyyy-zzzz",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates advisory with numeric ID", () => {
			const advisory = {
				id: 1234,
				title: "Test Advisory",
				severity: "moderate",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates advisory with string ID", () => {
			const advisory = {
				id: "GHSA-1234-5678-9012",
				title: "Test Advisory",
				severity: "moderate",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates all severity levels", () => {
			const severities = ["critical", "high", "moderate", "low", "info"];

			for (const severity of severities) {
				const advisory = {
					id: 1,
					title: "Test",
					severity,
					vulnerable_versions: "<1.0.0",
					url: "https://example.com",
				};

				const result = NpmAdvisorySchema.safeParse(advisory);
				expect(result.success).toBe(true);
			}
		});

		test("validates CWE as string", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "high",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
				cwe: "CWE-79",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates CWE as array", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "high",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
				cwe: ["CWE-79", "CWE-XSS"],
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("rejects invalid severity", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "extreme",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(false);
		});

		test("rejects missing required fields", () => {
			const advisory = {
				id: 1,
				title: "Test",
				// missing severity
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(false);
		});

		test("allows optional fields to be missing", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "low",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
				// all other fields are optional
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});
	});

	describe("NpmAuditResponseSchema", () => {
		test("validates empty response", () => {
			const response = {};

			const result = NpmAuditResponseSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("validates single advisory response", () => {
			const response = {
				"1065": {
					id: 1065,
					title: "Prototype Pollution",
					severity: "high",
					vulnerable_versions: "<4.17.21",
					url: "https://github.com/advisories/GHSA-xxxx",
				},
			};

			const result = NpmAuditResponseSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("validates multiple advisory response", () => {
			const response = {
				"1065": {
					id: 1065,
					title: "Prototype Pollution",
					severity: "high",
					vulnerable_versions: "<4.17.21",
					url: "https://github.com/advisories/GHSA-xxxx",
				},
				"GHSA-1234-5678-9012": {
					id: "GHSA-1234-5678-9012",
					title: "XSS Vulnerability",
					severity: "moderate",
					vulnerable_versions: "<2.0.0",
					url: "https://github.com/advisories/GHSA-1234",
				},
			};

			const result = NpmAuditResponseSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("rejects invalid advisory in response", () => {
			const response = {
				"1065": {
					id: 1065,
					title: "Test",
					// missing severity
					vulnerable_versions: "<1.0.0",
					url: "https://example.com",
				},
			};

			const result = NpmAuditResponseSchema.safeParse(response);
			expect(result.success).toBe(false);
		});
	});

	describe("NpmAuditResponseAltSchema", () => {
		test("validates alternative format with advisories", () => {
			const response = {
				advisories: {
					"1065": {
						id: 1065,
						title: "Test Advisory",
						severity: "high",
						vulnerable_versions: "<1.0.0",
						url: "https://example.com",
					},
				},
			};

			const result = NpmAuditResponseAltSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("validates alternative format with metadata", () => {
			const response = {
				advisories: {},
				metadata: {
					vulnerabilities: {
						info: 0,
						low: 1,
						moderate: 2,
						high: 3,
						critical: 0,
					},
				},
			};

			const result = NpmAuditResponseAltSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("validates alternative format without metadata", () => {
			const response = {
				advisories: {
					"1": {
						id: 1,
						title: "Test",
						severity: "low",
						vulnerable_versions: "*",
						url: "https://example.com",
					},
				},
			};

			const result = NpmAuditResponseAltSchema.safeParse(response);
			expect(result.success).toBe(true);
		});
	});

	describe("Real-World npm Audit Data", () => {
		test("validates lodash prototype pollution advisory", () => {
			const advisory = {
				id: 1065,
				title: "Prototype Pollution in lodash",
				name: "lodash",
				severity: "high",
				vulnerable_versions: "<4.17.21",
				patched_versions: ">=4.17.21",
				url: "https://github.com/advisories/GHSA-p6mc-m468-83gw",
				overview:
					"Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution.",
				recommendation: "Update to version 4.17.21 or later",
				cwe: ["CWE-1321"],
				cvss: {
					score: 7.4,
					vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
				},
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates event-stream malicious code advisory", () => {
			const advisory = {
				id: "GHSA-4xcv-9jjx-gfj3",
				title: "Malicious Package",
				name: "event-stream",
				severity: "critical",
				vulnerable_versions: "=3.3.6",
				url: "https://github.com/advisories/GHSA-4xcv-9jjx-gfj3",
				overview: "Malicious code injected into event-stream package",
				cwe: ["CWE-506"],
				cvss: {
					score: 9.8,
				},
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("validates axios SSRF advisory", () => {
			const advisory = {
				id: 1594,
				title: "Server-Side Request Forgery in axios",
				name: "axios",
				severity: "moderate",
				vulnerable_versions: ">=0.8.1 <0.21.1",
				patched_versions: ">=0.21.1",
				url: "https://github.com/advisories/GHSA-4w2v-q235-vp99",
				cves: ["CVE-2020-28168"],
				cvss: {
					score: 5.9,
					vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
				},
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});
	});

	describe("Edge Cases", () => {
		test("handles very long version ranges", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "low",
				vulnerable_versions:
					">=1.0.0 <1.0.1 || >=1.1.0 <1.1.1 || >=1.2.0 <1.2.1 || >=2.0.0 <2.0.1",
				url: "https://example.com",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});

		test("handles special characters in package names", () => {
			const request: NpmAuditRequest = {
				"@babel/core": ["7.0.0"],
				"lodash.merge": ["4.6.2"],
				"some-package": ["1.0.0"],
				some_package: ["2.0.0"],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("handles empty arrays in request", () => {
			const request: NpmAuditRequest = {
				lodash: [],
			};

			const result = NpmAuditRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("handles null CVSS", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "low",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
				cvss: null,
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			// null is not valid for optional fields - they should be undefined
			expect(result.success).toBe(false);
		});

		test("handles missing optional CVSS", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "low",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
				// cvss is undefined (not present)
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(true);
		});
	});

	describe("Type Safety", () => {
		test("request is type-safe", () => {
			const request: NpmAuditRequest = {
				lodash: ["4.17.20"],
			};

			// TypeScript should allow this
			const packageName: string = Object.keys(request)[0] ?? "";
			const versions: string[] = request[packageName] ?? [];

			expect(packageName).toBe("lodash");
			expect(versions).toEqual(["4.17.20"]);
		});

		test("advisory is type-safe", () => {
			const advisory: NpmAdvisory = {
				id: 1,
				title: "Test",
				severity: "high",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
			};

			// TypeScript should allow this
			const id: string | number = advisory.id;
			const severity: "critical" | "high" | "moderate" | "low" | "info" =
				advisory.severity;

			expect(typeof id).toBe("number");
			expect(severity).toBe("high");
		});
	});

	describe("Schema Strictness", () => {
		test("allows additional properties in advisory", () => {
			const advisory = {
				id: 1,
				title: "Test",
				severity: "low",
				vulnerable_versions: "<1.0.0",
				url: "https://example.com",
				customField: "custom value",
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			// Zod by default allows additional properties
			expect(result.success).toBe(true);
		});

		test("validates required fields strictly", () => {
			const advisory = {
				id: 1,
				title: "Test",
				// missing severity, vulnerable_versions, url
			};

			const result = NpmAdvisorySchema.safeParse(advisory);
			expect(result.success).toBe(false);
		});
	});
});

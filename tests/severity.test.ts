/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { beforeEach, describe, expect, test } from "bun:test";
import {
	isCvssScoreFatal,
	mapSeverityToLevel,
	severityToPriority,
} from "../src/severity.js";
import type { NpmSeverity } from "../src/types.js";

describe("Severity Assessment", () => {
	beforeEach(() => {
		// Set log level to error to reduce test output
		Bun.env.NPM_SCANNER_LOG_LEVEL = "error";
	});

	describe("mapSeverityToLevel", () => {
		test("maps critical to fatal", () => {
			const level = mapSeverityToLevel("critical");
			expect(level).toBe("fatal");
		});

		test("maps high to fatal", () => {
			const level = mapSeverityToLevel("high");
			expect(level).toBe("fatal");
		});

		test("maps moderate to warn", () => {
			const level = mapSeverityToLevel("moderate");
			expect(level).toBe("warn");
		});

		test("maps low to warn", () => {
			const level = mapSeverityToLevel("low");
			expect(level).toBe("warn");
		});

		test("maps info to warn", () => {
			const level = mapSeverityToLevel("info");
			expect(level).toBe("warn");
		});
	});

	describe("severityToPriority", () => {
		test("critical has highest priority", () => {
			expect(severityToPriority("critical")).toBe(5);
		});

		test("high has second highest priority", () => {
			expect(severityToPriority("high")).toBe(4);
		});

		test("moderate has medium priority", () => {
			expect(severityToPriority("moderate")).toBe(3);
		});

		test("low has low priority", () => {
			expect(severityToPriority("low")).toBe(2);
		});

		test("info has lowest priority", () => {
			expect(severityToPriority("info")).toBe(1);
		});

		test("priorities are in correct order", () => {
			const critical = severityToPriority("critical");
			const high = severityToPriority("high");
			const moderate = severityToPriority("moderate");
			const low = severityToPriority("low");
			const info = severityToPriority("info");

			expect(critical).toBeGreaterThan(high);
			expect(high).toBeGreaterThan(moderate);
			expect(moderate).toBeGreaterThan(low);
			expect(low).toBeGreaterThan(info);
		});

		test("handles unknown severity gracefully", () => {
			const priority = severityToPriority("unknown" as NpmSeverity);
			expect(priority).toBe(0);
		});
	});

	describe("isCvssScoreFatal", () => {
		test("returns true for CVSS 10.0", () => {
			expect(isCvssScoreFatal(10.0)).toBe(true);
		});

		test("returns true for CVSS 9.0", () => {
			expect(isCvssScoreFatal(9.0)).toBe(true);
		});

		test("returns true for CVSS 8.0", () => {
			expect(isCvssScoreFatal(8.0)).toBe(true);
		});

		test("returns true for CVSS 7.0 (threshold)", () => {
			expect(isCvssScoreFatal(7.0)).toBe(true);
		});

		test("returns false for CVSS 6.9 (below threshold)", () => {
			expect(isCvssScoreFatal(6.9)).toBe(false);
		});

		test("returns false for CVSS 5.0", () => {
			expect(isCvssScoreFatal(5.0)).toBe(false);
		});

		test("returns false for CVSS 3.0", () => {
			expect(isCvssScoreFatal(3.0)).toBe(false);
		});

		test("returns false for CVSS 0.0", () => {
			expect(isCvssScoreFatal(0.0)).toBe(false);
		});

		test("returns false for negative scores", () => {
			expect(isCvssScoreFatal(-1.0)).toBe(false);
		});

		test("returns true for scores above 10", () => {
			expect(isCvssScoreFatal(11.0)).toBe(true);
		});
	});

	describe("Boundary Testing", () => {
		test("CVSS 6.99 is not fatal", () => {
			expect(isCvssScoreFatal(6.99)).toBe(false);
		});

		test("CVSS 7.01 is fatal", () => {
			expect(isCvssScoreFatal(7.01)).toBe(true);
		});

		test("CVSS exactly 7.0 is fatal", () => {
			expect(isCvssScoreFatal(7.0)).toBe(true);
		});
	});

	describe("Real-World Scenarios", () => {
		test("remote code execution (critical) is fatal", () => {
			expect(mapSeverityToLevel("critical")).toBe("fatal");
			expect(severityToPriority("critical")).toBe(5);
		});

		test("SQL injection (high) is fatal", () => {
			expect(mapSeverityToLevel("high")).toBe("fatal");
			expect(severityToPriority("high")).toBe(4);
		});

		test("prototype pollution (moderate) is warning", () => {
			expect(mapSeverityToLevel("moderate")).toBe("warn");
			expect(severityToPriority("moderate")).toBe(3);
		});

		test("denial of service (low) is warning", () => {
			expect(mapSeverityToLevel("low")).toBe("warn");
			expect(severityToPriority("low")).toBe(2);
		});

		test("informational advisory (info) is warning", () => {
			expect(mapSeverityToLevel("info")).toBe("warn");
			expect(severityToPriority("info")).toBe(1);
		});
	});

	describe("Sorting by Priority", () => {
		test("can sort advisories by severity", () => {
			const severities: NpmSeverity[] = [
				"low",
				"critical",
				"info",
				"high",
				"moderate",
			];

			const sorted = [...severities].sort(
				(a, b) => severityToPriority(b) - severityToPriority(a),
			);

			expect(sorted).toEqual(["critical", "high", "moderate", "low", "info"]);
		});

		test("stable sort for equal priorities", () => {
			const items = [
				{ id: 1, severity: "critical" as NpmSeverity },
				{ id: 2, severity: "critical" as NpmSeverity },
				{ id: 3, severity: "high" as NpmSeverity },
			];

			const sorted = [...items].sort(
				(a, b) =>
					severityToPriority(b.severity) - severityToPriority(a.severity),
			);

			expect(sorted[0]?.severity).toBe("critical");
			expect(sorted[1]?.severity).toBe("critical");
			expect(sorted[2]?.severity).toBe("high");
		});
	});

	describe("Integration with Constants", () => {
		test("fatal severities match expected levels", () => {
			// These should be fatal
			expect(mapSeverityToLevel("critical")).toBe("fatal");
			expect(mapSeverityToLevel("high")).toBe("fatal");

			// These should be warnings
			expect(mapSeverityToLevel("moderate")).toBe("warn");
			expect(mapSeverityToLevel("low")).toBe("warn");
			expect(mapSeverityToLevel("info")).toBe("warn");
		});

		test("CVSS threshold matches constant", () => {
			// Should match SECURITY.CVSS_FATAL_THRESHOLD (7.0)
			expect(isCvssScoreFatal(7.0)).toBe(true);
			expect(isCvssScoreFatal(6.9)).toBe(false);
		});
	});

	describe("Type Safety", () => {
		test("only accepts valid npm severity values", () => {
			const validSeverities: NpmSeverity[] = [
				"critical",
				"high",
				"moderate",
				"low",
				"info",
			];

			for (const severity of validSeverities) {
				expect(() => mapSeverityToLevel(severity)).not.toThrow();
				expect(() => severityToPriority(severity)).not.toThrow();
			}
		});

		test("priority function returns numbers", () => {
			const priority = severityToPriority("critical");
			expect(typeof priority).toBe("number");
			expect(Number.isFinite(priority)).toBe(true);
		});

		test("isCvssScoreFatal returns boolean", () => {
			const result = isCvssScoreFatal(8.0);
			expect(typeof result).toBe("boolean");
		});
	});

	describe("Edge Cases", () => {
		test("handles very precise CVSS scores", () => {
			expect(isCvssScoreFatal(7.0000001)).toBe(true);
			expect(isCvssScoreFatal(6.9999999)).toBe(false);
		});

		test("handles floating point precision", () => {
			const score = 0.1 + 0.2; // JavaScript famous precision issue
			expect(typeof isCvssScoreFatal(score)).toBe("boolean");
		});

		test("handles Infinity gracefully", () => {
			expect(isCvssScoreFatal(Number.POSITIVE_INFINITY)).toBe(true);
			expect(isCvssScoreFatal(Number.NEGATIVE_INFINITY)).toBe(false);
		});

		test("handles NaN gracefully", () => {
			expect(isCvssScoreFatal(Number.NaN)).toBe(false);
		});
	});

	describe("npm Advisory Format Compatibility", () => {
		test("handles npm audit severity format", () => {
			// npm audit returns these exact strings
			const npmSeverities: NpmSeverity[] = [
				"critical",
				"high",
				"moderate",
				"low",
				"info",
			];

			for (const severity of npmSeverities) {
				const level = mapSeverityToLevel(severity);
				expect(["fatal", "warn"]).toContain(level);

				const priority = severityToPriority(severity);
				expect(priority).toBeGreaterThanOrEqual(0);
			}
		});

		test("maps severity to correct Bun level", () => {
			// critical and high -> fatal (blocks installation with --strict)
			expect(mapSeverityToLevel("critical")).toBe("fatal");
			expect(mapSeverityToLevel("high")).toBe("fatal");

			// moderate, low, info -> warn (logged but allows installation)
			expect(mapSeverityToLevel("moderate")).toBe("warn");
			expect(mapSeverityToLevel("low")).toBe("warn");
			expect(mapSeverityToLevel("info")).toBe("warn");
		});
	});

	describe("Performance", () => {
		test("severity mapping is fast", () => {
			const start = performance.now();

			for (let i = 0; i < 10000; i++) {
				mapSeverityToLevel("critical");
				mapSeverityToLevel("high");
				mapSeverityToLevel("moderate");
				mapSeverityToLevel("low");
				mapSeverityToLevel("info");
			}

			const duration = performance.now() - start;
			expect(duration).toBeLessThan(100); // Should be very fast
		});

		test("priority calculation is fast", () => {
			const start = performance.now();

			for (let i = 0; i < 10000; i++) {
				severityToPriority("critical");
				severityToPriority("high");
				severityToPriority("moderate");
				severityToPriority("low");
				severityToPriority("info");
			}

			const duration = performance.now() - start;
			expect(duration).toBeLessThan(100);
		});
	});
});

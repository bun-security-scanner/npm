/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { z } from "zod";

/**
 * npm Audit Bulk Request Schema
 * Format: { "package-name": ["version1", "version2"], ... }
 */
export const NpmAuditRequestSchema = z.record(z.string(), z.array(z.string()));

/**
 * npm Advisory Schema
 * Represents a single security advisory from npm registry
 */
export const NpmAdvisorySchema = z.object({
	/** Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx" or numeric ID) */
	id: z.union([z.string(), z.number()]),

	/** Advisory title/name */
	title: z.string(),

	/** Package name */
	name: z.string().optional(),

	/** Module name (deprecated, use name) */
	module_name: z.string().optional(),

	/** Severity level */
	severity: z.enum(["critical", "high", "moderate", "low", "info"]),

	/** Vulnerable version ranges */
	vulnerable_versions: z.string(),

	/** Patched versions */
	patched_versions: z.string().optional(),

	/** Advisory URL */
	url: z.string(),

	/** Detailed overview */
	overview: z.string().optional(),

	/** Recommendation */
	recommendation: z.string().optional(),

	/** References */
	references: z.string().optional(),

	/** Access (e.g., "public", "private") */
	access: z.string().optional(),

	/** CWE(s) */
	cwe: z.union([z.string(), z.array(z.string())]).optional(),

	/** CVE(s) */
	cves: z.array(z.string()).optional(),

	/** CVSS score */
	cvss: z
		.object({
			score: z.number(),
			vectorString: z.string().optional(),
		})
		.optional(),

	/** Affected package versions */
	findings: z
		.array(
			z.object({
				version: z.string(),
				paths: z.array(z.string()),
			}),
		)
		.optional(),

	/** Creation time */
	created: z.string().optional(),

	/** Update time */
	updated: z.string().optional(),

	/** Deleted flag */
	deleted: z.boolean().optional(),

	/** GitHub Advisory ID */
	github_advisory_id: z.string().optional(),
});

/**
 * npm Audit Bulk Response Schema
 * The response is an object where keys are advisory IDs and values are advisory objects
 */
export const NpmAuditResponseSchema = z.record(z.string(), NpmAdvisorySchema);

/**
 * Alternative response format: object with advisories property
 */
export const NpmAuditResponseAltSchema = z.object({
	advisories: z.record(z.string(), NpmAdvisorySchema),
	metadata: z.any().optional(),
});

// Exported types
export type NpmAuditRequest = z.infer<typeof NpmAuditRequestSchema>;
export type NpmAdvisory = z.infer<typeof NpmAdvisorySchema>;
export type NpmAuditResponse = z.infer<typeof NpmAuditResponseSchema>;
export type NpmAuditResponseAlt = z.infer<typeof NpmAuditResponseAltSchema>;

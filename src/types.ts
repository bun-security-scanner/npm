/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

// Bun Security Scanner API types
// These will be moved to @types/bun when officially released

// npm audit severity levels
export type FatalSeverity = "critical" | "high";
export type NpmSeverity = "critical" | "high" | "moderate" | "low" | "info";

// Extend global Bun namespace with missing types
declare global {
	namespace Bun {
		// Bun.semver types (missing from current bun-types)
		namespace semver {
			function satisfies(version: string, range: string): boolean;
		}

		// Augment Bun.Security.Advisory with missing properties
		namespace Security {
			interface Advisory {
				id: string;
				message: string;
			}
		}
	}
}

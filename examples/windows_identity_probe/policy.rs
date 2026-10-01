//! Portable fail-closed policy; tests never start services or touch ACLs.
pub fn admitted(windows: bool, actions: &str, environment: &str, consent: bool) -> bool {
    windows && actions == "true" && environment == "github-hosted" && consent
}

pub const OPERATIONS: [&str; 7] = [
    "read",
    "write",
    "create",
    "delete",
    "rename",
    "hardlink_out",
    "hardlink_in",
];
pub const TARGETS: [&str; 4] = [
    "memory.db",
    "memory.db-wal",
    "memory.db-shm",
    "rollback.db-journal",
];

pub fn exact_denials(cases: &[(&str, &str, u32)]) -> bool {
    cases.len() == TARGETS.len() * OPERATIONS.len()
        && TARGETS.iter().all(|target| {
            OPERATIONS.iter().all(|op| {
                cases
                    .iter()
                    .filter(|entry| entry.0 == *target && entry.1 == *op && entry.2 == 5)
                    .count()
                    == 1
            })
        })
}

pub fn identities_distinct(
    admin: &str,
    expected_a: &str,
    expected_b: &str,
    a: &str,
    b: &str,
) -> bool {
    a.starts_with("S-1-5-80-")
        && b.starts_with("S-1-5-80-")
        && a == expected_a
        && b == expected_b
        && a != b
        && a != admin
        && b != admin
}

/// Mutation bits only: FILE_GENERIC_WRITE also includes READ_CONTROL and SYNCHRONIZE.
pub fn namespace_mutation(mask: u32, ancestor: bool) -> bool {
    let replacement = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    let forbidden = if ancestor {
        replacement
    } else {
        replacement | 0x2 | 0x4 | 0x10 | 0x100
    };
    mask & forbidden != 0
}

pub fn fixture_ace_allowed(trusted: bool, writer: bool, reader: bool, mask: u32) -> bool {
    trusted || writer || (reader && !namespace_mutation(mask, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_allowlist_rejects_even_read_for_unknown_sids() {
        assert!(!fixture_ace_allowed(false, false, false, 0x1200a9));
        assert!(fixture_ace_allowed(false, false, true, 0x1200a9));
        assert!(!fixture_ace_allowed(false, false, true, 0x1f01ff));
        assert!(fixture_ace_allowed(false, true, false, 0x1f01ff));
        assert!(fixture_ace_allowed(true, false, false, 0x1f01ff));
    }
    #[test]
    fn read_execute_is_not_mutation_but_delete_child_is() {
        assert!(!namespace_mutation(0x1200a9, false));
        assert!(!namespace_mutation(0x1200a9, true));
        for bit in [
            0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000,
        ] {
            assert!(namespace_mutation(bit, false));
        }
        assert!(!namespace_mutation(0x4, true));
        assert!(namespace_mutation(0x40, true));
    }
    #[test]
    fn pins_actual_virtual_token_users_not_group_or_shared_identity() {
        let a = "S-1-5-80-1-2-3-4-5";
        let b = "S-1-5-80-6-7-8-9-10";
        assert!(identities_distinct("S-1-5-21-123", a, b, a, b));
        assert!(!identities_distinct(a, a, b, a, b));
        assert!(!identities_distinct("admin", a, b, a, a));
        assert!(!identities_distinct("admin", a, b, "S-1-5-19", b));
        assert!(!identities_distinct("admin", "S-1-5-19", b, "S-1-5-19", b));
    }
    #[test]
    fn denials_require_exact_unique_matrix_and_access_denied() {
        let cases: Vec<_> = TARGETS
            .iter()
            .flat_map(|target| OPERATIONS.iter().map(move |op| (*target, *op, 5)))
            .collect();
        assert!(exact_denials(&cases));
        assert!(!exact_denials(&cases[1..]));
        let mut altered = cases.clone();
        altered[0] = altered[1];
        assert!(!exact_denials(&altered));
        for error in [0, 2, 3, 32, 33, 80, 1314] {
            altered.clone_from(&cases);
            altered[0].2 = error;
            assert!(!exact_denials(&altered));
        }
    }
    #[test]
    fn admission_requires_all_four_explicit_gates() {
        assert!(admitted(true, "true", "github-hosted", true));
        assert!(!admitted(false, "true", "github-hosted", true));
        assert!(!admitted(true, "false", "github-hosted", true));
        assert!(!admitted(true, "true", "self-hosted", true));
        assert!(!admitted(true, "true", "github-hosted", false));
        assert!(!admitted(true, "TRUE", "github-hosted", true));
    }
}

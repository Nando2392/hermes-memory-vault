use crate::data::Result;
pub fn hosted_gate(
    allow: bool,
    reviewed: bool,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    if !allow || !reviewed {
        return Err(
            "requires explicit disposable-services consent and independent review acknowledgement"
                .into(),
        );
    }
    // These are deployment guards, NEVER security authority. Native admin token
    // and protected fresh namespace checks are still required before mutation.
    for (key, expected) in [
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("RUNNER_OS", "Windows"),
        ("ImageOS", "win22"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REF", "refs/heads/test/posix-sqlite-hardening"),
    ] {
        if env.get(key).map(String::as_str) != Some(expected) {
            return Err(format!("disposable host gate: {key} must equal {expected}").into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_local_wrong_branch_and_unreviewed_before_mutation() {
        let mut env = std::collections::BTreeMap::from([
            ("GITHUB_ACTIONS".into(), "true".into()),
            ("RUNNER_ENVIRONMENT".into(), "github-hosted".into()),
            ("RUNNER_OS".into(), "Windows".into()),
            ("ImageOS".into(), "win22".into()),
            ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
            (
                "GITHUB_REF".into(),
                "refs/heads/test/posix-sqlite-hardening".into(),
            ),
        ]);
        assert!(hosted_gate(true, true, &env).is_ok());
        assert!(hosted_gate(false, true, &env).is_err());
        assert!(hosted_gate(true, false, &env).is_err());
        for key in env.clone().keys() {
            let value = env.remove(key).unwrap();
            assert!(hosted_gate(true, true, &env).is_err(), "missing {key}");
            env.insert(key.clone(), value);
        }
        env.insert("GITHUB_REF".into(), "refs/heads/main".into());
        assert!(hosted_gate(true, true, &env).is_err());
    }
}

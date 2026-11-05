//! Guard the PolicyKit policy: pkexec picks the first action whose exec.path
//! matches and whose exec.argv1 matches *or is unset*, so a path-only action
//! could shadow the others. Every action must name its argv1, and only the
//! read/keep/undo actions may run without a password.

const POLICY: &str = include_str!("../assets/se.nirucon.nirusec.policy");

fn actions() -> Vec<(String, String, String)> {
    POLICY
        .split("<action id=\"")
        .skip(1)
        .map(|block| {
            let id = block.split('"').next().unwrap().to_string();
            let argv1 = block
                .split("org.freedesktop.policykit.exec.argv1\">")
                .nth(1)
                .map(|rest| rest.split('<').next().unwrap().to_string())
                .unwrap_or_default();
            let active = block
                .split("<allow_active>")
                .nth(1)
                .map(|rest| rest.split('<').next().unwrap().to_string())
                .unwrap_or_default();
            (id, argv1, active)
        })
        .collect()
}

#[test]
fn every_action_names_its_argv1_and_path() {
    let actions = actions();
    assert!(actions.len() >= 20);
    for block in POLICY.split("<action id=\"").skip(1) {
        assert!(block
            .contains("org.freedesktop.policykit.exec.path\">/usr/local/libexec/nirusec-helper<"));
        assert!(block.contains("<allow_any>no</allow_any>"));
        assert!(block.contains("<allow_inactive>no</allow_inactive>"));
    }
    let mut seen = std::collections::HashSet::new();
    for (id, argv1, _) in &actions {
        assert!(!argv1.is_empty(), "{id} has no exec.argv1");
        assert!(seen.insert(argv1.clone()), "argv1 {argv1} used twice");
    }
}

#[test]
fn only_read_keep_and_undo_skip_the_password() {
    for (id, argv1, active) in actions() {
        match argv1.as_str() {
            "ufw-status" | "tx-confirm" | "tx-undo" => assert_eq!(active, "yes", "{id}"),
            _ => assert_eq!(
                active, "auth_admin",
                "{id} must ask for a password every time"
            ),
        }
    }
    assert!(!POLICY.contains("<allow_active>auth_admin_keep"));
}

//! `--help` never prints an environment variable's value.

/// clap prints an env-backed arg's CURRENT value in `--help` unless the arg
/// hides it, so a secret sitting in the environment reaches the terminal, shell
/// logs and CI logs (#3026). Walked over the whole command tree, so a new flag
/// or subcommand that forgets `hide_env_values` reds here.
#[test]
fn help_never_prints_an_env_value() {
    fn walk(cmd: &clap::Command, seen: &mut usize, shown: &mut Vec<String>) {
        for arg in cmd.get_arguments().filter(|a| a.get_env().is_some()) {
            *seen += 1;
            if !arg.is_hide_env_values_set() {
                shown.push(format!("{} --{}", cmd.get_name(), arg.get_id()));
            }
        }
        for sub in cmd.get_subcommands() {
            walk(sub, seen, shown);
        }
    }
    let (mut seen, mut shown) = (0, Vec::new());
    walk(
        &<super::Args as clap::CommandFactory>::command(),
        &mut seen,
        &mut shown,
    );
    assert!(
        seen > 0,
        "no env-backed arg was found; the walk reached nothing"
    );
    assert!(
        shown.is_empty(),
        "--help would print the value of: {shown:?}"
    );
}

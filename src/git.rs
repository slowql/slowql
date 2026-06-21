use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn get_changed_files(since: Option<&str>) -> HashSet<PathBuf> {
    let mut changed: HashSet<PathBuf> = HashSet::new();

    let mut collect = |args: &[&str]| {
        if let Ok(output) = Command::new("git").args(args).output() {
            if output.status.success() {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    for line in stdout.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            let p = Path::new(trimmed);
                            if p.exists() && p.is_file() {
                                if let Ok(abs) = p.canonicalize() {
                                    changed.insert(abs);
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    if let Some(rev) = since {
        let spec = format!("{rev}...HEAD");
        collect(&["diff", "--name-only", &spec]);
    } else {
        collect(&["diff", "--name-only", "HEAD"]);
        collect(&["diff", "--name-only", "--cached"]);
    }

    collect(&["ls-files", "--others", "--exclude-standard"]);

    changed
}

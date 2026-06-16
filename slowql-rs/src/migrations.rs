use std::path::{Path, PathBuf};
use regex::Regex;
use once_cell::sync::Lazy;

#[derive(Debug, Clone)]
pub struct MigrationFile {
    pub version: String,
    pub path: PathBuf,
    pub content: String,
    pub framework: String,
}

/// Detect which migration framework is in use.
pub fn detect_framework(path: &Path) -> Option<&'static str> {
    if path.join("alembic.ini").exists() || path.join("versions").is_dir() || path.join("migrations/versions").is_dir() {
        return Some("alembic");
    }
    if path.join("schema.prisma").exists() || path.join("migrations").is_dir() {
        // Check for Prisma-style migrations (folders with migration.sql)
        let mig_dir = path.join("migrations");
        if mig_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&mig_dir) {
                for entry in entries.flatten() {
                    if entry.path().join("migration.sql").exists() {
                        return Some("prisma");
                    }
                }
            }
        }
    }
    // Flyway: V*__*.sql files
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('V') && name.contains("__") && name.ends_with(".sql") {
                return Some("flyway");
            }
        }
    }
    // Django: look for migrations/ dirs with Python files
    for entry in walkdir_simple(path) {
        if entry.ends_with("migrations") && entry.is_dir() {
            if let Ok(files) = std::fs::read_dir(&entry) {
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().to_string();
                    if name.ends_with(".py") && name != "__init__.py" && name.starts_with("0") {
                        return Some("django");
                    }
                }
            }
        }
    }
    None
}

/// Get migration SQL files from a directory.
pub fn get_migrations(path: &Path) -> Vec<MigrationFile> {
    let framework = match detect_framework(path) {
        Some(f) => f,
        None => return Vec::new(),
    };

    match framework {
        "flyway" => get_flyway_migrations(path),
        "prisma" => get_prisma_migrations(path),
        _ => Vec::new(), // Alembic/Django are Python-based, need special handling
    }
}

fn get_flyway_migrations(path: &Path) -> Vec<MigrationFile> {
    static FLYWAY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^V(\d+)__.*\.sql$").unwrap());
    let mut migrations = Vec::new();

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(caps) = FLYWAY_RE.captures(&name) {
                let version = caps[1].to_string();
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    migrations.push(MigrationFile {
                        version,
                        path: entry.path(),
                        content,
                        framework: "flyway".to_string(),
                    });
                }
            }
        }
    }

    migrations.sort_by(|a, b| a.version.cmp(&b.version));
    migrations
}

fn get_prisma_migrations(path: &Path) -> Vec<MigrationFile> {
    let mig_dir = path.join("migrations");
    let mut migrations = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&mig_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let sql_file = p.join("migration.sql");
                if sql_file.exists() {
                    if let Ok(content) = std::fs::read_to_string(&sql_file) {
                        migrations.push(MigrationFile {
                            version: entry.file_name().to_string_lossy().to_string(),
                            path: sql_file,
                            content,
                            framework: "prisma".to_string(),
                        });
                    }
                }
            }
        }
    }

    migrations.sort_by(|a, b| a.version.cmp(&b.version));
    migrations
}

fn walkdir_simple(path: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                result.push(p.clone());
                result.extend(walkdir_simple(&p));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_flyway() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("V1__init.sql"), "CREATE TABLE t (id INT);").unwrap();
        assert_eq!(detect_framework(dir.path()), Some("flyway"));
    }

    #[test]
    fn detect_prisma() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("schema.prisma"), "").unwrap();
        let mig = dir.path().join("migrations/20240101_init");
        std::fs::create_dir_all(&mig).unwrap();
        std::fs::write(mig.join("migration.sql"), "CREATE TABLE t (id INT);").unwrap();
        assert_eq!(detect_framework(dir.path()), Some("prisma"));
    }

    #[test]
    fn get_flyway_migrations_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("V2__add_column.sql"), "ALTER TABLE t ADD COLUMN name TEXT;").unwrap();
        std::fs::write(dir.path().join("V1__init.sql"), "CREATE TABLE t (id INT);").unwrap();

        let migrations = get_migrations(dir.path());
        assert_eq!(migrations.len(), 2);
        assert_eq!(migrations[0].version, "1");
        assert_eq!(migrations[1].version, "2");
    }

    #[test]
    fn no_framework_detected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("queries.sql"), "SELECT 1").unwrap();
        assert_eq!(detect_framework(dir.path()), None);
        assert!(get_migrations(dir.path()).is_empty());
    }
}

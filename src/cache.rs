use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

pub struct CacheManager {
    cache_dir: PathBuf,
}

impl CacheManager {
    pub fn new(cache_dir: &str) -> Self {
        let dir = PathBuf::from(cache_dir);
        std::fs::create_dir_all(&dir).ok();
        // Write .gitignore to prevent committing cache
        let gitignore = dir.join(".gitignore");
        if !gitignore.exists() {
            std::fs::write(&gitignore, "*\n").ok();
        }
        CacheManager { cache_dir: dir }
    }

    fn cache_key(&self, file_path: &Path, content: &str, config_hash: &str) -> String {
        let mut hasher = DefaultHasher::new();
        file_path.to_str().unwrap_or("").hash(&mut hasher);
        content.hash(&mut hasher);
        config_hash.hash(&mut hasher);
        env!("CARGO_PKG_VERSION").hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    pub fn get(&self, file_path: &Path, content: &str, config_hash: &str) -> Option<String> {
        let key = self.cache_key(file_path, content, config_hash);
        let cache_file = self.cache_dir.join(format!("{}.json", key));
        std::fs::read_to_string(&cache_file).ok()
    }

    pub fn set(&self, file_path: &Path, content: &str, config_hash: &str, result_json: &str) {
        let key = self.cache_key(file_path, content, config_hash);
        let cache_file = self.cache_dir.join(format!("{}.json", key));
        std::fs::write(&cache_file, result_json).ok();
    }

    pub fn clear(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    std::fs::remove_file(&path).ok();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::new(dir.path().to_str().unwrap());
        let path = Path::new("test.sql");

        assert!(cache.get(path, "SELECT 1", "hash1").is_none());

        cache.set(path, "SELECT 1", "hash1", r#"{"issues":[]}"#);
        let result = cache.get(path, "SELECT 1", "hash1");
        assert!(result.is_some());
        assert!(result.unwrap().contains("issues"));
    }

    #[test]
    fn cache_invalidates_on_content_change() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::new(dir.path().to_str().unwrap());
        let path = Path::new("test.sql");

        cache.set(path, "SELECT 1", "hash1", r#"{"old":true}"#);
        assert!(cache.get(path, "SELECT 2", "hash1").is_none());
    }

    #[test]
    fn cache_clear() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::new(dir.path().to_str().unwrap());
        let path = Path::new("test.sql");

        cache.set(path, "SELECT 1", "hash1", "data");
        cache.clear();
        assert!(cache.get(path, "SELECT 1", "hash1").is_none());
    }
}

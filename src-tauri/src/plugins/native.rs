use std::path::Path;
use std::sync::Arc;
use libloading::{Library, Symbol};
use crate::plugins::types::{
    AcquisitionSummary, OpenForensicPlugin, PluginContext, PluginCreateFn, PluginOutput, PluginType,
};

pub struct NativePlugin {
    // Declared before _lib so that inner is dropped before the dynamic library is unloaded
    inner: Box<dyn OpenForensicPlugin>,
    _lib: Arc<Library>,
}

unsafe impl Send for NativePlugin {}
unsafe impl Sync for NativePlugin {}

impl NativePlugin {
    /// Verify that the native plugin at `path` matches a trusted SHA-256 digest in ~/.openforensic/plugins_allowlist.json.
    pub fn verify_plugin_allowlist(path: &Path) -> Result<(), String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read plugin binary {}: {}", path.display(), e))?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hex_hash = hex::encode(hasher.finalize());

        let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".to_string());
        let allowlist_file = std::path::PathBuf::from(home).join(".openforensic").join("plugins_allowlist.json");

        if !allowlist_file.exists() {
            return Err(format!(
                "[SECURITY VIOLATION] Native plugin loading blocked! No trusted plugin allowlist found at {}. To trust this plugin, add its SHA-256 hash ({}) to a JSON array inside the allowlist file.",
                allowlist_file.display(), hex_hash
            ));
        }

        let content = std::fs::read_to_string(&allowlist_file)
            .map_err(|e| format!("Failed to read plugin allowlist: {}", e))?;
        
        let allowed: Vec<String> = serde_json::from_str(&content).map_err(|_| {
            "[SECURITY VIOLATION] Malformed plugin allowlist file. Must be a JSON array of trusted SHA-256 hex strings.".to_string()
        })?;

        if !allowed.iter().any(|h| h.eq_ignore_ascii_case(&hex_hash)) {
            return Err(format!(
                "[SECURITY VIOLATION] Unverified native plugin blocked! Plugin {} (SHA-256: {}) is not registered in the trusted allowlist ({}).",
                path.display(), hex_hash, allowlist_file.display()
            ));
        }

        Ok(())
    }

    /// Load a compiled native plugin (.so / .dll / .dylib) from disk and instantiate it after verifying its SHA-256 allowlist status.
    ///
    /// # Safety
    /// The caller must ensure that the library at `path` is a valid OpenForensic native plugin exposing
    /// a compatible `_openforensic_plugin_create` C ABI function that returns a valid trait object pointer.
    pub unsafe fn load(path: &Path) -> Result<Self, String> {
        Self::verify_plugin_allowlist(path)?;
        unsafe {
            let lib = Library::new(path)
                .map_err(|e| format!("Failed to load native library at {}: {}", path.display(), e))?;
            let lib = Arc::new(lib);

            let constructor: Symbol<PluginCreateFn> = lib
                .get(b"_openforensic_plugin_create\0")
                .map_err(|e| format!("Failed to find symbol '_openforensic_plugin_create' in {}: {}", path.display(), e))?;

            let raw_ptr = constructor();
            if raw_ptr.is_null() {
                return Err(format!("Plugin constructor in {} returned null pointer", path.display()));
            }

            let inner = Box::from_raw(raw_ptr);

            Ok(Self { inner, _lib: lib })
        }
    }
}

impl OpenForensicPlugin for NativePlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn version(&self) -> &str {
        self.inner.version()
    }

    fn plugin_type(&self) -> PluginType {
        self.inner.plugin_type()
    }

    fn pre_acquisition(&mut self, context: &PluginContext) -> Result<(), String> {
        self.inner.pre_acquisition(context)
    }

    fn on_block(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        self.inner.on_block(offset, data)
    }

    fn post_acquisition(&mut self, summary: &AcquisitionSummary) -> Result<PluginOutput, String> {
        self.inner.post_acquisition(summary)
    }
}

impl std::fmt::Debug for NativePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativePlugin")
            .field("name", &self.name())
            .field("version", &self.version())
            .field("type", &self.plugin_type())
            .finish()
    }
}

//! Approval backend routing for proxy endpoint-policy approvals.

use nono::{ApprovalBackend, NonoError};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Named approval backend registry used by endpoint-policy `approve` routes.
#[derive(Clone, Default)]
pub struct ApprovalBackendRegistry {
    default_backend: Option<String>,
    backends: Arc<BTreeMap<String, Arc<dyn ApprovalBackend>>>,
}

impl ApprovalBackendRegistry {
    /// Build a registry from named backends and an optional default route.
    #[must_use]
    pub fn new(
        default_backend: Option<String>,
        backends: BTreeMap<String, Arc<dyn ApprovalBackend>>,
    ) -> Self {
        Self {
            default_backend,
            backends: Arc::new(backends),
        }
    }

    /// Build a compatibility registry for callers that have one backend.
    #[must_use]
    pub fn singleton(backend: Arc<dyn ApprovalBackend>) -> Self {
        let name = backend.backend_name().to_string();
        let mut backends = BTreeMap::new();
        backends.insert(name.clone(), backend);
        Self::new(Some(name), backends)
    }

    /// Resolve an explicit backend name or the registry default.
    ///
    /// # Errors
    ///
    /// Returns an error when no explicit/default backend exists or when the
    /// resolved backend name is not registered.
    pub fn resolve(
        &self,
        backend: Option<&str>,
    ) -> nono::Result<(String, Arc<dyn ApprovalBackend>)> {
        let name = backend
            .map(str::to_string)
            .or_else(|| self.default_backend.clone())
            .ok_or_else(|| NonoError::SandboxInit("missing approval backend".to_string()))?;
        let backend =
            self.backends.get(&name).cloned().ok_or_else(|| {
                NonoError::SandboxInit(format!("unknown approval backend '{name}'"))
            })?;
        Ok((name, backend))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestBackend {
        name: &'static str,
    }

    impl ApprovalBackend for TestBackend {
        fn request_approval(
            &self,
            _request: &nono::ApprovalRequest,
        ) -> nono::Result<nono::ApprovalDecision> {
            Ok(nono::ApprovalDecision::Granted)
        }

        fn backend_name(&self) -> &str {
            self.name
        }
    }

    #[test]
    fn registry_resolves_explicit_and_default_backends() -> nono::Result<()> {
        let mut backends: BTreeMap<String, Arc<dyn ApprovalBackend>> = BTreeMap::new();
        backends.insert(
            "default".to_string(),
            Arc::new(TestBackend { name: "default" }),
        );
        backends.insert(
            "review".to_string(),
            Arc::new(TestBackend { name: "review" }),
        );
        let registry = ApprovalBackendRegistry::new(Some("default".to_string()), backends);

        let (name, _) = registry.resolve(None)?;
        assert_eq!(name, "default");
        let (name, _) = registry.resolve(Some("review"))?;
        assert_eq!(name, "review");

        Ok(())
    }

    #[test]
    fn registry_rejects_missing_default() {
        let registry = ApprovalBackendRegistry::new(None, BTreeMap::new());
        assert!(registry.resolve(None).is_err());
    }
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

mod middleware;
mod rbac;

pub use middleware::*;
pub use rbac::*;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Token generation failed: {0}")]
    TokenGenerationFailed(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

// =============================================================================
// JWT
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expires_in_secs: usize,
}

impl JwtConfig {
    /// Load the signing secret from the environment.
    ///
    /// There is deliberately **no default**. A fallback secret that ships in
    /// source and in the binary allows anyone to mint an admin token by
    /// HMAC-signing their own claims with a publicly known key, so the server
    /// refuses to start without an operator-supplied secret.
    ///
    /// `SPECTRA_JWT_SECRET` is the canonical variable name. `JWT_SECRET` is
    /// accepted as a deprecated alias because earlier documentation and compose
    /// files used it; using the alias emits a warning.
    pub fn from_env() -> AuthResult<Self> {
        const MIN_SECRET_BYTES: usize = 32;
        const ENV_CANONICAL: &str = "SPECTRA_JWT_SECRET";
        const ENV_LEGACY: &str = "JWT_SECRET";

        let (secret, source) = match std::env::var(ENV_CANONICAL) {
            Ok(v) => (v, ENV_CANONICAL),
            Err(_) => match std::env::var(ENV_LEGACY) {
                Ok(v) => {
                    tracing::warn!(
                        env = ENV_LEGACY,
                        "deprecated: use SPECTRA_JWT_SECRET instead"
                    );
                    (v, ENV_LEGACY)
                }
                Err(_) => {
                    return Err(AuthError::ConfigError(format!(
                        "{ENV_CANONICAL} is not set. Generate one with \
                         `openssl rand -base64 48` and set it in the environment. \
                         Spectra does not ship a default signing secret."
                    )));
                }
            },
        };

        if secret.len() < MIN_SECRET_BYTES {
            return Err(AuthError::ConfigError(format!(
                "{source} is too short: {} bytes, minimum is {MIN_SECRET_BYTES}. \
                 Generate one with `openssl rand -base64 48`.",
                secret.len()
            )));
        }

        Ok(Self {
            secret,
            expires_in_secs: default_token_ttl_secs(),
        })
    }
}

fn default_token_ttl_secs() -> usize {
    std::env::var("SPECTRA_JWT_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600)
}

impl Default for JwtConfig {
    /// Retained for tests and for callers that already hold a secret.
    ///
    /// The value here is a placeholder, not a usable secret: it is too short to
    /// satisfy [`JwtConfig::from_env`] and is obviously non-random. Production
    /// code must obtain a real secret via [`JwtConfig::from_env`].
    fn default() -> Self {
        Self {
            secret: String::new(),
            expires_in_secs: 3600,
        }
    }
}

pub struct JwtService {
    config: JwtConfig,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Token lifetime in seconds, so callers do not have to restate it.
    pub fn expires_in_secs(&self) -> usize {
        self.config.expires_in_secs
    }

    /// Reject an unset secret before it can be used to sign or verify anything.
    ///
    /// Without this, an empty key would HMAC consistently on both sides and
    /// silently authenticate every forged token.
    fn ensure_configured(&self) -> AuthResult<()> {
        if self.config.secret.is_empty() {
            return Err(AuthError::ConfigError(
                "JWT signing secret is empty; call JwtConfig::from_env() to load it".to_string(),
            ));
        }
        Ok(())
    }

    pub fn encode(&self, claims: &Claims) -> AuthResult<String> {
        self.ensure_configured()?;
        let header = serde_json::json!({
            "alg": "HS256",
            "typ": "JWT"
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header)
                .map_err(|e| AuthError::TokenGenerationFailed(e.to_string()))?,
        );

        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(claims)
                .map_err(|e| AuthError::TokenGenerationFailed(e.to_string()))?,
        );

        let message = format!("{}.{}", header_b64, payload_b64);

        let mut mac = HmacSha256::new_from_slice(self.config.secret.as_bytes())
            .map_err(|e| AuthError::TokenGenerationFailed(e.to_string()))?;
        mac.update(message.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        Ok(format!("{}.{}", message, signature))
    }

    pub fn decode(&self, token: &str) -> AuthResult<Claims> {
        self.ensure_configured()?;
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidToken(
                "Token must have 3 parts".to_string(),
            ));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let mut mac = HmacSha256::new_from_slice(self.config.secret.as_bytes())
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        mac.update(message.as_bytes());
        mac.verify_slice(&signature_bytes)
            .map_err(|_| AuthError::InvalidToken("Invalid signature".to_string()))?;

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let claims: Claims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let now = chrono::Utc::now().timestamp() as usize;
        if claims.exp < now {
            return Err(AuthError::TokenExpired);
        }

        Ok(claims)
    }

    pub fn create_token(
        &self,
        user_id: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> AuthResult<String> {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: user_id.to_string(),
            roles,
            permissions,
            iat: now,
            exp: now + self.config.expires_in_secs,
        };
        self.encode(&claims)
    }
}

// =============================================================================
// User
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: Vec<Role>,
    pub active: bool,
    pub created_at: String,
    pub last_login: Option<String>,
}

impl User {
    pub fn new(
        id: impl Into<String>,
        username: impl Into<String>,
        email: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            username: username.into(),
            email: email.into(),
            roles: Vec::new(),
            active: true,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_login: None,
        }
    }

    pub fn with_role(mut self, role: Role) -> Self {
        self.roles.push(role);
        self
    }

    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.roles.iter().any(|r| r.has_permission(permission))
    }

    pub fn effective_permissions(&self) -> Vec<Permission> {
        let mut perms = std::collections::HashSet::new();
        for role in &self.roles {
            for perm in &role.permissions() {
                perms.insert(perm.clone());
            }
        }
        perms.into_iter().collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_encode_decode() {
        let service = JwtService::new(JwtConfig {
            secret: "test-secret".to_string(),
            expires_in_secs: 3600,
        });

        let claims = Claims {
            sub: "user1".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec!["read".to_string(), "write".to_string()],
            iat: chrono::Utc::now().timestamp() as usize,
            exp: chrono::Utc::now().timestamp() as usize + 3600,
        };

        let token = service.encode(&claims).unwrap();
        let decoded = service.decode(&token).unwrap();
        assert_eq!(decoded.sub, "user1");
        assert_eq!(decoded.roles, vec!["admin"]);
    }

    #[test]
    fn jwt_expired_token() {
        let service = JwtService::new(JwtConfig {
            secret: "test-secret".to_string(),
            expires_in_secs: 3600,
        });

        let claims = Claims {
            sub: "user1".to_string(),
            roles: vec![],
            permissions: vec![],
            iat: 1000000000,
            exp: 1000000001,
        };

        let token = service.encode(&claims).unwrap();
        assert!(matches!(
            service.decode(&token),
            Err(AuthError::TokenExpired)
        ));
    }

    #[test]
    fn jwt_invalid_signature() {
        let service1 = JwtService::new(JwtConfig {
            secret: "secret1".to_string(),
            expires_in_secs: 3600,
        });
        let service2 = JwtService::new(JwtConfig {
            secret: "secret2".to_string(),
            expires_in_secs: 3600,
        });

        let claims = Claims {
            sub: "user1".to_string(),
            roles: vec![],
            permissions: vec![],
            iat: chrono::Utc::now().timestamp() as usize,
            exp: chrono::Utc::now().timestamp() as usize + 3600,
        };

        let token = service1.encode(&claims).unwrap();
        assert!(matches!(
            service2.decode(&token),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn user_roles() {
        let user = User::new("1", "admin", "admin@test.com")
            .with_role(Role::Admin)
            .with_role(Role::Viewer);

        assert!(user.has_role(&Role::Admin));
        assert!(user.has_role(&Role::Viewer));
        assert!(!user.has_role(&Role::Scanner));
    }

    #[test]
    fn user_permissions() {
        let user = User::new("1", "scanner", "scanner@test.com").with_role(Role::Scanner);

        assert!(user.has_permission(&Permission::ScansExecute));
        assert!(user.has_permission(&Permission::TargetsRead));
        assert!(!user.has_permission(&Permission::SettingsWrite));
    }
}

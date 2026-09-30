use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::rbac::Permission;
use crate::{Claims, JwtService};

/// Extension that holds the authenticated user's claims.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Claims);

/// Check that the caller on `request` holds `permission`.
///
/// Split out from the middleware so the decision is a plain function that can
/// be tested directly, rather than only observable through a routed request.
///
/// # Why this is not optional
///
/// This authorisation layer had no call sites, so every authenticated route was
/// in practice available to every authenticated caller. Adding routes without
/// it silently reintroduces that.
///
/// # Scope
///
/// Permissions come from the token claims, so a change to a caller's roles does
/// not take effect until the token is refreshed, and a token cannot be revoked
/// before it expires. Both are acceptable while roles are fixed at account
/// creation, and neither is acceptable once roles become user-assignable — at
/// that point this needs a store lookup, not a claim.
pub fn check_permission(user: &AuthUser, permission: &Permission) -> Result<(), StatusCode> {
    if user.has_permission(permission) {
        return Ok(());
    }
    tracing::warn!(
        subject = %user.subject(),
        required = %permission,
        "denied: caller lacks the required permission"
    );
    Err(StatusCode::FORBIDDEN)
}

/// As [`check_permission`], but for several permissions that must all be held.
pub fn check_all_permissions(
    user: &AuthUser,
    permissions: &[Permission],
) -> Result<(), StatusCode> {
    if user.has_all(permissions) {
        return Ok(());
    }
    let required: Vec<String> = permissions.iter().map(|p| p.to_string()).collect();
    tracing::warn!(
        subject = %user.subject(),
        ?required,
        "denied: caller lacks one or more required permissions"
    );
    Err(StatusCode::FORBIDDEN)
}

/// Pull the authenticated caller out of a request's extensions.
///
/// `None` means the authentication middleware did not run, or did not insert a
/// user. Callers should turn that into `401`, not `403`: the difference tells an
/// operator whether a route is missing its auth layer.
pub fn authenticated_user(request: &Request<Body>) -> Option<&AuthUser> {
    request.extensions().get::<AuthUser>()
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Authentication middleware for Axum.
///
/// Extracts the Bearer token from the Authorization header, validates it,
/// and inserts the `AuthUser` extension into the request.
///
/// # Why this takes state
///
/// This middleware must not read `SPECTRA_JWT_SECRET` itself. When it did, the
/// *verifier* was an independently constructed [`JwtService`] rebuilt from a
/// second environment read on every request, distinct from the
/// `AppState::jwt_service` that *signs* tokens. Two objects, two sources of
/// truth, able to silently disagree — and because the middleware could not see
/// the user store, revocation was structurally impossible.
///
/// Use [`auth_middleware_with_state`] so the same service that signed the token
/// verifies it.
#[allow(unused_variables)]
pub async fn auth_middleware(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    // No state available: fail closed rather than falling back to an
    // environment-derived secret. Callers should use the stateful variant.
    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Stateful variant of [`auth_middleware`].
///
/// Registered with `axum::middleware::from_fn_with_state`.
pub async fn auth_middleware_with_state(
    State(jwt_service): State<Arc<JwtService>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    let token = match auth_header {
        Some(header) => {
            if let Some(token) = header.strip_prefix("Bearer ") {
                token.trim().to_string()
            } else {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        None => {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match jwt_service.decode(&token) {
        Ok(claims) => {
            request.extensions_mut().insert(AuthUser(claims));
            Ok(next.run(request).await)
        }
        // Expired and invalid are both 401 by design: distinguishing them would
        // tell an unauthenticated caller which tokens exist.
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

// The layer-building middleware that used to live here as
// `require_permission_fn` is removed. It was a third implementation of "may this
// caller?", and it disagreed with the other two: it re-derived permissions from
// `claims.roles` and ignored `claims.permissions` entirely. Three answers to one
// question is how the bootstrap admin ended up granting `scans:write`, a
// permission this codebase does not define. There is now one
// (`check_permission`), and the middleware that applies it is built at the route
// table so each method's requirement is visible where the handler is.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JwtConfig, JwtService};

    fn test_claims() -> Claims {
        Claims {
            sub: "user1".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec!["orgs:read".to_string()],
            iat: chrono::Utc::now().timestamp() as usize,
            exp: chrono::Utc::now().timestamp() as usize + 3600,
        }
    }

    #[test]
    fn auth_user_extension() {
        let claims = test_claims();
        let user = AuthUser(claims.clone());
        assert_eq!(user.0.sub, "user1");
    }

    /// The grant list, not the role name, decides.
    ///
    /// `test_claims` carries the `admin` role but a single granted permission.
    /// The previous implementation consulted `claims.roles` and ignored
    /// `claims.permissions`, so it answered "yes" to everything for this token.
    /// Consulting roles at authorisation time makes the token self-escalating:
    /// anyone who can influence the role claim gains every permission, whatever
    /// the issuer actually granted. `permission_tests` covers the rest.
    #[test]
    fn an_admin_role_does_not_widen_a_narrow_grant_list() {
        let user = AuthUser(test_claims());
        assert!(user.0.roles.contains(&"admin".to_string()));

        assert_eq!(
            check_permission(&user, &crate::Permission::OrgsRead),
            Ok(())
        );
        assert_eq!(
            check_permission(&user, &crate::Permission::UsersWrite),
            Err(StatusCode::FORBIDDEN),
            "the token grants only orgs:read, so users:write must be refused"
        );
    }

    #[test]
    fn token_roundtrip() {
        let service = JwtService::new(JwtConfig {
            secret: "test-secret".to_string(),
            expires_in_secs: 3600,
        });

        let token = service
            .create_token(
                "user1",
                vec!["admin".to_string()],
                vec!["orgs:read".to_string()],
            )
            .unwrap();

        let claims = service.decode(&token).unwrap();
        assert_eq!(claims.sub, "user1");
        assert_eq!(claims.roles, vec!["admin"]);
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;
    use crate::rbac::Role;

    fn user(roles: &[&str], permissions: &[&str]) -> AuthUser {
        AuthUser(Claims {
            sub: "tester".to_string(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
            exp: 0,
            iat: 0,
        })
    }

    fn admin_user() -> AuthUser {
        let granted: Vec<String> = Role::Admin
            .permissions()
            .iter()
            .map(|p| p.to_string())
            .collect();
        user(
            &["admin"],
            &granted.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn granted_permission_is_admitted() {
        let user = admin_user();
        assert_eq!(check_permission(&user, &Permission::ScansExecute), Ok(()));
        assert_eq!(check_permission(&user, &Permission::UsersDelete), Ok(()));
    }

    #[test]
    fn absent_permission_is_forbidden() {
        let user = user(&["viewer"], &["findings:read"]);
        assert_eq!(
            check_permission(&user, &Permission::UsersDelete),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn empty_grant_list_denies_everything() {
        // The fail-open direction. A token with no permissions must not be
        // treated as unrestricted.
        let user = user(&["admin"], &[]);
        for permission in Role::Admin.permissions() {
            assert_eq!(
                check_permission(&user, &permission),
                Err(StatusCode::FORBIDDEN),
                "an empty grant list must not admit {permission}"
            );
        }
    }

    #[test]
    fn a_permission_no_role_defines_is_never_granted() {
        // Pins the drift that let `scans:write` sit in the admin's stored list
        // for so long: it is not a permission, so no role can ever grant it.
        assert!(
            "scans:write".parse::<Permission>().is_err(),
            "`scans:write` must not be a valid permission"
        );
        let user = user(&["admin"], &["scans:write"]);
        assert_eq!(
            check_permission(&user, &Permission::ScansExecute),
            Err(StatusCode::FORBIDDEN),
            "an unrecognised grant string must not map onto a real permission"
        );
    }

    #[test]
    fn roles_in_claims_do_not_grant_by_themselves() {
        // The token's grant list is the authority. If roles were consulted
        // directly here, deleting a role from an account would not revoke
        // anything until the token expired, and a token that claimed `admin`
        // would be self-escalating.
        let user = user(&["admin"], &["findings:read"]);
        assert_eq!(
            check_permission(&user, &Permission::UsersDelete),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(check_permission(&user, &Permission::FindingsRead), Ok(()));
    }

    #[test]
    fn all_of_requires_every_permission() {
        let user = user(&["scanner"], &["findings:read", "findings:write"]);
        assert_eq!(
            check_all_permissions(
                &user,
                &[Permission::FindingsRead, Permission::FindingsWrite]
            ),
            Ok(())
        );
        assert_eq!(
            check_all_permissions(&user, &[Permission::FindingsRead, Permission::UsersDelete]),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(check_all_permissions(&user, &[]), Ok(()));
    }

    #[test]
    fn subject_is_the_claim_not_the_password() {
        assert_eq!(user(&["viewer"], &[]).subject(), "tester");
    }

    #[test]
    fn unknown_role_name_grants_nothing() {
        assert!(!Role::is_known_name("superuser"));
        assert!(Role::permissions_for_name("superuser").is_empty());
        assert!(Role::is_known_name("admin"));
        assert!(!Role::permissions_for_name("admin").is_empty());
    }

    #[test]
    fn a_typo_in_a_role_name_is_detectable() {
        // `FromStr` accepts any string as `Role::Custom`, so a near-miss like
        // "admn" parses successfully and grants nothing. Without
        // `is_known_name` that is indistinguishable from a deliberate custom
        // role, and the account silently loses every permission.
        for typo in ["admn", "Adminn", "adminn", "admi", "vwier", "scannner"] {
            assert!(
                typo.parse::<Role>().is_ok(),
                "FromStr is expected to accept {typo} as a custom role"
            );
            assert!(
                !Role::is_known_name(typo),
                "{typo} must be reported as an unknown role, not silently treated as custom"
            );
            assert!(
                Role::permissions_for_name(typo).is_empty(),
                "{typo} must grant nothing"
            );
        }
    }

    #[test]
    fn role_names_are_case_insensitive() {
        for name in Role::builtin_names() {
            assert!(Role::is_known_name(name));
            assert!(Role::is_known_name(&name.to_uppercase()));
            assert_eq!(
                Role::permissions_for_name(&name.to_uppercase()),
                Role::permissions_for_name(name)
            );
        }
    }

    #[test]
    fn every_permission_round_trips_through_its_string() {
        // The wire format is the `Display` string. If a variant's string stops
        // parsing back, a granted permission silently stops matching what the
        // guard asks for, and the route denies everyone.
        for permission in Role::Admin.permissions() {
            let text = permission.to_string();
            let parsed: Permission = text
                .parse()
                .unwrap_or_else(|e| panic!("{text} must parse back: {e}"));
            assert_eq!(parsed, permission, "{text} did not round-trip");
        }
    }

    #[test]
    fn every_role_round_trips_through_its_string() {
        for role in [Role::Admin, Role::Manager, Role::Scanner, Role::Viewer] {
            let text = role.to_string();
            let parsed: Role = text
                .parse()
                .unwrap_or_else(|e| panic!("{text} must parse back: {e}"));
            assert_eq!(parsed, role, "{text} did not round-trip");
        }
    }

    #[test]
    fn admin_is_a_superset_of_every_other_role() {
        // Otherwise some role grants something the admin lacks, which is
        // always a mistake in this direction.
        let admin = Role::Admin.permissions();
        for role in [Role::Manager, Role::Scanner, Role::Viewer] {
            for permission in role.permissions() {
                assert!(
                    admin.contains(&permission),
                    "{role} holds {permission} but admin does not"
                );
            }
        }
    }

    #[test]
    fn a_custom_role_grants_nothing() {
        // Documented limitation, pinned so it is a deliberate state rather than
        // an accident: a custom role's grants are not represented anywhere, so
        // resolving it to nothing is the only fail-closed option available.
        assert!(Role::Custom("auditor".to_string()).permissions().is_empty());
        assert!(!Role::Custom("auditor".to_string()).has_permission(&Permission::FindingsRead));
    }
}

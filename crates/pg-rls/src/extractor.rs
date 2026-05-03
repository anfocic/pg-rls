use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use std::fmt;

/// A tenant identifier, serialized to a string.
///
/// `TenantId` wraps a `String` rather than a typed key (`Uuid`, `i64`, …)
/// because Postgres GUCs and `current_setting` only deal in text. Carrying
/// a string at the boundary lets the same crate serve apps whose tenant
/// IDs are UUIDs, integers, slugs, or anything else.
///
/// In the typical Axum path:
///
/// 1. your auth middleware decodes the caller's tenant identity
/// 2. it inserts `TenantId` into request extensions
/// 3. [`crate::pool::tenant_scope`] scopes that value for the async call chain
/// 4. the pool hooks read it and set the configured Postgres GUC
///
/// Construct from whatever shape your app uses:
///
/// ```
/// use pg_rls::TenantId;
/// use uuid::Uuid;
///
/// let by_uuid = TenantId::from(Uuid::new_v4());
/// let by_int  = TenantId::from(42_i64);
/// let by_slug = TenantId::from("acme-co".to_string());
/// ```
///
/// On the policy side, cast the GUC back to your column type:
///
/// ```sql
/// -- uuid tenants
/// USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
///
/// -- bigint tenants
/// USING (tenant_id = current_setting('app.tenant_id', true)::bigint)
///
/// -- text/slug tenants
/// USING (tenant_id = current_setting('app.tenant_id', true))
/// ```
///
/// Implements [`FromRequestParts`] by reading
/// [`Extension<TenantId>`](axum::Extension) off the request. Your own auth
/// middleware is expected to insert the extension; if it is missing the
/// extractor returns `500 Internal Server Error` because that indicates a
/// server wiring bug, not a client problem.
///
/// That makes it appropriate for handlers that should only run once your
/// app has already established tenant context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct a `TenantId` from anything string-like.
    ///
    /// Equivalent to `TenantId(value.into())`. Prefer the `From` impls
    /// for typed inputs (`Uuid`, integers); this helper is the catch-all.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string. The value that lands in
    /// `current_setting('app.tenant_id', ...)`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the underlying `String`.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for TenantId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<uuid::Uuid> for TenantId {
    fn from(u: uuid::Uuid) -> Self {
        Self(u.to_string())
    }
}

macro_rules! tenant_id_from_int {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for TenantId {
                fn from(n: $t) -> Self {
                    Self(n.to_string())
                }
            }
        )+
    };
}

tenant_id_from_int!(i32, i64, u32, u64, i128, u128);

impl<S> FromRequestParts<S> for TenantId
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<TenantId>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "pg-rls: TenantId extension missing — your auth layer must insert it",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn extracts_tenant_id_from_request_extensions() {
        let mut parts = Request::builder()
            .uri("/")
            .extension(TenantId::new("acme-co"))
            .body(())
            .expect("build request")
            .into_parts()
            .0;

        let tenant = TenantId::from_request_parts(&mut parts, &())
            .await
            .expect("extract tenant");

        assert_eq!(tenant.as_str(), "acme-co");
    }

    #[tokio::test]
    async fn missing_extension_is_a_server_error() {
        let mut parts = Request::builder()
            .uri("/")
            .body(())
            .expect("build request")
            .into_parts()
            .0;

        let err = TenantId::from_request_parts(&mut parts, &())
            .await
            .expect_err("missing extension should reject");

        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            err.1,
            "pg-rls: TenantId extension missing — your auth layer must insert it"
        );
    }
}

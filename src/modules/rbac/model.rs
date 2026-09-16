use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const USER_ROLE: &str = "user";
pub const ADMIN_ROLE: &str = "admin";

/// A role granted to an account. Role names are validated by a database constraint, so this
/// type stays a transparent wrapper rather than duplicating the rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn user() -> Self {
        Self(USER_ROLE.to_owned())
    }

    pub fn admin() -> Self {
        Self(ADMIN_ROLE.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_admin(&self) -> bool {
        self.0 == ADMIN_ROLE
    }
}

impl std::fmt::Display for RoleName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_roles_are_recognized() {
        assert!(RoleName::admin().is_admin());
        assert!(!RoleName::user().is_admin());
        assert_eq!(RoleName::user().to_string(), USER_ROLE);
    }
}

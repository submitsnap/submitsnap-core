use uuid::Uuid;

/// Result of presenting a refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The token was valid, has been marked used, and a replacement was issued.
    Rotated { user_id: Uuid, session_id: Uuid },
    /// The token had already been exchanged. Either it was stolen and replayed, or the
    /// legitimate client retried after its first refresh succeeded. Both cases must revoke
    /// the whole session family.
    Reused { user_id: Uuid, session_id: Uuid },
    /// Unknown, revoked, or expired: indistinguishable to the caller.
    Invalid,
}

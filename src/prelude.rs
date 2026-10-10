//! Rust type-checking facade for policy source. Authoritative execution uses the validated IR.
//! The async approval facade fails closed; the oracle interpreter supplies authenticated answers.
pub use crate::paysh;
pub use crate::primitives::OwnerLimit;
pub use crate::{ConfidenceInterval, Context};
use alloc::string::String;
pub type PolicyResult = Result<(), PolicyError>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub code: String,
    pub reason: String,
}
fn error(code: &str, reason: &str) -> PolicyError {
    PolicyError {
        code: code.into(),
        reason: reason.into(),
    }
}
pub fn fail(reason: &str) -> PolicyResult {
    Err(error("POLICY_REJECTED", reason))
}
/// Convert an exact six-decimal USDC amount to policy units. Zero is allowed for comparisons.
pub fn usdc(amount: &str) -> Result<u64, PolicyError> {
    crate::readability::decimal_units(amount, 6).map_err(|e| error(&e.code, &e.message))
}
/// Convert 0..=100 percent to basis points, with at most two decimal places.
pub fn percent(value: &str) -> Result<u64, PolicyError> {
    crate::readability::percentage_bps(value).map_err(|e| error(&e.code, &e.message))
}
/// Inclusive comparison in the policy's six-decimal USDC unit.
pub fn amount_at_most(ctx: &Context, amount: &str) -> Result<bool, PolicyError> {
    if ctx.token != "USDC" {
        return Err(error("TOKEN_MISMATCH", "Token does not match."));
    }
    Ok(ctx.amount_units <= usdc(amount)?)
}
/// Whether a return is no more than the specified percentage points below the benchmark.
pub fn within_percentage_points(
    candidate: u64,
    benchmark: u64,
    gap: &str,
) -> Result<bool, PolicyError> {
    let gap = percent(gap)?;
    Ok(candidate >= benchmark || benchmark - candidate <= gap)
}
pub fn set_cap(ctx: &Context, amount: &str, token: &str) -> PolicyResult {
    let cap =
        crate::validation::amount_units(amount).map_err(|e| error("INVALID_AMOUNT", &e.message))?;
    if token != "USDC" || ctx.token != token {
        return Err(error("TOKEN_MISMATCH", "Token does not match."));
    }
    if ctx
        .spent_units
        .checked_add(ctx.amount_units)
        .is_none_or(|n| n > cap)
    {
        return Err(error(
            "POLICY_CAP_EXCEEDED",
            "Total spending limit exceeded.",
        ));
    }
    Ok(())
}
pub fn cap_per_transaction(ctx: &Context, amount: &str, token: &str) -> PolicyResult {
    let cap =
        crate::validation::amount_units(amount).map_err(|e| error("INVALID_AMOUNT", &e.message))?;
    if token != "USDC" || ctx.token != token {
        return Err(error("TOKEN_MISMATCH", "Token does not match."));
    }
    if ctx.amount_units > cap {
        return Err(error("PURCHASE_CAP_EXCEEDED", "Purchase limit exceeded."));
    }
    Ok(())
}
#[cfg(feature = "oracle-ledger")]
pub fn cap_purchase_tiers(
    ctx: &Context,
    maximum: &str,
    first_count: u64,
    token: &str,
) -> PolicyResult {
    if token != "USDC" || ctx.token != token {
        return Err(error("TOKEN_MISMATCH", "Token does not match."));
    }
    let maximum = crate::validation::amount_units(maximum)
        .map_err(|e| error("INVALID_AMOUNT", &e.message))?;
    crate::spending::check_tiers(ctx, maximum, first_count).map_err(|e| error(&e.code, &e.reason))
}
#[cfg(not(feature = "oracle-ledger"))]
pub fn cap_purchase_tiers(
    _ctx: &Context,
    _maximum: &str,
    _first_count: u64,
    _token: &str,
) -> PolicyResult {
    Err(error(
        "LEDGER_REQUIRED",
        "Purchase tiers require the oracle ledger feature.",
    ))
}
pub fn allow_actions(ctx: &Context, actions: &[&str]) -> PolicyResult {
    if actions.contains(&ctx.action.as_str()) {
        Ok(())
    } else {
        Err(error("ACTION_NOT_ALLOWED", "Action is not permitted."))
    }
}
pub fn require_merchant(ctx: &Context, merchant: &str) -> PolicyResult {
    if ctx.merchant == merchant {
        Ok(())
    } else {
        Err(error("MERCHANT_NOT_ALLOWED", "Merchant is not permitted."))
    }
}
pub fn require_recipient(ctx: &Context, recipient: &str) -> PolicyResult {
    if ctx.recipient == recipient {
        Ok(())
    } else {
        Err(error(
            "RECIPIENT_NOT_ALLOWED",
            "Recipient is not permitted.",
        ))
    }
}
pub fn confidence(ctx: &Context, name: &str) -> Result<ConfidenceInterval, PolicyError> {
    let value = ctx
        .confidence
        .get(name)
        .ok_or_else(|| error("EVIDENCE_REQUIRED", "Confidence evidence is required."))?;
    if value.lower_bps > value.upper_bps || value.upper_bps > 10000 {
        return Err(error("INVALID_EVIDENCE", "Confidence bounds are invalid."));
    }
    Ok(*value)
}
pub fn semantic(ctx: &Context, question: &str) -> Result<ConfidenceInterval, PolicyError> {
    if question.trim().is_empty() || question.len() > 1024 {
        return Err(error(
            "INVALID_POLICY",
            "Use a preference question of 1–1,024 bytes.",
        ));
    }
    if ctx.original_intent.trim().is_empty() {
        return Err(error(
            "ORIGINAL_INTENT_REQUIRED",
            "Original policy instructions are required.",
        ));
    }
    confidence(ctx, &crate::semantic_evidence_key(question)).map_err(|e| {
        if e.code == "EVIDENCE_REQUIRED" {
            error(
                "SEMANTIC_EVIDENCE_REQUIRED",
                "A preference assessment is required.",
            )
        } else {
            e
        }
    })
}
pub fn context_u64(ctx: &Context, key: &str) -> Result<u64, PolicyError> {
    let value = ctx
        .runtime_context
        .get(key)
        .ok_or_else(|| error("CONTEXT_VALUE_REQUIRED", "A request value is missing."))?;
    value.as_u64().ok_or_else(|| {
        error(
            "INVALID_CONTEXT_VALUE",
            "The request value must be a non-negative whole number.",
        )
    })
}
/// Inclusive preference thresholds. Scores between enabled thresholds require owner input.
pub async fn check_preference(
    ctx: &Context,
    question: &str,
    auto_approve: bool,
    approve_percent: &str,
    auto_deny: bool,
    deny_percent: &str,
) -> PolicyResult {
    let approve = percent(approve_percent)?;
    let deny = percent(deny_percent)?;
    if auto_approve && auto_deny && deny >= approve {
        return Err(error("INVALID_POLICY", "Denial must be below approval."));
    }
    if question.trim().is_empty() || question.len() > 1024 {
        return Err(error(
            "INVALID_POLICY",
            "Use a preference question of 1–1,024 bytes.",
        ));
    }
    if !auto_approve && !auto_deny {
        return require_user_input(ctx, question).await;
    }
    let fit = semantic(ctx, question)?;
    if auto_deny && fit.upper_bps <= deny {
        return fail("The request does not meet this preference.");
    }
    if !auto_approve || fit.lower_bps < approve {
        require_user_input(ctx, question).await?;
    }
    Ok(())
}
pub async fn require_user_input(_ctx: &Context, _prompt: &str) -> PolicyResult {
    Err(error(
        "USER_INPUT_REQUIRED",
        "Use the trusted oracle to obtain an authenticated answer.",
    ))
}

/// Jev preference evidence and owner-feedback checks.
/// The trusted oracle supplies evidence and authenticated owner answers.
pub mod jev {
    pub use super::semantic;
    #[cfg(feature = "std")]
    pub use crate::primitives::check_preference;
    pub use crate::primitives::preference_evidence;
}

use allowit::v1::prelude::*;

struct PolicyParams { total_limit: u64 }
fn new() -> PolicyParams { PolicyParams { total_limit: 5_000_000 } }

async fn _execute(ctx: &Context, params: &PolicyParams) -> PolicyResult {
    allowit::set_cap(ctx.spent_units, ctx.amount_units, &ctx.token, params.total_limit, "HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv", 6)?;
    allowit::cap_per_transaction(ctx.amount_units, &ctx.token, 1000, "HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv", 6)?;
    jev::check_preference(jev::preference_evidence(ctx, "Does this air-quality request fit the owner's intent?"), "Does this air-quality request fit the owner's intent?", None, None).await?;
    if !paysh::call("air-quality", "canonical-service-input", 1000, 5000000, 100000) {
        return allowit::fail("Provider call is unavailable");
    }
    Ok(())
}

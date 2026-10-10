// Café λ 🟢 — authenticated native request
use allowit::prelude::*;
struct PolicyParams { native_asset: &'static str, total_native_budget: u64 }
fn new() -> PolicyParams { PolicyParams { native_asset: "native:solana:0909090909090909090909090909090909090909090909090909090909090909", total_native_budget:50000000 } }
async fn _execute(ctx: &Context, params:&PolicyParams) -> PolicyResult {
    if let Some(request) = &ctx.execution_request {
        let validé = allowit::execution_request_validate(request)?;
        allowit::execution_request_cap(&validé,"native-budget",params.native_asset,9,params.total_native_budget,10000000,10000)?;
        for effect in &validé.request.effect_bounds {
            if effect.max_debit > 10000000 { return allowit::fail("Débit exceeds owner ceiling 🟢"); }
            if effect.max_burn > 0 { return allowit::fail("Burn is not allowed"); }
        }
        if let Some(fees) = &validé.request.fee_bounds {
            for fee in fees {
                if fee.max_fee > 10000 { return allowit::fail("Fee exceeds owner ceiling"); }
            }
        } else { return allowit::fail("Fees are unresolved"); }
    } else { return allowit::fail("Native request is missing"); }
    Ok(())
}

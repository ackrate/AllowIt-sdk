use allowit::prelude::*;
struct PolicyParams { native_asset: &'static str, total_native_budget: u64, token_asset: &'static str, total_token_budget:u64 }
fn new() -> PolicyParams { PolicyParams { native_asset: "native:solana:0909090909090909090909090909090909090909090909090909090909090909", total_native_budget:50000000, token_asset:"token:solana:0909090909090909090909090909090909090909090909090909090909090909:1616161616161616161616161616161616161616161616161616161616161616:contract", total_token_budget:5000 } }
async fn _execute(ctx: &Context, params:&PolicyParams) -> PolicyResult {
    if let Some(request) = &ctx.curl_request {
        if let Some(outcome) = &ctx.curl_outcome {
            let proposed = paysh::payment_request_from_curl(outcome, request)?;
            if let Some(payment) = proposed {
                allowit::payment_request_cap(&payment,"token-budget",params.token_asset,6,params.total_token_budget,1000,0)?;
                allowit::payment_request_cap(&payment,"native-budget",params.native_asset,9,params.total_native_budget,0,10000)?;
                if payment.payment.units > 1000 { return allowit::fail("Payment exceeds owner ceiling"); }
                if payment.payment.decimals != 6 { return allowit::fail("Wrong decimal scale"); }
                if let Some(fees) = &payment.fee_bounds {
                    for fee in fees {
                        if fee.max_fee > 10000 { return allowit::fail("Fee exceeds owner ceiling"); }
                    }
                } else { return allowit::fail("Fees are unresolved"); }
            }
        } else { return allowit::fail("HTTP outcome is missing"); }
    } else { return allowit::fail("HTTP request is missing"); }
    Ok(())
}

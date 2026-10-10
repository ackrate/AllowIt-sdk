#[cfg(feature = "compiler")]
use crate::CompiledPolicy;
use crate::validation::amount_units;
use crate::{
    ConfidenceInterval, Context, Decision, Expr, Profile, Program, Statement, canonical_ir_hash,
    digest, validate_program,
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    String(String),
    Integer(u64),
    Boolean(bool),
    Unit,
    Context,
    Interval(ConfidenceInterval),
    Strings(Vec<String>),
    #[cfg(feature = "typed-workflow")]
    Workflow {
        ty: crate::typed_workflow::WorkflowType,
        data: serde_json::Value,
    },
}
type EvalResult = Result<Value, alloc::boxed::Box<Decision>>;

struct Evaluator<'a> {
    #[cfg(feature = "typed-workflow")]
    typed_profile: bool,
    context: &'a Context,
    profile: Profile,
    binding: String,
    steps: usize,
    #[cfg(feature = "typed-workflow")]
    system_operations: Vec<crate::ProviderCallPlan>,
    #[cfg(feature = "typed-workflow")]
    workflow_outputs: Vec<crate::typed_workflow::WorkflowOutput>,
    #[cfg(feature = "typed-workflow")]
    budget_guards: Vec<crate::typed_workflow::TypedBudgetRequirement>,
    #[cfg(feature = "compiler")]
    trace: Option<&'a mut crate::trace::TraceRecorder>,
    #[cfg(feature = "compiler")]
    block_depth: usize,
}
impl Evaluator<'_> {
    fn block(
        &mut self,
        statements: &[Statement],
        env: &mut BTreeMap<String, Value>,
    ) -> Result<bool, alloc::boxed::Box<Decision>> {
        #[cfg(feature = "compiler")]
        let top_level = self.block_depth == 0;
        #[cfg(feature = "compiler")]
        {
            self.block_depth += 1;
        }
        let result = (|| {
            for statement in statements {
                let result = (|| {
                    match statement {
                        Statement::Let { name, value, .. } => {
                            let value = self.expr(value, env)?;
                            env.insert(name.clone(), value);
                        }
                        Statement::Expression {
                            value, semicolon, ..
                        } => {
                            self.expr(value, env)?;
                            if !semicolon {
                                return Ok(true);
                            }
                        }
                        Statement::Return { value, .. } => {
                            self.expr(value, env)?;
                            return Ok(true);
                        }
                        #[cfg(feature = "typed-workflow")]
                        Statement::ForEach {
                            name, values, body, ..
                        } => {
                            let Value::Workflow {
                                ty: crate::typed_workflow::WorkflowType::Vec(inner),
                                data,
                            } = self.expr(values, env)?
                            else {
                                return Err(invalid());
                            };
                            let values = data.as_array().ok_or_else(invalid)?;
                            if values.len() > 64 {
                                return Err(failure(
                                    "WORKFLOW_LIMIT",
                                    "Typed collections contain at most 64 entries.",
                                ));
                            }
                            for item in values {
                                let mut branch = env.clone();
                                branch.insert(
                                    name.clone(),
                                    workflow_value((*inner).clone(), item.clone())?,
                                );
                                if self.block(body, &mut branch)? {
                                    return Err(invalid());
                                }
                            }
                        }
                        #[cfg(feature = "typed-workflow")]
                        Statement::IfSome {
                            name,
                            value,
                            then_branch,
                            else_branch,
                            ..
                        } => {
                            let Value::Workflow {
                                ty: crate::typed_workflow::WorkflowType::Option(inner),
                                data,
                            } = self.expr(value, env)?
                            else {
                                return Err(invalid());
                            };
                            let mut branch = env.clone();
                            let some = !data.is_null();
                            if some {
                                branch.insert(name.clone(), workflow_value(*inner, data)?);
                            }
                            if self
                                .block(if some { then_branch } else { else_branch }, &mut branch)?
                            {
                                return Ok(true);
                            }
                        }
                        Statement::If {
                            condition,
                            then_branch,
                            else_branch,
                            ..
                        } => {
                            let Value::Boolean(condition) = self.expr(condition, env)? else {
                                return Err(invalid());
                            };
                            if self.block(
                                if condition { then_branch } else { else_branch },
                                &mut env.clone(),
                            )? {
                                return Ok(true);
                            }
                        }
                    }
                    Ok(false)
                })();
                #[cfg(feature = "compiler")]
                if top_level && let Some(trace) = &mut self.trace {
                    trace.record(statement.span(), result.as_ref().err().map(|d| &**d));
                }
                match result {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(mut decision) => {
                        if decision.source_start.is_none() {
                            let span = statement.span();
                            decision.source_start = Some(span.start);
                            decision.source_end = Some(span.end);
                        }
                        return Err(decision);
                    }
                }
            }
            Ok(false)
        })();
        #[cfg(feature = "compiler")]
        {
            self.block_depth -= 1;
        }
        result
    }
    fn expr(&mut self, expr: &Expr, env: &BTreeMap<String, Value>) -> EvalResult {
        self.expr_inner(expr, env).map_err(|mut decision| {
            if decision.source_start.is_none()
                && let Expr::Call { span, .. } = expr
            {
                decision.source_start = Some(span.start);
                decision.source_end = Some(span.end);
            }
            decision
        })
    }
    fn expr_inner(&mut self, expr: &Expr, env: &BTreeMap<String, Value>) -> EvalResult {
        self.steps += 1;
        if self.steps > crate::MAX_NODES * 2 {
            return Err(failure(
                "RESOURCE_LIMIT",
                "Policy evaluation exceeded its operation limit.",
            ));
        }
        Ok(match expr {
            Expr::String { value } => Value::String(value.clone()),
            Expr::Integer { value } => Value::Integer(*value),
            Expr::Boolean { value } => Value::Boolean(*value),
            Expr::Unit => Value::Unit,
            Expr::Variable { name } => env.get(name).cloned().ok_or_else(invalid)?,
            Expr::Field { object, name } => match self.expr(object, env)? {
                Value::Context => match name.as_str() {
                    #[cfg(feature = "std")]
                    "native_daily_limit" | "native_action_limit" => {
                        let storage =
                            self.context.native_policy_storage.as_ref().ok_or_else(|| {
                                failure(
                                    "NATIVE_STORAGE_REQUIRED",
                                    "Verified native policy storage is required.",
                                )
                            })?;
                        Value::Integer(if name == "native_daily_limit" {
                            storage.daily_limit_units
                        } else {
                            storage.action_limit_units
                        })
                    }
                    #[cfg(feature = "typed-workflow")]
                    "execution_request" | "curl_request" | "curl_outcome" => {
                        let input = self.context.workflow.as_ref().ok_or_else(|| {
                            failure(
                                "WORKFLOW_INPUT_REQUIRED",
                                "Authenticated typed workflow input is required.",
                            )
                        })?;
                        match name.as_str() {
                            "execution_request" => {
                                optional_value("ExecutionRequest", &input.execution_request)?
                            }
                            "curl_request" => optional_value("CurlRequest", &input.curl_request)?,
                            _ => optional_value("CurlOutcome", &input.curl_outcome)?,
                        }
                    }
                    "amount_units" => Value::Integer(self.context.amount_units),
                    "allocation_units" => Value::Integer(self.context.allocation_units),
                    "spent_units" => Value::Integer(self.context.spent_units),
                    #[cfg(feature = "typed-workflow")]
                    "now" => Value::Integer(if self.typed_profile {
                        self.context
                            .workflow
                            .as_ref()
                            .map_or(self.context.now, |environment| {
                                environment.evaluated_at_seconds
                            })
                    } else {
                        self.context.now
                    }),
                    #[cfg(not(feature = "typed-workflow"))]
                    "now" => Value::Integer(self.context.now),
                    "action" => Value::String(self.context.action.clone()),
                    "merchant" => Value::String(self.context.merchant.clone()),
                    "recipient" => Value::String(self.context.recipient.clone()),
                    "token" => Value::String(self.context.token.clone()),
                    "network" => Value::String(self.context.network.clone()),
                    _ => return Err(invalid()),
                },
                #[cfg(feature = "typed-workflow")]
                Value::Workflow {
                    ty: crate::typed_workflow::WorkflowType::Named(ty),
                    data,
                } => {
                    let field_type =
                        crate::typed_workflow::field_type(&ty, name).ok_or_else(invalid)?;
                    let field = data.get(name).ok_or_else(invalid)?.clone();
                    workflow_value(field_type, field)?
                }
                Value::Interval(interval) => match name.as_str() {
                    "lower_bps" => Value::Integer(interval.lower_bps),
                    "upper_bps" => Value::Integer(interval.upper_bps),
                    _ => return Err(invalid()),
                },
                _ => return Err(invalid()),
            },
            Expr::Array { values } => Value::Strings(
                values
                    .iter()
                    .map(|v| match self.expr(v, env)? {
                        Value::String(s) => Ok(s),
                        _ => Err(invalid()),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Expr::Not { value } => match self.expr(value, env)? {
                Value::Boolean(v) => Value::Boolean(!v),
                _ => return Err(invalid()),
            },
            #[cfg(feature = "typed-workflow")]
            Expr::Borrow { value } => self.expr(value, env)?,
            Expr::Try { value } | Expr::Await { value } => self.expr(value, env)?,
            Expr::Binary { op, left, right } => {
                let a = self.expr(left, env)?;
                if op == "&&" && a == Value::Boolean(false) {
                    return Ok(Value::Boolean(false));
                }
                if op == "||" && a == Value::Boolean(true) {
                    return Ok(Value::Boolean(true));
                }
                let b = self.expr(right, env)?;
                #[cfg(feature = "typed-workflow")]
                if (matches!(
                    &a,
                    Value::Workflow {
                        ty: crate::typed_workflow::WorkflowType::Amount256,
                        ..
                    }
                ) || matches!(
                    &b,
                    Value::Workflow {
                        ty: crate::typed_workflow::WorkflowType::Amount256,
                        ..
                    }
                )) && let (Some(a), Some(b)) = (amount_value(&a), amount_value(&b))
                {
                    return Ok(Value::Boolean(match op.as_str() {
                        "==" => a == b,
                        "!=" => a != b,
                        ">" => a > b,
                        ">=" => a >= b,
                        "<" => a < b,
                        "<=" => a <= b,
                        _ => return Err(invalid()),
                    }));
                }
                match op.as_str() {
                    "==" => Value::Boolean(a == b),
                    "!=" => Value::Boolean(a != b),
                    "&&" | "||" => match (a, b) {
                        (Value::Boolean(a), Value::Boolean(b)) => {
                            Value::Boolean(if op == "&&" { a && b } else { a || b })
                        }
                        _ => return Err(invalid()),
                    },
                    _ => {
                        let (Value::Integer(a), Value::Integer(b)) = (a, b) else {
                            return Err(invalid());
                        };
                        match op.as_str() {
                            ">" => Value::Boolean(a > b),
                            ">=" => Value::Boolean(a >= b),
                            "<" => Value::Boolean(a < b),
                            "<=" => Value::Boolean(a <= b),
                            "+" | "-" | "*" | "/" | "%" => Value::Integer(
                                match op.as_str() {
                                    "+" => a.checked_add(b),
                                    "-" => a.checked_sub(b),
                                    "*" => a.checked_mul(b),
                                    "/" => a.checked_div(b),
                                    "%" => a.checked_rem(b),
                                    _ => None,
                                }
                                .ok_or_else(|| {
                                    failure(
                                        "ARITHMETIC_ERROR",
                                        "Calculation overflowed, underflowed or divided by zero.",
                                    )
                                })?,
                            ),
                            _ => return Err(invalid()),
                        }
                    }
                }
            }
            Expr::Call { name, args, span } => {
                let values = args
                    .iter()
                    .map(|a| self.expr(a, env))
                    .collect::<Result<Vec<_>, _>>()?;
                match name.as_str() {
                    #[cfg(feature = "typed-workflow")]
                    "allowit::execution_request_validate" => {
                        let [
                            Value::Workflow {
                                ty: crate::typed_workflow::WorkflowType::Named(ty),
                                data,
                            },
                        ] = values.as_slice()
                        else {
                            return Err(invalid());
                        };
                        let environment = self.context.workflow.as_ref().ok_or_else(invalid)?;
                        let request = environment.execution_request.as_ref().ok_or_else(invalid)?;
                        if ty != "ExecutionRequest"
                            || *data != serde_json::to_value(request).map_err(|_| invalid())?
                            || !crate::typed_workflow::execution_shape(request)
                            || request.operation != environment.binding.operation
                        {
                            return Err(failure(
                                "WORKFLOW_BINDING",
                                "Execution input does not match the authenticated complete request.",
                            ));
                        }
                        let result = environment
                            .host
                            .execution_request_validate(request, &environment.binding)
                            .map_err(|e| failure(&e.code, e.reason))?;
                        if !self.workflow_outputs.is_empty()
                            || !crate::typed_workflow::native_transfers_covered(
                                request,
                                &environment.binding.domain,
                            )
                            || request.effect_bounds.iter().any(|effect| {
                                !crate::typed_workflow::asset_in_domain(
                                    &effect.asset,
                                    &environment.binding.domain,
                                ) || !crate::typed_workflow::debit_authorized(
                                    &effect.source,
                                    &effect.asset,
                                    environment,
                                ) || effect.beneficiary.chain != environment.binding.domain.chain
                            })
                            || request.fee_bounds.as_ref().is_some_and(|fees| {
                                fees.iter().any(|fee| {
                                    !crate::typed_workflow::asset_in_domain(
                                        &fee.asset,
                                        &environment.binding.domain,
                                    ) || fee.payer.chain != environment.binding.domain.chain
                                })
                            })
                            || result.request != *request
                            || result.binding != environment.binding
                            || result.request_digest != environment.binding.request_digest
                            || result.profile_digest != environment.binding.profile_digest
                            || result.domain != environment.binding.domain
                            || result.signing_digest == [0; 32]
                            || matches!(&request.input,crate::typed_workflow::ExecutionInput::Instructions(v) if *v!=result.instructions)
                            || result.instructions.iter().any(|i| {
                                !crate::typed_workflow::instruction_shape(i)
                                    || !crate::typed_workflow::instruction_in_domain(
                                        i,
                                        &environment.binding.domain,
                                    )
                            })
                            || !crate::typed_workflow::native_transfers_covered(
                                &crate::typed_workflow::ExecutionRequest {
                                    input: crate::typed_workflow::ExecutionInput::Instructions(
                                        result.instructions.clone(),
                                    ),
                                    ..request.clone()
                                },
                                &environment.binding.domain,
                            )
                            || result.instructions.is_empty()
                            || result.instructions.len() > 16
                            || result.modules.is_empty()
                            || result.modules.len() > 16
                        {
                            return Err(failure(
                                "WORKFLOW_BINDING",
                                "Validated request does not match the installed binding.",
                            ));
                        }
                        let value = typed_value("ValidatedExecutionRequest", &result)?;
                        self.workflow_outputs
                            .push(crate::typed_workflow::WorkflowOutput::Execution(result));
                        value
                    }
                    #[cfg(feature = "typed-workflow")]
                    "paysh::payment_request_from_curl" => {
                        let [
                            Value::Workflow {
                                ty: crate::typed_workflow::WorkflowType::Named(a),
                                data: outcome,
                            },
                            Value::Workflow {
                                ty: crate::typed_workflow::WorkflowType::Named(b),
                                data: request,
                            },
                        ] = values.as_slice()
                        else {
                            return Err(invalid());
                        };
                        let environment = self.context.workflow.as_ref().ok_or_else(invalid)?;
                        let original = environment.curl_request.as_ref().ok_or_else(invalid)?;
                        let response = environment.curl_outcome.as_ref().ok_or_else(invalid)?;
                        if a != "CurlOutcome"
                            || b != "CurlRequest"
                            || *outcome != serde_json::to_value(response).map_err(|_| invalid())?
                            || *request != serde_json::to_value(original).map_err(|_| invalid())?
                            || !crate::typed_workflow::curl_shape(original)
                        {
                            return Err(failure(
                                "WORKFLOW_BINDING",
                                "HTTP request/outcome does not match authenticated preflight.",
                            ));
                        }
                        let result = environment
                            .host
                            .payment_request_from_curl(response, original, &environment.binding)
                            .map_err(|e| failure(&e.code, e.reason))?;
                        match &result {
                            Some(payment) => {
                                let crate::typed_workflow::CurlOutcome::PaymentRequired(challenge) =
                                    response
                                else {
                                    return Err(invalid());
                                };
                                if !self.workflow_outputs.is_empty()
                                    || !crate::typed_workflow::asset_in_domain(
                                        &payment.payment.asset,
                                        &environment.binding.domain,
                                    )
                                    || !crate::typed_workflow::debit_authorized(
                                        &payment.payer,
                                        &payment.payment.asset,
                                        environment,
                                    )
                                    || payment.payee.chain != environment.binding.domain.chain
                                    || payment.fee_payer.chain != environment.binding.domain.chain
                                    || payment.fee_bounds.as_ref().is_some_and(|fees| {
                                        fees.iter().any(|fee| {
                                            !crate::typed_workflow::asset_in_domain(
                                                &fee.asset,
                                                &environment.binding.domain,
                                            ) || fee.payer.chain != environment.binding.domain.chain
                                        })
                                    })
                                    || payment.binding != environment.binding
                                    || payment.operation != environment.binding.operation
                                    || payment.profile_digest != environment.binding.profile_digest
                                    || payment.http_request_digest != challenge.http_request_digest
                                    || challenge.network != environment.binding.domain.network
                                    || payment.scheme != challenge.scheme
                                    || payment.payee != challenge.payee
                                    || payment.fee_payer != challenge.fee_payer
                                    || payment.payment.asset
                                        != crate::typed_workflow::WorkflowAsset::Token(
                                            challenge.asset.clone(),
                                        )
                                    || payment.payment.units != challenge.amount
                                    || payment.expires_at_seconds != challenge.expires_at_seconds
                                    || payment.expires_at_seconds
                                        <= environment.evaluated_at_seconds
                                    || payment.response_access_key != challenge.response_access_key
                                    || challenge.amount == crate::typed_workflow::Amount256::from(0)
                                    || payment.evidence.kind
                                        != crate::typed_workflow::EvidenceKind::PaymentChallenge
                                    || payment.evidence.schema == 0
                                    || payment.evidence.namespace_id == 0
                                    || payment.evidence.digest != challenge.challenge_digest
                                    || payment.fee_bounds.as_ref().is_some_and(|v| v.len() > 16)
                                    || challenge.authenticated_wire_bytes.is_empty()
                                {
                                    return Err(failure(
                                        "WORKFLOW_BINDING",
                                        "Payment proposal does not match the authenticated challenge.",
                                    ));
                                }
                                self.workflow_outputs.push(
                                    crate::typed_workflow::WorkflowOutput::Payment(payment.clone()),
                                );
                            }
                            None => {
                                let crate::typed_workflow::CurlOutcome::Complete(response) =
                                    response
                                else {
                                    return Err(failure(
                                        "WORKFLOW_BINDING",
                                        "A payment challenge cannot become a free response.",
                                    ));
                                };
                                if !(200..300).contains(&response.status)
                                    || response.receipt_digest == [0; 32]
                                {
                                    return Err(failure(
                                        "WORKFLOW_BINDING",
                                        "Only a valid bound free response produces None.",
                                    ));
                                }
                                self.workflow_outputs.push(
                                    crate::typed_workflow::WorkflowOutput::FreeResponse {
                                        request_digest: environment.binding.request_digest,
                                        receipt_digest: response.receipt_digest,
                                    },
                                );
                            }
                        }
                        workflow_value(
                            crate::typed_workflow::WorkflowType::Option(alloc::boxed::Box::new(
                                crate::typed_workflow::WorkflowType::named("PaymentRequest"),
                            )),
                            serde_json::to_value(result).map_err(|_| invalid())?,
                        )?
                    }
                    #[cfg(feature = "typed-workflow")]
                    "allowit::execution_request_cap" | "allowit::payment_request_cap" => {
                        let [
                            Value::Workflow {
                                ty: crate::typed_workflow::WorkflowType::Named(ty),
                                data,
                            },
                            Value::String(budget_id),
                            Value::String(asset_id),
                            Value::Integer(decimals),
                            Value::Integer(total),
                            Value::Integer(debit),
                            Value::Integer(fee),
                        ] = values.as_slice()
                        else {
                            return Err(invalid());
                        };
                        let matching = self.workflow_outputs.iter().any(|o| match o {
                            crate::typed_workflow::WorkflowOutput::Execution(v) => {
                                name == "allowit::execution_request_cap"
                                    && ty == "ValidatedExecutionRequest"
                                    && serde_json::to_value(v).ok().as_ref() == Some(data)
                            }
                            crate::typed_workflow::WorkflowOutput::Payment(v) => {
                                name == "allowit::payment_request_cap"
                                    && ty == "PaymentRequest"
                                    && serde_json::to_value(v).ok().as_ref() == Some(data)
                            }
                            _ => false,
                        });
                        if !matching {
                            return Err(failure(
                                "WORKFLOW_BINDING",
                                "Budget guards require an actual authenticated node result.",
                            ));
                        }
                        let guard = crate::typed_workflow::TypedBudgetRequirement {
                            operation: name.clone(),
                            budget_id: budget_id.clone(),
                            asset_id: asset_id.clone(),
                            decimals: *decimals as u8,
                            total_budget_units: *total,
                            max_debit_units: *debit,
                            max_fee_units: *fee,
                        };
                        self.budget_guards.push(guard);
                        Value::Unit
                    }
                    #[cfg(feature = "typed-workflow")]
                    "paysh::call" => {
                        if self.profile != Profile::Oracle {
                            return Err(failure(
                                "PROVIDER_PROFILE_UNSUPPORTED",
                                "Provider effects require an authenticated host adapter.",
                            ));
                        }
                        if !self.system_operations.is_empty() {
                            return Err(failure(
                                "PROVIDER_CALL_LIMIT",
                                "Only one provider call is supported per run.",
                            ));
                        }
                        let service_id = string(&values, 0)?;
                        let input_key = string(&values, 1)?;
                        let binding =
                            self.context.provider_call_input.as_ref().ok_or_else(|| {
                                failure(
                                    "PROVIDER_INPUT_REQUIRED",
                                    "Authenticated provider input is required.",
                                )
                            })?;
                        if service_id.is_empty()
                            || service_id.len() > 200
                            || input_key.is_empty()
                            || input_key.len() > 200
                            || service_id != binding.service_id
                            || input_key != binding.input_key
                            || binding.request_digest.len() != 64
                            || !binding
                                .request_digest
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                        {
                            return Err(failure(
                                "PROVIDER_INPUT_MISMATCH",
                                "The operation does not match authenticated canonical run input.",
                            ));
                        }
                        let max_payment_units = integer(&values, 2)?;
                        let max_swap_lamports = integer(&values, 3)?;
                        let max_service_fee_lamports_per_execution = integer(&values, 4)?;
                        if self.context.amount_units > max_payment_units {
                            return Err(failure(
                                "PROVIDER_PAYMENT_UNBOUND",
                                "The exact guarded payment exceeds the source payment ceiling.",
                            ));
                        }
                        if self.context.amount_units == 0 || max_payment_units == 0 {
                            return Err(failure(
                                "PROVIDER_INVALID_PAYMENT",
                                "A paid call requires a positive payment ceiling.",
                            ));
                        }
                        self.system_operations.push(crate::ProviderCallPlan {
                            payment_asset: binding.payment_asset.clone(),
                            operation: "paysh::call".into(),
                            service_id,
                            input_key,
                            request_digest: binding.request_digest.clone(),
                            payment_units: self.context.amount_units,
                            max_payment_units,
                            max_swap_lamports,
                            max_service_fee_lamports_per_execution,
                        });
                        Value::Boolean(true)
                    }
                    "Ok" => Value::Unit,
                    "fail" => return Err(failure("POLICY_REJECTED", string(&values, 0)?)),
                    #[cfg(not(feature = "oracle-ledger"))]
                    "cap_purchase_tiers" => {
                        return Err(failure(
                            "LEDGER_REQUIRED",
                            "Purchase tiers require the oracle ledger feature.",
                        ));
                    }
                    #[cfg(feature = "oracle-ledger")]
                    "cap_purchase_tiers" => {
                        if self.profile == Profile::Contract {
                            return Err(failure(
                                "LEDGER_REQUIRED",
                                "This purchase-tier rule requires an authoritative host ledger.",
                            ));
                        }
                        let token = string(&values, 3)?;
                        if token != self.context.token {
                            return Err(failure("TOKEN_MISMATCH", "Token does not match."));
                        }
                        let maximum = amount_units(&string(&values, 1)?)
                            .map_err(|e| failure("INVALID_AMOUNT", e.message))?;
                        let Value::Integer(count) = values[2] else {
                            return Err(invalid());
                        };
                        crate::spending::check_tiers(self.context, maximum, count)
                            .map_err(alloc::boxed::Box::new)?;
                        Value::Unit
                    }
                    "set_cap" | "cap_per_transaction" => {
                        let token = string(&values, 2)?;
                        if token != self.context.token {
                            return Err(failure(
                                "TOKEN_MISMATCH",
                                "The requested token does not match the policy.",
                            ));
                        }
                        let cap = amount_units(&string(&values, 1)?)
                            .map_err(|e| failure("INVALID_AMOUNT", e.message))?;
                        let amount = if name == "set_cap" {
                            self.context
                                .spent_units
                                .checked_add(self.context.amount_units)
                                .ok_or_else(|| {
                                    failure(
                                        "BUDGET_EXCEEDED",
                                        "The request exceeds the remaining allowance.",
                                    )
                                })?
                        } else {
                            self.context.amount_units
                        };
                        if amount > cap {
                            return Err(failure(
                                if name == "set_cap" {
                                    "POLICY_CAP_EXCEEDED"
                                } else {
                                    "PURCHASE_CAP_EXCEEDED"
                                },
                                if name == "set_cap" {
                                    "The request exceeds this policy's remaining spending limit."
                                } else {
                                    "The purchase exceeds the per-transaction limit."
                                },
                            ));
                        }
                        Value::Unit
                    }
                    "allow_actions" => {
                        let Some(Value::Strings(actions)) = values.get(1) else {
                            return Err(invalid());
                        };
                        if !actions.contains(&self.context.action) {
                            return Err(failure(
                                "ACTION_NOT_ALLOWED",
                                "This action is not permitted by the policy.",
                            ));
                        }
                        Value::Unit
                    }
                    "require_merchant" => {
                        if string(&values, 1)? != self.context.merchant {
                            return Err(failure(
                                "MERCHANT_NOT_ALLOWED",
                                "This merchant is not permitted by the policy.",
                            ));
                        }
                        Value::Unit
                    }
                    "require_recipient" => {
                        if string(&values, 1)? != self.context.recipient {
                            return Err(failure(
                                "RECIPIENT_NOT_ALLOWED",
                                "This recipient is not permitted by the policy.",
                            ));
                        }
                        Value::Unit
                    }
                    "context_u64" => {
                        let key = string(&values, 1)?;
                        let value = self.context.runtime_context.get(&key).ok_or_else(|| {
                            failure(
                                "CONTEXT_VALUE_REQUIRED",
                                format!("The request must supply {key}."),
                            )
                        })?;
                        Value::Integer(value.as_u64().ok_or_else(|| {
                            failure(
                                "INVALID_CONTEXT_VALUE",
                                format!(
                                    "{key} must be a non-negative whole number that fits in u64."
                                ),
                            )
                        })?)
                    }
                    "confidence" | "semantic" => {
                        let is_semantic = name == "semantic";
                        let label = string(&values, 1)?;
                        if label.trim().is_empty() || label.len() > 1024 {
                            return Err(failure(
                                "INVALID_EVIDENCE",
                                "The assessment question is empty or exceeds its size limit.",
                            ));
                        }
                        if is_semantic && self.context.original_intent.trim().is_empty() {
                            return Err(failure(
                                "ORIGINAL_INTENT_REQUIRED",
                                "Preference assessment requires original policy instructions.",
                            ));
                        }
                        let key = if is_semantic {
                            crate::semantic_evidence_key(&label)
                        } else {
                            label.clone()
                        };
                        #[cfg(feature = "typed-workflow")]
                        let key = if self.typed_profile
                            && let Some(environment) = &self.context.workflow
                        {
                            crate::typed_workflow::evidence_key(&environment.binding, &label)
                        } else {
                            key
                        };
                        let interval = self.context.confidence.get(&key).ok_or_else(|| {
                            let mut decision = failure(
                                if is_semantic {
                                    "SEMANTIC_EVIDENCE_REQUIRED"
                                } else {
                                    "EVIDENCE_REQUIRED"
                                },
                                if is_semantic {
                                    "A preference assessment is required for this request.".into()
                                } else {
                                    format!("Confidence evidence is required for {key}.")
                                },
                            );
                            if is_semantic {
                                decision.question = Some(label);
                                decision.evidence_key = Some(key);
                            }
                            decision
                        })?;
                        if interval.lower_bps > interval.upper_bps || interval.upper_bps > 10000 {
                            return Err(failure(
                                "INVALID_EVIDENCE",
                                "Confidence bounds must be ordered between 0 and 10,000 basis points.",
                            ));
                        }
                        Value::Interval(*interval)
                    }
                    "require_user_input" => {
                        let prompt = string(&values, 1)?;
                        if prompt.trim().is_empty() {
                            return Err(failure(
                                "INVALID_INPUT_PROMPT",
                                "The approval prompt is empty.",
                            ));
                        }
                        if self.profile == Profile::Contract {
                            return Err(failure(
                                "USER_INPUT_REQUIRED",
                                "This request requires user input and cannot execute in a smart contract.",
                            ));
                        }
                        let key = digest(
                            format!(
                                "allowit-input-v1:{}:{}:{}",
                                self.binding, span.start, prompt
                            )
                            .as_bytes(),
                        );
                        #[cfg(feature = "typed-workflow")]
                        let key = if self.typed_profile
                            && let Some(environment) = &self.context.workflow
                        {
                            crate::typed_workflow::input_key(
                                &environment.binding,
                                span.start,
                                &prompt,
                            )
                        } else {
                            key
                        };
                        match self.context.answers.get(&key) {
                            Some(true) => Value::Unit,
                            Some(false) => {
                                return Err(failure(
                                    "USER_DECLINED",
                                    "The policy owner declined this request.",
                                ));
                            }
                            None => {
                                return Err(alloc::boxed::Box::new(Decision {
                                    #[cfg(feature = "typed-workflow")]
                                    system_operations: Vec::new(),
                                    #[cfg(feature = "typed-workflow")]
                                    workflow_outputs: Vec::new(),
                                    #[cfg(feature = "typed-workflow")]
                                    typed_budget_plans: Vec::new(),
                                    outcome: "awaiting_input".into(),
                                    code: "USER_INPUT_REQUIRED".into(),
                                    reason:
                                        "Your approval is required before evaluation can continue."
                                            .into(),
                                    prompt: Some(prompt),
                                    input_key: Some(key),
                                    question: None,
                                    evidence_key: None,
                                    source_start: None,
                                    source_end: None,
                                }));
                            }
                        }
                    }
                    _ => return Err(invalid()),
                }
            }
        })
    }
}
fn string(values: &[Value], index: usize) -> Result<String, alloc::boxed::Box<Decision>> {
    match values.get(index) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(invalid()),
    }
}
#[cfg(feature = "typed-workflow")]
fn integer(values: &[Value], index: usize) -> Result<u64, alloc::boxed::Box<Decision>> {
    match values.get(index) {
        Some(Value::Integer(value)) => Ok(*value),
        _ => Err(invalid()),
    }
}
fn invalid() -> alloc::boxed::Box<Decision> {
    failure(
        "INVALID_POLICY",
        "The policy contains an invalid operation.",
    )
}

fn validate_context(
    ctx: &Context,
    provider_profile: bool,
    private_provider_localnet: bool,
    native_payment_asset: Option<&crate::ProviderPaymentAsset>,
) -> Result<(), alloc::boxed::Box<Decision>> {
    #[cfg(not(feature = "typed-workflow"))]
    let _ = provider_profile;
    if native_payment_asset.is_some_and(|asset| {
        provider_profile
            || asset.network != ctx.network
            || asset.asset != ctx.token
            || asset.decimals != 6
            || asset.asset.is_empty()
            || asset.asset.len() > 32
            || !asset.asset.bytes().all(|b| b.is_ascii_alphanumeric())
            || !matches!(
                asset.network.as_str(),
                "tempo:localnet"
                    | "tempo:testnet"
                    | "solana:localnet"
                    | "solana:devnet"
                    | "solana:testnet"
            )
            || ctx.native_policy_storage.is_none()
    }) {
        return Err(failure(
            "NATIVE_PAYMENT_BINDING",
            "Native payment must match the host-verified six-decimal asset, network and storage.",
        ));
    }
    #[cfg(feature = "typed-workflow")]
    if native_payment_asset.is_none() && provider_profile {
        let binding = ctx.provider_call_input.as_ref().ok_or_else(|| {
            failure(
                "PROVIDER_INPUT_REQUIRED",
                "Authenticated provider input is required.",
            )
        })?;
        let asset = &binding.payment_asset;
        if asset.asset.is_empty()
            || asset.asset.len() > 128
            || asset.network != ctx.network
            || asset.decimals != 6
            || ctx.token != asset.asset
        {
            return Err(failure(
                "PROVIDER_ASSET_MISMATCH",
                "Context must match the authenticated six-decimal native payment asset.",
            ));
        }
    } else if native_payment_asset.is_none() && ctx.token != "USDC" {
        return Err(failure(
            "TOKEN_MISMATCH",
            "This policy supports six-decimal USDC.",
        ));
    }
    #[cfg(not(feature = "typed-workflow"))]
    if native_payment_asset.is_none() && ctx.token != "USDC" {
        return Err(failure(
            "TOKEN_MISMATCH",
            "This policy supports six-decimal USDC.",
        ));
    }
    if native_payment_asset.is_none()
        && !(private_provider_localnet && provider_profile && ctx.network == "solana:localnet")
        && ![
            "mainnet",
            "mainnet-beta",
            "devnet",
            "testnet",
            "stellar-mainnet",
            "stellar-testnet",
            "solana:mainnet",
            "solana:devnet",
            "solana:testnet",
            "stellar:mainnet",
            "stellar:testnet",
            "local:dev",
        ]
        .contains(&ctx.network.as_str())
    {
        return Err(failure(
            "INVALID_NETWORK",
            "The requested network is not supported.",
        ));
    }
    if ctx.amount_units == 0 || ctx.allocation_units == 0 {
        return Err(failure(
            "INVALID_AMOUNT",
            "The request and allocation amounts must be greater than zero.",
        ));
    }
    if ctx
        .spent_units
        .checked_add(ctx.amount_units)
        .is_none_or(|n| n > ctx.allocation_units)
    {
        return Err(failure(
            "BUDGET_EXCEEDED",
            "The request exceeds the remaining allowance.",
        ));
    }
    if ctx.action.is_empty()
        || ctx.action.len() > 128
        || ctx.merchant.len() > 256
        || ctx.recipient.len() > 256
        || ctx.answers.len() > 32
        || ctx.confidence.len() > 32
        || ctx.confidence.keys().any(|s| s.is_empty() || s.len() > 128)
        || ctx.answers.keys().any(|s| s.len() != 64)
        || ctx.original_intent.len() > 16384
    {
        return Err(failure(
            "INVALID_CONTEXT",
            "Request context lacks required values or exceeds its size limit.",
        ));
    }
    validate_runtime_context(&ctx.runtime_context)?;
    if ctx
        .confidence
        .values()
        .any(|v| v.lower_bps > v.upper_bps || v.upper_bps > 10000)
    {
        return Err(failure(
            "INVALID_EVIDENCE",
            "Confidence bounds must be ordered between 0 and 10,000 basis points.",
        ));
    }
    Ok(())
}

fn validate_runtime_context(value: &serde_json::Value) -> Result<(), alloc::boxed::Box<Decision>> {
    use serde_json::Value;
    let invalid = || {
        failure(
            "INVALID_CONTEXT",
            "Runtime context requires an object: at most 16 KiB, depth 8 and 128 entries.",
        )
    };
    if !value.is_object() {
        return Err(invalid());
    }
    let mut stack = alloc::vec![(value, 0usize)];
    let mut entries = 0usize;
    while let Some((value, depth)) = stack.pop() {
        if depth > 8 {
            return Err(invalid());
        }
        match value {
            Value::Object(map) => {
                entries += map.len();
                if entries > 128 || map.keys().any(|key| key.is_empty() || key.len() > 128) {
                    return Err(invalid());
                }
                for child in map.values() {
                    stack.push((child, depth + 1));
                }
            }
            Value::Array(values) => {
                entries += values.len();
                if entries > 128 {
                    return Err(invalid());
                }
                for child in values {
                    stack.push((child, depth + 1));
                }
            }
            Value::String(value) if value.len() > 16384 => return Err(invalid()),
            _ => {}
        }
    }
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > 16384 {
        return Err(invalid());
    }
    Ok(())
}

fn failure(code: &str, reason: impl Into<String>) -> alloc::boxed::Box<Decision> {
    alloc::boxed::Box::new(Decision::fail(code, reason))
}

fn run(ir: &Program, profile: Profile, ctx: &Context, binding: String) -> Decision {
    run_inner(
        ir,
        profile,
        ctx,
        binding,
        false,
        None,
        #[cfg(feature = "compiler")]
        None,
    )
}

fn run_inner(
    ir: &Program,
    profile: Profile,
    ctx: &Context,
    binding: String,
    private_provider_localnet: bool,
    native_payment_asset: Option<&crate::ProviderPaymentAsset>,
    #[cfg(feature = "compiler")] trace: Option<&mut crate::trace::TraceRecorder>,
) -> Decision {
    if let Err(error) = validate_program(ir) {
        return Decision::fail("INVALID_POLICY", error.message);
    }
    #[cfg(feature = "typed-workflow")]
    if crate::typed_workflow::required(ir) {
        if profile != Profile::Oracle {
            return Decision::fail(
                "WORKFLOW_PROFILE_UNSUPPORTED",
                "Typed host workflow nodes require the Oracle profile.",
            );
        }
        let Some(environment) = ctx.workflow.as_ref() else {
            return Decision::fail(
                "WORKFLOW_INPUT_REQUIRED",
                "Authenticated typed workflow input is required.",
            );
        };
        if environment.evaluated_at_seconds == 0
            || !matches!(
                (
                    &environment.execution_request,
                    &environment.curl_request,
                    &environment.curl_outcome
                ),
                (Some(_), None, None) | (None, Some(_), Some(_))
            )
        {
            return Decision::fail(
                "WORKFLOW_BINDING",
                "One authenticated ingress family and trusted nonzero evaluation time are required.",
            );
        }
        if crate::typed_workflow::request_digest(
            &environment.binding,
            &environment.execution_request,
            &environment.curl_request,
            &environment.curl_outcome,
        )
        .ok()
            != Some(environment.binding.request_digest)
            || !crate::typed_workflow::binding_valid(&environment.binding)
            || crate::typed_workflow::hex(&environment.binding.source_hash) != binding
                && crate::typed_workflow::hex(&environment.binding.ir_hash) != binding
            || canonical_ir_hash(ir).ok().as_deref()
                != Some(crate::typed_workflow::hex(&environment.binding.ir_hash).as_str())
        {
            return Decision::fail(
                "WORKFLOW_BINDING",
                "Typed inputs must bind the exact source and IR.",
            );
        }
    }
    #[cfg(feature = "typed-workflow")]
    if profile == Profile::Contract && crate::validation::provider_call_required(ir) {
        return Decision::fail(
            "PROVIDER_PROFILE_UNSUPPORTED",
            "This contract profile cannot execute provider operations; use the authenticated host settlement adapter.",
        );
    }
    #[cfg(feature = "std")]
    if crate::validation::native_storage_required(ir) {
        if profile == Profile::Contract {
            return Decision::fail(
                "NATIVE_STORAGE_UNSUPPORTED",
                "This contract profile cannot read native policy storage.",
            );
        }
        let Some(storage) = ctx.native_policy_storage.as_ref() else {
            return Decision::fail(
                "NATIVE_STORAGE_REQUIRED",
                "Verified native policy storage is required.",
            );
        };
        if storage.daily_limit_units > 50_000_000 || storage.action_limit_units > 50_000_000 {
            return Decision::fail(
                "INVALID_NATIVE_STORAGE",
                "Native limit exceeds its supported range.",
            );
        }
    }
    let typed_only = cfg!(feature = "typed-workflow")
        && crate::typed_workflow::required(ir)
        && !crate::validation::provider_call_required(ir);
    if let Err(error) = if typed_only {
        #[cfg(feature = "typed-workflow")]
        {
            validate_workflow_context(ctx)
        }
        #[cfg(not(feature = "typed-workflow"))]
        {
            Err(invalid())
        }
    } else {
        validate_context(
            ctx,
            cfg!(feature = "typed-workflow") && crate::validation::provider_call_required(ir),
            private_provider_localnet,
            native_payment_asset,
        )
    } {
        return *error;
    }
    if profile == Profile::Contract && ctx.network == "local:dev" {
        return Decision::fail(
            "INVALID_NETWORK",
            "Local dev policies run only in the oracle profile.",
        );
    }
    let mut evaluator = Evaluator {
        #[cfg(feature = "typed-workflow")]
        typed_profile: cfg!(feature = "typed-workflow") && crate::typed_workflow::required(ir),
        context: ctx,
        profile,
        binding,
        steps: 0,
        #[cfg(feature = "typed-workflow")]
        budget_guards: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        workflow_outputs: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        system_operations: Vec::new(),
        #[cfg(feature = "compiler")]
        trace,
        #[cfg(feature = "compiler")]
        block_depth: 0,
    };
    let mut env = BTreeMap::new();
    env.insert("ctx".to_string(), Value::Context);
    // Configuration is enforced before control flow, so even an early return cannot bypass the cap.
    for statement in &ir.statements {
        if let Statement::Expression {
            value: Expr::Try { value },
            ..
        } = statement
            && matches!(&**value,Expr::Call{name,..} if name=="set_cap" || name=="cap_purchase_tiers")
        {
            let result = evaluator.expr(value, &env);
            #[cfg(feature = "compiler")]
            if let Some(trace) = &mut evaluator.trace {
                trace.record(statement.span(), result.as_ref().err().map(|d| &**d));
            }
            if let Err(decision) = result {
                return *decision;
            }
        }
    }
    match evaluator.block(&ir.statements, &mut env) {
        Ok(true) => {
            #[cfg(feature = "typed-workflow")]
            {
                if crate::typed_workflow::required(ir) && evaluator.workflow_outputs.len() != 1 {
                    return Decision::fail(
                        "WORKFLOW_PROPOSAL_REQUIRED",
                        "One validated proposal or authenticated free response is required.",
                    );
                }
                if evaluator
                    .workflow_outputs
                    .iter()
                    .any(|output| match output {
                        crate::typed_workflow::WorkflowOutput::Execution(r) => {
                            r.request.fee_bounds.is_none()
                        }
                        crate::typed_workflow::WorkflowOutput::Payment(r) => r.fee_bounds.is_none(),
                        _ => false,
                    })
                {
                    return Decision::fail(
                        "WORKFLOW_FEES_UNRESOLVED",
                        "Final authorization requires explicit authenticated fee bounds.",
                    );
                }
                if evaluator
                    .workflow_outputs
                    .iter()
                    .any(|output| match output {
                        crate::typed_workflow::WorkflowOutput::Execution(r) => {
                            r.request.fee_bounds.as_ref().is_some_and(|fees| {
                                crate::typed_workflow::requires_zero_fee_proof(
                                    fees,
                                    crate::typed_workflow::authority_source(&r.domain),
                                    &r.domain,
                                )
                            })
                        }
                        crate::typed_workflow::WorkflowOutput::Payment(r) => {
                            r.fee_bounds.as_ref().is_some_and(|fees| {
                                crate::typed_workflow::requires_zero_fee_proof(
                                    fees,
                                    &r.fee_payer,
                                    &r.binding.domain,
                                )
                            })
                        }
                        _ => false,
                    })
                {
                    let Some(environment) = ctx.workflow.as_ref() else {
                        return *invalid();
                    };
                    if environment
                        .host
                        .zero_fee_evidence(&environment.binding)
                        .is_none_or(|proof| {
                            proof.binding != environment.binding
                                || proof.evidence.digest == [0; 32]
                                || proof.evidence.schema == 0
                                || proof.evidence.namespace_id == 0
                                || proof.evidence.kind
                                    != crate::typed_workflow::EvidenceKind::ExternalClaim
                        })
                    {
                        return Decision::fail(
                            "WORKFLOW_ZERO_FEE_EVIDENCE_REQUIRED",
                            "An empty fee list needs authenticated proof of no extra charge.",
                        );
                    }
                }
            }
            #[cfg(feature = "typed-workflow")]
            let mut decision = Decision::pass();
            #[cfg(not(feature = "typed-workflow"))]
            let decision = Decision::pass();
            #[cfg(feature = "typed-workflow")]
            {
                decision.system_operations = evaluator.system_operations;
            }
            #[cfg(feature = "typed-workflow")]
            if !evaluator.workflow_outputs.is_empty() {
                let Some(environment) = ctx.workflow.as_ref() else {
                    return *invalid();
                };
                decision.typed_budget_plans = match typed_budget_plans(
                    &evaluator.workflow_outputs,
                    &evaluator.budget_guards,
                    environment,
                ) {
                    Ok(plans) => plans,
                    Err(error) => return *error,
                };
            }
            #[cfg(feature = "typed-workflow")]
            {
                decision.workflow_outputs = evaluator.workflow_outputs;
            }
            decision
        }
        Ok(false) => *invalid(),
        Err(decision) => *decision,
    }
}

/// Evaluate an already compiled policy. Persisted artifacts are hash-checked before evaluation.
#[cfg(feature = "compiler")]
pub fn evaluate(policy: &CompiledPolicy, profile: Profile, ctx: &Context) -> Decision {
    if let Err(decision) = validate_artifact(policy) {
        return *decision;
    }
    run(&policy.ir, profile, ctx, policy.source_hash.clone())
}

/// Evaluate with bounded source-bound workflow evidence, only in the oracle profile.
/// Invalid artifacts have no trace. Metadata is reconstructed from the approved source,
/// never trusted from a caller-supplied workflow projection.
#[cfg(feature = "compiler")]
pub fn evaluate_with_trace(
    policy: &CompiledPolicy,
    ctx: &Context,
) -> (Decision, Option<crate::WorkflowTrace>) {
    evaluate_with_trace_inner(policy, ctx, false, None)
}

/// Explicit developer-host capability for authenticated provider input on a
/// private Solana validator. The host must verify its real genesis, deployment,
/// owner/source binding and loopback configuration before calling this method.
/// This capability neither aliases a public network nor changes the default
/// evaluator, wire protocol or Contract profile.
#[cfg(all(feature = "compiler", feature = "typed-workflow", feature = "std"))]
pub fn evaluate_with_trace_private_provider_localnet(
    policy: &CompiledPolicy,
    ctx: &Context,
) -> (Decision, Option<crate::WorkflowTrace>) {
    if ctx.network != "solana:localnet" || !crate::validation::provider_call_required(&policy.ir) {
        return (
            Decision::fail(
                "INVALID_NETWORK",
                "This capability requires a private Solana provider operation.",
            ),
            None,
        );
    }
    evaluate_with_trace_inner(policy, ctx, true, None)
}

#[cfg(feature = "compiler")]
fn evaluate_with_trace_inner(
    policy: &CompiledPolicy,
    ctx: &Context,
    private_provider_localnet: bool,
    native_payment_asset: Option<&crate::ProviderPaymentAsset>,
) -> (Decision, Option<crate::WorkflowTrace>) {
    let compiled = match validate_artifact(policy) {
        Ok(compiled) => compiled,
        Err(decision) => return (*decision, None),
    };
    let mut trace = crate::trace::TraceRecorder::new(&compiled);
    let decision = run_inner(
        &policy.ir,
        Profile::Oracle,
        ctx,
        policy.source_hash.clone(),
        private_provider_localnet,
        native_payment_asset,
        Some(&mut trace),
    );
    let trace = trace.finish(&decision);
    (decision, Some(trace))
}

#[cfg(feature = "compiler")]
fn validate_artifact(
    policy: &CompiledPolicy,
) -> Result<CompiledPolicy, alloc::boxed::Box<Decision>> {
    if policy.language != crate::LANGUAGE
        || !crate::supported_registry_version(&policy.registry_version)
        || (crate::validation::provider_call_required(&policy.ir)
            && matches!(
                policy.registry_version.as_str(),
                "1.0.0" | "1.1.0" | "1.2.0"
            ))
        || (crate::typed_workflow::required(&policy.ir)
            && policy.registry_version != crate::REGISTRY_VERSION)
        || digest(policy.source.as_bytes()) != policy.source_hash
        || canonical_ir_hash(&policy.ir).ok().as_ref() != Some(&policy.ir_hash)
    {
        return Err(failure(
            "INVALID_ARTIFACT",
            "The policy artifact failed its integrity check.",
        ));
    }
    let compiled = crate::compile(&policy.source)
        .map_err(|_| failure("INVALID_ARTIFACT", "The policy source is not valid."))?;
    if compiled.ir_hash != policy.ir_hash
        || compiled.limit != policy.limit
        || compiled.token != policy.token
        || compiled.execution_requirements != policy.execution_requirements
        || compiled.typed_budget_requirements != policy.typed_budget_requirements
        || compiled.typed_workflow_requirements != policy.typed_workflow_requirements
        || compiled.provider_call_requirements != policy.provider_call_requirements
    {
        return Err(failure(
            "INVALID_ARTIFACT",
            "The policy source does not match its executable artifact.",
        ));
    }
    Ok(compiled)
}

/// Evaluate validated IR inside a target adapter. The adapter must authenticate its owner and
/// bind the canonical IR hash, network, asset, action and fresh budget to the mandate.
pub fn evaluate_ir(ir: &Program, profile: Profile, ctx: &Context) -> Decision {
    let binding = match canonical_ir_hash(ir) {
        Ok(hash) => hash,
        Err(error) => return Decision::fail("INVALID_POLICY", error.message),
    };
    run(ir, profile, ctx, binding)
}

#[cfg(feature = "typed-workflow")]
fn workflow_value(ty: crate::typed_workflow::WorkflowType, data: serde_json::Value) -> EvalResult {
    use crate::typed_workflow::WorkflowType as T;
    Ok(match ty {
        T::U64 => Value::Integer(data.as_u64().ok_or_else(invalid)?),
        T::Bool => Value::Boolean(data.as_bool().ok_or_else(invalid)?),
        T::String => Value::String(data.as_str().ok_or_else(invalid)?.into()),
        other => Value::Workflow { ty: other, data },
    })
}
#[cfg(feature = "typed-workflow")]
fn typed_value(name: &str, value: &impl serde::Serialize) -> EvalResult {
    workflow_value(
        crate::typed_workflow::WorkflowType::named(name),
        serde_json::to_value(value).map_err(|_| invalid())?,
    )
}
#[cfg(feature = "typed-workflow")]
fn amount_value(value: &Value) -> Option<crate::typed_workflow::Amount256> {
    match value {
        Value::Integer(v) => Some((*v).into()),
        Value::Workflow {
            ty: crate::typed_workflow::WorkflowType::Amount256,
            data,
        } => serde_json::from_value(data.clone()).ok(),
        _ => None,
    }
}
#[cfg(feature = "typed-workflow")]
fn validate_workflow_context(ctx: &Context) -> Result<(), alloc::boxed::Box<Decision>> {
    if ctx.answers.len() > 32
        || ctx.confidence.len() > 32
        || ctx.confidence.keys().any(|s| s.is_empty() || s.len() > 128)
        || ctx.answers.keys().any(|s| s.len() != 64)
        || ctx.original_intent.len() > 16384
        || ctx
            .confidence
            .values()
            .any(|v| v.lower_bps > v.upper_bps || v.upper_bps > 10000)
    {
        return Err(invalid());
    }
    validate_runtime_context(&ctx.runtime_context)
}

#[cfg(feature = "typed-workflow")]
fn optional_value(name: &str, value: &impl serde::Serialize) -> EvalResult {
    workflow_value(
        crate::typed_workflow::WorkflowType::Option(alloc::boxed::Box::new(
            crate::typed_workflow::WorkflowType::named(name),
        )),
        serde_json::to_value(value).map_err(|_| invalid())?,
    )
}

#[cfg(feature = "typed-workflow")]
fn typed_budget_plans(
    outputs: &[crate::typed_workflow::WorkflowOutput],
    guards: &[crate::typed_workflow::TypedBudgetRequirement],
    environment: &crate::typed_workflow::WorkflowEnvironment,
) -> Result<Vec<crate::typed_workflow::TypedBudgetPlan>, alloc::boxed::Box<Decision>> {
    use crate::typed_workflow::{
        Amount256, TypedBudgetPlan, WorkflowAsset, WorkflowOutput, asset_identity,
    };
    let mut totals: BTreeMap<String, (WorkflowAsset, Amount256, Amount256, Option<u8>)> =
        BTreeMap::new();
    let mut add = |asset: &WorkflowAsset,
                   debit: Amount256,
                   fee: Amount256,
                   decimals: Option<u8>|
     -> Result<(), alloc::boxed::Box<Decision>> {
        let entry = totals.entry(asset_identity(asset)).or_insert((
            asset.clone(),
            0.into(),
            0.into(),
            decimals,
        ));
        if entry.3.is_some() && decimals.is_some() && entry.3 != decimals {
            return Err(failure(
                "WORKFLOW_ASSET_MISMATCH",
                "Conflicting authenticated decimal scales.",
            ));
        }
        if decimals.is_some() {
            entry.3 = decimals;
        }
        entry.1 = entry.1.checked_add(debit).ok_or_else(|| {
            failure(
                "WORKFLOW_AMOUNT_OVERFLOW",
                "Complete debit sum exceeds Amount256.",
            )
        })?;
        entry.2 = entry.2.checked_add(fee).ok_or_else(|| {
            failure(
                "WORKFLOW_AMOUNT_OVERFLOW",
                "Complete fee sum exceeds Amount256.",
            )
        })?;
        Ok(())
    };
    for output in outputs {
        let fees = match output {
            WorkflowOutput::Execution(r) => {
                for e in &r.request.effect_bounds {
                    if e.max_burn != Amount256::from(0) {
                        return Err(failure(
                            "WORKFLOW_BURN_UNSUPPORTED",
                            "This budget profile does not admit burn effects.",
                        ));
                    }
                    add(&e.asset, e.max_debit, 0.into(), None)?;
                }
                r.request.fee_bounds.as_ref()
            }
            WorkflowOutput::Payment(r) => {
                add(
                    &r.payment.asset,
                    r.payment.units,
                    0.into(),
                    Some(r.payment.decimals),
                )?;
                r.fee_bounds.as_ref()
            }
            WorkflowOutput::FreeResponse { .. } => continue,
        }
        .ok_or_else(|| {
            failure(
                "WORKFLOW_FEES_UNRESOLVED",
                "Final authorization requires explicit fee bounds.",
            )
        })?;
        for fee in fees {
            add(&fee.asset, 0.into(), fee.max_fee, None)?;
        }
    }
    let mut plans = Vec::new();
    for (id, (asset, debit, fee, decimals)) in totals {
        let guard = guards.iter().find(|g| g.asset_id == id).ok_or_else(|| {
            failure(
                "WORKFLOW_ASSET_UNGUARDED",
                "Every proposed debit and fee asset needs an executed owner budget guard.",
            )
        })?;
        let observations: Vec<_> = environment
            .budgets
            .iter()
            .filter(|b| b.budget_id == guard.budget_id)
            .collect();
        let [observation] = observations.as_slice() else {
            return Err(failure(
                "WORKFLOW_BUDGET_REQUIRED",
                "Exactly one protected budget observation is required.",
            ));
        };
        if observation.asset != asset
            || observation.decimals != guard.decimals
            || decimals.is_some_and(|d| d != guard.decimals)
            || observation.limit_units != Amount256::from(guard.total_budget_units)
        {
            return Err(failure(
                "WORKFLOW_ASSET_MISMATCH",
                "Source budget must match the installed asset, scale and total limit.",
            ));
        }
        if debit > guard.max_debit_units || fee > guard.max_fee_units {
            return Err(failure(
                "WORKFLOW_REQUEST_CAP_EXCEEDED",
                "Complete debit or cumulative fee exceeds the owner request ceiling.",
            ));
        }
        let total = debit
            .checked_add(fee)
            .and_then(|v| v.checked_add(observation.spent_units))
            .and_then(|v| v.checked_add(observation.reserved_units));
        if total.is_none_or(|v| v > observation.limit_units) {
            return Err(failure(
                "WORKFLOW_BUDGET_EXCEEDED",
                "Committed consumption, other reservations and this complete request exceed the total budget.",
            ));
        }
        plans.push(TypedBudgetPlan {
            requirement: guard.clone(),
            asset,
            debit_units: debit,
            fee_units: fee,
        });
    }
    Ok(plans)
}
/// Host-only native custody evaluation. The adapter must authenticate the real
/// chain, exact six-decimal token and current custody storage before calling.
/// This function never aliases chain/asset identifiers and is not exposed by
/// the public JSON protocol or the Contract evaluator.
#[cfg(all(feature = "compiler", feature = "std"))]
pub fn evaluate_with_trace_native_payment(
    policy: &CompiledPolicy,
    ctx: &Context,
    asset: &crate::ProviderPaymentAsset,
) -> (Decision, Option<crate::WorkflowTrace>) {
    if ctx.native_policy_storage.is_none()
        || crate::validation::provider_call_required(&policy.ir)
        || crate::typed_workflow::required(&policy.ir)
    {
        return (
            Decision::fail(
                "NATIVE_PAYMENT_BINDING",
                "Use the native custody host with authenticated storage and a compatible policy.",
            ),
            None,
        );
    }
    evaluate_with_trace_inner(policy, ctx, false, Some(asset))
}

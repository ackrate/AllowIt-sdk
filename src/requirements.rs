//! Instruction dependencies from validated, lowered IR. Includes both branches
//! and code after returns: this is conservative coverage, not authorization.
use crate::{CompileError, ExecutionFeature, ExecutionRequirements, Expr, Program, Statement};
use std::collections::BTreeSet;

#[derive(Default)]
struct Collector {
    features: BTreeSet<ExecutionFeature>,
    keys: BTreeSet<String>,
    dynamic: bool,
    provider_calls: Vec<crate::ProviderCallRequirement>,
}

impl Collector {
    fn expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        match expr {
            Expr::Call { name, args, .. } => {
                let feature = match name.as_str() {
                    "paysh::call" => {
                        let [
                            Expr::String { value: service_id },
                            Expr::String { value: input_key },
                            Expr::Integer {
                                value: max_payment_units,
                            },
                            Expr::Integer {
                                value: max_swap_lamports,
                            },
                            Expr::Integer {
                                value: max_service_fee_lamports_per_execution,
                            },
                        ] = args.as_slice()
                        else {
                            return Err(CompileError::new(
                                "UNSUPPORTED_REQUIREMENT",
                                "Provider requirements require validated source constants.",
                            ));
                        };
                        self.provider_calls.push(crate::ProviderCallRequirement {
                            payment_asset_id: String::new(),
                            operation: name.clone(),
                            service_id: service_id.clone(),
                            input_key: input_key.clone(),
                            max_payment_units: *max_payment_units,
                            max_swap_lamports: *max_swap_lamports,
                            max_service_fee_lamports_per_execution:
                                *max_service_fee_lamports_per_execution,
                        });
                        self.features.insert(ExecutionFeature::PaidHttpCall);
                        self.features.insert(ExecutionFeature::NativeSettlement);
                        Some(ExecutionFeature::ProviderCall)
                    }
                    "allowit::execution_request_validate"
                    | "paysh::payment_request_from_curl"
                    | "allowit::execution_request_cap"
                    | "allowit::payment_request_cap" => Some(ExecutionFeature::TypedWorkflow),
                    "semantic" => Some(ExecutionFeature::SemanticEvidence),
                    "confidence" => Some(ExecutionFeature::ConfidenceEvidence),
                    "require_user_input" => Some(ExecutionFeature::OwnerInput),
                    "cap_purchase_tiers" => Some(ExecutionFeature::PurchaseHistory),
                    "context_u64" => {
                        match args.get(1) {
                            Some(Expr::String { value }) => {
                                self.keys.insert(value.clone());
                            }
                            _ => self.dynamic = true,
                        }
                        Some(ExecutionFeature::RuntimeContextU64)
                    }
                    "set_cap"
                    | "cap_per_transaction"
                    | "allow_actions"
                    | "require_merchant"
                    | "require_recipient"
                    | "fail"
                    | "Ok" => None,
                    // A new primitive must declare its dependencies explicitly.
                    _ => {
                        return Err(CompileError::new(
                            "UNSUPPORTED_REQUIREMENT",
                            format!("No execution requirements declared for {name}."),
                        ));
                    }
                };
                if let Some(feature) = feature {
                    self.features.insert(feature);
                }
                for arg in args {
                    self.expr(arg)?;
                }
            }
            Expr::Borrow { value }
            | Expr::Try { value }
            | Expr::Await { value }
            | Expr::Not { value } => self.expr(value)?,
            Expr::Field { object, name } => {
                if name == "native_daily_limit" || name == "native_action_limit" {
                    self.features.insert(ExecutionFeature::NativePolicyStorage);
                }
                self.expr(object)?;
            }
            Expr::Binary { left, right, .. } => {
                self.expr(left)?;
                self.expr(right)?;
            }
            Expr::Array { values } => {
                for value in values {
                    self.expr(value)?;
                }
            }
            Expr::String { .. }
            | Expr::Integer { .. }
            | Expr::Boolean { .. }
            | Expr::Unit
            | Expr::Variable { .. } => {}
        }
        Ok(())
    }

    fn block(&mut self, block: &[Statement]) -> Result<(), CompileError> {
        for statement in block {
            match statement {
                Statement::Let { value, .. }
                | Statement::Return { value, .. }
                | Statement::Expression { value, .. } => self.expr(value)?,
                Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                }
                | Statement::IfSome {
                    value: condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    self.expr(condition)?;
                    self.block(then_branch)?;
                    self.block(else_branch)?;
                }
                Statement::ForEach { values, body, .. } => {
                    self.expr(values)?;
                    self.block(body)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn extract(program: &Program) -> Result<ExecutionRequirements, CompileError> {
    let mut collector = Collector::default();
    collector.block(&program.statements)?;
    Ok(ExecutionRequirements {
        version: 1,
        features: collector.features.into_iter().collect(),
        context_u64_keys: collector.keys.into_iter().collect(),
        dynamic_context_keys: collector.dynamic,
    })
}

pub(crate) fn provider_calls(
    program: &Program,
) -> Result<Vec<crate::ProviderCallRequirement>, CompileError> {
    let mut collector = Collector::default();
    collector.block(&program.statements)?;
    if !collector.provider_calls.is_empty() {
        let asset = crate::validation::provider_asset_id(program).ok_or_else(|| {
            CompileError::new(
                "UNSUPPORTED_REQUIREMENT",
                "Provider payment asset requires an unconditional numeric guard.",
            )
        })?;
        for call in &mut collector.provider_calls {
            call.payment_asset_id = asset.into();
        }
    }
    Ok(collector.provider_calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_primitives_must_declare_dependencies() {
        let mut collector = Collector::default();
        let error = collector
            .expr(&Expr::Call {
                name: "future_primitive".into(),
                args: vec![],
                span: Default::default(),
            })
            .unwrap_err();
        assert_eq!(error.code, "UNSUPPORTED_REQUIREMENT");
    }
}

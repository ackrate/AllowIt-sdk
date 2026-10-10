use crate::{CompileError, Expr, IR_VERSION, MAX_DEPTH, MAX_NODES, Program, Statement};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Type {
    String,
    ContextString,
    Integer,
    Boolean,
    Unit,
    Context,
    Interval,
    Strings,
    #[cfg(feature = "typed-workflow")]
    Workflow(crate::typed_workflow::WorkflowType),
    Result(Box<Type>),
    Future(Box<Type>),
}
fn result(t: Type) -> Type {
    Type::Result(Box::new(t))
}
fn bad(message: impl Into<String>) -> CompileError {
    CompileError::new("INVALID_POLICY", message)
}

pub(crate) fn amount_units(amount: &str) -> Result<u64, CompileError> {
    if amount.is_empty() || amount.len() > 24 || amount.starts_with('.') || amount.ends_with('.') {
        return Err(bad(
            "Use positive decimal amounts with at most six decimal places.",
        ));
    }
    let mut parts = amount.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || fraction.len() > 6
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad(
            "Amounts need decimal digits and at most six decimal places.",
        ));
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| bad("The amount is too large."))?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u64>()
            .map_err(|_| bad("Invalid amount."))?
            * 10_u64.pow(6 - fraction.len() as u32)
    };
    let units = whole
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(fraction))
        .ok_or_else(|| bad("The amount is too large."))?;
    if units == 0 {
        return Err(bad("Spending limits must be greater than zero."));
    }
    Ok(units)
}

struct Validator {
    nodes: usize,
    config_count: usize,
    #[cfg(feature = "typed-workflow")]
    provider_call_ids: Vec<String>,
    #[cfg(feature = "typed-workflow")]
    provider_profile: bool,
    #[cfg(feature = "typed-workflow")]
    loop_depth: usize,
    #[cfg(feature = "typed-workflow")]
    typed_nodes: Vec<crate::typed_workflow::TypedWorkflowNode>,
    #[cfg(feature = "typed-workflow")]
    typed_only: bool,
    #[cfg(feature = "typed-workflow")]
    budgets: Vec<crate::typed_workflow::TypedBudgetRequirement>,
    #[cfg(feature = "typed-workflow")]
    binding_states: BTreeMap<String, String>,
    #[cfg(feature = "oracle-ledger")]
    tier_count: usize,
}
impl Validator {
    #[inline(always)]
    fn typed_only(&self) -> bool {
        #[cfg(feature = "typed-workflow")]
        {
            self.typed_only
        }
        #[cfg(not(feature = "typed-workflow"))]
        {
            false
        }
    }
    #[inline(always)]
    fn provider_profile(&self) -> bool {
        #[cfg(feature = "typed-workflow")]
        {
            self.provider_profile
        }
        #[cfg(not(feature = "typed-workflow"))]
        {
            false
        }
    }

    fn tick(&mut self, depth: usize) -> Result<(), CompileError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > MAX_DEPTH {
            Err(bad("Policy complexity exceeds its limit."))
        } else {
            Ok(())
        }
    }
    fn block(
        &mut self,
        block: &[Statement],
        env: &mut BTreeMap<String, Type>,
        depth: usize,
        top: bool,
    ) -> Result<bool, CompileError> {
        if block.len() > MAX_NODES {
            return Err(bad("Too many statements."));
        }
        let mut terminal = false;
        for (index, statement) in block.iter().enumerate() {
            self.tick(depth)?;
            match statement {
                Statement::Let {
                    name,
                    value,
                    annotation,
                    ..
                } => {
                    if name == "ctx"
                        || env.contains_key(name)
                        || !(valid_name(name) || (self.typed_only() && valid_typed_name(name)))
                    {
                        return Err(bad("Use distinct variable names. Do not replace ctx."));
                    }
                    let ty = self.expr(value, env, depth + 1, false)?;
                    let supported = match ty {
                        Type::String
                        | Type::ContextString
                        | Type::Strings
                        | Type::Integer
                        | Type::Boolean
                        | Type::Interval => true,
                        #[cfg(feature = "typed-workflow")]
                        Type::Workflow(_) => true,
                        _ => false,
                    };
                    if !supported {
                        return Err(bad(
                            "Variables require immutable strings, integers, booleans or confidence intervals.",
                        ));
                    }
                    if let Some(annotation) = annotation {
                        let expected = match annotation.as_str() {
                            "u64" => Type::Integer,
                            "bool" => Type::Boolean,
                            "&str" => Type::String,
                            "ConfidenceInterval" => Type::Interval,
                            _ => return Err(bad("Unsupported variable type.")),
                        };
                        if ty != expected {
                            return Err(bad("Variable type does not match its value."));
                        }
                    }
                    #[cfg(feature = "typed-workflow")]
                    if let Some(last) = self.typed_nodes.last_mut()
                        && matches!(value,Expr::Try {value} if matches!(&**value,Expr::Call {span,..} if *span==last.span))
                    {
                        last.output_binding = Some(name.clone());
                        last.output_state = "via_try".into();
                        if let crate::typed_workflow::WorkflowType::Result(inner) =
                            &last.output_type
                        {
                            last.output_value_type = (**inner).clone();
                        }
                    }
                    #[cfg(feature = "typed-workflow")]
                    let state = match unborrow(value) {
                        Expr::Try { .. } => "via_try".into(),
                        Expr::Variable { name } => self
                            .binding_states
                            .get(name)
                            .cloned()
                            .unwrap_or_else(|| "bound".into()),
                        _ => "bound".into(),
                    };
                    #[cfg(feature = "typed-workflow")]
                    self.binding_states.insert(name.clone(), state);
                    env.insert(name.clone(), ty);
                }
                Statement::Expression {
                    value, semicolon, ..
                } => {
                    let direct_config = top
                        && matches!(value,Expr::Try {value} if matches!(&**value,Expr::Call{name,..} if name=="set_cap" || name=="cap_purchase_tiers"));
                    let ty = self.expr(value, env, depth + 1, direct_config)?;
                    if *semicolon {
                        if ty != Type::Unit {
                            return Err(bad(
                                "Check each function result with ?. Await user input before propagation.",
                            ));
                        }
                    } else {
                        if !top || index + 1 != block.len() || ty != result(Type::Unit) {
                            return Err(bad("Finish with Ok(()) or return fail(\"reason\")."));
                        }
                        terminal = true;
                    }
                }
                Statement::Return { value, .. } => {
                    #[cfg(feature = "typed-workflow")]
                    if self.loop_depth > 0 && !matches!(value,Expr::Call{name,..} if name=="fail") {
                        return Err(bad(
                            "A bounded loop can only return a refusal; it must check every entry before allowing.",
                        ));
                    }
                    if self.expr(value, env, depth + 1, false)? != result(Type::Unit) {
                        return Err(bad("A return must be Ok(()) or fail(\"reason\")."));
                    }
                    terminal = true;
                }
                #[cfg(feature = "typed-workflow")]
                Statement::IfSome {
                    name,
                    value,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    if env.contains_key(name)
                        || !(valid_name(name) || (self.typed_only() && valid_typed_name(name)))
                    {
                        return Err(bad("Some bindings must be distinct immutable variables."));
                    }
                    let Type::Workflow(crate::typed_workflow::WorkflowType::Option(inner)) =
                        self.expr(value, env, depth + 1, false)?
                    else {
                        return Err(bad("Some extraction requires a typed optional value."));
                    };
                    let mut branch = env.clone();
                    branch.insert(name.clone(), Type::Workflow(*inner));
                    #[cfg(feature = "typed-workflow")]
                    let states = self.binding_states.clone();
                    self.binding_states
                        .insert(name.clone(), "after_some".into());
                    let a = self.block(then_branch, &mut branch, depth + 1, false)?;
                    #[cfg(feature = "typed-workflow")]
                    {
                        self.binding_states = states.clone();
                    }
                    let b = self.block(else_branch, &mut env.clone(), depth + 1, false)?;
                    #[cfg(feature = "typed-workflow")]
                    {
                        self.binding_states = states;
                    }
                    terminal = a && b;
                }
                #[cfg(feature = "typed-workflow")]
                Statement::ForEach {
                    name, values, body, ..
                } => {
                    if self.loop_depth != 0 {
                        return Err(bad("Nested loops are not supported."));
                    }
                    if env.contains_key(name)
                        || !(valid_name(name) || (self.typed_only() && valid_typed_name(name)))
                    {
                        return Err(bad("Loop bindings must be distinct immutable variables."));
                    }
                    let Type::Workflow(crate::typed_workflow::WorkflowType::Vec(inner)) =
                        self.expr(values, env, depth + 1, false)?
                    else {
                        return Err(bad("Loops require a bounded typed workflow collection."));
                    };
                    let mut branch = env.clone();
                    branch.insert(name.clone(), Type::Workflow(*inner));
                    #[cfg(feature = "typed-workflow")]
                    let states = self.binding_states.clone();
                    self.loop_depth += 1;
                    let result = self.block(body, &mut branch, depth + 1, false);
                    self.loop_depth -= 1;
                    #[cfg(feature = "typed-workflow")]
                    {
                        self.binding_states = states;
                    }
                    result?;
                }
                Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    if self.expr(condition, env, depth + 1, false)? != Type::Boolean {
                        return Err(bad("An if condition must be boolean."));
                    }
                    #[cfg(feature = "typed-workflow")]
                    let states = self.binding_states.clone();
                    let a = self.block(then_branch, &mut env.clone(), depth + 1, false)?;
                    #[cfg(feature = "typed-workflow")]
                    {
                        self.binding_states = states.clone();
                    }
                    let b = self.block(else_branch, &mut env.clone(), depth + 1, false)?;
                    #[cfg(feature = "typed-workflow")]
                    {
                        self.binding_states = states;
                    }
                    if a && b && !else_branch.is_empty() {
                        terminal = true;
                    }
                }
            }
        }
        Ok(terminal)
    }
    fn expr(
        &mut self,
        expr: &Expr,
        env: &BTreeMap<String, Type>,
        depth: usize,
        config: bool,
    ) -> Result<Type, CompileError> {
        self.tick(depth)?;
        Ok(match expr {
            Expr::String { value } => {
                if value.len() > 1024 {
                    return Err(bad("Strings may contain at most 1,024 bytes."));
                }
                Type::String
            }
            Expr::Integer { .. } => Type::Integer,
            Expr::Boolean { .. } => Type::Boolean,
            Expr::Unit => Type::Unit,
            Expr::Variable { name } => env
                .get(name)
                .cloned()
                .ok_or_else(|| bad(format!("Unknown variable: {name}")))?,
            Expr::Field { object, name } => match self.expr(object, env, depth + 1, false)? {
                Type::Context => match name.as_str() {
                    "amount_units"
                    | "allocation_units"
                    | "spent_units"
                    | "token"
                    | "network"
                    | "action"
                    | "merchant"
                    | "recipient"
                    | "native_daily_limit"
                    | "native_action_limit"
                        if self.typed_only() =>
                    {
                        return Err(bad(
                            "Typed request policies must guard authenticated typed amounts and assets, not legacy scalar token observations.",
                        ));
                    }
                    "amount_units" | "allocation_units" | "spent_units" | "now" => Type::Integer,
                    #[cfg(feature = "std")]
                    "native_daily_limit" | "native_action_limit" => Type::Integer,
                    #[cfg(feature = "typed-workflow")]
                    "execution_request" => {
                        Type::Workflow(crate::typed_workflow::WorkflowType::Option(Box::new(
                            crate::typed_workflow::WorkflowType::named("ExecutionRequest"),
                        )))
                    }
                    #[cfg(feature = "typed-workflow")]
                    "curl_request" => Type::Workflow(crate::typed_workflow::WorkflowType::Option(
                        Box::new(crate::typed_workflow::WorkflowType::named("CurlRequest")),
                    )),
                    #[cfg(feature = "typed-workflow")]
                    "curl_outcome" => Type::Workflow(crate::typed_workflow::WorkflowType::Option(
                        Box::new(crate::typed_workflow::WorkflowType::named("CurlOutcome")),
                    )),
                    "action" | "merchant" | "recipient" | "token" | "network" => {
                        Type::ContextString
                    }
                    _ => return Err(bad(format!("Unsupported context field: {name}"))),
                },
                #[cfg(feature = "typed-workflow")]
                Type::Workflow(crate::typed_workflow::WorkflowType::Named(ref ty)) => {
                    Type::Workflow(
                        crate::typed_workflow::field_type(ty, name)
                            .ok_or_else(|| bad("Unsupported typed record field."))?,
                    )
                }
                Type::Interval if name == "lower_bps" || name == "upper_bps" => Type::Integer,
                _ => return Err(bad("This value has no such field.")),
            },
            Expr::Array { values } => {
                if values.is_empty() || values.len() > 32 {
                    return Err(bad("Action lists require 1 to 32 strings."));
                }
                for value in values {
                    if self.expr(value, env, depth + 1, false)? != Type::String {
                        return Err(bad("Action lists contain only strings."));
                    }
                }
                Type::Strings
            }
            Expr::Binary { op, left, right } => {
                let a = self.expr(left, env, depth + 1, false)?;
                let b = self.expr(right, env, depth + 1, false)?;
                #[cfg(feature = "typed-workflow")]
                let a = scalar_type(a);
                #[cfg(feature = "typed-workflow")]
                let b = scalar_type(b);
                #[cfg(feature = "typed-workflow")]
                if matches!(op.as_str(), "==" | "!=" | ">" | ">=" | "<" | "<=")
                    && ((a == Type::Workflow(crate::typed_workflow::WorkflowType::Amount256)
                        && b == Type::Integer)
                        || (b == Type::Workflow(crate::typed_workflow::WorkflowType::Amount256)
                            && a == Type::Integer)
                        || (a == b
                            && a == Type::Workflow(crate::typed_workflow::WorkflowType::Amount256)))
                {
                    return Ok(Type::Boolean);
                }
                #[cfg(feature = "typed-workflow")]
                if matches!(op.as_str(), "==" | "!=")
                    && a == b
                    && matches!(
                        a,
                        Type::Workflow(crate::typed_workflow::WorkflowType::Named(_))
                            | Type::Workflow(crate::typed_workflow::WorkflowType::Digest)
                    )
                {
                    return Ok(Type::Boolean);
                }
                match op.as_str() {
                    "+" | "-" | "*" | "/" | "%" if a == Type::Integer && b == Type::Integer => {
                        Type::Integer
                    }
                    ">" | ">=" | "<" | "<=" if a == Type::Integer && b == Type::Integer => {
                        Type::Boolean
                    }
                    "==" | "!="
                        if a == b && matches!(a, Type::String | Type::Integer | Type::Boolean) =>
                    {
                        Type::Boolean
                    }
                    "==" | "!="
                        if matches!(a, Type::String | Type::ContextString)
                            && matches!(b, Type::String | Type::ContextString) =>
                    {
                        Type::Boolean
                    }
                    "&&" | "||" if a == Type::Boolean && b == Type::Boolean => Type::Boolean,
                    _ => return Err(bad("Unsupported operator for these types.")),
                }
            }
            Expr::Not { value } => {
                if self.expr(value, env, depth + 1, false)? != Type::Boolean {
                    return Err(bad("! requires a boolean."));
                }
                Type::Boolean
            }
            #[cfg(feature = "typed-workflow")]
            Expr::Borrow { value } => {
                let ty = self.expr(value, env, depth + 1, false)?;
                if !matches!(
                    &ty,
                    Type::Workflow(
                        crate::typed_workflow::WorkflowType::Named(_)
                            | crate::typed_workflow::WorkflowType::Option(_)
                            | crate::typed_workflow::WorkflowType::Vec(_)
                    )
                ) {
                    return Err(bad(
                        "Only immutable typed workflow records and collections support this borrow.",
                    ));
                }
                ty
            }
            Expr::Try { value } => match self.expr(value, env, depth + 1, config)? {
                Type::Result(inner) => *inner,
                _ => return Err(bad("? requires a predefined function result.")),
            },
            Expr::Await { value } => match self.expr(value, env, depth + 1, false)? {
                Type::Future(inner) => *inner,
                _ => return Err(bad("Await only require_user_input.")),
            },
            Expr::Call { name, args, span } => {
                #[cfg(not(feature = "typed-workflow"))]
                let _ = span;
                #[cfg(not(feature = "oracle-ledger"))]
                if name == "cap_purchase_tiers" {
                    return Err(CompileError::new(
                        "LEDGER_REQUIRED",
                        "Purchase tiers require the oracle ledger feature.",
                    ));
                }
                let types = args
                    .iter()
                    .map(|a| self.expr(a, env, depth + 1, false))
                    .collect::<Result<Vec<_>, _>>()?;
                let expected = match name.as_str() {
                    #[cfg(feature = "typed-workflow")]
                    "allowit::execution_request_validate" => alloc::vec![Type::Workflow(
                        crate::typed_workflow::WorkflowType::named("ExecutionRequest")
                    )],
                    #[cfg(feature = "typed-workflow")]
                    "paysh::payment_request_from_curl" => alloc::vec![
                        Type::Workflow(crate::typed_workflow::WorkflowType::named("CurlOutcome")),
                        Type::Workflow(crate::typed_workflow::WorkflowType::named("CurlRequest"))
                    ],
                    #[cfg(feature = "typed-workflow")]
                    "allowit::execution_request_cap" | "allowit::payment_request_cap" => {
                        alloc::vec![
                            Type::Workflow(crate::typed_workflow::WorkflowType::named(
                                if name == "allowit::execution_request_cap" {
                                    "ValidatedExecutionRequest"
                                } else {
                                    "PaymentRequest"
                                }
                            )),
                            Type::String,
                            Type::String,
                            Type::Integer,
                            Type::Integer,
                            Type::Integer,
                            Type::Integer
                        ]
                    }
                    #[cfg(feature = "typed-workflow")]
                    "paysh::call" => alloc::vec![
                        Type::String,
                        Type::String,
                        Type::Integer,
                        Type::Integer,
                        Type::Integer
                    ],
                    "set_cap" | "cap_per_transaction" => {
                        alloc::vec![Type::Context, Type::String, Type::String]
                    }
                    #[cfg(feature = "oracle-ledger")]
                    "cap_purchase_tiers" => {
                        alloc::vec![Type::Context, Type::String, Type::Integer, Type::String]
                    }
                    "allow_actions" => alloc::vec![Type::Context, Type::Strings],
                    "require_merchant" | "require_recipient" | "confidence" | "semantic"
                    | "context_u64" | "require_user_input" => {
                        alloc::vec![Type::Context, Type::String]
                    }
                    "fail" => alloc::vec![Type::String],
                    "Ok" => alloc::vec![Type::Unit],
                    _ => return Err(bad(format!("Unknown function: {name}"))),
                };
                if types != expected {
                    return Err(bad(format!("Arguments do not match {name}.")));
                }
                #[cfg(feature = "typed-workflow")]
                if [
                    "allowit::execution_request_cap",
                    "allowit::payment_request_cap",
                ]
                .contains(&name.as_str())
                {
                    let [
                        _,
                        Expr::String { value: budget_id },
                        Expr::String { value: asset_id },
                        Expr::Integer { value: decimals },
                        Expr::Integer { value: total },
                        Expr::Integer { value: debit },
                        Expr::Integer { value: fee },
                    ] = args.as_slice()
                    else {
                        return Err(bad(
                            "Typed budgets require source literals or constructor-folded constants.",
                        ));
                    };
                    if self.loop_depth > 0
                        || budget_id.is_empty()
                        || budget_id.len() > 128
                        || crate::typed_workflow::asset_from_identity(asset_id).is_none()
                        || *decimals > 18
                        || *total == 0
                        || debit.checked_add(*fee).is_none_or(|v| v == 0 || v > *total)
                        || self
                            .budgets
                            .iter()
                            .any(|b| b.budget_id == *budget_id || b.asset_id == *asset_id)
                        || self.budgets.len() >= 16
                    {
                        return Err(bad(
                            "Declare distinct exact-asset budgets with positive total and bounded debit/fee ceilings, outside loops.",
                        ));
                    }
                    self.budgets
                        .push(crate::typed_workflow::TypedBudgetRequirement {
                            operation: name.clone(),
                            budget_id: budget_id.clone(),
                            asset_id: asset_id.clone(),
                            decimals: *decimals as u8,
                            total_budget_units: *total,
                            max_debit_units: *debit,
                            max_fee_units: *fee,
                        });
                }
                #[cfg(feature = "typed-workflow")]
                if let Some(signature) = crate::typed_workflow::signature(name) {
                    if signature.effect == "pure_validation"
                        && (self.loop_depth != 0
                            || self.typed_nodes.iter().any(|node| {
                                matches!(
                                    node.operation.as_str(),
                                    "allowit::execution_request_validate"
                                        | "paysh::payment_request_from_curl"
                                )
                            }))
                    {
                        return Err(bad(
                            "One producing workflow node is supported per run, outside loops.",
                        ));
                    }
                    self.typed_nodes
                        .push(crate::typed_workflow::TypedWorkflowNode {
                            operation: name.clone(),
                            span: *span,
                            span_encoding: "utf8_bytes".into(),
                            inputs: signature
                                .parameters
                                .iter()
                                .zip(args)
                                .map(|(p, a)| crate::typed_workflow::TypedWorkflowPort {
                                    name: p.name.clone(),
                                    value_type: p.value_type.clone(),
                                    binding: a.clone(),
                                    state: match unborrow(a) {
                                        Expr::String { .. }
                                        | Expr::Integer { .. }
                                        | Expr::Boolean { .. } => "literal".into(),
                                        Expr::Variable { name } => self
                                            .binding_states
                                            .get(name)
                                            .cloned()
                                            .unwrap_or_else(|| "bound".into()),
                                        _ => "bound".into(),
                                    },
                                })
                                .collect(),
                            output_type: signature.result.clone(),
                            output_value_type: signature.result.clone(),
                            output_state: "result".into(),
                            output_binding: None,
                        });
                    return Ok(match signature.result {
                        crate::typed_workflow::WorkflowType::Result(inner) => {
                            if *inner == crate::typed_workflow::WorkflowType::named("Unit") {
                                result(Type::Unit)
                            } else {
                                result(Type::Workflow(*inner))
                            }
                        }
                        _ => return Err(bad("Invalid typed signature.")),
                    });
                }
                #[cfg(feature = "typed-workflow")]
                if name == "paysh::call" {
                    if self.loop_depth > 0 {
                        return Err(bad(
                            "Effectful calls are not supported inside bounded loops.",
                        ));
                    }
                    if !matches!(args.first(), Some(Expr::String { .. }))
                        || !matches!(args.get(1), Some(Expr::String { .. }))
                        || args[2..]
                            .iter()
                            .any(|arg| !matches!(arg, Expr::Integer { .. }))
                    {
                        return Err(bad(
                            "Provider operation arguments must be source literals or initialized constructor constants.",
                        ));
                    }
                    for arg in &args[..2] {
                        if let Expr::String { value } = arg
                            && (value.trim().is_empty() || value.len() > 200)
                        {
                            return Err(bad("Provider identifiers require 1 to 200 bytes."));
                        }
                    }
                    if let Expr::String { value } = &args[0] {
                        if !value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
                        {
                            return Err(bad(
                                "Provider service identifiers require ASCII letters, digits or ._:/-.",
                            ));
                        }
                        if self.provider_call_ids.len() >= 8
                            || self.provider_call_ids.contains(value)
                        {
                            return Err(bad(
                                "Declare at most eight distinct provider services per policy.",
                            ));
                        }
                        self.provider_call_ids.push(value.clone());
                    }
                }
                if self.typed_only()
                    && [
                        "set_cap",
                        "cap_per_transaction",
                        "cap_purchase_tiers",
                        "require_recipient",
                        "require_merchant",
                        "allow_actions",
                        "context_u64",
                        "native_storage",
                    ]
                    .contains(&name.as_str())
                {
                    return Err(bad(
                        "Typed request policies use typed effect and fee guards; scalar token limits cannot represent native assets.",
                    ));
                }
                if name == "set_cap" {
                    self.config_count += 1;
                    if !config || self.config_count > 1 {
                        return Err(bad(
                            "Declare set_cap at most once, unconditionally at top level, with literal arguments.",
                        ));
                    }
                    match (args.get(1), args.get(2)) {
                        (
                            Some(Expr::String { value: amount }),
                            Some(Expr::String { value: token }),
                        ) if token == "USDC"
                            || (self.provider_profile()
                                && !token.is_empty()
                                && token.len() <= 128) =>
                        {
                            amount_units(amount)?;
                        }
                        _ => {
                            return Err(bad(
                                "set_cap requires a positive amount literal and the string \"USDC\".",
                            ));
                        }
                    }
                }
                #[cfg(feature = "oracle-ledger")]
                if name == "cap_purchase_tiers" {
                    self.tier_count += 1;
                    if self.tier_count > 1 {
                        return Err(bad("Declare purchase tiers only once."));
                    }
                    if !config {
                        return Err(bad(
                            "Purchase tiers must be an unconditional top-level call.",
                        ));
                    }
                    match (args.get(1), args.get(2), args.get(3)) {
                        (
                            Some(Expr::String { value: amount }),
                            Some(Expr::Integer { value: count }),
                            Some(Expr::String { value: token }),
                        ) if (token == "USDC"
                            || (self.provider_profile()
                                && !token.is_empty()
                                && token.len() <= 128))
                            && *count > 0
                            && *count <= 1_000_000 =>
                        {
                            if amount_units(amount)? > 1_000_000_000_000 {
                                return Err(bad(
                                    "The purchase ceiling must be at most 1000000 USDC.",
                                ));
                            }
                        }
                        _ => {
                            return Err(bad(
                                "Use a positive maximum USDC amount, a count from 1 to 1000000 and USDC.",
                            ));
                        }
                    }
                }
                if name == "cap_per_transaction" {
                    if let Some(Expr::String { value }) = args.get(1) {
                        amount_units(value)?;
                    }
                    if let Some(Expr::String { value }) = args.get(2) {
                        if self.provider_profile() && (value.is_empty() || value.len() > 128) {
                            return Err(bad("Provider asset identifiers require 1 to 128 bytes."));
                        }
                        if value != "USDC" && !self.provider_profile() {
                            return Err(bad("Version 1 supports six-decimal USDC only."));
                        }
                    }
                }
                if [
                    "require_user_input",
                    "require_merchant",
                    "require_recipient",
                    "confidence",
                    "semantic",
                    "context_u64",
                ]
                .contains(&name.as_str())
                    && let Some(Expr::String { value }) = args.get(1)
                    && value.trim().is_empty()
                {
                    return Err(bad("The function argument must not be empty."));
                }
                #[cfg(feature = "typed-workflow")]
                if name == "paysh::call" {
                    return Ok(Type::Boolean);
                }
                if name == "confidence" || name == "semantic" {
                    result(Type::Interval)
                } else if name == "context_u64" {
                    result(Type::Integer)
                } else if name == "require_user_input" {
                    Type::Future(Box::new(result(Type::Unit)))
                } else {
                    result(Type::Unit)
                }
            }
        })
    }
}
fn valid_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|v| v.is_ascii_alphabetic() || v == b'_')
        && b.all(|v| v.is_ascii_alphanumeric() || v == b'_')
        && s.len() <= 64
}

/// Validate every branch of an IR program, including unreachable code.
/// This is also required when a contract receives serialized IR.
pub fn validate_program(program: &Program) -> Result<(), CompileError> {
    #[cfg(not(feature = "typed-workflow"))]
    if program.version != IR_VERSION {
        return Err(bad("Unsupported canonical IR version."));
    }
    #[cfg(feature = "typed-workflow")]
    if (crate::typed_workflow::required(program) && provider_call_required(program))
        || (!crate::typed_workflow::required(program) && program.version != IR_VERSION)
        || ![IR_VERSION, crate::TYPED_IR_VERSION].contains(&program.version.as_str())
        || (crate::typed_workflow::required(program) && program.version != crate::TYPED_IR_VERSION)
    {
        return Err(bad("Unsupported canonical IR version."));
    }
    let mut env = BTreeMap::new();
    env.insert("ctx".to_string(), Type::Context);
    let mut validator = Validator {
        #[cfg(feature = "typed-workflow")]
        loop_depth: 0,
        #[cfg(feature = "typed-workflow")]
        typed_nodes: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        budgets: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        binding_states: BTreeMap::new(),
        #[cfg(feature = "typed-workflow")]
        typed_only: cfg!(feature = "typed-workflow")
            && crate::typed_workflow::required(program)
            && !provider_call_required(program),
        #[cfg(feature = "typed-workflow")]
        provider_call_ids: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        provider_profile: cfg!(feature = "typed-workflow") && provider_call_required(program),
        nodes: 0,
        config_count: 0,
        #[cfg(feature = "oracle-ledger")]
        tier_count: 0,
    };
    if !validator.block(&program.statements, &mut env, 0, true)? {
        return Err(bad("Each path must return Ok(()) or fail(\"reason\")."));
    }
    #[cfg(feature = "typed-workflow")]
    if validator.provider_profile()
        && provider_asset_id(program).is_none_or(|asset| ["USDC", "SOL"].contains(&asset))
    {
        return Err(bad(
            "Provider policies require one unconditional set_cap with a literal asset identifier, not a currency symbol.",
        ));
    }
    Ok(())
}

/// The payment asset comes from the same unconditional numeric guard as funding metadata.
#[cfg(feature = "typed-workflow")]
pub(crate) fn provider_asset_id(program: &Program) -> Option<&str> {
    program.statements.iter().find_map(|statement| {
        let Statement::Expression {
            value: Expr::Try { value },
            ..
        } = statement
        else {
            return None;
        };
        let Expr::Call { name, args, .. } = &**value else {
            return None;
        };
        if name != "set_cap" {
            return None;
        }
        match args.get(2) {
            Some(Expr::String { value }) => Some(value.as_str()),
            _ => None,
        }
    })
}

/// Detect native storage reads in every branch, including unreachable statements.
#[cfg(feature = "std")]
pub(crate) fn native_storage_required(program: &Program) -> bool {
    let mut statements: Vec<&Statement> = program.statements.iter().collect();
    let mut expressions = Vec::new();
    while let Some(statement) = statements.pop() {
        match statement {
            Statement::Let { value, .. }
            | Statement::Expression { value, .. }
            | Statement::Return { value, .. } => expressions.push(value),
            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                expressions.push(condition);
                statements.extend(then_branch);
                statements.extend(else_branch);
            }
            #[cfg(feature = "typed-workflow")]
            Statement::IfSome {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                expressions.push(value);
                statements.extend(then_branch);
                statements.extend(else_branch);
            }
            #[cfg(feature = "typed-workflow")]
            Statement::ForEach { values, body, .. } => {
                expressions.push(values);
                statements.extend(body);
            }
        }
    }
    while let Some(expr) = expressions.pop() {
        match expr {
            Expr::Field { object, name } => {
                if name == "native_daily_limit" || name == "native_action_limit" {
                    return true;
                }
                expressions.push(object);
            }
            Expr::Call { args, .. } | Expr::Array { values: args } => expressions.extend(args),
            #[cfg(feature = "typed-workflow")]
            Expr::Borrow { value } => expressions.push(value),
            Expr::Try { value } | Expr::Await { value } | Expr::Not { value } => {
                expressions.push(value)
            }
            Expr::Binary { left, right, .. } => {
                expressions.push(left);
                expressions.push(right);
            }
            Expr::String { .. }
            | Expr::Integer { .. }
            | Expr::Boolean { .. }
            | Expr::Unit
            | Expr::Variable { .. } => {}
        }
    }
    false
}

/// Provider operations require host settlement even when an IR branch is not taken.
#[cfg(feature = "typed-workflow")]
pub(crate) fn provider_call_required(program: &Program) -> bool {
    let mut statements: Vec<&Statement> = program.statements.iter().collect();
    let mut expressions = Vec::new();
    while let Some(statement) = statements.pop() {
        match statement {
            Statement::Let { value, .. }
            | Statement::Expression { value, .. }
            | Statement::Return { value, .. } => expressions.push(value),
            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                expressions.push(condition);
                statements.extend(then_branch);
                statements.extend(else_branch);
            }
            #[cfg(feature = "typed-workflow")]
            Statement::IfSome {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                expressions.push(value);
                statements.extend(then_branch);
                statements.extend(else_branch);
            }
            #[cfg(feature = "typed-workflow")]
            Statement::ForEach { values, body, .. } => {
                expressions.push(values);
                statements.extend(body);
            }
        }
    }
    while let Some(expr) = expressions.pop() {
        match expr {
            Expr::Field { object, .. } => {
                expressions.push(object);
            }
            Expr::Call { name, args, .. } => {
                if name == "paysh::call" {
                    return true;
                }
                expressions.extend(args);
            }
            Expr::Array { values } => expressions.extend(values),
            #[cfg(feature = "typed-workflow")]
            Expr::Borrow { value } => expressions.push(value),
            Expr::Try { value } | Expr::Await { value } | Expr::Not { value } => {
                expressions.push(value)
            }
            Expr::Binary { left, right, .. } => {
                expressions.push(left);
                expressions.push(right);
            }
            Expr::String { .. }
            | Expr::Integer { .. }
            | Expr::Boolean { .. }
            | Expr::Unit
            | Expr::Variable { .. } => {}
        }
    }
    false
}

#[cfg(not(feature = "typed-workflow"))]
pub(crate) fn provider_call_required(_program: &Program) -> bool {
    false
}

#[cfg(feature = "typed-workflow")]
fn scalar_type(ty: Type) -> Type {
    match ty {
        #[cfg(feature = "typed-workflow")]
        Type::Workflow(crate::typed_workflow::WorkflowType::U64) => Type::Integer,
        #[cfg(feature = "typed-workflow")]
        Type::Workflow(crate::typed_workflow::WorkflowType::Bool) => Type::Boolean,
        #[cfg(feature = "typed-workflow")]
        Type::Workflow(crate::typed_workflow::WorkflowType::String) => Type::String,
        other => other,
    }
}

#[cfg(feature = "compiler")]
pub(crate) fn typed_nodes(
    program: &Program,
) -> Result<Vec<crate::typed_workflow::TypedWorkflowNode>, CompileError> {
    validate_program(program)?;
    let mut validator = Validator {
        #[cfg(feature = "typed-workflow")]
        loop_depth: 0,
        #[cfg(feature = "typed-workflow")]
        typed_nodes: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        budgets: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        binding_states: BTreeMap::new(),
        #[cfg(feature = "typed-workflow")]
        typed_only: crate::typed_workflow::required(program) && !provider_call_required(program),
        #[cfg(feature = "typed-workflow")]
        provider_call_ids: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        provider_profile: provider_call_required(program),
        nodes: 0,
        config_count: 0,
        #[cfg(feature = "oracle-ledger")]
        tier_count: 0,
    };
    let mut env = BTreeMap::new();
    env.insert("ctx".into(), Type::Context);
    validator.block(&program.statements, &mut env, 0, true)?;
    Ok(validator.typed_nodes)
}

#[cfg(feature = "compiler")]
pub(crate) fn typed_budgets(
    program: &Program,
) -> Result<Vec<crate::typed_workflow::TypedBudgetRequirement>, CompileError> {
    validate_program(program)?;
    let mut v = Validator {
        #[cfg(feature = "typed-workflow")]
        loop_depth: 0,
        #[cfg(feature = "typed-workflow")]
        typed_nodes: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        budgets: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        binding_states: BTreeMap::new(),
        #[cfg(feature = "typed-workflow")]
        typed_only: crate::typed_workflow::required(program) && !provider_call_required(program),
        #[cfg(feature = "typed-workflow")]
        provider_call_ids: Vec::new(),
        #[cfg(feature = "typed-workflow")]
        provider_profile: provider_call_required(program),
        nodes: 0,
        config_count: 0,
        #[cfg(feature = "oracle-ledger")]
        tier_count: 0,
    };
    let mut env = BTreeMap::new();
    env.insert("ctx".into(), Type::Context);
    v.block(&program.statements, &mut env, 0, true)?;
    Ok(v.budgets)
}

#[cfg(feature = "typed-workflow")]
fn unborrow(expr: &Expr) -> &Expr {
    match expr {
        #[cfg(feature = "typed-workflow")]
        Expr::Borrow { value } => unborrow(value),
        _ => expr,
    }
}

#[cfg(feature = "typed-workflow")]
fn valid_typed_name(s: &str) -> bool {
    use unicode_normalization::UnicodeNormalization;
    use unicode_script::{Script, UnicodeScript};
    let mut script = None;
    for c in s.chars() {
        let current = c.script();
        if matches!(current, Script::Common | Script::Inherited) {
            continue;
        }
        if script.is_some_and(|prior| prior != current) {
            return false;
        }
        script = Some(current);
    }
    if !s.nfc().eq(s.chars()) {
        return false;
    }
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| unicode_ident::is_xid_start(c) || c == '_')
        && chars.all(unicode_ident::is_xid_continue)
        && s.len() <= 64
}

#[cfg(not(feature = "typed-workflow"))]
fn valid_typed_name(_s: &str) -> bool {
    false
}

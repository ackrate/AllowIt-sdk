use crate::{
    CallSite, CompileError, CompiledPolicy, Expr, IR_VERSION, LANGUAGE, MAX_SOURCE_BYTES, Program,
    REGISTRY_VERSION, SourceSpan, Statement, WorkflowBlock, canonical_ir_hash, digest,
    registry::function, validate_program,
};
use proc_macro2::Span;
use std::collections::BTreeSet;
use syn::{BinOp, Expr as SynExpr, FnArg, Item, Pat, ReturnType, Stmt, Type, spanned::Spanned};

fn error(span: Span, message: impl Into<String>) -> CompileError {
    let p = span.start();
    CompileError {
        code: "INVALID_POLICY".into(),
        message: message.into(),
        line: Some(p.line),
        column: Some(p.column + 1),
    }
}
fn range(span: Span) -> SourceSpan {
    let r = span.byte_range();
    SourceSpan {
        start: r.start,
        end: r.end,
    }
}
// Namespace paths are bounded and resolved against the exact registry spelling.
pub(crate) fn registered_path(path: &syn::Path) -> Option<String> {
    if path.leading_colon.is_some()
        || path.segments.len() > 2
        || path
            .segments
            .iter()
            .any(|segment| !segment.arguments.is_empty())
    {
        return None;
    }
    let name = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    crate::registry::canonical_function(&name)
}

fn unparen(expr: &SynExpr) -> &SynExpr {
    match expr {
        SynExpr::Paren(p) => unparen(&p.expr),
        _ => expr,
    }
}
fn bare_context_string(expr: &SynExpr) -> bool {
    matches!(unparen(expr),SynExpr::Field(f) if matches!(unparen(&f.base),SynExpr::Path(p) if p.qself.is_none() && simple_path(&p.path,"ctx")) && matches!(&f.member,syn::Member::Named(n) if ["action","merchant","recipient","token","network"].contains(&n.to_string().as_str())))
}

fn simple_path(path: &syn::Path, name: &str) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 1
        && path.segments[0].ident == name
        && path.segments[0].arguments.is_empty()
}
fn annotation(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(p)
            if p.qself.is_none()
                && p.path.segments.len() == 1
                && p.path.segments[0].arguments.is_empty() =>
        {
            Some(p.path.segments[0].ident.to_string())
        }
        Type::Reference(r)
            if r.mutability.is_none()
                && r.lifetime.is_none()
                && matches!(&*r.elem,Type::Path(p) if simple_path(&p.path,"str")) =>
        {
            Some("&str".into())
        }
        _ => None,
    }
}

fn preference_threshold(expr: &SynExpr, direction: &str) -> Result<(bool, String), CompileError> {
    let default = if direction == "deny" { "40" } else { "85" };
    if matches!(expr, SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path, "None"))
    {
        return Ok((false, default.into()));
    }
    if let SynExpr::Call(c) = expr
        && c.attrs.is_empty()
        && c.args.len() == 1
        && matches!(&*c.func, SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path, "auto"))
        && matches!(&c.args[0], SynExpr::Lit(l) if l.attrs.is_empty() && matches!(&l.lit, syn::Lit::Str(s) if s.suffix().is_empty() && s.value() == direction))
    {
        return Ok((true, format!("{default}.00")));
    }
    if let SynExpr::Lit(l) = expr {
        let literal = match &l.lit {
            syn::Lit::Float(v) if v.suffix().is_empty() => Some(v.to_string()),
            syn::Lit::Int(v) if v.suffix().is_empty() => Some(v.to_string()),
            _ => None,
        };
        if l.attrs.is_empty()
            && let Some(literal) = literal
        {
            let bps = crate::readability::decimal_units(&literal, 4)
                .map_err(|e| error(expr.span(), e.message))?;
            if bps <= 10_000 {
                return Ok((true, format!("{}.{:02}", bps / 100, bps % 100)));
            }
        }
    }
    Err(error(
        expr.span(),
        "Use a literal score in 0..1 with at most four decimal places, None, or auto with the matching decision name.",
    ))
}

struct Parser {
    nodes: usize,
    params: Option<std::collections::BTreeMap<String, Expr>>,
    helper_calls: Vec<(String, SourceSpan)>,
    preference_steps: Vec<(SourceSpan, Vec<String>)>,
}
impl Parser {
    fn primitive_call(
        &mut self,
        call: &syn::ExprCall,
        depth: usize,
    ) -> Result<Option<Expr>, CompileError> {
        if self.params.is_none() {
            return Ok(None);
        }
        let SynExpr::Path(path) = &*call.func else {
            return Ok(None);
        };
        let Some(name) = registered_path(&path.path) else {
            return Ok(None);
        };
        if ![
            "set_cap",
            "cap_per_transaction",
            "cap_purchase_tiers",
            "allow_actions",
            "require_merchant",
            "require_recipient",
        ]
        .contains(&name.as_str())
        {
            return Ok(None);
        }
        if path.path.segments.len() != 2 || !path.attrs.is_empty() || !call.attrs.is_empty() {
            return Err(error(
                call.span(),
                "Use the namespaced primitive guard signature.",
            ));
        }
        let expected: &[(&str, bool)] = match name.as_str() {
            "set_cap" => &[
                ("spent_units", false),
                ("amount_units", false),
                ("token", true),
            ],
            "cap_per_transaction" => &[("amount_units", false), ("token", true)],
            "cap_purchase_tiers" => &[
                ("amount_units", false),
                ("token", true),
                ("purchase_counts", true),
            ],
            "allow_actions" => &[("action", true)],
            "require_merchant" => &[("merchant", true)],
            _ => &[("recipient", true)],
        };
        let financial = matches!(
            name.as_str(),
            "set_cap" | "cap_per_transaction" | "cap_purchase_tiers"
        );
        let suffix = if name == "cap_purchase_tiers" {
            4
        } else if financial {
            3
        } else {
            1
        };
        if call.args.len() != expected.len() + suffix {
            return Err(error(
                call.span(),
                "Arguments do not match the primitive guard signature.",
            ));
        }
        for (arg, (field, borrowed)) in call.args.iter().zip(expected) {
            let observed = if *borrowed {
                match arg {
                    SynExpr::Reference(r) if r.attrs.is_empty() && r.mutability.is_none() => {
                        &*r.expr
                    }
                    _ => return Err(error(arg.span(), "Borrow the exact authenticated field.")),
                }
            } else {
                arg
            };
            if !matches!(observed,SynExpr::Field(f) if f.attrs.is_empty() && matches!(&f.member,syn::Member::Named(n) if n==field) && matches!(&*f.base,SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path,"ctx")))
            {
                return Err(error(
                    arg.span(),
                    "Use the exact authenticated context field. Caller substitutes cannot enforce this guard.",
                ));
            }
        }
        let mut args = vec![Expr::Variable { name: "ctx".into() }];
        let index = expected.len();
        if financial {
            let Expr::Integer { value } = self.expr(&call.args[index], depth + 1)? else {
                return Err(error(
                    call.args[index].span(),
                    "Use a fixed amount in integer units or a declared constructor parameter.",
                ));
            };
            if value == 0 {
                return Err(error(
                    call.args[index].span(),
                    "The limit must be positive.",
                ));
            }
            let count = usize::from(name == "cap_purchase_tiers");
            let currency = self.expr(&call.args[index + 1 + count], depth + 1)?;
            let decimals = self.expr(&call.args[index + 2 + count], depth + 1)?;
            if !matches!(&currency,Expr::String{value} if !value.is_empty() && value.len()<=128)
                || !matches!(decimals, Expr::Integer { value: 6 })
            {
                return Err(error(
                    call.span(),
                    "Use one explicit bound asset identifier with exactly six decimals.",
                ));
            }
            let amount = if value % 1_000_000 == 0 {
                format!("{}", value / 1_000_000)
            } else {
                format!("{}.{:06}", value / 1_000_000, value % 1_000_000)
            };
            args.push(Expr::String { value: amount });
            if count == 1 {
                args.push(self.expr(&call.args[index + 1], depth + 1)?);
            }
            args.push(currency);
        } else {
            args.push(self.expr(&call.args[index], depth + 1)?);
        }
        Ok(Some(Expr::Call {
            name,
            args,
            span: range(path.span()),
        }))
    }

    fn preference_step(
        &mut self,
        stmt: &Stmt,
        depth: usize,
    ) -> Result<Option<Vec<Statement>>, CompileError> {
        let Stmt::Expr(SynExpr::Try(t), Some(_)) = stmt else {
            return Ok(None);
        };
        let SynExpr::Await(a) = &*t.expr else {
            return Ok(None);
        };
        let SynExpr::Call(c) = &*a.base else {
            return Ok(None);
        };
        let SynExpr::Path(p) = &*c.func else {
            return Ok(None);
        };
        if p.qself.is_some() || registered_path(&p.path).as_deref() != Some("check_preference") {
            return Ok(None);
        }
        if p.path.segments.len() == 2 && c.args.len() != 4 {
            return Err(error(
                c.span(),
                "Use the four-argument namespaced preference check.",
            ));
        }
        self.tick(stmt.span(), depth)?;
        if !t.attrs.is_empty()
            || !a.attrs.is_empty()
            || !c.attrs.is_empty()
            || !p.attrs.is_empty()
            || ![4, 6].contains(&c.args.len())
        {
            return Err(error(
                stmt.span(),
                "Use check_preference(ctx, question, auto_approve, approve_percent, auto_deny, deny_percent).await?; with literal settings.",
            ));
        }
        let context_arg = if self.params.is_some() {
            if p.path.segments.len() != 2 || c.args.len() != 4 {
                return Err(error(
                    c.span(),
                    "Use a namespaced preference guard with explicit evidence.",
                ));
            }
            let SynExpr::Call(reader) = &c.args[0] else {
                return Err(error(
                    c.args[0].span(),
                    "Read bound preference evidence explicitly before checking thresholds.",
                ));
            };
            let valid_reader = reader.attrs.is_empty()
                && reader.args.len() == 2
                && matches!(&*reader.func,SynExpr::Path(r) if r.attrs.is_empty() && r.qself.is_none() && r.path.segments.len()==2 && registered_path(&r.path).as_deref()==Some("preference_evidence"));
            if !valid_reader
                || !matches!(&reader.args[0],SynExpr::Path(r) if r.attrs.is_empty() && r.qself.is_none() && simple_path(&r.path,"ctx"))
            {
                return Err(error(
                    reader.span(),
                    "Use jev::preference_evidence(ctx, the same literal question).",
                ));
            }
            let read_question = self.expr(&reader.args[1], depth + 1)?;
            let guard_question = self.expr(&c.args[1], depth + 1)?;
            if !matches!(&read_question, Expr::String { .. }) || read_question != guard_question {
                return Err(error(
                    reader.span(),
                    "The evidence reader and guard must use the same question.",
                ));
            }
            Expr::Variable { name: "ctx".into() }
        } else {
            self.expr(&c.args[0], depth + 1)?
        };
        let args = if c.args.len() == 4 {
            let (deny, below) = preference_threshold(&c.args[2], "deny")?;
            let (approve, above) = preference_threshold(&c.args[3], "approve")?;
            vec![
                context_arg,
                self.expr(&c.args[1], depth + 1)?,
                Expr::Boolean { value: approve },
                Expr::String { value: above },
                Expr::Boolean { value: deny },
                Expr::String { value: below },
            ]
        } else {
            c.args
                .iter()
                .map(|a| self.expr(a, depth + 1))
                .collect::<Result<Vec<_>, _>>()?
        };
        let [
            Expr::Variable { name: ctx },
            Expr::String { value: question },
            Expr::Boolean { value: approve },
            Expr::String { value: above },
            Expr::Boolean { value: deny },
            Expr::String { value: below },
        ] = args.as_slice()
        else {
            return Err(error(
                c.span(),
                "Preference settings must be literal booleans and decimal percentage strings.",
            ));
        };
        if ctx != "ctx" || question.trim().is_empty() || question.len() > 1024 {
            return Err(error(
                c.span(),
                "Use ctx and a preference question of 1–1,024 bytes.",
            ));
        }
        let upper =
            crate::readability::percentage_bps(above).map_err(|e| error(c.span(), e.message))?;
        let lower =
            crate::readability::percentage_bps(below).map_err(|e| error(c.span(), e.message))?;
        if *approve && *deny && lower >= upper {
            return Err(error(
                c.span(),
                "The automatic denial threshold must be below the automatic approval threshold.",
            ));
        }
        let span = range(stmt.span());
        let call_span = range(p.span());
        let variable = format!("__allowit_preference_{}", span.start);
        let call = |name: &str, args| Expr::Call {
            name: name.into(),
            args,
            span: call_span,
        };
        let context = || Expr::Variable { name: "ctx".into() };
        let string = |s: &str| Expr::String { value: s.into() };
        let field = |name: &str| Expr::Field {
            object: Box::new(Expr::Variable {
                name: variable.clone(),
            }),
            name: name.into(),
        };
        let compare = |op: &str, left, value| Expr::Binary {
            op: op.into(),
            left: Box::new(left),
            right: Box::new(Expr::Integer { value }),
        };
        let mut statements = vec![];
        if *approve || *deny {
            statements.push(Statement::Let {
                name: variable.clone(),
                annotation: None,
                value: Expr::Try {
                    value: Box::new(call("semantic", vec![context(), string(question)])),
                },
                span,
            });
        }
        if *deny {
            statements.push(Statement::If {
                condition: compare("<=", field("upper_bps"), lower),
                then_branch: vec![Statement::Return {
                    value: call(
                        "fail",
                        vec![string("The request does not meet this preference.")],
                    ),
                    span,
                }],
                else_branch: vec![],
                span,
            });
        }
        statements.push(Statement::If {
            condition: if *approve {
                compare("<", field("lower_bps"), upper)
            } else {
                Expr::Boolean { value: true }
            },
            then_branch: vec![Statement::Expression {
                value: Expr::Try {
                    value: Box::new(Expr::Await {
                        value: Box::new(call(
                            "require_user_input",
                            vec![context(), string(question)],
                        )),
                    }),
                },
                semicolon: true,
                span,
            }],
            else_branch: vec![],
            span,
        });
        self.helper_calls
            .push(("check_preference".into(), call_span));
        self.preference_steps
            .push((span, args[1..].iter().map(argument).collect()));
        Ok(Some(statements))
    }
    // Readability helpers are checked source sugar. Contracts receive only the existing
    // integer/comparison IR; they never parse decimals or trust a new runtime opcode.
    fn readable_helper(
        &mut self,
        expr: &SynExpr,
        depth: usize,
    ) -> Result<Option<Expr>, CompileError> {
        let SynExpr::Call(call) = expr else {
            return Ok(None);
        };
        let SynExpr::Path(path) = &*call.func else {
            return Ok(None);
        };
        if self.params.is_some() && path.path.segments.len() != 2 {
            return Err(error(
                path.span(),
                "Use the exact namespaced system function.",
            ));
        }
        if path.qself.is_none() && registered_path(&path.path).as_deref() == Some("stored_limit") {
            if self.params.is_none()
                || path.path.segments.len() != 2
                || !call.attrs.is_empty()
                || !path.attrs.is_empty()
                || call.args.len() != 2
                || !matches!(&call.args[0],SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path,"ctx"))
            {
                return Err(error(
                    call.span(),
                    "Read a declared owner limit with stored_limit(ctx, params.field)?.",
                ));
            }
            let SynExpr::Field(field) = &call.args[1] else {
                return Err(error(call.span(), "Use a declared OwnerLimit field."));
            };
            if !field.attrs.is_empty()
                || !matches!(&*field.base,SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path,"params"))
            {
                return Err(error(call.span(), "Use a declared OwnerLimit field."));
            }
            let binding = self.expr(&call.args[1], depth + 1)?;
            let Expr::Array { values } = binding else {
                return Err(error(call.span(), "Use a declared OwnerLimit field."));
            };
            let [Expr::String { value: key }, Expr::Integer { .. }] = values.as_slice() else {
                return Err(error(call.span(), "Use a declared OwnerLimit field."));
            };
            self.helper_calls
                .push(("stored_limit".into(), range(path.span())));
            return Ok(Some(Expr::Field {
                object: Box::new(Expr::Variable { name: "ctx".into() }),
                name: key.clone(),
            }));
        }
        if path.qself.is_none() && registered_path(&path.path).as_deref() == Some("is_one_of") {
            if call.args.len() != 2 || !call.attrs.is_empty() || !path.attrs.is_empty() {
                return Err(error(call.span(), "Use is_one_of(value, &[\"allowed\"])?."));
            }
            if bare_context_string(&call.args[0]) {
                return Err(error(
                    call.args[0].span(),
                    "Borrow the authenticated string field.",
                ));
            }
            let value = self.expr(&call.args[0], depth + 1)?;
            if !matches!(
                value,
                Expr::Field { .. } | Expr::String { .. } | Expr::Variable { .. }
            ) {
                return Err(error(
                    call.span(),
                    "Use a primitive value or a bound scalar field.",
                ));
            }
            let Expr::Array { values } = self.expr(&call.args[1], depth + 1)? else {
                return Err(error(
                    call.span(),
                    "Use an inline string list or a declared list parameter.",
                ));
            };
            if values.is_empty()
                || values.len() > 32
                || !values.iter().all(|v| matches!(v, Expr::String { .. }))
            {
                return Err(error(call.span(), "Use 1 to 32 literal strings."));
            }
            let mut checks = values.into_iter().map(|right| Expr::Binary {
                op: "==".into(),
                left: Box::new(value.clone()),
                right: Box::new(right),
            });
            let result = checks.next().expect("nonempty");
            let result = checks.fold(result, |left, right| Expr::Binary {
                op: "||".into(),
                left: Box::new(left),
                right: Box::new(right),
            });
            self.helper_calls
                .push(("is_one_of".into(), range(path.span())));
            return Ok(Some(result));
        }
        let Some(name) = [
            "usdc",
            "percent",
            "amount_at_most",
            "within_percentage_points",
        ]
        .into_iter()
        .find(|name| path.qself.is_none() && registered_path(&path.path).as_deref() == Some(*name)) else {
            return Ok(None);
        };
        self.tick(call.span(), depth)?;
        if !call.attrs.is_empty() || !path.attrs.is_empty() {
            return Err(error(call.span(), "Helper attributes are not supported."));
        }
        if self.params.is_some() && name == "amount_at_most" && path.path.segments.len() != 2 {
            return Err(error(
                call.span(),
                "Use the primitive namespaced amount comparison.",
            ));
        }
        let count = match name {
            "amount_at_most" => 2,
            "within_percentage_points" => 3,
            _ => 1,
        };
        if call.args.len() != count {
            return Err(error(
                call.span(),
                "Arguments do not match the helper signature.",
            ));
        }
        let literal = &call.args[count - 1];
        let SynExpr::Lit(value) = literal else {
            return Err(error(
                literal.span(),
                "Amount and percentage helpers require decimal string literals.",
            ));
        };
        let syn::Lit::Str(value_string) = &value.lit else {
            return Err(error(
                literal.span(),
                "Use a decimal string literal, such as \"25.50\".",
            ));
        };
        if !value.attrs.is_empty() || !value_string.suffix().is_empty() {
            return Err(error(
                literal.span(),
                "Use an unadorned decimal string literal.",
            ));
        }
        let value = if name == "percent" || name == "within_percentage_points" {
            crate::readability::percentage_bps(&value_string.value())
        } else {
            crate::readability::decimal_units(&value_string.value(), 6)
        }
        .map_err(|e| error(literal.span(), e.message))?;
        let integer = Expr::Integer { value };
        let binary = |op: &str, left, right| Expr::Binary {
            op: op.into(),
            left: Box::new(left),
            right: Box::new(right),
        };
        let result = match name {
            "amount_at_most" => {
                if self.params.is_some() && path.path.segments.len() == 2 {
                    if !matches!(&call.args[0], SynExpr::Field(f) if f.attrs.is_empty() && matches!(&f.member,syn::Member::Named(n) if n=="amount_units") && matches!(&*f.base,SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path,"ctx")))
                    {
                        return Err(error(
                            call.args[0].span(),
                            "Use the authenticated ctx.amount_units for this purchase guard.",
                        ));
                    }
                    let observed = self.expr(&call.args[0], depth + 1)?;
                    self.helper_calls.push((name.into(), range(path.span())));
                    return Ok(Some(binary("<=", observed, integer)));
                }
                if !matches!(&call.args[0], SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path, "ctx"))
                {
                    return Err(error(
                        call.args[0].span(),
                        "Use amount_at_most(ctx, \"25.50\")?.",
                    ));
                }
                binary(
                    "<=",
                    Expr::Field {
                        object: Box::new(Expr::Variable { name: "ctx".into() }),
                        name: "amount_units".into(),
                    },
                    integer,
                )
            }
            "within_percentage_points" => {
                // Restrict operands before recursing: repeating nested helpers could expand
                // exponentially, and repeated effectful expressions would be misleading.
                for arg in call.args.iter().take(2) {
                    if !matches!(arg, SynExpr::Path(_) | SynExpr::Lit(_)) {
                        return Err(error(
                            arg.span(),
                            "Bind each return to a variable before comparing returns.",
                        ));
                    }
                }
                let candidate = self.expr(&call.args[0], depth + 1)?;
                let benchmark = self.expr(&call.args[1], depth + 1)?;
                // Short-circuit before subtraction: safe even at u64::MAX.
                binary(
                    "||",
                    binary(">=", candidate.clone(), benchmark.clone()),
                    binary("<=", binary("-", benchmark, candidate), integer),
                )
            }
            _ => integer,
        };
        self.helper_calls.push((name.into(), range(path.span())));
        Ok(Some(result))
    }
    fn tick(&mut self, span: Span, depth: usize) -> Result<(), CompileError> {
        self.nodes += 1;
        if self.nodes > crate::MAX_NODES || depth > crate::MAX_DEPTH {
            Err(error(
                span,
                "Policy complexity exceeds the supported limit.",
            ))
        } else {
            Ok(())
        }
    }
    fn block(&mut self, block: &syn::Block, depth: usize) -> Result<Vec<Statement>, CompileError> {
        let mut statements = vec![];
        for stmt in &block.stmts {
            if let Some(expanded) = self.preference_step(stmt, depth + 1)? {
                statements.extend(expanded);
            } else {
                statements.push(self.statement(stmt, depth + 1)?);
            }
        }
        Ok(statements)
    }
    fn statement(&mut self, stmt: &Stmt, depth: usize) -> Result<Statement, CompileError> {
        self.tick(stmt.span(), depth)?;
        let span = range(stmt.span());
        Ok(match stmt {
            Stmt::Local(local) => {
                if !local.attrs.is_empty() {
                    return Err(error(
                        local.span(),
                        "Attributes are not supported in policies.",
                    ));
                }
                let (pat, ty) = match &local.pat {
                    Pat::Type(p) => (
                        &*p.pat,
                        Some(
                            annotation(&p.ty)
                                .ok_or_else(|| error(p.ty.span(), "Unsupported variable type."))?,
                        ),
                    ),
                    p => (p, None),
                };
                let Pat::Ident(ident) = pat else {
                    return Err(error(pat.span(), "Use a simple immutable variable name."));
                };
                if ident.ident == "params" || ident.ident.to_string().starts_with("__allowit_") {
                    return Err(error(
                        ident.span(),
                        "This variable prefix is reserved for policy helpers.",
                    ));
                }
                if ident.mutability.is_some() || ident.by_ref.is_some() || ident.subpat.is_some() {
                    return Err(error(pat.span(), "Variables must be immutable."));
                }
                let init = local
                    .init
                    .as_ref()
                    .ok_or_else(|| error(local.span(), "Variables require an initial value."))?;
                if init.diverge.is_some() {
                    return Err(error(local.span(), "let-else is not supported."));
                }
                if bare_context_string(&init.expr)
                    || matches!(unparen(&init.expr),SynExpr::Path(p) if p.qself.is_none() && simple_path(&p.path,"ctx"))
                {
                    return Err(error(
                        init.expr.span(),
                        "Borrow a string field instead of moving it or copying the context.",
                    ));
                }
                Statement::Let {
                    name: ident.ident.to_string(),
                    value: self.expr(&init.expr, depth + 1)?,
                    annotation: ty,
                    span,
                }
            }
            Stmt::Expr(SynExpr::Return(ret), _) => Statement::Return {
                value: self.expr(
                    ret.expr
                        .as_ref()
                        .ok_or_else(|| error(ret.span(), "Return Ok(()) or fail(\"reason\")."))?,
                    depth + 1,
                )?,
                span,
            },
            Stmt::Expr(SynExpr::ForLoop(f), _) => {
                if !f.attrs.is_empty() || f.label.is_some() {
                    return Err(error(
                        f.span(),
                        "Only bounded typed collection loops are supported.",
                    ));
                }
                let Pat::Ident(binding) = &*f.pat else {
                    return Err(error(f.span(), "Use one immutable loop binding."));
                };
                if binding.mutability.is_some()
                    || binding.by_ref.is_some()
                    || binding.subpat.is_some()
                {
                    return Err(error(f.span(), "Use one immutable loop binding."));
                }
                Statement::ForEach {
                    name: binding.ident.to_string(),
                    values: self.expr(&f.expr, depth + 1)?,
                    body: self.block(&f.body, depth + 1)?,
                    span: range(f.span()),
                }
            }
            Stmt::Expr(SynExpr::If(i), _) => self.if_statement(i, depth + 1)?,
            Stmt::Expr(expr, semi) => Statement::Expression {
                value: self.expr(expr, depth + 1)?,
                semicolon: semi.is_some(),
                span,
            },
            _ => {
                return Err(error(
                    stmt.span(),
                    "Only immutable variables, predefined calls, if statements and returns are supported.",
                ));
            }
        })
    }
    fn if_statement(&mut self, i: &syn::ExprIf, depth: usize) -> Result<Statement, CompileError> {
        self.tick(i.span(), depth)?;
        if !i.attrs.is_empty() {
            return Err(error(i.span(), "Attributes are not supported."));
        }
        let else_branch = if let Some((_, branch)) = &i.else_branch {
            match &**branch {
                SynExpr::Block(b) if b.label.is_none() && b.attrs.is_empty() => {
                    self.block(&b.block, depth + 1)?
                }
                SynExpr::If(other) => vec![self.if_statement(other, depth + 1)?],
                _ => return Err(error(branch.span(), "Unsupported else branch.")),
            }
        } else {
            vec![]
        };
        if let SynExpr::Let(condition) = &*i.cond {
            if !condition.attrs.is_empty() {
                return Err(error(condition.span(), "Attributes are not supported."));
            }
            let Pat::TupleStruct(pattern) = &*condition.pat else {
                return Err(error(
                    condition.span(),
                    "Use if let Some(name) = optional_value.",
                ));
            };
            if !simple_path(&pattern.path, "Some") || pattern.elems.len() != 1 {
                return Err(error(pattern.span(), "Only Some extraction is supported."));
            }
            let Pat::Ident(binding) = &pattern.elems[0] else {
                return Err(error(pattern.span(), "Use one immutable Some binding."));
            };
            if binding.mutability.is_some() || binding.by_ref.is_some() || binding.subpat.is_some()
            {
                return Err(error(pattern.span(), "Use one immutable Some binding."));
            }
            return Ok(Statement::IfSome {
                name: binding.ident.to_string(),
                value: self.expr(&condition.expr, depth + 1)?,
                then_branch: self.block(&i.then_branch, depth + 1)?,
                else_branch,
                span: range(i.span()),
            });
        }
        Ok(Statement::If {
            condition: self.expr(&i.cond, depth + 1)?,
            then_branch: self.block(&i.then_branch, depth + 1)?,
            else_branch,
            span: range(i.span()),
        })
    }
    fn expr(&mut self, expr: &SynExpr, depth: usize) -> Result<Expr, CompileError> {
        self.tick(expr.span(), depth)?;
        let has_attrs = match expr {
            SynExpr::Lit(e) => !e.attrs.is_empty(),
            SynExpr::Path(e) => !e.attrs.is_empty(),
            SynExpr::Field(e) => !e.attrs.is_empty(),
            SynExpr::Binary(e) => !e.attrs.is_empty(),
            SynExpr::Unary(e) => !e.attrs.is_empty(),
            SynExpr::Try(e) => !e.attrs.is_empty(),
            SynExpr::Await(e) => !e.attrs.is_empty(),
            SynExpr::Call(e) => !e.attrs.is_empty(),
            SynExpr::Reference(e) => !e.attrs.is_empty(),
            SynExpr::Array(e) => !e.attrs.is_empty(),
            SynExpr::Paren(e) => !e.attrs.is_empty(),
            SynExpr::Tuple(e) => !e.attrs.is_empty(),
            _ => false,
        };
        if has_attrs {
            return Err(error(expr.span(), "Attributes are not supported."));
        }
        Ok(match expr {
            SynExpr::Lit(lit) => match &lit.lit {
                syn::Lit::Str(s) if s.suffix().is_empty() => Expr::String { value: s.value() },
                syn::Lit::Int(i) if i.suffix().is_empty() || i.suffix() == "u64" => Expr::Integer {
                    value: i
                        .base10_parse::<u64>()
                        .map_err(|_| error(i.span(), "Integers must fit in u64."))?,
                },
                syn::Lit::Bool(b) => Expr::Boolean { value: b.value },
                _ => {
                    return Err(error(
                        lit.span(),
                        "Use strings, booleans or non-negative u64 integers.",
                    ));
                }
            },
            SynExpr::Path(p)
                if p.qself.is_none()
                    && p.path.leading_colon.is_none()
                    && p.path.segments.len() == 1
                    && p.path.segments[0].arguments.is_empty() =>
            {
                if p.path.segments[0]
                    .ident
                    .to_string()
                    .starts_with("__allowit_")
                {
                    return Err(error(
                        p.span(),
                        "This variable prefix is reserved for policy helpers.",
                    ));
                }
                Expr::Variable {
                    name: p.path.segments[0].ident.to_string(),
                }
            }
            SynExpr::Tuple(t) if t.elems.is_empty() => Expr::Unit,
            SynExpr::Paren(p) => self.expr(&p.expr, depth + 1)?,
            SynExpr::Reference(r)
                if r.mutability.is_none() && matches!(&*r.expr, SynExpr::Array(_)) =>
            {
                let SynExpr::Array(a) = &*r.expr else {
                    unreachable!()
                };
                Expr::Array {
                    values: a
                        .elems
                        .iter()
                        .map(|e| self.expr(e, depth + 1))
                        .collect::<Result<_, _>>()?,
                }
            }
            SynExpr::Field(f) => {
                if matches!(&*f.base,SynExpr::Path(p) if p.attrs.is_empty() && p.qself.is_none() && simple_path(&p.path,"params"))
                {
                    let syn::Member::Named(name) = &f.member else {
                        return Err(error(f.span(), "Use a named constructor parameter."));
                    };
                    return self
                        .params
                        .as_ref()
                        .and_then(|p| p.get(&name.to_string()))
                        .cloned()
                        .ok_or_else(|| {
                            error(
                                f.span(),
                                "Declare this parameter and initialize it in new().",
                            )
                        });
                }
                let syn::Member::Named(name) = &f.member else {
                    return Err(error(
                        f.span(),
                        "Only named context and confidence fields are supported.",
                    ));
                };
                if name == "native_daily_limit" || name == "native_action_limit" {
                    return Err(error(
                        f.span(),
                        "Read declared native storage with stored_limit.",
                    ));
                }
                Expr::Field {
                    object: Box::new(self.expr(&f.base, depth + 1)?),
                    name: name.to_string(),
                }
            }
            SynExpr::Binary(b)
                if self.params.is_some() && matches!(b.op, BinOp::And(_) | BinOp::Or(_)) =>
            {
                return Err(error(
                    b.span(),
                    "Use separate sequential guards instead of a combined boolean condition.",
                ));
            }
            SynExpr::Binary(b) => Expr::Binary {
                op: match b.op {
                    BinOp::Add(_) => "+",
                    BinOp::Sub(_) => "-",
                    BinOp::Mul(_) => "*",
                    BinOp::Div(_) => "/",
                    BinOp::Rem(_) => "%",
                    BinOp::Eq(_) => "==",
                    BinOp::Ne(_) => "!=",
                    BinOp::Gt(_) => ">",
                    BinOp::Ge(_) => ">=",
                    BinOp::Lt(_) => "<",
                    BinOp::Le(_) => "<=",
                    BinOp::And(_) => "&&",
                    BinOp::Or(_) => "||",
                    _ => return Err(error(b.op.span(), "This operator is not supported.")),
                }
                .into(),
                left: Box::new(self.expr(&b.left, depth + 1)?),
                right: Box::new(self.expr(&b.right, depth + 1)?),
            },
            SynExpr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => Expr::Not {
                value: Box::new(self.expr(&u.expr, depth + 1)?),
            },
            SynExpr::Reference(r)
                if r.mutability.is_none()
                    && matches!(&*r.expr,SynExpr::Field(f) if matches!(&f.member,syn::Member::Named(name) if ["token","action","merchant","recipient","network"].contains(&name.to_string().as_str())) && matches!(&*f.base,SynExpr::Path(p) if p.qself.is_none() && simple_path(&p.path,"ctx"))) =>
            {
                self.expr(&r.expr, depth + 1)?
            }
            SynExpr::Reference(r) if r.mutability.is_none() => Expr::Borrow {
                value: Box::new(self.expr(&r.expr, depth + 1)?),
            },
            SynExpr::Try(t) => match self.readable_helper(&t.expr, depth + 1)? {
                Some(lowered) => lowered,
                None => Expr::Try {
                    value: Box::new(self.expr(&t.expr, depth + 1)?),
                },
            },
            SynExpr::Await(a) => Expr::Await {
                value: Box::new(self.expr(&a.base, depth + 1)?),
            },
            SynExpr::Call(c) => {
                if let Some(lowered) = self.primitive_call(c, depth + 1)? {
                    return Ok(lowered);
                }
                let SynExpr::Path(p) = &*c.func else {
                    return Err(error(
                        c.func.span(),
                        "Only direct predefined function calls are supported.",
                    ));
                };
                let name = if p.qself.is_none() && simple_path(&p.path, "Ok") {
                    "Ok".into()
                } else if p.qself.is_none() {
                    registered_path(&p.path).ok_or_else(|| {
                        error(p.span(), "Use an exact registered policy function name.")
                    })?
                } else {
                    return Err(error(p.span(), "Qualified type calls are not supported."));
                };
                if self.params.is_some() && name != "Ok" && p.path.segments.len() != 2 {
                    return Err(error(p.span(), "Use the exact namespaced system function."));
                }
                Expr::Call {
                    name,
                    args: c
                        .args
                        .iter()
                        .map(|e| self.expr(e, depth + 1))
                        .collect::<Result<_, _>>()?,
                    span: range(p.span()),
                }
            }
            _ => {
                return Err(error(
                    expr.span(),
                    "This Rust construct is outside the AllowIt policy subset.",
                ));
            }
        })
    }
}

fn valid_import(use_item: &syn::ItemUse) -> bool {
    if !use_item.attrs.is_empty()
        || use_item.leading_colon.is_some()
        || !matches!(use_item.vis, syn::Visibility::Inherited)
    {
        return false;
    }
    let syn::UseTree::Path(a) = &use_item.tree else {
        return false;
    };
    if a.ident != "allowit" {
        return false;
    }
    let tree = match &*a.tree {
        syn::UseTree::Path(v) if v.ident == "v1" => &*v.tree,
        other => other,
    };
    matches!(tree, syn::UseTree::Path(p) if p.ident == "prelude" && matches!(&*p.tree, syn::UseTree::Glob(_)))
}
fn offset(source: &str, byte: usize) -> usize {
    source[..byte.min(source.len())].encode_utf16().count()
}
fn source_slice(source: &str, span: SourceSpan) -> String {
    source.get(span.start..span.end).unwrap_or("").to_string()
}
fn direct_call(expr: &Expr) -> Option<(&str, &[Expr])> {
    match expr {
        Expr::Try { value } | Expr::Await { value } => direct_call(value),
        Expr::Call { name, args, .. } if name != "Ok" => Some((name, args)),
        _ => None,
    }
}
fn literal(expr: &Expr) -> bool {
    match expr {
        Expr::String { .. } | Expr::Integer { .. } | Expr::Boolean { .. } => true,
        Expr::Variable { name } => name == "ctx",
        Expr::Array { values } => values.iter().all(literal),
        _ => false,
    }
}
fn argument(expr: &Expr) -> String {
    match expr {
        Expr::String { value } => value.clone(),
        Expr::Integer { value } => value.to_string(),
        Expr::Boolean { value } => value.to_string(),
        Expr::Array { values } => values.iter().map(argument).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}
fn walk_expr(expr: &Expr, calls: &mut Vec<(String, SourceSpan)>) {
    match expr {
        Expr::Call { name, args, span } => {
            if name != "Ok" {
                calls.push((name.clone(), *span));
            }
            for arg in args {
                walk_expr(arg, calls);
            }
        }
        Expr::Borrow { value }
        | Expr::Try { value }
        | Expr::Await { value }
        | Expr::Not { value } => walk_expr(value, calls),
        Expr::Field { object, .. } => walk_expr(object, calls),
        Expr::Binary { left, right, .. } => {
            walk_expr(left, calls);
            walk_expr(right, calls);
        }
        Expr::Array { values } => {
            for value in values {
                walk_expr(value, calls);
            }
        }
        _ => {}
    }
}
fn walk_block(block: &[Statement], calls: &mut Vec<(String, SourceSpan)>) {
    for s in block {
        match s {
            Statement::Let { value, .. }
            | Statement::Return { value, .. }
            | Statement::Expression { value, .. } => walk_expr(value, calls),
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
                walk_expr(condition, calls);
                walk_block(then_branch, calls);
                walk_block(else_branch, calls);
            }
            Statement::ForEach { values, body, .. } => {
                walk_expr(values, calls);
                walk_block(body, calls);
            }
        }
    }
}

/// Parse source as Rust, reject unsupported syntax, type/effect-check every branch and
/// produce the sole executable IR and its source-preserving workflow projection.
pub fn compile(source: &str) -> Result<CompiledPolicy, CompileError> {
    struct SpanCleanup;
    impl Drop for SpanCleanup {
        fn drop(&mut self) {
            proc_macro2::extra::invalidate_current_thread_spans();
        }
    }
    let _cleanup = SpanCleanup;
    compile_inner(source)
}

fn compile_inner(source: &str) -> Result<CompiledPolicy, CompileError> {
    if source.chars().any(|c| matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'|'\u{200e}'|'\u{200f}'|'\u{061c}')) {
        return Err(CompileError::new("INVALID_POLICY","Bidirectional text controls are not allowed in policy source."));
    }
    if source.starts_with('\u{feff}') {
        return Err(CompileError::new(
            "INVALID_POLICY",
            "Save the policy as UTF-8 without a byte-order mark.",
        ));
    }
    if source.len() > MAX_SOURCE_BYTES {
        return Err(CompileError::new(
            "SOURCE_TOO_LARGE",
            "Policy source may contain at most 32 KiB.",
        ));
    }
    let tokens = source
        .parse::<proc_macro2::TokenStream>()
        .map_err(|e| error(e.span(), e.to_string()))?;
    validate_token_budget(&tokens)?;
    let (tokens, params) = crate::params::extract(&tokens)?;
    validate_signature(&tokens)?;
    validate_block_shapes(&tokens)?;
    let file = syn::parse2::<syn::File>(tokens).map_err(|e| error(e.span(), e.to_string()))?;
    if !file.attrs.is_empty() || file.shebang.is_some() {
        return Err(CompileError::new(
            "INVALID_POLICY",
            "File attributes and shebangs are not supported.",
        ));
    }
    let mut policy_fn = None;
    let mut imported = false;
    for item in &file.items {
        match item {
            Item::Use(u) if !imported && valid_import(u) => imported = true,
            Item::Fn(f) if policy_fn.is_none() => policy_fn = Some(f),
            _ => {
                return Err(error(
                    item.span(),
                    "A policy contains only an optional allowit::prelude import and the execute function.",
                ));
            }
        }
    }
    let f = policy_fn.ok_or_else(|| {
        CompileError::new(
            "INVALID_POLICY",
            "Define async fn _execute(ctx: &Context) -> PolicyResult.",
        )
    })?;
    let sig = &f.sig;
    let valid_entry = (sig.ident == "_execute" && matches!(f.vis, syn::Visibility::Inherited))
        || ((sig.ident == "execute" || sig.ident == "evaluate" || sig.ident == "exec")
            && matches!(f.vis, syn::Visibility::Public(_)));
    if !f.attrs.is_empty()
        || !valid_entry
        || sig.asyncness.is_none()
        || sig.constness.is_some()
        || sig.unsafety.is_some()
        || sig.abi.is_some()
        || sig.variadic.is_some()
        || !sig.generics.params.is_empty()
        || sig.generics.where_clause.is_some()
        || sig.inputs.len() != if params.is_some() { 2 } else { 1 }
        || (params.is_some() && sig.ident != "_execute")
    {
        return Err(error(
            sig.span(),
            "Use private async fn _execute(ctx: &Context) -> PolicyResult, or a public legacy entrypoint.",
        ));
    }
    let valid_arg = matches!(&sig.inputs[0],FnArg::Typed(arg) if arg.attrs.is_empty()&&matches!(&*arg.pat,Pat::Ident(p) if p.ident=="ctx"&&p.mutability.is_none()&&p.by_ref.is_none()&&p.subpat.is_none())&&matches!(&*arg.ty,Type::Reference(r) if r.mutability.is_none()&&r.lifetime.is_none()&&matches!(&*r.elem,Type::Path(p) if p.qself.is_none()&&simple_path(&p.path,"Context"))));
    let valid_params = params.is_none()
        || matches!(&sig.inputs[1],FnArg::Typed(arg) if arg.attrs.is_empty()&&matches!(&*arg.pat,Pat::Ident(p) if p.ident=="params"&&p.mutability.is_none()&&p.by_ref.is_none()&&p.subpat.is_none())&&matches!(&*arg.ty,Type::Reference(r) if r.mutability.is_none()&&r.lifetime.is_none()&&matches!(&*r.elem,Type::Path(p) if p.qself.is_none()&&simple_path(&p.path,"PolicyParams"))));
    let valid_return = matches!(&sig.output,ReturnType::Type(_,ty) if matches!(&**ty,Type::Path(p) if p.qself.is_none()&&simple_path(&p.path,"PolicyResult")));
    if !valid_arg || !valid_params || !valid_return {
        return Err(error(
            sig.span(),
            "Use private async fn _execute(ctx: &Context) -> PolicyResult, or a public legacy entrypoint.",
        ));
    }
    let mut parser = Parser {
        nodes: 0,
        params,
        helper_calls: vec![],
        preference_steps: vec![],
    };
    let mut ir = Program {
        version: IR_VERSION.into(),
        statements: parser.block(&f.block, 0)?,
    };
    if crate::typed_workflow::required(&ir) {
        ir.version = crate::TYPED_IR_VERSION.into();
    }
    validate_program(&ir)?;
    let source_hash = digest(source.as_bytes());
    let ir_hash = canonical_ir_hash(&ir)?;
    let mut workflow: Vec<WorkflowBlock> = vec![];
    let mut limit = String::new();
    let mut projected_preferences = BTreeSet::new();
    for statement in &ir.statements {
        let span = statement.span();
        if let Some((_, arguments)) = parser.preference_steps.iter().find(|(s, _)| *s == span) {
            if projected_preferences.insert(span.start) {
                let info = function("check_preference").expect("registered helper");
                workflow.push(WorkflowBlock {
                    id: digest(format!("{source_hash}:{}:preference", span.start).as_bytes())[..16]
                        .into(),
                    kind: "preference".into(),
                    name: info.name,
                    label: info.title,
                    description: info.description,
                    arguments: arguments.clone(),
                    score_thresholds: vec![],
                    source: source_slice(source, span),
                    start: offset(source, span.start),
                    end: offset(source, span.end),
                });
            }
            continue;
        }
        let value = match statement {
            Statement::Expression { value, .. }
            | Statement::Return { value, .. }
            | Statement::Let { value, .. } => Some(value),
            _ => None,
        };
        let predefined = value
            .and_then(direct_call)
            .filter(|(_, args)| args.iter().all(literal));
        let pass = matches!(value,Some(Expr::Call{name,..}) if name=="Ok");
        let (kind, name, label, description, arguments) = if let Some((name, args)) = predefined {
            let info = function(name).expect("validator checked the registry");
            if name == "set_cap" {
                limit = argument(&args[1]);
            }
            (
                "function",
                name.to_string(),
                info.title,
                info.description,
                args.iter()
                    .filter(|a| !matches!(a,Expr::Variable{name} if name=="ctx"))
                    .map(argument)
                    .collect(),
            )
        } else if pass {
            (
                "pass",
                "Ok".into(),
                "Pass the policy check".into(),
                "The request meets the policy's rules. This result is not a transfer receipt."
                    .into(),
                vec![],
            )
        } else {
            ("custom","custom".into(),"Custom code".into(),"These conditions and calculations run in the order shown. Open the code to inspect their exact rules.".into(),vec![])
        };
        if kind == "custom" && workflow.last().is_some_and(|b| b.kind == "custom") {
            let last = workflow.last_mut().expect("checked");
            last.end = offset(source, span.end);
            let start = source
                .char_indices()
                .scan(0usize, |u, (byte, c)| {
                    let old = *u;
                    *u += c.len_utf16();
                    Some((old, byte))
                })
                .find(|(u, _)| *u == last.start)
                .map(|(_, b)| b)
                .unwrap_or(0);
            last.source = source.get(start..span.end).unwrap_or("").into();
            continue;
        }
        workflow.push(WorkflowBlock {
            id: digest(format!("{source_hash}:{}:{kind}", span.start).as_bytes())[..16].into(),
            kind: kind.into(),
            name,
            label,
            description,
            arguments,
            score_thresholds: vec![],
            source: source_slice(source, span),
            start: offset(source, span.start),
            end: offset(source, span.end),
        });
    }
    crate::editing::annotate(source, f, &mut workflow);
    let mut found = parser.helper_calls;
    walk_block(&ir.statements, &mut found);
    found.sort_by_key(|(_, s)| s.start);
    let mut seen = BTreeSet::new();
    let calls = found
        .into_iter()
        .filter(|(_, s)| seen.insert(s.start))
        .map(|(name, span)| CallSite {
            name,
            start: offset(source, span.start),
            end: offset(source, span.end),
        })
        .collect();
    Ok(CompiledPolicy {
        language: LANGUAGE.into(),
        source_hash,
        ir_hash,
        registry_version: REGISTRY_VERSION.into(),
        execution_requirements: crate::requirements::extract(&ir)?,
        provider_call_requirements: crate::requirements::provider_calls(&ir)?,
        typed_workflow_requirements: crate::validation::typed_nodes(&ir)?,
        typed_budget_requirements: crate::validation::typed_budgets(&ir)?,
        limit,
        token: if crate::typed_workflow::required(&ir)
            && !crate::validation::provider_call_required(&ir)
        {
            String::new()
        } else {
            crate::validation::provider_asset_id(&ir)
                .unwrap_or("USDC")
                .into()
        },
        source: source.into(),
        workflow,
        calls,
        ir,
    })
}

// Validate the only supported item/signature without invoking syn's recursive type parser.
// Type aliases, generic parameters, nested references and function-pointer types are not DSL
// features, so they must never reach that parser even when their token count is small.
fn validate_signature(tokens: &proc_macro2::TokenStream) -> Result<(), CompileError> {
    use proc_macro2::{Delimiter, TokenTree};
    fn invalid() -> CompileError {
        CompileError::new(
            "INVALID_POLICY",
            "Use an optional allowit::v1::prelude import and one private async fn _execute(ctx: &Context) -> PolicyResult { ... }, or a public legacy entrypoint.",
        )
    }
    fn matches(token: Option<TokenTree>, expected: &str) -> bool {
        match token {
            Some(TokenTree::Ident(ident)) => ident == expected,
            Some(TokenTree::Punct(punct)) => {
                expected.len() == 1 && expected.starts_with(punct.as_char())
            }
            _ => false,
        }
    }
    fn expect(
        iter: &mut proc_macro2::token_stream::IntoIter,
        expected: &[&str],
    ) -> Result<(), CompileError> {
        for word in expected {
            if !matches(iter.next(), word) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    let mut iter = tokens.clone().into_iter();
    let mut first = iter.next();
    if matches(first.clone(), "use") {
        expect(&mut iter, &["allowit", ":", ":"])?;
        let segment = iter.next();
        if matches(segment.clone(), "v1") {
            expect(&mut iter, &[":", ":", "prelude"])?;
        } else if !matches(segment, "prelude") {
            return Err(invalid());
        }
        expect(&mut iter, &[":", ":", "*", ";"])?;
        first = iter.next();
    }
    let public = matches(first.clone(), "pub");
    if public {
        expect(&mut iter, &["async"])?;
    } else if !matches(first, "async") {
        return Err(invalid());
    }
    expect(&mut iter, &["fn"])?;
    let name = iter.next();
    let valid_name = if public {
        matches(name.clone(), "execute")
            || matches(name.clone(), "exec")
            || matches(name, "evaluate")
    } else {
        matches(name, "_execute")
    };
    if !valid_name {
        return Err(invalid());
    }
    let Some(TokenTree::Group(params)) = iter.next() else {
        return Err(invalid());
    };
    if params.delimiter() != Delimiter::Parenthesis {
        return Err(invalid());
    }
    let mut params = params.stream().into_iter();
    expect(&mut params, &["ctx", ":", "&", "Context"])?;
    if let Some(last) = params.next() {
        if !matches(Some(last), ",") {
            return Err(invalid());
        }
        if let Some(next) = params.next() {
            if public || !matches(Some(next), "params") {
                return Err(invalid());
            }
            expect(&mut params, &[":", "&", "PolicyParams"])?;
            if let Some(last) = params.next()
                && (!matches(Some(last), ",") || params.next().is_some())
            {
                return Err(invalid());
            }
        }
    }
    expect(&mut iter, &["-", ">", "PolicyResult"])?;
    if !matches!(iter.next(), Some(TokenTree::Group(body)) if body.delimiter() == Delimiter::Brace)
        || iter.next().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

// syn creates deep ASTs for shallow postfix chains. Count tokens iteratively before parsing;
// parentheses/brackets contribute to their enclosing expression rather than resetting its budget.
fn validate_token_budget(tokens: &proc_macro2::TokenStream) -> Result<(), CompileError> {
    use proc_macro2::{Delimiter, TokenTree};
    enum Pending {
        Tokens(proc_macro2::token_stream::IntoIter, bool),
        End(Delimiter),
    }
    let mut stack = vec![Pending::Tokens(tokens.clone().into_iter(), true)];
    let (mut count, mut operators, mut flow, mut elses, mut total) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let limit = || {
        CompileError::new(
            "RESOURCE_LIMIT",
            "A policy expression exceeds the parser resource limit (256 tokens, 96 operators, 32 control prefixes, or 32 else branches). Split the conditions into separate statements.",
        )
    };
    let total_limit = || {
        CompileError::new(
            "RESOURCE_LIMIT",
            "A policy may contain at most 1,024 syntax tokens, including delimiters. Simplify the policy or split it into separate policies.",
        )
    };
    while let Some(pending) = stack.pop() {
        let (token, statements) = match pending {
            Pending::End(Delimiter::Brace) => {
                total += 1;
                if total > 1024 {
                    return Err(total_limit());
                }
                count = 0;
                operators = 0;
                flow = 0;
                continue;
            }
            Pending::End(_) => {
                total += 1;
                if total > 1024 {
                    return Err(total_limit());
                }
                count += 1;
                if count > 256 {
                    return Err(limit());
                }
                continue;
            }
            Pending::Tokens(mut iter, statements) => match iter.next() {
                Some(token) => {
                    stack.push(Pending::Tokens(iter, statements));
                    (token, statements)
                }
                None => continue,
            },
        };
        total += 1;
        if total > 1024 {
            return Err(total_limit());
        }
        count += 1;
        match token {
            TokenTree::Group(group) => {
                if group.delimiter() == Delimiter::Brace {
                    count = 0;
                    operators = 0;
                    flow = 0;
                }
                stack.push(Pending::End(group.delimiter()));
                stack.push(Pending::Tokens(
                    group.stream().into_iter(),
                    group.delimiter() == Delimiter::Brace,
                ));
            }
            TokenTree::Punct(p) if p.as_char() == ';' && statements => {
                count = 0;
                operators = 0;
                flow = 0;
            }
            TokenTree::Punct(p) if "!+-*/%&|<>=?.".contains(p.as_char()) => operators += 1,
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                if ["if", "return", "break", "yield"].contains(&name.as_str()) {
                    flow += 1;
                }
                if name == "else" {
                    elses += 1;
                }
            }
            _ => {}
        }
        if count > 256 || operators > 96 || flow > 32 || elses > 32 {
            return Err(limit());
        }
    }
    Ok(())
}

// The subset has braces only for the evaluate body and if/else bodies. Reject expression
// blocks before syn: otherwise f({})({})... could repeatedly reset a flat token budget while
// still constructing a deep postfix AST. Each nested group is visited iteratively.
fn validate_block_shapes(tokens: &proc_macro2::TokenStream) -> Result<(), CompileError> {
    use proc_macro2::{Delimiter, TokenTree};
    #[derive(Clone, Copy, PartialEq)]
    enum Scope {
        File,
        Body,
        Expression,
    }
    struct Frame {
        iter: proc_macro2::token_stream::IntoIter,
        scope: Scope,
        expects_body: bool,
        statement_start: bool,
        after_if_body: bool,
        pending_else: bool,
        expects_operand: bool,
        depth: usize,
    }
    fn frame(tokens: proc_macro2::TokenStream, scope: Scope, depth: usize) -> Frame {
        Frame {
            iter: tokens.into_iter(),
            scope,
            expects_body: false,
            statement_start: true,
            after_if_body: false,
            pending_else: false,
            expects_operand: true,
            depth,
        }
    }
    let mut stack = vec![frame(tokens.clone(), Scope::File, 0)];
    let mut file_bodies = 0usize;
    while let Some(mut current) = stack.pop() {
        let Some(token) = current.iter.next() else {
            continue;
        };
        if current.scope == Scope::Body && current.after_if_body {
            match &token {
                TokenTree::Ident(ident) if ident == "else" => {
                    current.expects_body = true;
                    current.pending_else = true;
                    current.after_if_body = false;
                    current.statement_start = false;
                    stack.push(current);
                    continue;
                }
                TokenTree::Ident(ident)
                    if ident == "let"
                        || ident == "if"
                        || ident == "for"
                        || ident == "return"
                        || ident == "Ok"
                        || ident == "allowit"
                        || ident == "jev"
                        || ident == "paysh"
                        || crate::registry::function(&ident.to_string()).is_some() =>
                {
                    current.after_if_body = false;
                    current.statement_start = true;
                }
                TokenTree::Punct(p) if p.as_char() == ';' => {
                    current.after_if_body = false;
                    current.statement_start = true;
                    stack.push(current);
                    continue;
                }
                _ => {
                    return Err(error(
                        token.span(),
                        "An if/else block must be followed by else or a new statement.",
                    ));
                }
            }
        }
        match token {
            TokenTree::Group(group) => {
                // The signature preflight already checked the fixed parameter group.
                if current.scope == Scope::File && group.delimiter() != Delimiter::Brace {
                    stack.push(current);
                    continue;
                }
                let depth = current.depth + 1;
                if depth > 32 {
                    return Err(error(
                        group.span(),
                        "Policy delimiter depth exceeds 32 levels.",
                    ));
                }
                let scope = if group.delimiter() == Delimiter::Brace {
                    if current.scope == Scope::File {
                        file_bodies += 1;
                        if file_bodies > 1 {
                            return Err(error(
                                group.span(),
                                "A policy contains one execute function.",
                            ));
                        }
                    } else if current.scope != Scope::Body || !current.expects_body {
                        return Err(error(
                            group.span(),
                            "Only the execute body and if/else bodies may contain code blocks.",
                        ));
                    }
                    current.expects_body = false;
                    current.pending_else = false;
                    current.after_if_body = current.scope == Scope::Body;
                    Scope::Body
                } else {
                    current.statement_start = false;
                    current.expects_operand = false;
                    Scope::Expression
                };
                stack.push(current);
                stack.push(frame(group.stream(), scope, depth));
            }
            TokenTree::Ident(ident) => {
                if current.scope != Scope::File
                    && (ident == "allowit" || ident == "jev" || ident == "paysh")
                {
                    let mut lookahead = current.iter.clone();
                    if matches!(lookahead.next(), Some(TokenTree::Punct(p)) if p.as_char() == ':' && p.spacing() == proc_macro2::Spacing::Joint)
                        && matches!(lookahead.next(), Some(TokenTree::Punct(p)) if p.as_char() == ':')
                    {
                        let Some(TokenTree::Ident(operation)) = lookahead.next() else {
                            return Err(error(
                                ident.span(),
                                "Use an exact registered policy function name.",
                            ));
                        };
                        let name = format!("{ident}::{operation}");
                        if crate::registry::canonical_function(&name).is_none()
                            || !matches!(lookahead.clone().next(), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis)
                        {
                            return Err(error(
                                ident.span(),
                                "Use an exact registered policy function call.",
                            ));
                        }
                        current.iter = lookahead;
                    }
                }

                if current.scope != Scope::File
                    && [
                        "as", "type", "fn", "impl", "dyn", "const", "static", "struct", "enum",
                        "union", "trait", "mod", "use", "extern", "while", "loop", "match",
                        "unsafe", "async", "move",
                    ]
                    .contains(&ident.to_string().as_str())
                {
                    return Err(error(
                        ident.span(),
                        "Type declarations, casts and custom items are not supported.",
                    ));
                }
                if current.scope == Scope::Expression
                    && ["if", "else", "return", "break", "yield", "match"]
                        .contains(&ident.to_string().as_str())
                {
                    return Err(error(
                        ident.span(),
                        "Control flow is supported only as a policy statement.",
                    ));
                }
                if current.scope == Scope::Body {
                    if ident == "let" {
                        if !current.statement_start {
                            return Err(error(
                                ident.span(),
                                "let is supported only at the start of a statement.",
                            ));
                        }
                        validate_let_header(&mut current.iter)?;
                    } else if ident == "for" {
                        if !current.statement_start {
                            return Err(error(
                                ident.span(),
                                "for is supported only as a bounded collection statement.",
                            ));
                        }
                        current.expects_body = true;
                        let Some(TokenTree::Ident(_)) = current.iter.next() else {
                            return Err(error(ident.span(), "Use for name in collection."));
                        };
                        if !matches!(current.iter.next(), Some(TokenTree::Ident(n)) if n=="in") {
                            return Err(error(ident.span(), "Use for name in collection."));
                        }
                    } else if ident == "if" {
                        if !current.statement_start && !current.pending_else {
                            return Err(error(
                                ident.span(),
                                "if is supported only at the start of a statement or after else.",
                            ));
                        }
                        current.expects_body = true;
                        current.pending_else = false;
                        if matches!(current.iter.clone().next(),Some(TokenTree::Ident(n)) if n=="let")
                        {
                            current.iter.next();
                            if !matches!(current.iter.next(),Some(TokenTree::Ident(n)) if n=="Some")
                                || !matches!(current.iter.next(),Some(TokenTree::Group(g)) if g.delimiter()==Delimiter::Parenthesis)
                                || !matches!(current.iter.next(),Some(TokenTree::Punct(p)) if p.as_char()=='=')
                            {
                                return Err(error(
                                    ident.span(),
                                    "Use if let Some(name) = optional_value.",
                                ));
                            }
                        }
                    } else if ident == "else" {
                        return Err(error(
                            ident.span(),
                            "else must immediately follow an if body.",
                        ));
                    } else if ident == "return" && !current.statement_start {
                        return Err(error(
                            ident.span(),
                            "return is supported only at the start of a statement.",
                        ));
                    }
                    current.statement_start = false;
                }
                current.expects_operand = ident == "if" || ident == "return" || ident == "let";
                stack.push(current);
            }
            TokenTree::Punct(p) => {
                if current.scope != Scope::File
                    && p.as_char() == '-'
                    && matches!(current.iter.clone().next(), Some(TokenTree::Punct(next)) if next.as_char() == '>')
                {
                    return Err(error(
                        p.span(),
                        "Function types and closures are not supported.",
                    ));
                }
                if current.scope != Scope::File
                    && p.as_char() == '|'
                    && (current.expects_operand
                        || p.spacing() != proc_macro2::Spacing::Joint
                        || !matches!(current.iter.next(), Some(TokenTree::Punct(next)) if next.as_char() == '|'))
                {
                    return Err(error(
                        p.span(),
                        "Use || between boolean expressions. Closures and bitwise operators are not supported.",
                    ));
                }
                if current.scope != Scope::File && p.as_char() == ':' {
                    return Err(error(
                        p.span(),
                        "Type syntax is supported only in the fixed signature and simple let annotations.",
                    ));
                }
                if current.scope != Scope::File && p.as_char() == '<' && current.expects_operand {
                    return Err(error(
                        p.span(),
                        "Qualified type expressions are not supported.",
                    ));
                }
                if p.as_char() == ';' {
                    if current.scope == Scope::Expression {
                        return Err(error(
                            p.span(),
                            "Semicolons are supported only between policy statements, not inside expressions.",
                        ));
                    }
                    current.expects_body = false;
                    current.pending_else = false;
                    current.statement_start = true;
                } else {
                    current.statement_start = false;
                }
                current.expects_operand = p.as_char() != '?';
                stack.push(current);
            }
            _ => {
                current.statement_start = false;
                current.expects_operand = false;
                stack.push(current);
            }
        }
    }
    Ok(())
}

// Consume only the simple let header, leaving its initializer to the expression validator.
// Other colons are rejected before syn, except exact registered function paths.
// Recursive types cannot enter through annotations, closures, casts or turbofish.
fn validate_let_header(iter: &mut proc_macro2::token_stream::IntoIter) -> Result<(), CompileError> {
    use proc_macro2::TokenTree;
    let invalid = || {
        CompileError::new(
            "INVALID_POLICY",
            "Use let name = value, optionally annotated with u64, bool, &str or ConfidenceInterval.",
        )
    };
    if !matches!(iter.next(), Some(TokenTree::Ident(_))) {
        return Err(invalid());
    }
    match iter.next() {
        Some(TokenTree::Punct(p)) if p.as_char() == '=' => return Ok(()),
        Some(TokenTree::Punct(p)) if p.as_char() == ':' => {}
        _ => return Err(invalid()),
    }
    match iter.next() {
        Some(TokenTree::Ident(ident))
            if ["u64", "bool", "ConfidenceInterval"].contains(&ident.to_string().as_str()) => {}
        Some(TokenTree::Punct(p)) if p.as_char() == '&' => {
            if !matches!(iter.next(), Some(TokenTree::Ident(ident)) if ident == "str") {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    if !matches!(iter.next(), Some(TokenTree::Punct(p)) if p.as_char() == '=') {
        return Err(invalid());
    }
    Ok(())
}

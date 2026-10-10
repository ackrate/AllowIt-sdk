#[cfg(feature = "compiler")]
use crate::{Context, Profile};
#[cfg(feature = "compiler")]
use alloc::format;
use alloc::string::{String, ToString};
use serde_json::{Value, json};

fn failure(code: &str, message: &str) -> Value {
    json!({"ok":false,"error":{"code":code,"message":message}})
}

/// JSON wire interface shared by the CLI, browser/Go WebAssembly host and native engine.
pub fn process_json(input: &str) -> String {
    if input.len() > 262144 {
        return failure("REQUEST_TOO_LARGE", "The request exceeds 256 KiB.").to_string();
    }
    match serde_json::from_str::<Value>(input) {
        Ok(request) => process_value(request).to_string(),
        Err(_) => failure("INVALID_JSON", "The request is not valid JSON.").to_string(),
    }
}
pub fn process_value(request: Value) -> Value {
    let Some(operation) = request.get("operation").and_then(Value::as_str) else {
        return failure("INVALID_REQUEST", "Specify an operation.");
    };
    let allowed: &[&str] = match operation {
        "registry" => &["operation"],
        "evaluate" => &["operation", "source", "profile", "context", "trace"],
        "edit_preference" => &["operation", "source", "settings"],
        "edit_score_thresholds" => &["operation", "source", "step_id", "values"],
        _ => &["operation", "source"],
    };
    if request
        .as_object()
        .is_none_or(|object| object.keys().any(|key| !allowed.contains(&key.as_str())))
    {
        return failure(
            "INVALID_REQUEST",
            "The request contains unsupported fields. Evaluation requires source, not supplied executable IR.",
        );
    }
    if operation == "registry" {
        return json!({"ok":true,"language":crate::LANGUAGE,"registry_version":crate::REGISTRY_VERSION,"functions":crate::registry(),"type_declarations":crate::typed_workflow::type_declarations()});
    }
    #[cfg(feature = "compiler")]
    {
        if ![
            "compile",
            "check",
            "workflow",
            "evaluate",
            "edit_preference",
            "edit_score_thresholds",
        ]
        .contains(&operation)
        {
            return failure(
                "INVALID_OPERATION",
                "Use compile, check, workflow, evaluate or registry.",
            );
        }
        let Some(source) = request.get("source").and_then(Value::as_str) else {
            return failure("INVALID_REQUEST", "Supply Rust policy source.");
        };
        let policy = match crate::compile(source) {
            Ok(policy) => policy,
            Err(error) => return json!({"ok":false,"error":error}),
        };
        if operation == "edit_preference" || operation == "edit_score_thresholds" {
            let edited = if operation == "edit_preference" {
                match request
                    .get("settings")
                    .cloned()
                    .and_then(|s| serde_json::from_value(s).ok())
                {
                    Some(settings) => crate::editing::edit_preference(source, &policy, settings),
                    None => return failure("INVALID_EDIT", "Supply preference settings."),
                }
            } else {
                let Some(step) = request.get("step_id").and_then(Value::as_str) else {
                    return failure("INVALID_EDIT", "Supply a step ID.");
                };
                let Some(values) = request
                    .get("values")
                    .cloned()
                    .and_then(|v| serde_json::from_value::<alloc::vec::Vec<u64>>(v).ok())
                else {
                    return failure("INVALID_EDIT", "Supply integer basis point values.");
                };
                crate::editing::edit_score_thresholds(source, &policy, step, &values)
            };
            return match edited {
                Ok(source) => match crate::compile(&source) {
                    Ok(policy) => json!({"ok":true,"source":source,"policy":policy}),
                    Err(error) => json!({"ok":false,"error":error}),
                },
                Err(error) => json!({"ok":false,"error":error}),
            };
        }
        if operation != "evaluate" {
            return json!({"ok":true,"policy":policy});
        }
        let profile: Profile = match request.get("profile").cloned() {
            Some(v) => match serde_json::from_value(v) {
                Ok(p) => p,
                Err(_) => return failure("INVALID_PROFILE", "Choose oracle or contract."),
            },
            None => return failure("INVALID_PROFILE", "Choose oracle or contract."),
        };
        let trace = match request.get("trace") {
            None | Some(Value::Bool(false)) => false,
            Some(Value::Bool(true)) if profile == Profile::Oracle => true,
            Some(Value::Bool(true)) => {
                return failure(
                    "INVALID_REQUEST",
                    "Workflow traces are available only in the oracle profile.",
                );
            }
            Some(_) => return failure("INVALID_REQUEST", "trace must be a boolean."),
        };
        if request
            .get("context")
            .and_then(|v| v.get("provider_call_input"))
            .is_some()
        {
            return failure(
                "INVALID_CONTEXT",
                "Request JSON cannot supply authenticated provider input. Use the trusted typed adapter.",
            );
        }
        if request
            .get("context")
            .and_then(|v| v.get("native_policy_storage"))
            .is_some()
        {
            return failure(
                "INVALID_CONTEXT",
                "Request JSON cannot supply native policy storage. Use the typed evaluator with verified adapter state.",
            );
        }
        let context: Context = match request.get("context").cloned() {
            Some(v) => match serde_json::from_value(v) {
                Ok(ctx) => ctx,
                Err(e) => {
                    return failure(
                        "INVALID_CONTEXT",
                        &format!("Invalid evaluation context: {e}"),
                    );
                }
            },
            None => return failure("INVALID_CONTEXT", "Supply an evaluation context."),
        };
        if trace {
            let (decision, trace) = crate::evaluate_with_trace(&policy, &context);
            let mut response = json!({"ok":true,"decision":decision,"source_hash":policy.source_hash,"ir_hash":policy.ir_hash});
            if let Some(trace) = trace {
                response["trace"] = json!(trace);
            }
            response
        } else {
            json!({"ok":true,"decision":crate::evaluate(&policy,profile,&context),"source_hash":policy.source_hash,"ir_hash":policy.ir_hash})
        }
    }
    #[cfg(not(feature = "compiler"))]
    {
        let _ = request;
        failure(
            "COMPILER_UNAVAILABLE",
            "The contract build evaluates authenticated IR; it does not parse source.",
        )
    }
}

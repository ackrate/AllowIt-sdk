use allowit_sdk::lsp::LanguageServer;
use serde_json::json;
#[test]
fn diagnostics_hover_completion_and_workflow_share_the_compiler() {
    let mut server = LanguageServer::default();
    let init = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}));
    assert_eq!(init[0]["result"]["capabilities"]["hoverProvider"], true);
    let source = "pub async fn evaluate(ctx: &Context) -> PolicyResult { set_cap(ctx, \"100\", \"USDC\")?; Ok(()) }";
    let open=server.handle(json!({"method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///policy.rs","text":source}}}));
    assert_eq!(open[0]["params"]["diagnostics"], json!([]));
    let hover=server.handle(json!({"id":2,"method":"textDocument/hover","params":{"textDocument":{"uri":"file:///policy.rs"},"position":{"line":0,"character":source.find("set_cap").unwrap()}}}));
    assert!(
        hover[0]["result"]["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("Total spending limit")
    );
    let completion = server.handle(json!({"id":3,"method":"textDocument/completion","params":{}}));
    assert_eq!(completion[0]["result"].as_array().unwrap().len(), 48);
    let workflow=server.handle(json!({"id":4,"method":"allowit/workflow","params":{"textDocument":{"uri":"file:///policy.rs"}}}));
    assert_eq!(
        workflow[0]["result"]["policy"]["workflow"][0]["name"],
        "set_cap"
    );
    let changed=server.handle(json!({"method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///policy.rs"},"contentChanges":[{"text":"bad source"}]}}));
    assert_eq!(
        changed[0]["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn diagnostic_columns_use_utf16_after_non_bmp_text() {
    let source = "pub async fn evaluate(ctx: &Context) -> PolicyResult { let message = \"😀\"; ctx.clone(); Ok(()) }";
    let mut server = LanguageServer::default();
    let result=server.handle(json!({"method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///unicode.rs","text":source}}}));
    assert_eq!(
        result[0]["params"]["diagnostics"][0]["range"]["start"]["character"],
        source[..source.find("ctx.clone").unwrap()]
            .encode_utf16()
            .count()
    );
}

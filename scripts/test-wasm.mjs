import assert from 'node:assert/strict';
import fs from 'node:fs';

const path = process.argv[2] ?? 'target/wasm32-unknown-unknown/release/allowit_sdk.wasm';
const module = await WebAssembly.compile(fs.readFileSync(path));
assert.deepEqual(WebAssembly.Module.imports(module), [], 'The compiler must not import host capabilities');
const { exports: api } = await WebAssembly.instantiate(module, {});
function invoke(value) {
  const input = new TextEncoder().encode(JSON.stringify(value));
  const pointer = api.alloc(input.length);
  new Uint8Array(api.memory.buffer, pointer, input.length).set(input);
  const packed = api.process(pointer, input.length);
  const resultPointer = Number(packed >> 32n);
  const resultLength = Number(packed & 0xffffffffn);
  try {
    return JSON.parse(new TextDecoder().decode(new Uint8Array(api.memory.buffer, resultPointer, resultLength)));
  } finally {
    api.dealloc(pointer, input.length);
    api.dealloc(resultPointer, resultLength);
  }
}

const source = fs.readFileSync('examples/approval.rs', 'utf8');
const context = JSON.parse(fs.readFileSync('examples/context.json', 'utf8'));
const compiled = invoke({ operation: 'compile', source });
assert.equal(compiled.ok, true);
assert.equal(compiled.policy.language, 'allowit-rust-v1');
assert.equal(compiled.policy.limit, '50');
for (const call of compiled.policy.calls) assert.equal(source.slice(call.start, call.end), call.name);
for (const block of compiled.policy.workflow) assert.equal(source.slice(block.start, block.end), block.source);
const awaiting = invoke({ operation: 'evaluate', source, profile: 'oracle', context });
assert.equal(awaiting.decision.outcome, 'awaiting_input');
context.answers[awaiting.decision.input_key] = true;
assert.equal(invoke({ operation: 'evaluate', source, profile: 'oracle', context }).decision.outcome, 'pass');
assert.equal(invoke({ operation: 'evaluate', source, profile: 'contract', context }).decision.code, 'USER_INPUT_REQUIRED');
assert.equal(invoke({ operation: 'compile', source: source.replace('Ok(())', 'panic!("no")') }).ok, false);
const registryResponse = invoke({ operation: 'registry' });
assert.equal(registryResponse.registry_version, '1.4.0');
const registry = registryResponse.functions;
assert.equal(registry.length, 48);
for (const name of ['allowit::set_cap', 'allowit::amount_at_most', 'jev::semantic', 'jev::check_preference']) {
  assert.ok(registry.some(entry => entry.name === name), `Missing registered namespace ${name}`);
}
const qualifiedSource = 'async fn _execute(ctx: &Context) -> PolicyResult { allowit::set_cap(ctx, "50", "USDC")?; jev::check_preference(ctx, "Research?", None, None).await?; Ok(()) }';
const qualified = invoke({ operation: 'compile', source: qualifiedSource });
assert.equal(qualified.ok, true);
assert.equal(qualified.policy.limit, '50');
assert.equal(qualified.policy.calls[0].name, 'set_cap');
assert.equal(qualifiedSource.slice(qualified.policy.calls[0].start, qualified.policy.calls[0].end), 'allowit::set_cap');
assert.equal(JSON.stringify(qualified.policy.ir).includes('allowit::'), false);
assert.equal(invoke({ operation: 'evaluate', source: qualifiedSource, profile: 'oracle', context }).decision.outcome, 'awaiting_input');
assert.equal(invoke({ operation: 'evaluate', source: qualifiedSource, profile: 'contract', context }).decision.code, 'USER_INPUT_REQUIRED');
assert.equal(invoke({ operation: 'compile', source: qualifiedSource.replace('allowit::set_cap', 'paysh::set_cap') }).ok, false);
assert.equal(invoke({ operation: 'compile', source: qualifiedSource.replace('jev::check_preference', 'other::check_preference') }).ok, false);
for (let i = 0; i < 100; i++) {
  assert.equal(invoke({ operation: 'compile', source }).policy.ir_hash, compiled.policy.ir_hash);
}
const greenSource = fs.readFileSync('examples/green-investments.rs', 'utf8');
const greenContext = JSON.parse(fs.readFileSync('examples/green-context.json', 'utf8'));
const assessment = invoke({ operation: 'evaluate', source: greenSource, profile: 'oracle', context: greenContext });
assert.equal(assessment.decision.code, 'SEMANTIC_EVIDENCE_REQUIRED');
assert.match(assessment.decision.evidence_key, /^[a-f0-9]{64}$/);
assert.equal(typeof assessment.decision.question, 'string');
greenContext.confidence[assessment.decision.evidence_key] = { lower_bps: 9000, upper_bps: 9000 };
const environmental = invoke({ operation: 'evaluate', source: greenSource, profile: 'oracle', context: greenContext });
assert.equal(environmental.decision.code, 'SEMANTIC_EVIDENCE_REQUIRED');
assert.notEqual(environmental.decision.evidence_key, assessment.decision.evidence_key);
greenContext.confidence[environmental.decision.evidence_key] = { lower_bps: 9000, upper_bps: 9000 };
assert.equal(invoke({ operation: 'evaluate', source: greenSource, profile: 'oracle', context: greenContext }).decision.outcome, 'pass');
greenContext.runtime_context.candidate_yield_bps = 399;
assert.equal(invoke({ operation: 'evaluate', source: greenSource, profile: 'oracle', context: greenContext }).decision.code, 'POLICY_REJECTED');

const longSource = `/*${'x'.repeat(29000)}*/\n${source}`;
for (let i = 0; i < 5; i++) assert.equal(invoke({ operation: 'compile', source: longSource }).ok, true);
const warmedMemory = api.memory.buffer.byteLength;
for (let i = 0; i < 500; i++) assert.equal(invoke({ operation: 'compile', source: longSource }).ok, true);
assert.ok(api.memory.buffer.byteLength <= warmedMemory + 2 * 1024 * 1024, 'Parser spans must not retain every document revision');
for (const body of [
  `let y = f${'()'.repeat(15000)}; Ok(())`,
  `let y = f${'({})'.repeat(7000)}; Ok(())`,
  `let y = x${'[0]'.repeat(10000)}; Ok(())`,
  `let y = ${'if true {} = '.repeat(1000)}1; Ok(())`,
  `let y = ${'if true {} + '.repeat(2000)}1; Ok(())`,
  `let y = x${' = [0;0]'.repeat(3500)}; Ok(())`,
  `let y = 1${' + [0;0]'.repeat(2000)}; Ok(())`,
  `let y = f${'([0;0])'.repeat(3500)}; Ok(())`,
  `let y = x${'.f([0;0])'.repeat(3500)}; Ok(())`,
  `let a = br"\\"; ${'if a {'.repeat(1000)}${'}'.repeat(1000)}// "\nOk(())`,
  `let a = cr"\\"; ${'if a {'.repeat(1000)}${'}'.repeat(1000)}// "\nOk(())`,
]) {
  assert.equal(invoke({ operation: 'compile', source: `pub async fn evaluate(ctx: &Context) -> PolicyResult { ${body} }` }).ok, false);
  assert.equal(invoke({ operation: 'compile', source }).ok, true, 'Rejected syntax must leave the instance usable');
}
const flatCalls = `${'cap_per_transaction(ctx,"10","USDC")?;'.repeat(200)}Ok(())`;
const globalLimit = invoke({ operation: 'compile', source: `pub async fn evaluate(ctx: &Context) -> PolicyResult { ${flatCalls} }` });
assert.equal(globalLimit.error.code, 'RESOURCE_LIMIT');
assert.match(globalLimit.error.message, /1,024/);
for (const depth of [1, 8, 16, 31]) {
  for (const clauses of [1, 8, 16]) {
    const condition = Array(clauses).fill('ctx.amount_units > 0').join(' && ');
    const body = `${`if ${condition} {`.repeat(depth)}${'}'.repeat(depth)}Ok(())`;
    invoke({ operation: 'compile', source: `pub async fn evaluate(ctx: &Context) -> PolicyResult { ${body} }` });
  }
}
assert.equal(invoke({ operation: 'compile', source }).ok, true);
const simple = 'pub async fn evaluate(ctx: &Context) -> PolicyResult { Ok(()) }';
for (const typeSource of [
  `pub async fn evaluate(ctx: ${'&'.repeat(90)}Context) -> PolicyResult { Ok(()) }`,
  `type T = ${'A<'.repeat(47)}u8${'>'.repeat(47)}; ${simple}`,
  `type T = ${'*const '.repeat(90)}u8; ${simple}`,
  `type T = ${'impl A<'.repeat(47)}u8${'>'.repeat(47)}; ${simple}`,
  `type T = ${'Box<dyn A<'.repeat(23)}u8${'>>'.repeat(23)}; ${simple}`,
  `type T = ${'fn() -> '.repeat(47)}u8; ${simple}`,
  `pub async fn evaluate(ctx: &Context) -> PolicyResult { let a: ${'&'.repeat(90)}u8 = 1; Ok(()) }`,
  `pub async fn evaluate(ctx: &Context) -> PolicyResult { let a = <${'A<'.repeat(47)}u8${'>'.repeat(48)}; Ok(()) }`,
  `pub async fn evaluate(ctx: &Context) -> PolicyResult { if || -> ${'&'.repeat(90)}u8 { 1 } { return fail("No"); } Ok(()) }`,
]) {
  assert.equal(invoke({ operation: 'compile', source: typeSource }).ok, false);
  assert.equal(invoke({ operation: 'compile', source }).ok, true);
}
console.log('WebAssembly ABI, no host imports, source spans, oracle/contract outcomes, semantic JSON, numeric limits, bounded parsing and stable memory checks passed.');

// Decimal helpers compile to the same contract-safe integer IR.
const readable = 'pub async fn evaluate(ctx: &Context) -> PolicyResult { if !amount_at_most(ctx, "5")? { return fail("Above limit"); } let amount = usdc("0.000001")?; let score = percent("85.25")?; let candidate = 400; let benchmark = 500; if !within_percentage_points(candidate, benchmark, "1")? { return fail("Return gap"); } Ok(()) }';
const readableCompiled = invoke({operation: 'compile', source: readable});
assert.equal(readableCompiled.ok, true);
assert.equal(readableCompiled.policy.calls.filter(c => ['amount_at_most', 'usdc', 'percent', 'within_percentage_points'].includes(c.name)).length, 4);
for (const c of readableCompiled.policy.calls) assert.equal(readable.slice(c.start, c.end), c.name);
for (const profile of ['oracle', 'contract']) {
 assert.equal(invoke({operation: 'evaluate', source: readable, profile, context}).decision.outcome, 'pass');
 assert.equal(invoke({operation: 'evaluate', source: readable, profile, context: {...context, amount_units: 5000001}}).decision.outcome, 'fail');
}
assert.equal(invoke({operation: 'compile', source: readable.replace('"0.000001"', '"0.0000001"')}).ok, false);

// Opt-in workflow evidence records execution, including caps hoisted past early returns.
const traceSource = 'pub async fn exec(ctx: &Context) -> PolicyResult { if ctx.amount_units > 0 { return Ok(()); } require_merchant(ctx,"unreached")?; set_cap(ctx,"10","USDC")?; Ok(()) }';
const traceContext = {...context, amount_units: 750000};
const traceRequest = {operation: 'evaluate', source: traceSource, profile: 'oracle', context: traceContext};
const untraced = invoke(traceRequest);
assert.equal(untraced.trace, undefined);
const traced = invoke({...traceRequest, trace: true});
assert.deepEqual(traced.decision, untraced.decision);
assert.equal(traced.trace.version, 1);
assert.equal(traced.trace.source_hash, traced.source_hash);
assert.equal(traced.trace.ir_hash, traced.ir_hash);
assert.equal(traced.trace.complete, true);
assert.deepEqual(traced.trace.steps.map(s => s.status), ['passed', 'skipped', 'passed', 'skipped']);
assert.deepEqual(traced.trace.steps.map(s => s.visited), [true, false, true, false]);
const traceWorkflow = invoke({operation: 'compile', source: traceSource}).policy.workflow;
assert.deepEqual(traced.trace.steps.map(s => s.node_id), traceWorkflow.map(s => s.id));
const pendingSource = 'pub async fn exec(ctx: &Context) -> PolicyResult { check_preference(ctx,"Primary 🌱 evidence?",0.40,0.85).await?; Ok(()) }';
const pendingTrace = invoke({...traceRequest, source: pendingSource, context: {...traceContext, original_intent: 'Buy original evidence'}, trace: true});
assert.equal(pendingTrace.decision.code, 'SEMANTIC_EVIDENCE_REQUIRED');
assert.equal(pendingTrace.trace.complete, false);
assert.deepEqual(pendingTrace.trace.steps.map(s => s.status), ['verifying', 'inactive']);
assert.equal(invoke({...traceRequest, profile: 'contract', trace: true}).error.code, 'INVALID_REQUEST');
assert.equal(invoke({...traceRequest, trace: 'true'}).error.code, 'INVALID_REQUEST');
console.log('Opt-in oracle workflow traces preserve actual execution, source bindings and contract isolation.');

const providerSource = fs.readFileSync('tests/fixtures/provider-call-policy.rs', 'utf8');
const providerCompiled = invoke({operation: 'compile', source: providerSource});
assert.equal(providerCompiled.ok, true);
assert.ok(providerCompiled.policy.calls.some(call => call.name === 'paysh::call'));
assert.ok(providerCompiled.policy.execution_requirements.features.includes('provider_call'));
const forgedProvider = invoke({operation: 'evaluate', source: providerSource, profile: 'oracle', context: {...context, provider_call_input: {service_id: 'air-quality', input_key: 'canonical-service-input', request_digest: 'a'.repeat(64)}}});
assert.equal(forgedProvider.error.code, 'INVALID_CONTEXT');
console.log('Registered provider source compiles; public Wasm evaluation rejects forged host input.');

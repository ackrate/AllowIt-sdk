//! Versioned, bounded binary transport for the SAME SDK Program. No evaluator or
//! policy semantics live here. Reject depth/node/length limits while decoding,
//! before recursion/allocation, then run the shared structural/type validator.
use crate::{Artifact, Error, MAX_CHAIN_ARTIFACT_BYTES, MAX_CHAIN_IR_DEPTH, MAX_CHAIN_IR_NODES};
use alloc::{boxed::Box, string::String, vec::Vec};
use allowit_sdk::{Expr, Program, SourceSpan, Statement};

const MAGIC: &[u8; 8] = b"ALITIR01";

pub fn encode(artifact: &Artifact) -> Result<Vec<u8>, Error> {
    crate::validate_chain_program(&artifact.ir)?;
    if serde_json::to_vec(artifact)
        .map_err(|_| Error::InvalidArtifact)?
        .len()
        > MAX_CHAIN_ARTIFACT_BYTES
    {
        return Err(Error::InvalidArtifact);
    }
    allowit_sdk::validate_program(&artifact.ir).map_err(|_| Error::InvalidArtifact)?;
    let mut out = Encoder(MAGIC.to_vec());
    for value in [
        &artifact.original_intent,
        &artifact.source_hash,
        &artifact.ir_hash,
        &artifact.registry_version,
        &artifact.core_version,
        &artifact.compiler_version,
        &artifact.ir.version,
    ] {
        out.string(value)?;
    }
    out.statements(&artifact.ir.statements)?;
    if artifact.original_intent.len() > 2048 || out.0.len() > MAX_CHAIN_ARTIFACT_BYTES {
        return Err(Error::InvalidArtifact);
    }
    Ok(out.0)
}

pub fn decode(bytes: &[u8]) -> Result<Artifact, Error> {
    if bytes.len() > MAX_CHAIN_ARTIFACT_BYTES || !bytes.starts_with(MAGIC) {
        return Err(Error::InvalidArtifact);
    }
    let mut input = Decoder {
        bytes: &bytes[MAGIC.len()..],
        nodes: 0,
    };
    let original_intent = input.string()?;
    if original_intent.len() > 2048 {
        return Err(Error::InvalidArtifact);
    }
    let source_hash = input.string()?;
    let ir_hash = input.string()?;
    let registry_version = input.string()?;
    let core_version = input.string()?;
    let compiler_version = input.string()?;
    let version = input.string()?;
    let statements = input.statements(1)?;
    if !input.bytes.is_empty() {
        return Err(Error::InvalidArtifact);
    }
    Ok(Artifact {
        original_intent,
        source_hash,
        ir_hash,
        registry_version,
        core_version,
        compiler_version,
        ir: Program {
            version,
            statements,
        },
    })
}

struct Encoder(Vec<u8>);
impl Encoder {
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    fn count(&mut self, value: usize) -> Result<(), Error> {
        let n = u16::try_from(value).map_err(|_| Error::InvalidArtifact)?;
        self.0.extend_from_slice(&n.to_le_bytes());
        Ok(())
    }
    fn string(&mut self, value: &str) -> Result<(), Error> {
        self.count(value.len())?;
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
    fn span(&mut self, value: &SourceSpan) -> Result<(), Error> {
        for n in [value.start, value.end] {
            self.0.extend_from_slice(
                &u32::try_from(n)
                    .map_err(|_| Error::InvalidArtifact)?
                    .to_le_bytes(),
            );
        }
        Ok(())
    }
    fn statements(&mut self, values: &[Statement]) -> Result<(), Error> {
        self.count(values.len())?;
        for value in values {
            self.statement(value)?;
        }
        Ok(())
    }
    // Reject host-only variants when SDK features unify in a native caller.
    #[allow(unreachable_patterns)]
    fn statement(&mut self, value: &Statement) -> Result<(), Error> {
        match value {
            Statement::Let {
                name,
                value,
                annotation,
                span,
            } => {
                self.byte(0);
                self.string(name)?;
                self.expr(value)?;
                self.byte(u8::from(annotation.is_some()));
                if let Some(a) = annotation {
                    self.string(a)?;
                }
                self.span(span)?;
            }
            Statement::Expression {
                value,
                semicolon,
                span,
            } => {
                self.byte(1);
                self.expr(value)?;
                self.byte(u8::from(*semicolon));
                self.span(span)?;
            }
            Statement::Return { value, span } => {
                self.byte(2);
                self.expr(value)?;
                self.span(span)?;
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
                span,
            } => {
                self.byte(3);
                self.expr(condition)?;
                self.statements(then_branch)?;
                self.statements(else_branch)?;
                self.span(span)?;
            }
            _ => return Err(Error::InvalidArtifact),
        }
        Ok(())
    }
    fn expressions(&mut self, values: &[Expr]) -> Result<(), Error> {
        self.count(values.len())?;
        for value in values {
            self.expr(value)?;
        }
        Ok(())
    }
    // Reject host-only variants when SDK features unify in a native caller.
    #[allow(unreachable_patterns)]
    fn expr(&mut self, value: &Expr) -> Result<(), Error> {
        match value {
            Expr::String { value } => {
                self.byte(0);
                self.string(value)?;
            }
            Expr::Integer { value } => {
                self.byte(1);
                self.0.extend_from_slice(&value.to_le_bytes());
            }
            Expr::Boolean { value } => {
                self.byte(2);
                self.byte(u8::from(*value));
            }
            Expr::Unit => self.byte(3),
            Expr::Variable { name } => {
                self.byte(4);
                self.string(name)?;
            }
            Expr::Field { object, name } => {
                self.byte(5);
                self.expr(object)?;
                self.string(name)?;
            }
            Expr::Array { values } => {
                self.byte(6);
                self.expressions(values)?;
            }
            Expr::Binary { op, left, right } => {
                self.byte(7);
                self.string(op)?;
                self.expr(left)?;
                self.expr(right)?;
            }
            Expr::Not { value } => {
                self.byte(8);
                self.expr(value)?;
            }
            Expr::Call { name, args, span } => {
                self.byte(9);
                self.string(name)?;
                self.expressions(args)?;
                self.span(span)?;
            }
            Expr::Try { value } => {
                self.byte(10);
                self.expr(value)?;
            }
            Expr::Await { value } => {
                self.byte(11);
                self.expr(value)?;
            }
            _ => return Err(Error::InvalidArtifact),
        }
        Ok(())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    nodes: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.bytes.len() {
            return Err(Error::InvalidArtifact);
        }
        let (value, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidArtifact),
        }
    }
    fn count(&mut self) -> Result<usize, Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| Error::InvalidArtifact)?,
        ) as usize)
    }
    fn string(&mut self) -> Result<String, Error> {
        let len = self.count()?;
        let text = core::str::from_utf8(self.take(len)?).map_err(|_| Error::InvalidArtifact)?;
        Ok(text.into())
    }
    fn span(&mut self) -> Result<SourceSpan, Error> {
        let start = u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| Error::InvalidArtifact)?,
        ) as usize;
        let end = u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| Error::InvalidArtifact)?,
        ) as usize;
        Ok(SourceSpan { start, end })
    }
    fn node(&mut self, depth: usize) -> Result<(), Error> {
        self.nodes += 1;
        if self.nodes > MAX_CHAIN_IR_NODES || depth > MAX_CHAIN_IR_DEPTH {
            Err(Error::InvalidArtifact)
        } else {
            Ok(())
        }
    }
    fn list_count(&mut self) -> Result<usize, Error> {
        let count = self.count()?;
        if count > MAX_CHAIN_IR_NODES - self.nodes || count > self.bytes.len() {
            return Err(Error::InvalidArtifact);
        }
        Ok(count)
    }
    fn statements(&mut self, depth: usize) -> Result<Vec<Statement>, Error> {
        let count = self.list_count()?;
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(self.statement(depth)?);
        }
        Ok(out)
    }
    fn statement(&mut self, depth: usize) -> Result<Statement, Error> {
        self.node(depth)?;
        Ok(match self.byte()? {
            0 => Statement::Let {
                name: self.string()?,
                value: self.expr(depth + 1)?,
                annotation: if self.boolean()? {
                    Some(self.string()?)
                } else {
                    None
                },
                span: self.span()?,
            },
            1 => Statement::Expression {
                value: self.expr(depth + 1)?,
                semicolon: self.boolean()?,
                span: self.span()?,
            },
            2 => Statement::Return {
                value: self.expr(depth + 1)?,
                span: self.span()?,
            },
            3 => Statement::If {
                condition: self.expr(depth + 1)?,
                then_branch: self.statements(depth + 1)?,
                else_branch: self.statements(depth + 1)?,
                span: self.span()?,
            },
            _ => return Err(Error::InvalidArtifact),
        })
    }
    fn expressions(&mut self, depth: usize) -> Result<Vec<Expr>, Error> {
        let count = self.list_count()?;
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(self.expr(depth)?);
        }
        Ok(out)
    }
    fn expr(&mut self, depth: usize) -> Result<Expr, Error> {
        self.node(depth)?;
        Ok(match self.byte()? {
            0 => Expr::String {
                value: self.string()?,
            },
            1 => Expr::Integer {
                value: u64::from_le_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| Error::InvalidArtifact)?,
                ),
            },
            2 => Expr::Boolean {
                value: self.boolean()?,
            },
            3 => Expr::Unit,
            4 => Expr::Variable {
                name: self.string()?,
            },
            5 => Expr::Field {
                object: Box::new(self.expr(depth + 1)?),
                name: self.string()?,
            },
            6 => Expr::Array {
                values: self.expressions(depth + 1)?,
            },
            7 => Expr::Binary {
                op: self.string()?,
                left: Box::new(self.expr(depth + 1)?),
                right: Box::new(self.expr(depth + 1)?),
            },
            8 => Expr::Not {
                value: Box::new(self.expr(depth + 1)?),
            },
            9 => Expr::Call {
                name: self.string()?,
                args: self.expressions(depth + 1)?,
                span: self.span()?,
            },
            10 => Expr::Try {
                value: Box::new(self.expr(depth + 1)?),
            },
            11 => Expr::Await {
                value: Box::new(self.expr(depth + 1)?),
            },
            _ => return Err(Error::InvalidArtifact),
        })
    }
}

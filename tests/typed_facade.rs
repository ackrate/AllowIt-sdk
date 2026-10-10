//! Compile the approved typed policy examples through rustc as well as the restricted compiler.
extern crate allowit_sdk as allowit;
#[allow(dead_code)]
mod execution {
    include!("fixtures/typed-execution-policy.rs");
}
#[allow(dead_code)]
mod payment {
    include!("fixtures/typed-payment-policy.rs");
}
#[allow(dead_code)]
mod unicode {
    include!("fixtures/typed-execution-unicode-policy.rs");
}

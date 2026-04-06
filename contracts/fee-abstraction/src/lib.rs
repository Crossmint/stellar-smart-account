#![no_std]
#![allow(clippy::too_many_arguments)]

mod fee_forwarder;

#[cfg(test)]
mod tests;

pub use fee_forwarder::FeeForwarder;

//! SIP message types, parsing, serialization, dialog helpers, and **experimental** transaction
//! scaffolding (`transaction` is not used by shipping binaries; see that module and `AGENTS.md`).

pub mod dialog;
pub mod overload;
pub mod parser;
pub mod serialize;
pub mod transaction;
pub mod types;

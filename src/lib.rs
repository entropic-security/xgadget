#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

// Macro Import --------------------------------------------------------------------------------------------------------

#[macro_use]
extern crate bitflags;

// Direct Exports ------------------------------------------------------------------------------------------------------

mod binary;
pub use crate::binary::*;

mod gadget;
pub use crate::gadget::*;

mod search;
pub use crate::search::*;

mod error;
pub use crate::error::Error;

// Module Exports ------------------------------------------------------------------------------------------------------

pub mod filters;
pub use crate::filters::*;

pub mod semantics;
pub use crate::semantics::*;

// Crate-internal ------------------------------------------------------------------------------------------------------

#[cfg(not(feature = "cli-bin"))]
mod fess;

#[cfg(feature = "cli-bin")]
pub mod fess;

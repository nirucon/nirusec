//! Shared NIRUSEC data, system probes and privileged-operation primitives.
//!
//! The GUI and the root helper both use this crate. Nothing in the probe layer
//! requires root; write operations live behind the small helper boundary.

pub mod access;
pub mod cache;
pub mod explain;
pub mod firewall;
pub mod model;
pub mod profiles;
pub mod stage;
pub mod system;
pub mod tx;
pub mod ufw;

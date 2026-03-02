//! Undo system: content-addressable snapshots with Merkle tree integrity
//!
//! Provides filesystem state capture, change detection, and atomic restoration.
//! Every snapshot computes a Merkle root that cryptographically commits to the
//! entire tracked filesystem state.

pub mod exclusion;
pub mod merkle;
pub mod object_store;
pub mod snapshot;
pub mod types;

pub use exclusion::{ExclusionConfig, ExclusionFilter};
pub use merkle::MerkleTree;
pub use object_store::ObjectStore;
pub use snapshot::{SnapshotManager, WalkBudget};
pub use types::*;

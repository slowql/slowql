pub mod scanning;
pub mod indexing;
pub mod joins;
pub mod aggregation;
pub mod locking;
pub mod execution;
pub mod cursors;
pub mod hints;
pub mod memory;
pub mod batching;
pub mod network;

use crate::rules::base::Rule;

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    rules.extend(scanning::rules());
    rules.extend(indexing::rules());
    rules.extend(joins::rules());
    rules.extend(aggregation::rules());
    rules.extend(locking::rules());
    rules.extend(execution::rules());
    rules.extend(cursors::rules());
    rules.extend(hints::rules());
    rules.extend(memory::rules());
    rules.extend(batching::rules());
    rules.extend(network::rules());
    rules
}

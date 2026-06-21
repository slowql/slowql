pub mod authentication;
pub mod authorization;
pub mod command;
pub mod configuration;
pub mod cryptography;
pub mod data_protection;
pub mod dos;
pub mod information;
pub mod injection;
pub mod logging;
pub mod session;

use crate::rules::base::Rule;

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    rules.extend(injection::rules());
    rules.extend(authentication::rules());
    rules.extend(authorization::rules());
    rules.extend(cryptography::rules());
    rules.extend(data_protection::rules());
    rules.extend(command::rules());
    rules.extend(configuration::rules());
    rules.extend(dos::rules());
    rules.extend(information::rules());
    rules.extend(logging::rules());
    rules.extend(session::rules());
    rules
}

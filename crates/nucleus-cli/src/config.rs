//! Configuration handling

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration file
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// Default permission profile
    #[serde(default)]
    pub default_profile: String,

    /// Budget settings
    #[serde(default)]
    pub budget: BudgetConfig,

    /// Authentication settings
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum cost per task in USD
    #[serde(default = "default_max_cost")]
    pub max_cost_usd: f64,

    /// Maximum input tokens
    #[serde(default = "default_input_tokens")]
    pub max_input_tokens: u64,

    /// Maximum output tokens
    #[serde(default = "default_output_tokens")]
    pub max_output_tokens: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_cost_usd: default_max_cost(),
            max_input_tokens: default_input_tokens(),
            max_output_tokens: default_output_tokens(),
        }
    }
}

fn default_max_cost() -> f64 {
    5.0
}
fn default_input_tokens() -> u64 {
    100_000
}
fn default_output_tokens() -> u64 {
    10_000
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Use macOS Keychain for Claude OAuth
    #[serde(default)]
    pub use_keychain: bool,
}

impl Config {
    /// Load config from a file path
    pub fn load(path: &str) -> Result<Self> {
        let expanded = shellexpand::tilde(path).to_string();
        let path = Path::new(&expanded);

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

/// Show current configuration
pub fn show(config_path: &str) -> Result<()> {
    let config = Config::load(config_path)?;

    println!("Nucleus Configuration");
    println!("=====================");
    println!();
    println!("Config file: {}", config_path);
    println!();
    println!("[budget]");
    println!("  max_cost_usd = {}", config.budget.max_cost_usd);
    println!("  max_input_tokens = {}", config.budget.max_input_tokens);
    println!("  max_output_tokens = {}", config.budget.max_output_tokens);
    println!();
    println!("[auth]");
    println!("  use_keychain = {}", config.auth.use_keychain);
    println!();
    println!(
        "Default profile: {}",
        if config.default_profile.is_empty() {
            "restrictive"
        } else {
            &config.default_profile
        }
    );

    Ok(())
}

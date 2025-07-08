use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Verbs {
    #[default]
    #[serde(rename = "*")]
    All,
    Create,
    Delete,
    Get,
    List,
    Proxy,
    Update,
    Watch,
    Patch,
    DeleteCollection,
}

impl Display for Verbs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verbs::Create => write!(f, "create"),
            Verbs::Update => write!(f, "update"),
            Verbs::Delete => write!(f, "delete"),
            Verbs::Get => write!(f, "get"),
            Verbs::List => write!(f, "list"),
            Verbs::Watch => write!(f, "watch"),
            Verbs::Proxy => write!(f, "proxy"),
            Verbs::All => write!(f, "*"),
            Verbs::Patch => write!(f, "patch"),
            Verbs::DeleteCollection => write!(f, "deletecollection"),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub(crate) struct Rule {
    pub namespace: Option<String>,
    #[serde(rename = "apiGroups")]
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<Verbs>,
}
// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(default)]
pub(crate) struct Settings {
    #[serde(rename = "blockRules")]
    pub block_rules: Vec<Rule>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        if self.block_rules.is_empty() {
            return Err("block_rules cannot be empty".to_string());
        }
        for rule in &self.block_rules {
            if let Err(e) = rule.validate() {
                return Err(format!("Invalid rule: {e}"));
            }
        }
        Ok(())
    }
}

impl Rule {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.api_groups.is_empty() || self.resources.is_empty() || self.verbs.is_empty() {
            return Err("Rule must specify apiGroups, resources, and verbs".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_missing_settings() {
        let settings = Settings {
            ..Default::default()
        };

        assert!(settings.validate().is_err());
    }

    #[test]
    fn validate_empty_settings() {
        let settings = Settings {
            block_rules: vec![Rule {
                namespace: None,
                api_groups: vec!["".to_owned()],
                resources: vec![],
                verbs: vec![],
            }],
        };

        assert!(settings.validate().is_err());
    }
}

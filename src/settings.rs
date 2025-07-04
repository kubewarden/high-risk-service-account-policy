use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub(crate) struct Rule {
    pub namespace: Option<String>,
    #[serde(rename = "apiGroups")]
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
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

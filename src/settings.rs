use std::fmt::Display;

use kubewarden::host_capabilities::kubernetes::ResourceAttributes;
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
#[serde(rename_all = "camelCase")]
pub(crate) struct Rule {
    pub namespace: Option<String>,
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<Verbs>,
}
// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct Settings {
    pub block_rules: Vec<Rule>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        if self.block_rules.is_empty() {
            return Err("block_rules cannot be empty".to_owned());
        }
        for rule in &self.block_rules {
            if let Err(e) = rule.validate() {
                return Err(format!("Invalid rule: {e}"));
            }
        }
        Ok(())
    }
}

impl From<&Rule> for Vec<ResourceAttributes> {
    fn from(rule: &Rule) -> Self {
        rule.api_groups
            .iter()
            .flat_map(|api_group| {
                rule.resources.iter().flat_map(|resource| {
                    rule.verbs.iter().map(|verb| ResourceAttributes {
                        namespace: rule.namespace.clone(),
                        verb: verb.to_string(),
                        group: Some(api_group.to_owned()),
                        resource: resource.to_owned(),
                        subresource: None,
                        name: None,
                        ..Default::default()
                    })
                })
            })
            .collect()
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
    use rstest::rstest;

    use kubewarden_policy_sdk::settings::Validatable;

    #[rstest]
    #[case(Settings { ..Default::default() }, false)]
    #[case(Settings {
            block_rules: vec![Rule {
                namespace: None,
                api_groups: vec!["".to_owned()],
                resources: vec![],
                verbs: vec![],
            }],
        }, false)]
    #[case(Settings {
            block_rules: vec![Rule {
                namespace: Some("default".to_owned()),
                api_groups: vec!["apps".to_owned()],
                resources: vec!["deployments".to_owned()],
                verbs: vec![Verbs::Create],
            }],
        }, true)]
    fn validate_missing_settings(#[case] settings: Settings, #[case] should_succeed: bool) {
        assert_eq!(settings.validate().is_ok(), should_succeed);
    }
}

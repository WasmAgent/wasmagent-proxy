//! PROV-DM-inspired causal graph types.
//! Maps AEP actions onto Activity/Entity/Agent triples for causal traversal.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvActivity {
    pub id: String,
    pub label: String,
    pub used: Vec<String>,
    pub generated: Vec<String>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvEntity {
    pub id: String,
    pub digest: Option<String>,
    pub generated_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvAgent {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProvGraph {
    pub activities: HashMap<String, ProvActivity>,
    pub entities: HashMap<String, ProvEntity>,
    pub agents: HashMap<String, ProvAgent>,
}

impl ProvGraph {
    pub fn ancestors(&self, entity_id: &str) -> Vec<String> {
        let mut visited = vec![];
        let mut queue = vec![entity_id.to_string()];
        while let Some(eid) = queue.pop() {
            if let Some(e) = self.entities.get(&eid) {
                if let Some(act_id) = &e.generated_by {
                    visited.push(act_id.clone());
                    if let Some(act) = self.activities.get(act_id) {
                        queue.extend(act.used.clone());
                    }
                }
            }
        }
        visited
    }
}

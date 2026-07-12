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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestors_returns_empty_for_unknown_entity() {
        let graph = ProvGraph::default();
        assert!(graph.ancestors("nonexistent-entity").is_empty());
    }

    #[test]
    fn ancestors_returns_empty_when_entity_has_no_generated_by() {
        let mut graph = ProvGraph::default();
        graph.entities.insert(
            "e1".into(),
            ProvEntity {
                id: "e1".into(),
                digest: None,
                generated_by: None,
            },
        );
        assert!(graph.ancestors("e1").is_empty());
    }

    #[test]
    fn ancestors_traces_single_activity() {
        let mut graph = ProvGraph::default();
        graph.entities.insert(
            "e1".into(),
            ProvEntity {
                id: "e1".into(),
                digest: None,
                generated_by: Some("a1".into()),
            },
        );
        graph.activities.insert(
            "a1".into(),
            ProvActivity {
                id: "a1".into(),
                label: "test-activity".into(),
                used: vec![],
                generated: vec!["e1".into()],
                timestamp_ms: 1000,
            },
        );
        let ancestors = graph.ancestors("e1");
        assert_eq!(ancestors, vec!["a1"]);
    }

    #[test]
    fn ancestors_traces_multi_hop_chain() {
        let mut graph = ProvGraph::default();

        // e1 --generated_by--> a1 --used--> e2 --generated_by--> a2
        graph.entities.insert(
            "e1".into(),
            ProvEntity {
                id: "e1".into(),
                digest: None,
                generated_by: Some("a1".into()),
            },
        );
        graph.activities.insert(
            "a1".into(),
            ProvActivity {
                id: "a1".into(),
                label: "first".into(),
                used: vec!["e2".into()],
                generated: vec!["e1".into()],
                timestamp_ms: 100,
            },
        );
        graph.entities.insert(
            "e2".into(),
            ProvEntity {
                id: "e2".into(),
                digest: None,
                generated_by: Some("a2".into()),
            },
        );
        graph.activities.insert(
            "a2".into(),
            ProvActivity {
                id: "a2".into(),
                label: "second".into(),
                used: vec![],
                generated: vec!["e2".into()],
                timestamp_ms: 200,
            },
        );

        let ancestors = graph.ancestors("e1");
        assert_eq!(ancestors, vec!["a1", "a2"]);
    }

    #[test]
    fn serde_roundtrip() {
        let mut graph = ProvGraph::default();
        graph.entities.insert(
            "e1".into(),
            ProvEntity {
                id: "e1".into(),
                digest: Some("sha256:abc".into()),
                generated_by: Some("a1".into()),
            },
        );
        graph.activities.insert(
            "a1".into(),
            ProvActivity {
                id: "a1".into(),
                label: "build".into(),
                used: vec![],
                generated: vec!["e1".into()],
                timestamp_ms: 42,
            },
        );
        let json = serde_json::to_string(&graph).unwrap();
        let restored: ProvGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(graph.activities.len(), restored.activities.len());
        assert_eq!(graph.entities.len(), restored.entities.len());
        assert_eq!(
            graph.entities.get("e1").unwrap().digest,
            restored.entities.get("e1").unwrap().digest
        );
    }
}

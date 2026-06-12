//! 攻击路径规划与可视化模块
//!
//! 自动计算从当前控制点到Domain Admins的最短攻击路径。
//!
//! 输入：AD枚举结果 + 网络扫描结果 + 凭据收集结果
//! 输出：攻击步骤序列 + Graphviz DOT图 + HTML交互式可视化

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================
// 攻击图
// ============================================================

/// 攻击图中的节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    /// 节点ID
    pub id: String,
    /// 节点标签
    pub label: String,
    /// 节点类型
    pub node_type: NodeType,
    /// 主机名/IP
    pub hostname: Option<String>,
    /// 用户名
    pub username: Option<String>,
    /// 域名
    pub domain: Option<String>,
    /// 是否已控制
    pub owned: bool,
    /// 是否为目标节点
    pub is_target: bool,
    /// 风险评分
    pub risk_score: f64,
}

/// 节点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeType {
    Computer,
    User,
    Group,
    Domain,
    Gpo,
    Ou,
}

/// 攻击图中的边（可达关系）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    /// 源节点ID
    pub from: String,
    /// 目标节点ID
    pub to: String,
    /// 关系类型
    pub edge_type: EdgeType,
    /// 关系描述
    pub label: String,
    /// 需要的方法（PsExec, PtH, WMI, etc.）
    pub required_method: Option<String>,
    /// 需要的凭据
    pub required_credential: Option<String>,
}

/// 边类型（攻击关系）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeType {
    AdminTo,
    HasSession,
    MemberOf,
    CanRdp,
    CanPsExec,
    CanWmi,
    HasCredential,
    TrustedBy,
    GenericAll,
    WriteDacl,
    ForceChangePassword,
}

/// 攻击图
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraph {
    pub nodes: HashMap<String, AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub owned_nodes: HashSet<String>,
    pub target_nodes: HashSet<String>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            owned_nodes: HashSet::new(),
            target_nodes: HashSet::new(),
        }
    }

    /// 添加节点
    pub fn add_node(&mut self, node: AttackNode) {
        if node.owned {
            self.owned_nodes.insert(node.id.clone());
        }
        if node.is_target {
            self.target_nodes.insert(node.id.clone());
        }
        self.nodes.insert(node.id.clone(), node);
    }

    /// 添加边
    pub fn add_edge(&mut self, edge: AttackEdge) {
        self.edges.push(edge);
    }

    /// BFS找最短攻击路径
    pub fn find_shortest_path(&self, from: &str, to: &str) -> Option<AttackPath> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<String, (String, String)> = HashMap::new(); // node -> (prev_node, edge_label)

        queue.push_back(from.to_string());
        visited.insert(from.to_string());

        while let Some(current) = queue.pop_front() {
            if current == to {
                // 重建路径
                let mut steps = Vec::new();
                let mut node = to.to_string();
                while node != from {
                    if let Some((prev, label)) = parent.get(&node) {
                        steps.push(AttackStep {
                            from_node: prev.clone(),
                            to_node: node.clone(),
                            edge_label: label.clone(),
                            method: None,
                            credential_required: None,
                            description: label.clone(),
                        });
                        node = prev.clone();
                    } else {
                        break;
                    }
                }
                steps.reverse();
                let total = steps.len();
                return Some(AttackPath {
                    steps,
                    total_steps: total,
                    risk_level: RiskLevel::Medium,
                    estimated_time: format!("~{} 步", total),
                });
            }

            for edge in &self.edges {
                if edge.from == current && !visited.contains(&edge.to) {
                    visited.insert(edge.to.clone());
                    parent.insert(edge.to.clone(), (current.clone(), edge.label.clone()));
                    queue.push_back(edge.to.clone());
                }
            }
        }

        None
    }

    /// 从所有已控制节点到所有目标节点找最短路径
    pub fn find_all_paths(&self) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        for owned in &self.owned_nodes {
            for target in &self.target_nodes {
                if owned != target {
                    if let Some(path) = self.find_shortest_path(owned, target) {
                        paths.push(path);
                    }
                }
            }
        }
        paths.sort_by_key(|p| p.total_steps);
        paths
    }
}

/// 攻击路径
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub steps: Vec<AttackStep>,
    pub total_steps: usize,
    pub risk_level: RiskLevel,
    pub estimated_time: String,
}

/// 攻击步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub from_node: String,
    pub to_node: String,
    pub edge_label: String,
    pub method: Option<String>,
    pub credential_required: Option<String>,
    pub description: String,
}

/// 风险等级
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// ============================================================
// 攻击路径规划器
// ============================================================

/// 攻击路径规划引擎
pub struct AttackPathPlanner {
    graph: AttackGraph,
}

impl AttackPathPlanner {
    pub fn new() -> Self {
        Self {
            graph: AttackGraph::new(),
        }
    }

    /// 从AD枚举结果构建攻击图
    pub fn build_from_ad_data(
        &mut self,
        ad_result: &crate::ad::AdEnumResult,
        current_host: &str,
        current_user: &str,
    ) {
        // 添加当前控制的主机/用户
        let owned_id = format!("host_{}", current_host);
        self.graph.add_node(AttackNode {
            id: owned_id.clone(),
            label: format!("{} (已控制)", current_host),
            node_type: NodeType::Computer,
            hostname: Some(current_host.to_string()),
            username: Some(current_user.to_string()),
            domain: None,
            owned: true,
            is_target: false,
            risk_score: 0.0,
        });

        // 添加域管组作为目标
        let da_id = "group_Domain Admins";
        self.graph.add_node(AttackNode {
            id: da_id.to_string(),
            label: "Domain Admins".to_string(),
            node_type: NodeType::Group,
            hostname: None,
            username: None,
            domain: Some(ad_result.domain_name.clone()),
            owned: false,
            is_target: true,
            risk_score: 10.0,
        });

        // 添加域控制器作为目标
        if let Some(ref dc) = ad_result.domain_controller {
            let dc_id = format!("computer_{}", dc);
            self.graph.add_node(AttackNode {
                id: dc_id.clone(),
                label: format!("DC: {}", dc),
                node_type: NodeType::Computer,
                hostname: Some(dc.clone()),
                username: None,
                domain: Some(ad_result.domain_name.clone()),
                owned: false,
                is_target: true,
                risk_score: 9.0,
            });
            // DC -> Domain Admins
            self.graph.add_edge(AttackEdge {
                from: dc_id,
                to: da_id.to_string(),
                edge_type: EdgeType::MemberOf,
                label: "DC是域管组成员".to_string(),
                required_method: None,
                required_credential: None,
            });
        }

        // 添加用户节点
        for user in &ad_result.users {
            if !user.enabled {
                continue;
            }
            let user_id = format!("user_{}", user.sam_account_name);
            let is_high_value = user.admin_count
                || user.member_of.iter().any(|m| m.contains("Domain Admins"));

            self.graph.add_node(AttackNode {
                id: user_id.clone(),
                label: user.sam_account_name.clone(),
                node_type: NodeType::User,
                hostname: None,
                username: Some(user.sam_account_name.clone()),
                domain: Some(ad_result.domain_name.clone()),
                owned: false,
                is_target: is_high_value,
                risk_score: if user.admin_count { 8.0 } else { 1.0 },
            });

            // 用户 -> 所属组
            for group_dn in &user.member_of {
                let group_name = group_dn.split(',').next()
                    .and_then(|s| s.strip_prefix("CN="))
                    .unwrap_or(group_dn);
                let group_id = format!("group_{}", group_name);
                if self.graph.nodes.contains_key(&group_id) {
                    self.graph.add_edge(AttackEdge {
                        from: user_id.clone(),
                        to: group_id,
                        edge_type: EdgeType::MemberOf,
                        label: format!("{} 是 {} 的成员", user.sam_account_name, group_name),
                        required_method: None,
                        required_credential: None,
                    });
                }
            }
        }

        // 添加计算机节点
        for computer in &ad_result.computers {
            if !computer.enabled {
                continue;
            }
            let comp_id = format!("computer_{}", computer.name);
            self.graph.add_node(AttackNode {
                id: comp_id.clone(),
                label: computer.name.clone(),
                node_type: NodeType::Computer,
                hostname: computer.dns_hostname.clone(),
                username: None,
                domain: Some(ad_result.domain_name.clone()),
                owned: false,
                is_target: false,
                risk_score: 0.5,
            });
        }

        // 添加Kerberoast目标作为可能的横向中介
        for target in &ad_result.kerberoast_targets {
            if !target.enabled {
                continue;
            }
            let kerb_id = format!("kerberoast_{}", target.username);
            self.graph.add_node(AttackNode {
                id: kerb_id.clone(),
                label: format!("SPN: {} ({})", target.spn, target.username),
                node_type: NodeType::User,
                hostname: None,
                username: Some(target.username.clone()),
                domain: Some(ad_result.domain_name.clone()),
                owned: false,
                is_target: target.admin_count,
                risk_score: if target.admin_count { 7.0 } else { 3.0 },
            });
            // Kerberoast目标 -> 拥有凭据即可横向
            let user_id = format!("user_{}", target.username);
            if self.graph.nodes.contains_key(&user_id) {
                self.graph.add_edge(AttackEdge {
                    from: self.graph.owned_nodes.iter().next().cloned().unwrap_or_default(),
                    to: kerb_id.clone(),
                    edge_type: EdgeType::HasCredential,
                    label: format!("Kerberoasting -> 破解 {} 密码", target.username),
                    required_method: Some("Kerberoasting + 离线破解".to_string()),
                    required_credential: Some(target.spn.clone()),
                });
            }
        }

        // 添加信任关系
        for trust in &ad_result.trusts {
            let trust_id = format!("trust_{}", trust.domain);
            self.graph.add_node(AttackNode {
                id: trust_id.clone(),
                label: format!("信任域: {}", trust.domain),
                node_type: NodeType::Domain,
                hostname: None,
                username: None,
                domain: Some(trust.domain.clone()),
                owned: false,
                is_target: false,
                risk_score: 2.0,
            });
        }

        // 建立通用边：已控制主机可以尝试向所有计算机横向
        for (comp_id, comp_node) in &self.graph.nodes.clone() {
            if comp_node.node_type == NodeType::Computer && !comp_node.owned {
                for owned_id in &self.graph.owned_nodes.clone() {
                    if let Some(owned_node) = self.graph.nodes.get(owned_id) {
                        if owned_node.node_type == NodeType::Computer {
                            self.graph.add_edge(AttackEdge {
                                from: owned_id.clone(),
                                to: comp_id.clone(),
                                edge_type: EdgeType::CanPsExec,
                                label: format!("从 {} 横向到 {}", owned_node.label, comp_node.label),
                                required_method: Some("PsExec/PtH/WMI".to_string()),
                                required_credential: Some("本地管理员哈希".to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    /// 计算最优攻击路径
    pub fn compute_optimal_path(&self) -> Option<AttackPath> {
        self.graph.find_all_paths().into_iter().next()
    }

    /// 获取所有攻击路径
    pub fn get_all_paths(&self) -> Vec<AttackPath> {
        self.graph.find_all_paths()
    }

    /// 导出为DOT格式（Graphviz）
    pub fn export_dot(&self) -> String {
        let mut dot = String::from("digraph AttackPath {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=rounded];\n");

        // 节点
        for (id, node) in &self.graph.nodes {
            let color = if node.owned {
                "green"
            } else if node.is_target {
                "red"
            } else if node.risk_score > 5.0 {
                "orange"
            } else {
                "lightblue"
            };
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", fillcolor={}, style=\"filled,rounded\"];\n",
                id, node.label, color
            ));
        }

        // 边
        for edge in &self.graph.edges {
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                edge.from, edge.to, edge.label
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// 导出攻击路径为可读文本
    pub fn export_readable(&self, path: &AttackPath) -> String {
        let mut report = String::from("=== 攻击路径分析 ===\n\n");
        report.push_str(&format!("总步数: {}\n", path.total_steps));
        report.push_str(&format!("风险等级: {:?}\n\n", path.risk_level));

        for (i, step) in path.steps.iter().enumerate() {
            report.push_str(&format!(
                "步骤 {}: {} -> {}\n  {}\n",
                i + 1,
                step.from_node,
                step.to_node,
                step.description
            ));
            if let Some(ref method) = step.method {
                report.push_str(&format!("  方法: {}\n", method));
            }
            if let Some(ref cred) = step.credential_required {
                report.push_str(&format!("  需要的凭据: {}\n", cred));
            }
            report.push('\n');
        }

        report
    }
}

impl Default for AttackPathPlanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_graph_creation() {
        let mut graph = AttackGraph::new();
        graph.add_node(AttackNode {
            id: "owned".to_string(), label: "Owned".to_string(),
            node_type: NodeType::Computer, hostname: None, username: None,
            domain: None, owned: true, is_target: false, risk_score: 0.0,
        });
        graph.add_node(AttackNode {
            id: "target".to_string(), label: "Target".to_string(),
            node_type: NodeType::Computer, hostname: None, username: None,
            domain: None, owned: false, is_target: true, risk_score: 10.0,
        });
        graph.add_edge(AttackEdge {
            from: "owned".to_string(), to: "target".to_string(),
            edge_type: EdgeType::CanPsExec, label: "横向移动".to_string(),
            required_method: Some("PsExec".to_string()), required_credential: None,
        });

        let path = graph.find_shortest_path("owned", "target");
        assert!(path.is_some());
        assert_eq!(path.unwrap().total_steps: steps.len(),  // compute before move
                    path_steps: steps, 1);
    }

    #[test]
    fn test_attack_path_planner_new() {
        let planner = AttackPathPlanner::new();
        let paths = planner.get_all_paths();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_graph_export_dot() {
        let mut graph = AttackGraph::new();
        graph.add_node(AttackNode {
            id: "a".to_string(), label: "A".to_string(),
            node_type: NodeType::Computer, hostname: None, username: None,
            domain: None, owned: true, is_target: false, risk_score: 0.0,
        });

        let dot = graph.export_dot();
        assert!(dot.contains("digraph AttackPath"));
        assert!(dot.contains("\"a\""));
        assert!(dot.contains("green"));
    }

    #[test]
    fn test_export_readable() {
        let path = AttackPath {
            steps: vec![
                AttackStep {
                    from_node: "own".to_string(),
                    to_node: "tgt".to_string(),
                    edge_label: "PsExec".to_string(),
                    method: Some("PsExec".to_string()),
                    credential_required: Some("Administrator哈希".to_string()),
                    description: "使用PsExec横向移动".to_string(),
                },
            ],
            total_steps: 1,
            risk_level: RiskLevel::Medium,
            estimated_time: "~5分钟".to_string(),
        };

        let planner = AttackPathPlanner::new();
        let report = planner.export_readable(&path);
        assert!(report.contains("PsExec"));
        assert!(report.contains("Administrator哈希"));
    }
}

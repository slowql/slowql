use crate::models::issue::{Issue, Severity};
use crate::models::query::Query;

pub struct ComplexityScorer {
    base_score: u32,
    pub threshold_optimal: u32,
    pub threshold_complex: u32,
}

impl ComplexityScorer {
    pub fn new() -> Self {
        ComplexityScorer {
            base_score: 10,
            threshold_optimal: 40,
            threshold_complex: 70,
        }
    }

    pub fn from_config(config: &crate::config::ComplexityConfig) -> Self {
        ComplexityScorer {
            base_score: 10,
            threshold_optimal: config.threshold_optimal,
            threshold_complex: config.threshold_complex,
        }
    }

    pub fn classify(&self, score: u32) -> &'static str {
        if score <= self.threshold_optimal {
            "optimal"
        } else if score <= self.threshold_complex {
            "complex"
        } else {
            "critical"
        }
    }

    pub fn calculate(&self, query: &Query, issues: &[Issue]) -> u32 {
        let mut score = self.base_score;

        // Structural complexity
        let upper = query.raw_upper();
        score += upper.matches("JOIN").count() as u32 * 10;
        score += upper.matches("(SELECT").count() as u32 * 15;
        score += upper.matches("COUNT(").count() as u32 * 5;
        score += upper.matches("SUM(").count() as u32 * 5;
        score += upper.matches("AVG(").count() as u32 * 5;

        // Issue complexity
        for issue in issues {
            score += match issue.severity {
                Severity::Critical => 25,
                Severity::High => 15,
                Severity::Medium => 10,
                Severity::Low => 5,
                Severity::Info => 2,
            };
        }

        score.min(100)
    }
}

impl Default for ComplexityScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ComplexityScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "optimal<={}, complex<={}, critical>{}",
            self.threshold_optimal, self.threshold_complex, self.threshold_complex
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Dimension, Location};

    fn make_query(sql: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            ..Default::default()
        }
    }

    #[test]
    fn simple_query_low_score() {
        let scorer = ComplexityScorer::new();
        let q = make_query("SELECT id FROM users WHERE id = 1");
        let score = scorer.calculate(&q, &[]);
        assert!(score < 20);
    }

    #[test]
    fn complex_query_high_score() {
        let scorer = ComplexityScorer::new();
        let q = make_query("SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id JOIN d ON c.id=d.id WHERE EXISTS (SELECT 1 FROM e) AND x IN (SELECT id FROM f)");
        let score = scorer.calculate(&q, &[]);
        assert!(score > 40);
    }

    #[test]
    fn issues_increase_score() {
        let scorer = ComplexityScorer::new();
        let q = make_query("SELECT 1");
        let issues = vec![
            Issue::new(
                "T-1",
                "test",
                Severity::Critical,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
            Issue::new(
                "T-2",
                "test",
                Severity::High,
                Dimension::Security,
                Location::new(1, 1),
                "x",
            ),
        ];
        let score = scorer.calculate(&q, &issues);
        assert!(score >= 50);
    }

    #[test]
    fn score_capped_at_100() {
        let scorer = ComplexityScorer::new();
        let q = make_query("SELECT * FROM a JOIN b ON 1=1 JOIN c ON 1=1 JOIN d ON 1=1 JOIN e ON 1=1 JOIN f ON 1=1 JOIN g ON 1=1 JOIN h ON 1=1 JOIN i ON 1=1 JOIN j ON 1=1");
        let score = scorer.calculate(&q, &[]);
        assert_eq!(score, 100);
    }

    #[test]
    fn classify_scores() {
        let scorer = ComplexityScorer::new();
        assert_eq!(scorer.classify(10), "optimal");
        assert_eq!(scorer.classify(40), "optimal");
        assert_eq!(scorer.classify(50), "complex");
        assert_eq!(scorer.classify(70), "complex");
        assert_eq!(scorer.classify(80), "critical");
    }

    #[test]
    fn from_config() {
        let config = crate::config::ComplexityConfig::default();
        let scorer = ComplexityScorer::from_config(&config);
        assert_eq!(scorer.threshold_optimal, 0);
    }

    #[test]
    fn display() {
        let scorer = ComplexityScorer::new();
        let s = format!("{}", scorer);
        assert!(s.contains("optimal"));
        assert!(s.contains("complex"));
        assert!(s.contains("critical"));
    }

    #[test]
    fn default_impl() {
        let scorer = ComplexityScorer::default();
        assert_eq!(scorer.threshold_optimal, 40);
    }
}

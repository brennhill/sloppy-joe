use std::sync::atomic::{AtomicUsize, Ordering};

/// Tracks registry errors across all checks. When the budget is exceeded
/// (>5 errors OR >10% failure rate), the scan should emit a blocking issue
/// and stop further registry-dependent checks.
pub struct ErrorBudget {
    errors: AtomicUsize,
    queries: AtomicUsize,
    hard_limit: usize,
    rate_threshold: f64,
}

impl ErrorBudget {
    pub fn new() -> Self {
        Self {
            errors: AtomicUsize::new(0),
            queries: AtomicUsize::new(0),
            hard_limit: 5,
            rate_threshold: 0.10,
        }
    }

    pub fn record_success(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn is_exceeded(&self) -> bool {
        let errors = self.errors.load(Ordering::Relaxed);
        let queries = self.queries.load(Ordering::Relaxed);
        if errors > self.hard_limit {
            return true;
        }
        if queries > 0 {
            let rate = errors as f64 / queries as f64;
            if rate > self.rate_threshold {
                return true;
            }
        }
        false
    }

    pub fn summary(&self) -> (usize, usize) {
        (
            self.errors.load(Ordering::Relaxed),
            self.queries.load(Ordering::Relaxed),
        )
    }
}

impl Default for ErrorBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_budget_not_exceeded() {
        let budget = ErrorBudget::new();
        assert!(!budget.is_exceeded());
        assert_eq!(budget.summary(), (0, 0));
    }

    #[test]
    fn success_only_not_exceeded() {
        let budget = ErrorBudget::new();
        for _ in 0..100 {
            budget.record_success();
        }
        assert!(!budget.is_exceeded());
        assert_eq!(budget.summary(), (0, 100));
    }

    #[test]
    fn exceeds_hard_limit() {
        let budget = ErrorBudget::new();
        for _ in 0..100 {
            budget.record_success();
        }
        for _ in 0..6 {
            budget.record_error();
        }
        assert!(budget.is_exceeded());
        assert_eq!(budget.summary(), (6, 106));
    }

    #[test]
    fn exceeds_rate_threshold() {
        let budget = ErrorBudget::new();
        // 2 errors out of 10 queries = 20% > 10%
        for _ in 0..8 {
            budget.record_success();
        }
        for _ in 0..2 {
            budget.record_error();
        }
        assert!(budget.is_exceeded());
    }

    #[test]
    fn below_rate_threshold() {
        let budget = ErrorBudget::new();
        // 1 error out of 100 queries = 1% < 10%
        for _ in 0..99 {
            budget.record_success();
        }
        budget.record_error();
        assert!(!budget.is_exceeded());
        assert_eq!(budget.summary(), (1, 100));
    }

    #[test]
    fn exactly_at_hard_limit_not_exceeded() {
        let budget = ErrorBudget::new();
        for _ in 0..95 {
            budget.record_success();
        }
        // 5 errors out of 100 = 5% < 10%, and 5 == hard_limit (not >)
        for _ in 0..5 {
            budget.record_error();
        }
        assert!(!budget.is_exceeded());
    }
}

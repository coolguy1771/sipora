//! Integration test: `SiporaError` is `#[non_exhaustive]`; matches need a wildcard arm.

use sipora_core::error::SiporaError;

#[test]
fn sipora_error_match_includes_fallback_arm() {
    let e = SiporaError::Internal("x".into());
    let s = match e {
        SiporaError::Config(x) => x,
        SiporaError::Transport(x) => x,
        SiporaError::Sip(x) => x,
        SiporaError::Auth(x) => x,
        SiporaError::Database(x) => x,
        SiporaError::Redis(x) => x,
        SiporaError::Internal(x) => x,
        _ => "future variant".to_string(),
    };
    assert_eq!(s, "x");
}

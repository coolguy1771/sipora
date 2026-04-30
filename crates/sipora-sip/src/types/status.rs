use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const TRYING: Self = Self(100);
    pub const RINGING: Self = Self(180);
    pub const SESSION_PROGRESS: Self = Self(183);
    pub const OK: Self = Self(200);
    pub const ACCEPTED: Self = Self(202);
    pub const MOVED_PERMANENTLY: Self = Self(301);
    pub const MOVED_TEMPORARILY: Self = Self(302);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    /// RFC 3903 / conditional requests.
    pub const PRECONDITION_FAILED: Self = Self(412);
    /// Payload too large (HTTP-derived use in SIP MESSAGE bodies).
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self(413);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const PROXY_AUTH_REQUIRED: Self = Self(407);
    pub const REQUEST_TIMEOUT: Self = Self(408);
    pub const SESSION_INTERVAL_TOO_SMALL: Self = Self(422);
    pub const INTERVAL_TOO_BRIEF: Self = Self(423);
    /// RFC 8224 §5 — Identity header absent when required.
    pub const USE_IDENTITY_HEADER: Self = Self(428);
    /// RFC 8224 §5 — info= URL unreachable or cert invalid.
    pub const BAD_IDENTITY_INFO: Self = Self(436);
    /// RFC 8224 §5 — credential algorithm or attestation level not acceptable.
    pub const UNSUPPORTED_CREDENTIAL: Self = Self(437);
    /// RFC 8224 §5 — PASSporT signature verification failed.
    pub const INVALID_IDENTITY_HEADER: Self = Self(438);
    pub const TEMPORARILY_UNAVAILABLE: Self = Self(480);
    pub const CALL_DOES_NOT_EXIST: Self = Self(481);
    pub const TOO_MANY_HOPS: Self = Self(483);
    pub const BUSY_HERE: Self = Self(486);
    pub const NOT_ACCEPTABLE_HERE: Self = Self(488);
    /// RFC 3265 / 6665 unknown Event package.
    pub const BAD_EVENT: Self = Self(489);
    pub const NOT_IMPLEMENTED: Self = Self(501);
    pub const SERVER_INTERNAL_ERROR: Self = Self(500);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    pub const SERVER_TIMEOUT: Self = Self(504);

    pub fn reason_phrase(self) -> &'static str {
        match self.0 {
            100 => "Trying",
            180 => "Ringing",
            183 => "Session Progress",
            200 => "OK",
            202 => "Accepted",
            301 => "Moved Permanently",
            302 => "Moved Temporarily",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            412 => "Precondition Failed",
            413 => "Request Entity Too Large",
            405 => "Method Not Allowed",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            422 => "Session Interval Too Small",
            423 => "Interval Too Brief",
            428 => "Use Identity Header",
            436 => "Bad Identity Info",
            437 => "Unsupported Credential",
            438 => "Invalid Identity Header",
            480 => "Temporarily Unavailable",
            481 => "Call/Transaction Does Not Exist",
            483 => "Too Many Hops",
            486 => "Busy Here",
            488 => "Not Acceptable Here",
            489 => "Bad Event",
            501 => "Not Implemented",
            500 => "Server Internal Error",
            503 => "Service Unavailable",
            504 => "Server Timeout",
            _ => "Unknown",
        }
    }

    pub fn class(self) -> u16 {
        self.0 / 100
    }

    pub fn is_provisional(self) -> bool {
        self.class() == 1
    }

    pub fn is_success(self) -> bool {
        self.class() == 2
    }

    pub fn is_redirect(self) -> bool {
        self.class() == 3
    }

    pub fn is_client_error(self) -> bool {
        self.class() == 4
    }

    pub fn is_server_error(self) -> bool {
        self.class() == 5
    }

    pub fn is_global_error(self) -> bool {
        self.class() == 6
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason_phrase())
    }
}

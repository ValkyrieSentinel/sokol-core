pub const MAX_KEYS: usize = 32;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    EmptyPayload,
    InvalidFraming,
    SyntaxErrorKey,
    UnterminatedKey,
    DuplicateKey,
    KeyCapacityExceeded,
    ExpectedColon,
    UnexpectedEndValue,
    UnterminatedStringValue,
    UnterminatedNestedBlock,
    ExpectedCommaOrEnd,
    InvalidIpFormat,
}

impl CanonicalError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyPayload => "Payload is empty",
            Self::InvalidFraming => {
                "Invalid object framing: must strictly start with '{' and end with '}'"
            }
            Self::SyntaxErrorKey => "Syntax error: expected string key in object",
            Self::UnterminatedKey => "Unterminated key string",
            Self::DuplicateKey => {
                "Consensus fault: duplicate key detected in strict object payload"
            }
            Self::KeyCapacityExceeded => "Exceeded maximum key capacity in strict validator buffer",
            Self::ExpectedColon => "Expected ':' separator after key",
            Self::UnexpectedEndValue => "Unexpected end of payload inside value field",
            Self::UnterminatedStringValue => "Unterminated string value",
            Self::UnterminatedNestedBlock => "Unterminated nested structure block",
            Self::ExpectedCommaOrEnd => "Expected ',' or end of object structure",
            Self::InvalidIpFormat => "Invalid IPv6 or IPv4 string format in payload",
        }
    }
}

impl From<CanonicalError> for &'static str {
    fn from(err: CanonicalError) -> Self {
        err.as_str()
    }
}

#[cfg(all(feature = "std", not(target_arch = "bpf")))]
impl std::error::Error for CanonicalError {}

impl core::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub struct CanonicalParser;

impl CanonicalParser {
    pub fn validate_strict_json_object(input: &str) -> Result<(), CanonicalError> {
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Err(CanonicalError::EmptyPayload);
        }

        let mut start = 0;
        while start < bytes.len() && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        let mut end = bytes.len();
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }

        if start >= end || bytes[start] != b'{' || bytes[end - 1] != b'}' {
            return Err(CanonicalError::InvalidFraming);
        }

        let inner = &bytes[start + 1..end - 1];
        Self::parse_and_check_keys(inner)
    }

    pub fn parse_ipv6_bytes(ip_str: &str) -> Result<[u8; 16], CanonicalError> {
        use core::net::Ipv6Addr;

        match ip_str.parse::<Ipv6Addr>() {
            Ok(addr) => Ok(addr.octets()),
            Err(_) => Err(CanonicalError::InvalidIpFormat),
        }
    }

    fn parse_and_check_keys(inner: &[u8]) -> Result<(), CanonicalError> {
        let mut keys: [Option<&[u8]>; MAX_KEYS] = [None; MAX_KEYS];
        let mut key_count = 0;

        let mut i = 0;
        let len = inner.len();

        while i < len {
            while i < len && inner[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= len {
                break;
            }

            if inner[i] != b'"' {
                return Err(CanonicalError::SyntaxErrorKey);
            }
            i += 1;
            let key_start = i;
            let mut escaped = false;
            while i < len {
                if escaped {
                    escaped = false;
                } else if inner[i] == b'\\' {
                    escaped = true;
                } else if inner[i] == b'"' {
                    break;
                }
                i += 1;
            }

            if i >= len || inner[i] != b'"' {
                return Err(CanonicalError::UnterminatedKey);
            }
            let key_bytes = &inner[key_start..i];
            i += 1;

            if keys[..key_count].iter().flatten().any(|&k| k == key_bytes) {
                return Err(CanonicalError::DuplicateKey);
            }

            if key_count >= keys.len() {
                return Err(CanonicalError::KeyCapacityExceeded);
            }
            keys[key_count] = Some(key_bytes);
            key_count += 1;

            while i < len && inner[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= len || inner[i] != b':' {
                return Err(CanonicalError::ExpectedColon);
            }
            i += 1;

            i = Self::skip_value(inner, i)?;

            while i < len && inner[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < len {
                if inner[i] == b',' {
                    i += 1;
                    let mut check_i = i;
                    while check_i < len && inner[check_i].is_ascii_whitespace() {
                        check_i += 1;
                    }
                    if check_i >= len {
                        return Err(CanonicalError::SyntaxErrorKey);
                    }
                } else {
                    return Err(CanonicalError::ExpectedCommaOrEnd);
                }
            }
        }

        Ok(())
    }

    fn skip_value(inner: &[u8], mut i: usize) -> Result<usize, CanonicalError> {
        let len = inner.len();
        while i < len && inner[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return Err(CanonicalError::UnexpectedEndValue);
        }

        let first = inner[i];
        if first == b'"' {
            i += 1;
            let mut escaped = false;
            while i < len {
                if escaped {
                    escaped = false;
                } else if inner[i] == b'\\' {
                    escaped = true;
                } else if inner[i] == b'"' {
                    break;
                }
                i += 1;
            }
            if i >= len || inner[i] != b'"' {
                return Err(CanonicalError::UnterminatedStringValue);
            }
            Ok(i + 1)
        } else if first == b'{' || first == b'[' {
            let open = first;
            let close = if first == b'{' { b'}' } else { b']' };
            let mut depth = 1;
            let mut in_string = false;
            let mut escaped = false;
            i += 1;
            while i < len && depth > 0 {
                let b = inner[i];
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if b == b'\\' {
                        escaped = true;
                    } else if b == b'"' {
                        in_string = false;
                    }
                } else {
                    if b == b'"' {
                        in_string = true;
                    } else if b == open {
                        depth += 1;
                    } else if b == close {
                        depth -= 1;
                    }
                }
                i += 1;
            }
            if depth > 0 {
                return Err(CanonicalError::UnterminatedNestedBlock);
            }
            Ok(i)
        } else {
            while i < len && inner[i] != b',' && inner[i] != b'}' && !inner[i].is_ascii_whitespace()
            {
                i += 1;
            }
            Ok(i)
        }
    }
}

use bytes::{Buf, Bytes};
use chrono::Utc;
use log::debug;
use prost::Message;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use whoami::username;

use crate::HadoopError as HdfsError;
use crate::proto::common::CredentialsProto;
use crate::proto::common::TokenProto;
use crate::security::gssapi::GssapiSession;

const HADOOP_USER_NAME: &str = "HADOOP_USER_NAME";
const HADOOP_PROXY_USER: &str = "HADOOP_PROXY_USER";
const HADOOP_TOKEN_FILE_LOCATION: &str = "HADOOP_TOKEN_FILE_LOCATION";
const TOKEN_STORAGE_MAGIC: &[u8] = "HDTS".as_bytes();

#[derive(Debug)]
#[allow(dead_code)]
struct TokenIdentifier {
    owner: String,
    renewer: String,
    real_user: String,
    issue_date: i64,
    max_date: i64,
    sequence_number: i32,
    master_key_id: i32,
}

impl TryFrom<Vec<u8>> for TokenIdentifier {
    type Error = HdfsError;

    /// Parses a Writable-encoded `AbstractDelegationTokenIdentifier`. Other token kinds, such as
    /// YARN's protobuf-encoded identifiers, return an error rather than panicking.
    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        let mut buf = Bytes::from(value);
        ensure_remaining(&buf, 1)?;
        let version = buf.get_u8();
        if version != 0 {
            return Err(HdfsError::InvalidArgument(format!(
                "unsupported delegation token identifier version {version}"
            )));
        }

        let owner = parse_vint_string(&mut buf)?;
        let renewer = parse_vint_string(&mut buf)?;
        let real_user = parse_vint_string(&mut buf)?;
        let issue_date = parse_vlong(&mut buf)?;
        let max_date = parse_vlong(&mut buf)?;
        let sequence_number = parse_vint(&mut buf)?;
        let master_key_id = parse_vint(&mut buf)?;

        Ok(TokenIdentifier {
            owner,
            renewer,
            real_user,
            issue_date,
            max_date,
            sequence_number,
            master_key_id,
        })
    }
}

/// A Hadoop security token: an opaque identifier and password issued by a service, plus the
/// token kind and the service it authenticates to.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub(crate) alias: String,
    pub(crate) identifier: Vec<u8>,
    pub(crate) password: Vec<u8>,
    pub(crate) kind: String,
    pub(crate) service: String,
}

impl Token {
    /// Creates a token from its parts.
    pub fn new(
        identifier: Vec<u8>,
        password: Vec<u8>,
        kind: impl Into<String>,
        service: impl Into<String>,
    ) -> Self {
        Self {
            alias: String::new(),
            identifier,
            password,
            kind: kind.into(),
            service: service.into(),
        }
    }

    /// The alias the token was stored under in a credentials file, if any.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The serialized token identifier.
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// The token password.
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    /// The token kind, such as `HDFS_DELEGATION_TOKEN` or `YARN_AM_RM_TOKEN`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The service the token authenticates to, usually `host:port`.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Replaces the service the token authenticates to.
    pub fn set_service(&mut self, service: impl Into<String>) {
        self.service = service.into();
    }

    /// Converts the token to its protobuf representation.
    pub fn to_proto(&self) -> TokenProto {
        TokenProto {
            identifier: self.identifier.clone(),
            password: self.password.clone(),
            kind: self.kind.clone(),
            service: self.service.clone(),
        }
    }

    /// Loads the tokens in the file named by `HADOOP_TOKEN_FILE_LOCATION`.
    ///
    /// Returns an empty list when the variable is unset or the file does not exist or cannot be
    /// parsed.
    pub fn from_token_file_env() -> Vec<Self> {
        match env::var(HADOOP_TOKEN_FILE_LOCATION).map(PathBuf::from) {
            Ok(path) if path.exists() => Self::read_token_file(&path).ok().unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Reads a Hadoop credentials file in either the Writable or the protobuf format.
    pub fn read_token_file(path: &Path) -> std::io::Result<Vec<Self>> {
        let mut content = Bytes::from(fs::read(path)?);

        ensure_remaining(&content, 5)?;
        let magic = content.copy_to_bytes(4);

        if magic != TOKEN_STORAGE_MAGIC {
            debug!("Invalid token in magic file");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid token in magic file",
            ));
        }

        let format = content.copy_to_bytes(1);

        if format[0] == 0 {
            Self::parse_writable(&mut content)
        } else if format[0] == 1 {
            Self::parse_protobuf(content)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown token format",
            ))
        }
    }

    fn parse_writable(reader: &mut impl Buf) -> io::Result<Vec<Token>> {
        let token_count = parse_length(reader)?;
        let mut tokens = Vec::<Token>::with_capacity(token_count.min(1024));

        for _ in 0..token_count {
            let alias = String::from_utf8(parse_bytes(reader)?)
                .map_err(|_| io::Error::other("Failed to parse token".to_string()))?;

            let identifier = parse_bytes(reader)?;

            let password = parse_bytes(reader)?;

            let kind = parse_vint_string(reader)?;
            let service = parse_vint_string(reader)?;

            tokens.push(Token {
                alias,
                identifier,
                password,
                kind,
                service,
            })
        }

        Ok(tokens)
    }

    fn parse_protobuf(reader: impl Buf) -> io::Result<Vec<Token>> {
        let storage = CredentialsProto::decode_length_delimited(reader)?;

        let tokens: Vec<Token> = storage
            .tokens
            .into_iter()
            .flat_map(|mut credential| {
                credential.token.take().into_iter().map(move |token| Token {
                    alias: credential.alias.clone(),
                    identifier: token.identifier,
                    password: token.password,
                    kind: token.kind,
                    service: token.service,
                })
            })
            .collect();

        Ok(tokens)
    }
}

impl From<TokenProto> for Token {
    fn from(value: TokenProto) -> Self {
        Self {
            alias: String::new(),
            identifier: value.identifier,
            password: value.password,
            kind: value.kind,
            service: value.service,
        }
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("alias", &self.alias)
            .field("kind", &self.kind)
            .field("service", &self.service)
            .field("identifier_len", &self.identifier.len())
            .field("password", &"[REDACTED]")
            .finish()
    }
}

fn ensure_remaining(reader: &impl Buf, length: usize) -> io::Result<()> {
    if reader.remaining() < length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated Hadoop Writable data",
        ));
    }
    Ok(())
}

/// Parse a non-negative vlong length.
fn parse_length(reader: &mut impl Buf) -> io::Result<usize> {
    let length = parse_vlong(reader)?;
    usize::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid length {length} in Hadoop Writable data"),
        )
    })
}

/// Parse a byte array prefixed with its length as a vlong.
fn parse_bytes(reader: &mut impl Buf) -> io::Result<Vec<u8>> {
    let length = parse_length(reader)?;
    ensure_remaining(reader, length)?;
    Ok(reader.copy_to_bytes(length).to_vec())
}

/// Adapted from WritableUtils class in Hadoop
fn parse_vlong(reader: &mut impl Buf) -> io::Result<i64> {
    ensure_remaining(reader, 1)?;
    let first_byte = reader.get_i8();

    let length = if first_byte >= -112 {
        1
    } else if first_byte < -120 {
        -119 - first_byte
    } else {
        -111 - first_byte
    };

    if length == 1 {
        return Ok(first_byte as i64);
    }

    ensure_remaining(reader, (length - 1) as usize)?;
    let mut i = 0i64;
    for _ in 0..length - 1 {
        let b = reader.get_u8();
        i <<= 8;
        i |= b as i64;
    }

    let is_negative = first_byte < -120 || (-112..0).contains(&first_byte);

    Ok(if is_negative { i ^ -1 } else { i })
}

fn parse_vint(reader: &mut impl Buf) -> io::Result<i32> {
    // Same method as a long, but it should just be in the int range
    let n = parse_vlong(reader)?;
    i32::try_from(n).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("vint {n} out of range in Hadoop Writable data"),
        )
    })
}

fn parse_string(reader: &mut impl Buf, length: i32) -> io::Result<String> {
    let length = usize::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid string length {length} in Hadoop Writable data"),
        )
    })?;
    ensure_remaining(reader, length)?;
    String::from_utf8(reader.copy_to_bytes(length).to_vec())
        .map_err(|_| io::Error::other("Failed to parse string from writable".to_string()))
}

/// Parse a string prefixed with the length as an int
#[allow(dead_code)]
fn parse_int_string(reader: &mut impl Buf) -> io::Result<Option<String>> {
    ensure_remaining(reader, 4)?;
    let length = reader.get_i32();
    let value = if length == -1 {
        None
    } else {
        Some(parse_string(reader, length)?)
    };
    Ok(value)
}

/// Parse a string prefixed with the length as a vint
fn parse_vint_string(reader: &mut impl Buf) -> io::Result<String> {
    let length = parse_vint(reader)?;
    parse_string(reader, length)
}

#[derive(Debug)]
pub struct UserInfo {
    pub real_user: Option<String>,
    pub effective_user: Option<String>,
}

#[derive(Debug)]
pub struct User {
    #[allow(dead_code)]
    tokens: Vec<Token>,
}

impl User {
    pub(crate) fn get() -> Self {
        let tokens = Token::from_token_file_env();
        User { tokens }
    }

    pub(crate) fn get_token(&self, kind: &str, service: &str) -> Option<&Token> {
        self.tokens
            .iter()
            .filter(|t| t.kind == kind && t.service == service)
            .find(|t| {
                // Ignore any delegation tokens that are set to expire in the next 60 seconds.
                // Other token kinds don't use the delegation identifier format, so there is no
                // expiry to check.
                match TokenIdentifier::try_from(t.identifier.clone()) {
                    Ok(token_identifier) => {
                        debug!("Token Identifier: {:?}", token_identifier);
                        token_identifier.max_date > Utc::now().timestamp_millis() + 60000
                    }
                    Err(error) => {
                        debug!("Not checking expiry of {} token: {error}", t.kind);
                        true
                    }
                }
            })
    }

    pub fn get_user_info_from_principal(
        principal: &str,
        effective_user: Option<String>,
    ) -> UserInfo {
        UserInfo {
            real_user: Some(User::get_user_from_principal(principal)),
            effective_user: effective_user.or_else(|| env::var(HADOOP_PROXY_USER).ok()),
        }
    }

    pub(crate) fn get_simple_user(effective_user: Option<String>) -> UserInfo {
        UserInfo {
            real_user: None,
            effective_user: Some(
                effective_user
                    .or_else(|| env::var(HADOOP_USER_NAME).ok())
                    .unwrap_or_else(|| username().unwrap_or_else(|_| "unknown".to_string())),
            ),
        }
    }

    pub fn get_user_info(effective_user: Option<String>, security_enabled: bool) -> UserInfo {
        if security_enabled && let Ok(principal) = GssapiSession::get_default_principal() {
            let user_info = User::get_user_info_from_principal(&principal, effective_user);
            return user_info;
        }

        User::get_simple_user(effective_user)
    }

    fn get_user_from_principal(principal: &str) -> String {
        // If there's a /, take the part before it.
        if let Some(index) = principal.find('/') {
            principal[0..index].to_string()
        } else if let Some(index) = principal.find('@') {
            principal[0..index].to_string()
        } else {
            principal.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_get_user_info_uses_provided_effective_user_for_simple_auth() {
        let user_info = User::get_user_info(Some("alice".to_string()), false);

        assert_eq!(user_info.real_user, None);
        assert_eq!(user_info.effective_user.as_deref(), Some("alice"));
    }

    #[test]
    fn test_load_writable_token() {
        use base64::{Engine as _, engine::general_purpose};
        let b64_token = "SERUUwABDjEyNy4wLjAuMTo5MDAwLgAaaGRmcy9sb2NhbGhvc3RARVhBTVBMRS5DT00AAIoBiX/hghSKAYmj7gYUAQIUadF4ni3ObKqU8niv40WBFsGhFm4VSERGU19ERUxFR0FUSU9OX1RPS0VODjEyNy4wLjAuMTo5MDAwAA==";
        let mut token_file = NamedTempFile::new().unwrap();
        token_file
            .write_all(
                general_purpose::STANDARD
                    .decode(b64_token)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        token_file.flush().unwrap();

        let tokens = Token::read_token_file(token_file.path()).unwrap();

        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, "HDFS_DELEGATION_TOKEN");
        assert_eq!(tokens[0].service, "127.0.0.1:9000");

        let token_identifier: TokenIdentifier = tokens[0].identifier.clone().try_into().unwrap();
        assert_eq!(token_identifier.max_date, 1690672432660)
    }

    #[test]
    fn test_load_protobuf_token() {
        use base64::{Engine as _, engine::general_purpose};
        let b64_token = "SERUUwGBAQp/Cg5sb2NhbGhvc3Q6OTAwMBJtCi4AGmhkZnMvbG9jYWxob3N0QEVYQU1QTEUuQ09NAACKAYiiTtt9igGIxltffQECEhQoROcYNFMxMuoK9UHlAna6ZmhQSBoVSERGU19ERUxFR0FUSU9OX1RPS0VOIg4xMjcuMC4wLjE6OTAwMA==";
        let mut token_file = NamedTempFile::new().unwrap();
        token_file
            .write_all(
                general_purpose::STANDARD
                    .decode(b64_token)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        token_file.flush().unwrap();

        let tokens = Token::read_token_file(token_file.path()).unwrap();

        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, "HDFS_DELEGATION_TOKEN");
        assert_eq!(tokens[0].service, "127.0.0.1:9000");

        let token_identifier: TokenIdentifier = tokens[0].identifier.clone().try_into().unwrap();
        assert_eq!(token_identifier.max_date, 1686955057021)
    }

    #[test]
    fn test_truncated_token_files_return_errors() {
        let mut token_file = NamedTempFile::new().unwrap();
        // Writable format claiming one token, then ending.
        token_file.write_all(b"HDTS\x00\x01").unwrap();
        token_file.flush().unwrap();
        assert!(Token::read_token_file(token_file.path()).is_err());

        let mut token_file = NamedTempFile::new().unwrap();
        token_file.write_all(b"HD").unwrap();
        token_file.flush().unwrap();
        assert!(Token::read_token_file(token_file.path()).is_err());
    }

    #[test]
    fn test_non_delegation_identifiers_are_rejected_without_panicking() {
        // A protobuf-encoded identifier, as YARN uses for AMRM and NM tokens.
        let identifier = vec![0x0a, 0x04, 0x08, 0x01, 0x10, 0x02];
        assert!(TokenIdentifier::try_from(identifier).is_err());
        assert!(TokenIdentifier::try_from(Vec::new()).is_err());
    }

    #[test]
    fn test_get_token_accepts_tokens_without_delegation_identifiers() {
        let user = User {
            tokens: vec![Token::new(
                vec![0x0a, 0x04, 0x08, 0x01, 0x10, 0x02],
                b"password".to_vec(),
                "YARN_AM_RM_TOKEN",
                "127.0.0.1:8030",
            )],
        };

        let token = user
            .get_token("YARN_AM_RM_TOKEN", "127.0.0.1:8030")
            .unwrap();
        assert_eq!(token.kind(), "YARN_AM_RM_TOKEN");
        assert!(user.get_token("YARN_AM_RM_TOKEN", "other:8030").is_none());
    }

    #[test]
    fn test_token_debug_redacts_password() {
        let token = Token::new(b"id".to_vec(), b"secret-password".to_vec(), "KIND", "svc");
        let debug = format!("{token:?}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(debug.contains("KIND"));
    }

    #[test]
    fn test_token_proto_round_trip() {
        let token = Token::new(b"id".to_vec(), b"pw".to_vec(), "KIND", "svc");
        assert_eq!(Token::from(token.to_proto()), token);
    }
}

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use clap::Parser;
use hmac::{Hmac, Mac};
use sha3::Sha3_512;
use std::collections::HashSet;
use thiserror::Error;
use zeroize::Zeroizing;

// Alias for HMAC-SHA3-512 for easier usage
type HmacSha512 = Hmac<Sha3_512>;

// Argon2 configuration constants
const ARGON2_MEMORY_COST: u32 = 512_000; // 512 MiB for better security
const ARGON2_TIME_COST: u32 = 4; // Iterations count for the Argon2 algorithm
const ARGON2_PARALLELISM: u32 = 1; // Multi-threaded processing
const ARGON2_VERSION: Version = Version::V0x13; // Argon2 algorithm version

// Other security-related constants
const MIN_PASSWORD_LENGTH: usize = 20; // Minimum required password length
const MAX_REHASH_ITERATIONS: usize = 5; // Maximum allowed re-hashing attempts
const MIN_MASTER_KEY_LENGTH: usize = 32; // Minimum required length for the master key
const MIN_ENTROPY_THRESHOLD: usize = 16; // Minimum entropy threshold for password generation

/// Minimum entropy threshold for a valid BIP-39 mnemonic
const MIN_ENTROPY_BITS: usize = 256; // 128 bits of entropy for 12 words, 160 bits for 15 words, 192 bits for 18 words, 224 bits for 21 words, 256 bits for 24 words

// Allowed characters for password generation
const ALLOWED_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*_-+=`|\\(){}[]:;\"'<>,.?/";

// Command-line argument structure
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    master_key: String, // The master key used to derive passwords

    #[arg(short, long)]
    service: String, // The name of the service for which the password is generated

    #[arg(short, long)]
    pepper: Option<String>, // An optional pepper value for added security

    #[arg(short, long)]
    context: Option<String>, // Optional additional context for more uniqueness

    #[arg(long, default_value_t = false)]
    allow_master_key_no_bip39: bool, // Flag to allow using non-BIP-39 keys

    #[arg(short, long, default_value_t = 64)]
    length: usize, // Desired length of the generated password
}

// Custom error types to handle possible failures
#[derive(Debug, Error)]
enum CryptoError {
    #[error("HMAC initialization failed")]
    Hmac,
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("Insufficient entropy: {0}")]
    Entropy(String),
    #[error("Mnemonic error: {0}")]
    Mnemonic(String),
}

// Normalize the service name by converting to lowercase and trimming spaces
fn normalize_service(service: &str) -> String {
    service.trim().to_lowercase()
}

/// Validates a BIP-39 mnemonic phrase
fn validate_bip39_phrase(phrase: String) -> Result<(), CryptoError> {
    // Validate BIP-39 structure (checksum, format)
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase)
        .map_err(|e| CryptoError::Mnemonic(e.to_string()))?;

    // Calculate actual entropy (according to the standard)
    let entropy_bits = mnemonic.to_entropy().len() * 8;

    // Validate the minimum configurable entropy
    if entropy_bits < MIN_ENTROPY_BITS {
        return Err(CryptoError::Mnemonic(format!(
            "Insufficient entropy: {} bits (minimum required: {}).",
            entropy_bits, MIN_ENTROPY_BITS
        )));
    }

    // Validate unique words (additional requirement)
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let unique_words = words.iter().collect::<HashSet<_>>().len();
    if unique_words != words.len() {
        return Err(CryptoError::Mnemonic(
            "The mnemonic contains repeated words.".into(),
        ));
    }

    Ok(())
}

/// Normalizes and validates the master key, supporting both BIP-39 mnemonics and custom keys
fn normalize_and_validate_master_key(
    master_key: &mut String,
    allow_master_key_no_bip39: bool,
) -> Result<(), CryptoError> {
    if allow_master_key_no_bip39 {
        if master_key.len() < MIN_MASTER_KEY_LENGTH {
            return Err(CryptoError::Entropy(format!(
                "Custom master key is too short ({} characters). Minimum required: {}.",
                master_key.len(),
                MIN_MASTER_KEY_LENGTH
            )));
        }
    } else {
        // Normalize spaces and update the master key with formatted value
        let formatted_key = master_key.split_whitespace().collect::<Vec<_>>().join(" ");
        *master_key = formatted_key.clone();

        // Validate BIP-39 mnemonic phrase
        validate_bip39_phrase(master_key.to_string())?;
    }

    Ok(())
}

// Generate a deterministic salt using HMAC-SHA3-512 with an optional pepper
fn generate_deterministic_salt(
    pepper: Option<&[u8]>,
    service: &str,
) -> Result<Vec<u8>, CryptoError> {
    let mut mac =
        HmacSha512::new_from_slice(pepper.unwrap_or(b"")).map_err(|_| CryptoError::Hmac)?;
    mac.update(service.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

// Calculate entropy by counting unique byte values
fn calculate_entropy(data: &[u8]) -> usize {
    data.iter().copied().collect::<HashSet<u8>>().len()
}

// Map bytes produced by Argon2 to allowed characters for the final password
fn map_bytes_to_chars(
    bytes: &[u8],
    length: usize,
    argon2: &Argon2<'_>,
    salt: &[u8],
) -> Result<Zeroizing<String>, CryptoError> {
    let allowed_len = ALLOWED_CHARS.len();
    let rejection_threshold = (256 / allowed_len) * allowed_len;
    let mut password = Zeroizing::new(String::with_capacity(length));
    let mut current_bytes = bytes.to_vec();
    let mut iterations = 0;

    // Determine the minimum entropy threshold (dynamic)
    let min_entropy = (length / 2).max(MIN_ENTROPY_THRESHOLD);

    while password.len() < length && iterations < MAX_REHASH_ITERATIONS {
        let entropy = calculate_entropy(&current_bytes);
        if entropy < min_entropy {
            return Err(CryptoError::Entropy(format!(
                "Insufficient entropy detected: {} unique bytes found, {} required.",
                entropy, min_entropy
            )));
        }

        for &byte in &current_bytes {
            if byte < rejection_threshold as u8 {
                password.push(ALLOWED_CHARS[(byte as usize) % allowed_len] as char);
                if password.len() == length {
                    return Ok(password);
                }
            }
        }

        // Re-hash if the password length is insufficient
        let mut new_bytes = vec![0u8; length];
        argon2
            .hash_password_into(&current_bytes, salt, &mut new_bytes)
            .map_err(|e| CryptoError::Argon2(e.to_string()))?;
        current_bytes = new_bytes;
        iterations += 1;
    }

    if password.len() < length {
        return Err(CryptoError::Entropy(format!(
            "Failed to generate a password of sufficient length ({} characters generated, {} required).",
            password.len(),
            length
        )));
    }

    Ok(password)
}

// Derive a secure password using Argon2id with additional security options
fn derive_password(
    mut master_key: String,
    service: &str,
    length: usize,
    pepper: Option<&str>,
    context: Option<&str>,
    allow_master_key_no_bip39: bool,
) -> Result<Zeroizing<String>, CryptoError> {
    normalize_and_validate_master_key(&mut master_key, allow_master_key_no_bip39)?;

    if master_key.len() < MIN_MASTER_KEY_LENGTH {
        return Err(CryptoError::Entropy(format!(
            "Master key is too short ({} characters). Minimum required: {}.",
            master_key.len(),
            MIN_MASTER_KEY_LENGTH
        )));
    }

    let service_with_context = match context {
        Some(ctx) => format!("{}{}", normalize_service(service), ctx),
        None => normalize_service(service),
    };

    let salt = generate_deterministic_salt(pepper.map(|p| p.as_bytes()), &service_with_context)?;

    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(length),
    )
    .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, ARGON2_VERSION, params);

    let mut output = vec![0u8; length];
    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut output)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    map_bytes_to_chars(&output, length, &argon2, &salt)
}

fn main() -> Result<(), CryptoError> {
    let args = Args::parse();

    if args.length < MIN_PASSWORD_LENGTH {
        return Err(CryptoError::Entropy(format!(
            "Password length too short ({}). Minimum required: 20.",
            args.length
        )));
    }

    let password = derive_password(
        args.master_key,
        &args.service,
        args.length,
        args.pepper.as_deref(),
        args.context.as_deref(),
        args.allow_master_key_no_bip39,
    )?;
    println!("{}", &*password);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test: Generate a deterministic salt with and without a pepper
    #[test]
    fn test_generate_deterministic_salt() {
        let service = "test-service";

        let salt1 = generate_deterministic_salt(None, service).unwrap();
        let salt2 = generate_deterministic_salt(Some(b"secret-pepper"), service).unwrap();
        let salt3 = generate_deterministic_salt(Some(b"another-pepper"), service).unwrap();

        assert_ne!(salt1, salt2, "Salt should be different with a pepper");
        assert_ne!(salt2, salt3, "Salts should differ for different peppers");
        assert_eq!(salt1.len(), 64, "Salt length should be 64 bytes");
    }

    // Test: Ensure Argon2 password derivation works as expected
    #[test]
    fn test_derive_password_valid() {
        let master_key = "this_is_a_secure_master_key_123456".to_string(); // Fixed to 32+ characters
        let service = "test.com";
        let password = derive_password(master_key, service, 64, None, None, true).unwrap();

        assert_eq!(
            password.len(),
            64,
            "Generated password should have the correct length"
        );
        assert!(
            password.chars().all(|c| ALLOWED_CHARS.contains(&(c as u8))),
            "Password should contain only allowed characters"
        );
    }

    // Test: Derive password with pepper and context
    #[test]
    fn test_derive_password_with_pepper_and_context() {
        let master_key = "this_is_a_secure_master_key_123456".to_string(); // Fixed length
        let service = "myapp.com";
        let pepper = Some("extra_security");
        let context = Some("user@domain.com");

        let password1 =
            derive_password(master_key.clone(), service, 64, pepper, context, true).unwrap();
        let password2 =
            derive_password(master_key.clone(), service, 64, pepper, context, true).unwrap();
        let password3 = derive_password(
            master_key.clone(),
            service,
            64,
            Some("different_pepper"),
            context,
            true,
        )
        .unwrap();

        // with same pepper. no context
        let password4 =
            derive_password(master_key.clone(), service, 64, Some("pepper"), None, true).unwrap();
        let password5 =
            derive_password(master_key.clone(), service, 64, Some("pepper"), None, true).unwrap();

        //with same context. no pepper
        let password6 =
            derive_password(master_key.clone(), service, 64, None, Some("context"), true).unwrap();
        let password7 =
            derive_password(master_key.clone(), service, 64, None, Some("context"), true).unwrap();

        assert_eq!(
            password1, password2,
            "Passwords should be consistent with same inputs"
        );

        assert_ne!(
            password1, password3,
            "Different peppers should produce different passwords"
        );

        assert_eq!(
            password4, password5,
            "Same pepper should produce the same password"
        );

        assert_eq!(
            password6, password7,
            "Same context should produce the same password"
        );
    }

    // Test: Error when master key is too short
    #[test]
    fn test_derive_password_short_master_key() {
        let result = derive_password("short_key".to_string(), "test.com", 64, None, None, true);
        assert!(
            matches!(result, Err(CryptoError::Entropy(_))),
            "Should fail with entropy error"
        );
    }

    // Test: Handle empty service name gracefully
    #[test]
    fn test_empty_service_name() {
        let master_key = "this_is_a_secure_master_key_123456".to_string();
        let result = derive_password(master_key, "", 64, None, None, true);
        assert!(result.is_ok(), "Empty service should be handled gracefully");
    }

    // Test: Validate password length
    #[test]
    fn test_password_length() {
        let master_key = "this_is_a_secure_master_key_123456".to_string();
        let service = "secureapp";
        let generated_password =
            derive_password(master_key, service, 32, None, None, true).unwrap();

        assert_eq!(
            generated_password.len(),
            32,
            "Password should match requested length"
        );
    }

    // Test: Maximum password length
    #[test]
    fn test_maximum_password_length() {
        let master_key = "this_is_a_secure_master_key_123456".to_string();
        let service = "max_length_test";
        let password = derive_password(master_key, service, 128, None, None, true).unwrap();

        assert_eq!(
            password.len(),
            128,
            "Generated password should match requested max length"
        );
    }

    // Test: Validate allowed characters in the password
    #[test]
    fn test_password_allowed_characters() {
        let master_key = "this_is_a_secure_master_key_123456".to_string();
        let service = "allowed_chars_test";

        let password = derive_password(master_key, service, 64, None, None, true).unwrap();

        for ch in password.chars() {
            assert!(
                ALLOWED_CHARS.contains(&(ch as u8)),
                "Password contains invalid characters"
            );
        }
    }

    // Test: Validate consistent output for same input
    #[test]
    fn test_password_consistency() {
        let master_key = "this_is_a_secure_master_key_123456".to_string();
        let service = "consistent_service";

        let password1 = derive_password(master_key.clone(), service, 64, None, None, true).unwrap();
        let password2 = derive_password(master_key.clone(), service, 64, None, None, true).unwrap();

        assert_eq!(
            password1, password2,
            "Same inputs should always produce the same password"
        );
    }

    // Test: Check failure in mapping bytes to characters (insufficient entropy)
    #[test]
    fn test_map_bytes_to_chars_failure() {
        let fake_bytes = vec![255; 10]; // Fake bytes with no entropy
        let argon2 = Argon2::new(Algorithm::Argon2id, ARGON2_VERSION, Params::default());
        let salt = vec![0u8; 16];

        let result = map_bytes_to_chars(&fake_bytes, 64, &argon2, &salt);

        assert!(
            matches!(result, Err(CryptoError::Entropy(_))),
            "Expected an Entropy error, but got success"
        );
    }
    #[test]
    fn test_long_master_key() {
        let master_key = "a".repeat(128); // Very long master key
        let service = "long-key-service";

        let result = derive_password(master_key, service, 64, None, None, true);
        assert!(result.is_ok());
    }
    #[test]
    fn test_master_key_normalization() {
        let mut master_key = String::from(" tag core steel little vibrant under check   favorite future arena tide art surge goat coyote network math  dignity scout october square shop crystal minor");
        normalize_and_validate_master_key(&mut master_key, false).unwrap();
        assert_eq!(
        master_key,
        "tag core steel little vibrant under check favorite future arena tide art surge goat coyote network math dignity scout october square shop crystal minor",
        "Master key should be normalized with single spaces"
        );
    }

    #[test]
    fn test_invalid_bip39_entropy() {
        let invalid_mnemonic = String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
        let result = validate_bip39_phrase(invalid_mnemonic);
        assert!(
            matches!(result, Err(CryptoError::Mnemonic(_))),
            "Low entropy mnemonic should fail validation"
        );
    }

    #[test]
    fn test_normalize_service() {
        let service = "   EXAMPLE.com  ";
        let normalized = normalize_service(service);
        assert_eq!(
            normalized, "example.com",
            "Service should be normalized to lowercase and trimmed"
        );
    }

    #[test]
    fn test_short_password_length() {
        let master_key = "this_is_a_secure_master_key_123456".to_string();
        let service = "shortpassword";
        let result = derive_password(master_key, service, 5, None, None, true);

        assert!(
            matches!(result, Err(CryptoError::Entropy(_))),
            "Should fail when password length is too short"
        );
    }
}

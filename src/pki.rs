use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
#[cfg(feature = "p384")]
use crate::der_certificate::ECDSA_SHA384;
#[cfg(feature = "ed25519")]
use crate::der_certificate::ED25519;
use crate::der_certificate::{
    DecodedCertificate, ECDSA_SHA256, HOSTNAME_MAXLEN, MAX_SAN_DNS_NAMES, Time,
    extract_common_name, extract_san_dns_names,
};
#[cfg(feature = "rsa")]
use crate::der_certificate::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::CertificateVerifyRef,
};
use crate::parse_buffer::ParseError;
use core::marker::PhantomData;
use der::Decode;
use digest::Digest;
use heapless::Vec;

pub struct CertificateNames {
    pub common_name: Option<heapless::String<HOSTNAME_MAXLEN>>,
    pub san_dns_names: heapless::Vec<heapless::String<HOSTNAME_MAXLEN>, MAX_SAN_DNS_NAMES>,
}

pub struct CertVerifier<'a, CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    ca: Certificate<&'a [u8]>,
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    certificate: Option<OwnedCertificate<CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

impl<'a, CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<'a, CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    #[must_use]
    pub fn new(ca: Certificate<&'a [u8]>) -> Self {
        Self {
            ca,
            host: None,
            certificate_transcript: None,
            certificate: None,
            _clock: PhantomData,
        }
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> TlsVerifier<CipherSuite>
    for CertVerifier<'_, CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|_| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: ServerCertificate,
    ) -> Result<(), TlsError> {
        let names = verify_certificate_chain(&self.ca, &cert, Clock::now())?;

        if !tls_hostname_match(&names, &self.host) {
            error!(
                "Hostname ({:?}) does not match certificate names (CN={:?}, SANs={:?})",
                self.host, names.common_name, names.san_dns_names
            );
            return Err(TlsError::InvalidCertificate);
        }

        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 146> = Vec::new();
        msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
        msg.extend_from_slice(ctx_str)
            .map_err(|_| TlsError::EncodeError)?;
        msg.extend_from_slice(&handshake_hash.finalize())
            .map_err(|_| TlsError::EncodeError)?;

        let certificate = unwrap!(self.certificate.as_ref()).try_into()?;
        verify_signature(&msg[..], &certificate, &verify)?;
        Ok(())
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let verified;

    let certificate =
        if let Some(CertificateEntryRef::X509(certificate)) = certificate.entries.first() {
            certificate
        } else {
            return Err(TlsError::DecodeError);
        };

    let certificate =
        DecodedCertificate::from_der(certificate).map_err(|_| TlsError::DecodeError)?;

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    match verify.signature_scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "p384")]
        SignatureScheme::EcdsaSecp384r1Sha384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "ed25519")]
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let verifying_key: VerifyingKey =
                VerifyingKey::from_bytes(public_key.try_into().unwrap())
                    .map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha256 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha256;

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha256>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha384 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha384;

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| TlsError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha384>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha512 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha512;

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| TlsError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha512>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        _ => {
            error!(
                "InvalidSignatureScheme: {:?} Are you missing a feature?",
                verify.signature_scheme
            );
            return Err(TlsError::InvalidSignatureScheme);
        }
    }

    if !verified {
        return Err(TlsError::InvalidSignature);
    }
    Ok(())
}

fn get_certificate_tlv_bytes<'a>(input: &[u8]) -> der::Result<&[u8]> {
    use der::{Decode, Reader, SliceReader};

    let mut reader = SliceReader::new(input)?;
    let top_header = der::Header::decode(&mut reader)?;
    top_header.tag().assert_eq(der::Tag::Sequence)?;

    let header = der::Header::peek(&mut reader)?;
    header.tag().assert_eq(der::Tag::Sequence)?;

    reader.tlv_bytes()
}

fn get_cert_time(time: &Time) -> u64 {
    match time {
        Time::UtcTime(utc_time) => utc_time.to_unix_duration().as_secs(),
        Time::GeneralTime(generalized_time) => generalized_time.to_unix_duration().as_secs(),
    }
}

/// Checks whether `issuer_public_key` produced `subject`'s signature. A `false`
/// result just means this issuer isn't the right one (expected while probing
/// candidates); errors are reserved for problems with `subject` itself that no
/// issuer choice could fix.
fn verify_signature_only(
    issuer_public_key: &[u8],
    subject: &DecodedCertificate,
    subject_der: &[u8],
) -> Result<bool, TlsError> {
    let signature_data = subject
        .signature
        .as_bytes()
        .ok_or(TlsError::ParseError(ParseError::InvalidData))?;

    let certificate_data =
        get_certificate_tlv_bytes(subject_der).map_err(|_| TlsError::DecodeError)?;

    let verified = match subject.signature_algorithm {
        ECDSA_SHA256 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(issuer_public_key) else {
                return Ok(false);
            };
            let Ok(signature) = Signature::from_der(signature_data) else {
                return Ok(false);
            };
            verifying_key.verify(&certificate_data, &signature).is_ok()
        }
        #[cfg(feature = "p384")]
        ECDSA_SHA384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(issuer_public_key) else {
                return Ok(false);
            };
            let Ok(signature) = Signature::from_der(signature_data) else {
                return Ok(false);
            };
            verifying_key.verify(&certificate_data, &signature).is_ok()
        }
        #[cfg(feature = "ed25519")]
        ED25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let Ok(key_bytes) = issuer_public_key.try_into() else {
                return Ok(false);
            };
            let Ok(verifying_key) = VerifyingKey::from_bytes(key_bytes) else {
                return Ok(false);
            };
            let Ok(signature) = Signature::try_from(signature_data) else {
                return Ok(false);
            };
            verifying_key.verify(certificate_data, &signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        a if a == RSA_PKCS1_SHA256 => {
            use rsa::{
                pkcs1::DecodeRsaPublicKey,
                pkcs1v15::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha256;

            let Ok(verifying_key) = VerifyingKey::<Sha256>::from_pkcs1_der(issuer_public_key)
            else {
                return Ok(false);
            };
            let Ok(signature) = Signature::try_from(signature_data) else {
                return Ok(false);
            };
            verifying_key.verify(certificate_data, &signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        a if a == RSA_PKCS1_SHA384 => {
            use rsa::{
                pkcs1::DecodeRsaPublicKey,
                pkcs1v15::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha384;

            let Ok(verifying_key) = VerifyingKey::<Sha384>::from_pkcs1_der(issuer_public_key)
            else {
                return Ok(false);
            };
            let Ok(signature) = Signature::try_from(signature_data) else {
                return Ok(false);
            };
            verifying_key.verify(certificate_data, &signature).is_ok()
        }
        #[cfg(feature = "rsa")]
        a if a == RSA_PKCS1_SHA512 => {
            use rsa::{
                pkcs1::DecodeRsaPublicKey,
                pkcs1v15::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha512;

            let Ok(verifying_key) = VerifyingKey::<Sha512>::from_pkcs1_der(issuer_public_key)
            else {
                return Ok(false);
            };
            let Ok(signature) = Signature::try_from(signature_data) else {
                return Ok(false);
            };
            verifying_key.verify(certificate_data, &signature).is_ok()
        }
        _ => {
            error!(
                "Unsupported signature alg: {:?}",
                subject.signature_algorithm
            );
            return Err(TlsError::InvalidSignatureScheme);
        }
    };

    Ok(verified)
}

fn check_validity(subject: &DecodedCertificate, now: Option<u64>) -> Result<(), TlsError> {
    if let Some(now) = now {
        if get_cert_time(&subject.tbs_certificate.validity.not_before) > now
            || get_cert_time(&subject.tbs_certificate.validity.not_after) < now
        {
            return Err(TlsError::InvalidCertificate);
        }
        debug!("Epoch is {} and certificate is valid!", now)
    }
    Ok(())
}

fn decode_x509_entry<'a>(
    entry: &CertificateEntryRef<'a>,
) -> Result<(&'a [u8], DecodedCertificate<'a>), TlsError> {
    let CertificateEntryRef::X509(der) = entry else {
        return Err(TlsError::DecodeError);
    };
    let decoded = DecodedCertificate::from_der(der).map_err(|_| TlsError::DecodeError)?;
    Ok((der, decoded))
}

/// Validates a server certificate chain against `ca`.
///
/// The chain is walked leaf-outward. At each step, `ca` is tried as the
/// issuer first; as soon as it matches, the chain is trusted and any
/// remaining (unneeded) entries the server sent are ignored — servers may
/// send extra certificates beyond what's needed to reach a given trust
/// anchor (e.g. a cross-signed root, for compatibility with other clients).
/// If `ca` never matches, positional entries are chained (`entries[i]`
/// issued by `entries[i+1]`) until one does.
fn verify_certificate_chain(
    ca: &Certificate<&[u8]>,
    cert: &ServerCertificate,
    now: Option<u64>,
) -> Result<CertificateNames, TlsError> {
    let entries = &cert.entries;

    let (leaf_der, leaf_decoded) = entries
        .first()
        .ok_or(TlsError::InvalidCertificate)
        .and_then(decode_x509_entry)?;

    let common_name = extract_common_name(&leaf_decoded.tbs_certificate)
        .map_err(|_| TlsError::DecodeError)?;
    debug!("CommonName: {:?}", common_name);

    let san_dns_names = extract_san_dns_names(&leaf_decoded.tbs_certificate)
        .map_err(|_| TlsError::DecodeError)?;
    debug!("SANs: {:?}", san_dns_names);

    let ca_entry: CertificateEntryRef = ca.into();
    let (_, ca_decoded) = decode_x509_entry(&ca_entry)?;
    let ca_public_key = ca_decoded
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    let mut idx = 0;
    let mut current_der = leaf_der;
    let mut current_decoded = leaf_decoded;
    let mut trusted = false;

    loop {
        if verify_signature_only(ca_public_key, &current_decoded, current_der)? {
            check_validity(&current_decoded, now)?;
            trusted = true;
            break;
        }

        let Some(next_entry) = entries.get(idx + 1) else {
            break;
        };
        let (next_der, next_decoded) = decode_x509_entry(next_entry)?;
        let next_public_key = next_decoded
            .tbs_certificate
            .subject_public_key_info
            .public_key
            .as_bytes()
            .ok_or(TlsError::DecodeError)?;

        if !verify_signature_only(next_public_key, &current_decoded, current_der)? {
            return Err(TlsError::InvalidCertificate);
        }
        check_validity(&current_decoded, now)?;

        idx += 1;
        current_der = next_der;
        current_decoded = next_decoded;
    }

    if !trusted {
        return Err(TlsError::InvalidCertificate);
    }

    Ok(CertificateNames {
        common_name,
        san_dns_names,
    })
}

/// Match a hostname against the certificate's names.
///
/// Per RFC 6125 Section 6.4.4, if the certificate contains Subject Alternative
/// Names (SANs), only the SANs are used for matching and the Common Name (CN)
/// is ignored. If no SANs are present, the CN is used as a fallback.
fn tls_hostname_match(
    names: &CertificateNames,
    hostname: &Option<heapless::String<HOSTNAME_MAXLEN>>,
) -> bool {
    let hostname = match hostname.as_ref() {
        Some(h) => h,
        None => {
            return names.common_name.is_none() && names.san_dns_names.is_empty();
        }
    };

    for san in &names.san_dns_names {
        if tls_hostname_match_impl(san.as_bytes(), hostname.as_bytes()) {
            return true;
        }
    }

    match names.common_name.as_ref() {
        Some(cn) => tls_hostname_match_impl(cn.as_bytes(), hostname.as_bytes()),
        None => false,
    }
}

fn tls_hostname_match_impl(cn: &[u8], host: &[u8]) -> bool {
    let mut cn_labels = 1;
    let mut host_labels = 1;
    let mut stars = 0;

    for &b in cn {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'*' => {}
            _ => return false,
        }
        if b == b'.' {
            cn_labels += 1;
        }
        if b == b'*' {
            stars += 1;
        }
    }

    for &b in host {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' => {}
            _ => return false,
        }
        if b == b'.' {
            host_labels += 1;
        }
    }

    if stars == 0 {
        if cn.len() != host.len() {
            return false;
        }
        for i in 0..cn.len() {
            if cn[i].to_ascii_lowercase() != host[i].to_ascii_lowercase() {
                return false;
            }
        }
        return true;
    }

    // RFC 6125 wildcard rules
    if stars != 1 {
        return false;
    }
    if !cn.starts_with(b"*.") {
        return false;
    }
    if cn_labels < 3 {
        return false;
    }
    if cn_labels != host_labels {
        return false;
    }

    let suffix = &cn[2..];
    let mut dot_idx = None;
    for i in 0..host.len() {
        if host[i] == b'.' {
            dot_idx = Some(i);
            break;
        }
    }
    let dot_idx = match dot_idx {
        Some(i) => i,
        None => return false,
    };
    let host_suffix = &host[dot_idx + 1..];

    if suffix.len() != host_suffix.len() {
        return false;
    }

    for i in 0..suffix.len() {
        if suffix[i].to_ascii_lowercase() != host_suffix[i].to_ascii_lowercase() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::tls_hostname_match_impl;

    #[test]
    fn exact_match() {
        assert!(tls_hostname_match_impl(b"example.com", b"example.com"));
        assert!(tls_hostname_match_impl(b"EXAMPLE.COM", b"example.com"));
        assert!(tls_hostname_match_impl(b"example.com", b"EXAMPLE.COM"));
    }

    #[test]
    fn exact_mismatch() {
        assert!(!tls_hostname_match_impl(b"example.com", b"example.org"));
        assert!(!tls_hostname_match_impl(b"example.com", b"sub.example.com"));
    }

    #[test]
    fn valid_wildcard_match() {
        assert!(tls_hostname_match_impl(
            b"*.example.com",
            b"api.example.com"
        ));
        assert!(tls_hostname_match_impl(
            b"*.example.com",
            b"WWW.example.com"
        ));
    }

    #[test]
    fn wildcard_single_label_only() {
        assert!(!tls_hostname_match_impl(
            b"*.example.com",
            b"a.b.example.com"
        ));
    }

    #[test]
    fn wildcard_requires_same_label_count() {
        assert!(!tls_hostname_match_impl(b"*.example.com", b"example.com"));
        assert!(!tls_hostname_match_impl(
            b"*.example.com",
            b"deep.api.example.com"
        ));
    }

    #[test]
    fn wildcard_must_be_leftmost_label() {
        assert!(!tls_hostname_match_impl(
            b"api.*.example.com",
            b"api.test.example.com"
        ));
        assert!(!tls_hostname_match_impl(
            b"foo*.example.xx",
            b"foobar.example.xx"
        ));
    }

    #[test]
    fn wildcard_requires_minimum_three_labels() {
        assert!(!tls_hostname_match_impl(b"*.com", b"example.com"));
        assert!(!tls_hostname_match_impl(b"*.org", b"test.org"));
    }

    #[test]
    fn multiple_wildcards_rejected() {
        assert!(!tls_hostname_match_impl(
            b"*.*.example.com",
            b"a.b.example.com"
        ));
        assert!(!tls_hostname_match_impl(
            b"**.example.com",
            b"api.example.com"
        ));
    }

    #[test]
    fn idna_a_label_supported() {
        assert!(tls_hostname_match_impl(
            b"xn--bcher-kva.example",
            b"xn--bcher-kva.example"
        ));

        assert!(tls_hostname_match_impl(
            b"*.xn--bcher-kva.example",
            b"api.xn--bcher-kva.example"
        ));
    }

    #[test]
    fn unicode_rejected() {
        assert!(!tls_hostname_match_impl(
            "bücher.example".as_bytes(),
            "bücher.example".as_bytes()
        ));
        assert!(!tls_hostname_match_impl(
            "*.bücher.example".as_bytes(),
            "api.bücher.example".as_bytes()
        ));
    }

    #[test]
    fn invalid_characters_rejected() {
        assert!(!tls_hostname_match_impl(b"example!.com", b"example!.com"));
        assert!(!tls_hostname_match_impl(b"example.com", b"exa mple.com"));
    }
}

#[cfg(test)]
mod chain_verification_tests {
    use super::*;

    fn chain_of<'a>(entries: &[&'a [u8]]) -> ServerCertificate<'a> {
        let mut cert = ServerCertificate::with_context(&[]);
        for der in entries {
            cert.add(CertificateEntryRef::X509(der)).unwrap();
        }
        cert
    }

    // The server sends [leaf, intermediate, decoy]: `intermediate` is
    // directly signed by `ca`, but `decoy` shares `ca`'s public key while
    // actually being signed by a different (untrusted) issuer — mirroring
    // AWS IoT Core sending a cross-signed root cert beyond what's needed to
    // reach the configured trust anchor. The walk must stop at
    // `intermediate` and ignore `decoy`, not fail trying to verify it.
    #[test]
    fn chain_with_trailing_cross_signed_cert_succeeds() {
        let leaf = pem_parser::pem_to_der(include_str!("../tests/data/im-server-cert.pem"));
        let intermediate = pem_parser::pem_to_der(include_str!("../tests/data/im-cert.pem"));
        let decoy = pem_parser::pem_to_der(include_str!("../tests/data/ca-cross-signed.pem"));
        let ca = pem_parser::pem_to_der(include_str!("../tests/data/ca-cert.pem"));

        let cert = chain_of(&[leaf.as_slice(), intermediate.as_slice(), decoy.as_slice()]);
        let result = verify_certificate_chain(&Certificate::X509(ca.as_slice()), &cert, None);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    // Without `decoy` in the chain, nothing presented ever chains up to
    // `alt_root` (it only signs `decoy`, which isn't sent here), so the walk
    // must exhaust the chain and fail rather than trust it anyway.
    #[test]
    fn chain_without_trust_anchor_match_fails() {
        let leaf = pem_parser::pem_to_der(include_str!("../tests/data/im-server-cert.pem"));
        let intermediate = pem_parser::pem_to_der(include_str!("../tests/data/im-cert.pem"));
        let alt_root = pem_parser::pem_to_der(include_str!("../tests/data/alt-root-cert.pem"));

        let cert = chain_of(&[leaf.as_slice(), intermediate.as_slice()]);
        let result = verify_certificate_chain(&Certificate::X509(alt_root.as_slice()), &cert, None);
        assert!(matches!(result, Err(TlsError::InvalidCertificate)));
    }

    #[test]
    fn two_cert_chain_still_works() {
        let leaf = pem_parser::pem_to_der(include_str!("../tests/data/im-server-cert.pem"));
        let intermediate = pem_parser::pem_to_der(include_str!("../tests/data/im-cert.pem"));
        let ca = pem_parser::pem_to_der(include_str!("../tests/data/ca-cert.pem"));

        let cert = chain_of(&[leaf.as_slice(), intermediate.as_slice()]);
        let result = verify_certificate_chain(&Certificate::X509(ca.as_slice()), &cert, None);
        assert!(result.is_ok(), "{:?}", result.err());
    }
}

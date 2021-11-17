use std::prelude::v1::*;
use sgx_types::*;
use super::cert;

pub struct ClientAuth {
    outdated_ok: bool,
}

impl ClientAuth {
    pub fn new(outdated_ok: bool) -> ClientAuth {
        ClientAuth{ outdated_ok }
    }
}

impl rustls::ClientCertVerifier for ClientAuth {
    fn client_auth_root_subjects(&self, _sni: Option<&webpki::DNSName>) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(&self, _certs: &[rustls::Certificate], _sni: Option<&webpki::DNSName>)
    -> Result<rustls::ClientCertVerified, rustls::TLSError> {
            println!("client cert: {:?}", _certs);
            // This call will automatically verify cert is properly signed
            match cert::verify_mra_cert(&_certs[0].0) {
                Ok(()) => {
                    return Ok(rustls::ClientCertVerified::assertion());
                }
                Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                    if self.outdated_ok {
                        println!("outdated_ok is set, overriding outdated error");
                        return Ok(rustls::ClientCertVerified::assertion());
                    } else {
                        return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                    }
                }
                Err(_) => {
                    return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                }
            }
    }
}

pub struct ServerAuth {
    outdated_ok: bool
}

impl ServerAuth {
    pub fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth{ outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(&self,
              _roots: &rustls::RootCertStore,
              _certs: &[rustls::Certificate],
              _hostname: webpki::DNSNameRef,
              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        println!("server cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                return Ok(rustls::ServerCertVerified::assertion());
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    return Ok(rustls::ServerCertVerified::assertion());
                } else {
                    return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                }
            }
            Err(_) => {
                return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
            }
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EccPrivateKey {
    pub r: [u8; SGX_ECP256_KEY_SIZE]
}

impl From<sgx_ec256_private_t> for EccPrivateKey {
    fn from(key: sgx_ec256_private_t) -> Self {
        EccPrivateKey { r: key.r }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EccPublicKey {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE]
}

impl From<sgx_ec256_public_t> for EccPublicKey {
    fn from(key: sgx_ec256_public_t) -> Self {
        EccPublicKey {
            gx: key.gx,
            gy: key.gy
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EccSignature {
    pub x: [u32; SGX_NISTP_ECP256_KEY_SIZE],
    pub y: [u32; SGX_NISTP_ECP256_KEY_SIZE],
}

impl From<sgx_ec256_signature_t> for EccSignature {
    fn from(sig: sgx_ec256_signature_t) -> Self {
        EccSignature {
            x: sig.x,
            y: sig.y,
        }
    }
}
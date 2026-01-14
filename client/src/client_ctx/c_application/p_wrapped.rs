//! yTLS Wrapped Record (Application) Processor

use crate::TlsClientCtxConfig;
use ytls_ctx::CtxError;
use ytls_traits::{CryptoConfig, CryptoRng};

use crate::ClientApplicationCtx;

use ytls_traits::ServerApRecordProcessor;

impl<Crypto> ServerApRecordProcessor for ClientApplicationCtx<Crypto> where Crypto: CryptoConfig {}

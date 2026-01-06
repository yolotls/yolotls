//! Record Builders

mod record_buffer;
#[doc(inline)]
pub use record_buffer::*;

mod static_record;
#[doc(inline)]
pub use static_record::*;

//-------------------------------
// Server Handshakes
//-------------------------------
mod b_server_hello;
// Server Handshakes (Wrapped)
mod b_dhs_encrypted_extensions;
mod b_dhs_server_certificate;
mod b_dhs_server_certificate_verify;
mod b_dhs_server_handshake_finished;

//-------------------------------
// Application Data (Wrapped)
//-------------------------------
mod b_wrap_application_data;

mod formatter;

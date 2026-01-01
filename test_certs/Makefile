ed25519: ca-ed25519-key ca-ed25519-crt ed25519-key ed25519-csr ca-sign-ed25519-csr

rsa4096: ca-rsa4096-key ca-rsa4096-crt rsa4096-key rsa4096-csr ca-sign-rsa4096-csr

prime256v1: ca-prime256v1-key ca-prime256v1-crt prime256v1-key prime256v1-csr ca-sign-prime256v1-csr

clean:
	rm rustcryp.to.key rustcryp.to.csr rustcryp.to.crt

## Server Cert Keys

ed25519-key:
	openssl genpkey -algorithm ED25519 -out rustcryp.to.ed25519.key -outform PEM

rsa4096-key:
	openssl genrsa -out rustcryp.to.rsa4096.key 4096

prime256v1-key:
	openssl ecparam -genkey -name prime256v1 -noout -out rustcryp.to.prime256v1.pem


## CA

ca-ed25519-key:
	openssl genpkey -algorithm ED25519 -out ca.ed25519.key -outform PEM

ca-rsa4096-key:
	openssl genrsa -out ca.rsa4096.key 4096

ca-prime256v1-key:
	openssl ecparam -genkey -name prime256v1 -noout -out ca.prime256v1.pem

ca-rsa4096-crt:
	openssl req -x509 -new -nodes -key ca.rsa4096.key -out ca.rsa4096.crt -\
		-subj /C=XX/ST=YY/L=Antarctica/O=RustCrypto/OU=CA-Maintainers/CN=ca.rustcryp.to

ca-ed25519-crt:
	openssl req -x509 -new -nodes -key ca.ed25519.key -out ca.ed25519.crt \
		-subj /C=XX/ST=YY/L=Antarctica/O=RustCrypto/OU=CA-Maintainers/CN=ca.rustcryp.to

ca-prime256v1-crt:
	openssl req -x509 -new -nodes -key ca.prime256v1.pem -out ca.prime256v1.crt \
		-subj /C=XX/ST=YY/L=Antarctica/O=RustCrypto/OU=CA-Maintainers/CN=ca.rustcryp.to

## CSR

ed25519-csr:
	openssl req -new -out rustcryp.to.ed25519.csr -key rustcryp.to.ed25519.key -config cert.cnf

rsa4096-csr:
	openssl req -new -out rustcryp.to.rsa4096.csr -key rustcryp.to.rsa4096.key -config cert.cnf

prime256v1-csr:
	openssl req -new -out rustcryp.to.prime256v1.csr -key rustcryp.to.prime256v1.pem -config cert.cnf


## Sign PKCS10 CA certified

ca-sign-rsa4096-csr:
	openssl x509 -req \
		-in rustcryp.to.rsa4096.csr \
		-out rustcryp.to.rsa4096.ca_signed.crt \
		-CA ca.rsa4096.crt \
		-CAkey ca.rsa4096.key \
		-CAcreateserial  \
		-days 365 \
		-extensions v3_end \
		-extfile openssl.cnf

ca-sign-ed25519-csr:
	openssl x509 -req \
		-in rustcryp.to.ed25519.csr \
		-out rustcryp.to.ed25519.ca_signed.crt \
		-CA ca.ed25519.crt \
		-CAkey ca.ed25519.key \
		-CAcreateserial  \
		-days 365 \
		-extensions v3_end \
		-extfile openssl.cnf

ca-sign-prime256v1-csr:
	openssl x509 -req \
		-in rustcryp.to.prime256v1.csr \
		-out rustcryp.to.prime256v1.ca_signed.crt \
		-CA ca.prime256v1.crt \
		-CAkey ca.prime256v1.pem \
		-CAcreateserial  \
		-days 365 \
		-extensions v3_end \
		-extfile openssl.cnf

## Sign PKCS10 self-certified

sign-ed25591-csr:
	openssl x509 -req -days 365 -in rustcryp.to.ed25519.csr -signkey rustcryp.to.ed25519.key -out rustcryp.to.ed25519.crt

sign-rsa4096-csr:
	openssl x509 -req -days 365 -in rustcryp.to.rsa4096.csr -signkey rustcryp.to.rsa4096.key -out rustcryp.to.rsa4096.crt

sign-prime256v1-csr:
	openssl x509 -req -days 365 -in rustcryp.to.prime256v1.csr -signkey rustcryp.to.prive256v1.pem -out rustcryp.to.prime256v1.crt

## Export PKCS12
#
#pk12-ed25519:
#	openssl pkcs12 -export -out rustcryp.to.ed25519.pfx -inkey rustcryp.to.ed25519.key -in rustcryp.to.ed25519.crt -passout pas#s:test
#
#pk12-rsa4096:
#	openssl pkcs12 -export -out rustcryp.to.rsa4096.pfx -inkey rustcryp.to.rsa4096.key -in rustcryp.to.rsa4096.crt -passout pas#s:test

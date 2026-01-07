# yolotls sans-io (Server) related functionality

The server implements all the TLS Processor traits and provides a stateful context from the server end PoV.

## Try it out

Note: The below assumes hostname is test.rustcryp.to on IPv4 address 192.168.64.3.

Generate the example secp256v1 certificates
```text
$ cd ../test_certs
$ make prime256v1
```

Start the server listener
```text
$ cargo run --example listener
```

And then PING with the openssl client:
```text
$ openssl s_client -CAfile test_certs/ca.prime256v1.crt -debug -msg -tls1_3 -security_debug_verbose -state 192.168.64.3:9999
```

Once the openssl client is connected, you can type PING<LF> and then get a PONG<LF> as per listener example.

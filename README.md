# yoloTLS

[![CI](https://github.com/yolotls/yolotls/actions/workflows/CI.yml/badge.svg)](https://github.com/yolotls/yolotls/actions/workflows/CI.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![MSRV](https://img.shields.io/badge/MSRV-1.60.0-blue)

yoloTLS is when / We Can / but not necessarily whether / We Should

# Goals / Problems To Solve

| #               | Topic                                                   |
| :---            | :---                                                    |
| [2](issues/2)   | **We Can**: Experimental Fun Hobby Project (tm)         |
| [3](issues/3)   | `no_std` with std as opt-in                             |
| [4](issues/4)   | Modern API designed from scratch                        |
| [5](issues/5)   | Both TLS and DTLS primary citizens                      |
| [6](issues/6)   | Pluggable De-Coupled Cipher suites / Algos              |
| [7](issues/7)   | Portability and Safety focus with Performance second    |
| [8](issues/8)   | wasm32-wasi and wasm32-u-u support from start           |
| [9](issues/9)   | sans-io de-coupled I/O with both Completion and Evented |
| [10](issues/10) | de-coupled Protocol model                               |
| [11](issues/11) | Unsafe TLS/SSL as "pluggable" opt-ins                   |
| [12](issues/12)   | API Abstractions / Bindings to other languages          |

Any /current/new/ goal can be adjusted / adopted etc. by proposing via a PR to above list linking to the relevant proposed Goal.

# Crates

| Crate           | Description                          |
| :---            | :---                                 |
| [ytls-record](./record)     | Record layer                         |
| [ytls-typed](./typed)      | Typed conversions from protocol data |
| [ytls-server](./server)     | Server context                       |
| [ytls-extensions](./extensions) | Extensions handling                  |

# Non-Goals as of Now

- **We Should**: Taking It Seriously (tm)
- FIPS / Regulation

# Testbeds

- [ ] yolotls_client - utility knife for client side operations
- [ ] yolotls_server - utility knife for serving side operations
- [ ] yaws Integration demonstrating wasm32-wasi w/ WebRTC (DTLS) + h1/2specs + QUIC
- [ ] e-mail server / client integration

## Run

Lunatic Flavor:

$ `RUSTFLAGS="--cfg yaws_flavor=\"lunatic\"" cargo run --bin yolotls_client --target wasm32-wasi`

io_uring Flavor:

$ `RUSTFLAGS="--cfg yaws_flavor=\"io_uring\"" cargo run --bin yolotls_client`

## yaws Library

yoloTLS has non-exclusive options

- [ ] `cfg(yaws_x = "a")` - `x` - TODO
- [ ] `cfg(yaws_x = "b")` - `y` - TODO

## License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


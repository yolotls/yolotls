# yoloTLS

[![CI](https://github.com/yolotls/yolotls/actions/workflows/CI.yml/badge.svg)](https://github.com/yolotls/yolotls/actions/workflows/CI.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![MSRV](https://img.shields.io/badge/MSRV-1.60.0-blue)

de-coupled no_std, no_alloc TLS 1.3 suite

⚠️  **Experimental - This has not received any security etc. reviews** ⚠️

# Context

| Crate                       | Description                          |
| ;---                        | :---                                 |
| [ytls-server](./server)     | Server TLS context                   |
| [ytls-client](./client)     | Client TLS context                   |

# Protocol

| Crate                           | Description                          |
| :---                            | :---                                 |
| [ytls-traits](./traits)         | Traits used throughout the suite     |
| [ytls-keys](./keys)             | Keying operations used               |
| [ytls-record](./record)         | Record layer parsing and building    |
| [ytls-typed](./typed)           | Typed conversions from protocol raw  |
| [ytls-extensions](./extensions) | Extensions handling                  |
| [utls-util](./util)             | Various utilities                    |

# Cryptography

| Crate                                  | Description                          |
| :---                                   | :---                                 |
| [ytls-rustcrypto](./crypto/rustcrypto) | Rustcrypto derived cryptography      |

## License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


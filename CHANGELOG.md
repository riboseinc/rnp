## Changelog

### 0.15.2 [2021-06-28]

#### General

* Be less strict in userid validation: allow to use userids with self-signature, which has key expiration in the past.
* Do not mark signature as invalid if key which produced it is expired now, but was valid during signing.
* Fix incorrect key expiration calculation in some cases.
* Fix incorrect version number in `version.txt`.

#### FFI

* Allow to pass NULL hash parameter to `rnp_key_add_uid()` to pick the default one.
* Use the same approach as in `rnp_op_encrypt_add_recipient()` for encryption subkey selection in `rnp_key_export_autocrypt()`.

#### CLI

* `rnp`: Show error message if encryption failed.

### 0.15.1 [2021-05-28]

#### General

* Make man pages building optional.
* Fixed updating of expiration time for a key with multiple user ids.
* Fixed key expiry check for keys valid after the year 2038.
* Pick up key expiration time from direct-key signature or primary userid certification if available.

#### FFI

* Added function `rnp_key_valid_till64()` to correctly handle keys which expire after the year 2038.
* Added RNP_FEATURE_* defines to be used instead of raw strings.

#### Security

* Fixed issue with cleartext key data after the `rnp_key_unprotect()`/`rnp_key_protect()` calls (CVE-2021-33589).

### 0.15.0 [2021-04-04]

#### General

* Added CMake options to allow offline builds, i.e. without Googletest/ruby-rnp downloads.
* Removed major library version from the library name (librnp-0.so/dll -> librnp.so/dll).
* Improved handling of cleartext signatures, when empty line between headers and contents contains some whitespace characters.
* Relaxed requirements for the armored messages CRC (allow absence of the CRC, and issue warning instead of complete failure).
* Updated build instructions for MSVC.
* Improved support of 32-bit platforms (year 2038 problem).

#### CLI

* Added up-to-date manual pages for `rnp` and `rnpkeys`.
* rnpkeys: added `--remove-key` command.

#### FFI

* Added up-to-date manual page for `librnp`.
* Added function `rnp_signature_remove`
* Added function `rnp_uid_remove`
* Added function `rnp_key_remove_signatures` for batch signature removal and filtering.

### 0.14.0 [2021-01-15]

#### General

* Improved key validation: require to have at least one valid, non-expiring self signature.
* Added support for 'stripped' keys without userids and certifications but with valid subkey binding signature.
* Added support for Windows via MinGW/MSYS2.
* Added support for Windows via MSVC.
* Fixed secret key locking when it is updated with new signatures/subkeys.
* Fixed key expiry/flags calculation (take in account only the latest valid self-signature/subkey binding).
* Fixed MDC reading if it appears on 8k boundary.
* Disabled logging by default in release builds and added support for environment variable `RNP_LOG_CONSOLE` to enable it back.
* Fixed leading zeroes for secp521r1 b & n field constants.
* Allowed keys and signatures with invalid MPI bit count.
* Added support for private/experimental signature subpackets, used by GnuPG and other implementations.
* Added support for reserved/placeholder signatures.
* Added support for zero-size userid/attr packet.
* Relaxed packet dumping, ignoring invalid packets and allowing to find wrong packet easier.
* Improved logging of errored keys/subkeys information for easier debugging.
* Fixed support for old RSA sign-only/encrypt-only and ElGamal encrypt-and-sign keys.
* Fixed support for ElGamal keys larger then 3072 bits.
* Fixed symbol visibility so only FFI functions are exposed outside of the library.
* Added support for unwrapping of raw literal packets.
* Fixed crash with non-detached signature input, fed into the `rnp_op_verify_detached_create()`.
* Significantly reduced memory usage for the keys large number of signatures.
* Fixed long armor header lines processing.
* Added basic support for GnuPG's offline primary keys (`gnupg --export-secret-subkeys`) and secret keys, stored on card.
* Fixed primary key binding signature validation when hash algorithm differs from the one used in the subkey binding signature.
* Fixed multiple memory leaks related to invalid algorithms/versions/etc.
* Fixed possible crashes during processing of malformed armored input.
* Limited allowed nesting levels for OpenPGP packets.
* Fixed support for text-mode signatures.
* Replaced strcpy calls with std::string and memcpy where applicable.
* Removed usage of mktemp, replacing it with mkstemp.
* Replaced usage of deprecated `botan_pbkdf()` with `botan_pwdhash()`.
* Added support for the marker packet, issued by some implementations.
* Added support for unknown experimental s2ks.
* Fixed armored message contents detection (so armored revocation signature is not more reported as the public key).
* Changed behaviour to use latest encryption subkey by default.
* Fixed support for widechar parameters/file names on Windows.
* Implemented userid validity checks so only certified/non-expired/non-revoked userid may be searched.
* Fixed GnuPG compatibility issues with CR (`\r`) characters in text-mode and cleartext-signed documents.
* Improved performance of the key/uid signatures access.
* Migrated tests to the Python 3.
* Migrated most of the internal code to C++.

#### CLI

* Do not load keyring when it is not required, avoiding extra `keyring not found` output.
* Input/output data via the tty, if available, instead of stdin/stdout.
* Fixed possible crash when HOME variable is not set.
* rnpkeys: Added `--import-sigs` and changed behavior of `--import` to check whether input is key or signature.
* rnpkeys: Added `--export-rev` command to export key's revocation, parameters `--rev-type`, `--rev-reason`.
* rnpkeys: Added `--revoke-key` command.
* rnpkeys: Added `--permissive` parameter to `--import-keys` command.
* rnpkeys: Added `--password` options, allowing to specify password and/or generate unprotected key.

#### FFI

* Added keystore type constants `RNP_KEYSTORE_*`.
* Added `rnp_import_signatures`.
* Added `rnp_key_export_revocation`.
* Added `rnp_key_revoke`.
* Added `rnp_request_password`.
* Added `rnp_key_set_expiration` to update key's/subkey's expiration time.
* Added flag `RNP_LOAD_SAVE_PERMISSIVE` to `rnp_import_keys`, allowing to skip erroneous packets.
* Added flag `RNP_LOAD_SAVE_SINGLE`, allowing to import keys one-by-one.
* Added `rnp_op_verify_get_protection_info` to check mode and cipher used to encrypt message.
* Added functions to retrieve recipients information (`rnp_op_verify_get_recipient_count`, `rnp_op_verify_get_symenc_count`, etc.).
* Added flag `RNP_KEY_REMOVE_SUBKEYS` to `rnp_key_remove` function.
* Added function `rnp_output_pipe` allowing to write data from input to the output.
* Added function `rnp_output_armor_set_line_length` allowing to change base64 encoding line length.
* Added function `rnp_key_export_autocrypt` to export public key in autocrypt-compatible format.
* Added functions to retrieve information about the secret key's protection (`rnp_key_get_protection_type`, etc.).
* Added functions `rnp_uid_get_type`, `rnp_uid_get_data`, `rnp_uid_is_primary`.
* Added function `rnp_uid_is_valid`.
* Added functions `rnp_key_get_revocation_signature` and `rnp_uid_get_revocation_signature`.
* Added function `rnp_signature_get_type`.
* Added function `rnp_signature_is_valid`.
* Added functions `rnp_key_is_valid` and `rnp_key_valid_till`.
* Added exception guard to FFI boundary.
* Fixed documentation for the `rnp_unload_keys` function.

#### Security

* Removed version header from armored messages (see https://mailarchive.ietf.org/arch/msg/openpgp/KikdJaxvdulxIRX_yxU2_i3lQ7A/ ).
* Enabled fuzzing via oss-fuzz and fixed reported issues.
* Fixed a bunch of issues reported by static analyzer.
* Require at least Botan 2.14.0.

### 0.13.1 [2020-01-15]
#### Security

* rnpkeys: Fix issue #1030 where rnpkeys would generate unprotected secret keys.

### 0.13.0 [2019-12-31]
#### General

* Fixed a double-free on invalid armor headers.
* Fixed broken versioning when used as a git submodule.
* Fixed an infinite loop on parsing truncated armored keys.
* Fixed armored stream parsing to be more flexible and allow blank lines before trailer.
* Fixed the armor header for detached signatures (previously MESSAGE, now SIGNATURE).
* Improved setting of default qbits for DSA.
* Fixed a crash when retrieving signature revocation reason.
* Stop using expensive tests for key material validation.

#### CLI

* rnpkeys: Removed a few redundant commands (--get-key, --print-sigs, --trusted-keys, ...).
* rnpkeys: Added --secret option.
* rnpkeys: Display 'ssb' for secret subkeys.
* rnp: Added `--list-packets` parameters (`--json`, etc.).
* rnp: Removed `--show-keys`.

#### FFI

* Added `rnp_version_commit_timestamp` to retrieve the commit timestamp
  (for non-release builds).
* Added a new (non-JSON) key generation API (`rnp_op_generate_create` etc.).
* Added `rnp_unload_keys` function to unload all keys.
* Added `rnp_key_remove` to unload a single key.
* Expanded bit length support for JSON key generation.
* Added `rnp_key_get_subkey_count`/`rnp_key_get_subkey_at`.
* Added various key property accessors (`rnp_key_get_bits`, `rnp_key_get_curve`).
* Added `rnp_op_generate_set_protection_password`.
* Added `rnp_key_packets_to_json`/`rnp_dump_packets_to_json`.
* Added `rnp_key_get_creation`, `rnp_key_get_expiration`.
* Added `rnp_key_get_uid_handle_at`, `rnp_uid_is_revoked`, etc.
* Added `rnp_key_is_revoked` and related functions to check for revocation.
* Added `rnp_output_to_path` and `rnp_output_finish`.
* Added `rnp_import_keys`.
* Added `rnp_calculate_iterations`.
* Added `rnp_supports_feature`/`rnp_supported_features`.
* Added `rnp_enable_debug`/`rnp_disable_debug`.
* Added `rnp_key_get_primary_grip`.
* Added `rnp_output_to_armor`.
* Added `rnp_op_generate_set_request_password`.
* Added `rnp_dump_packets_to_output`.
* Added `rnp_output_write`.
* Added `rnp_guess_contents`.
* Implemented `rnp_op_set_file_name`/`rnp_op_set_file_mtime`.
* Added `rnp_op_encrypt_set_aead_bits`.
* Added `rnp_op_verify_signature_get_handle`.
* Added `rnp_signature_packet_to_json`.

#### Packaging

* RPM: Split packages into librnp0, librnp0-devel, and rnp0.

### 0.12.0 [2019-01-13]
#### General

* We now require Botan 2.8+.
* Fixed key grip calculations for various key types.
* Fixed SM2 signatures hashing the hash of the message. See comment in issue #436.
* Added support for G10 ECC keys.
* Fixed dumping of partial-length packets.
* Added support for extra ECC curves:
  * Brainpool p256, p384, p512 ECDSA/ECDH
  * secp256k1 ECDSA/ECDH
  * x25519
* Fixed AEAD with newer versions of Botan.
* Removed a lot of legacy code.

#### CLI

* rnp: Added -f/--keyfile option to load keys directly from a file.
* rnp: Fixed issue with selecting G10 secret keys via userid.
* rnpkeys: Added support for SM2 with arbitrary hashes.
* redumper: Added -g option to dump fingerprints and grips.
* redumper: Display key id/fingerprint/grip in packet listings.

#### FFI

* Added FFI examples.
* Fixed a regression with loading subkeys directly.
* Implemented support for per-signature hash and creation/expiration time.
* Added AEAD support.

### 0.11.0 [2018-09-16]
#### General

* Remove some old SSH key support.
* Add support for dynamically calculating the S2K iterations.
* Add support for extracting the public key from the secret key.
* Add support for merging information between keys.

#### CLI

* Add options for custom S2K iterations/times (dynamic by default).

### 0.10.0 [2018-08-20]
#### General

* Fixed some compiler warnings.
* Switched armoring to use PRIVATE KEY instead of SECRET KEY.

#### ECDSA

* Use the matching hash to be used for the deterministic nonce generation.
* Check that the input is of the expected length.
* Removed the code to truncate the ECDSA input since this is now handled by Botan.

#### FFI

* Added enarmor and dearmor support.
* Added library version retrieval.
* Removed rnp_export_public_key, added rnp_key_export.


### 0.9.2 [2018-08-13]
#### General

* Support for generation and verification of embedded signature subpacket for signing subkeys
* Verification of public key signatures and key material
* Improved performance of asymmetric operations (key material is now validated on load)

#### FFI

* Fixed rnp_op_add_signature for G10 keys


### 0.9.1 [2018-07-12]
#### General

* Added issuer fingerprint to certifications and subkey bindings.

#### CLI

* Added support for keyid/fpr usage with (some) spaces and 0x prefix in
  operations (--sign, etc).

#### FFI

* Fixed key search by fingerprint. 


### 0.9.0 [2018-06-27]
* First official release.

// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Generalized signers
//!
//! This module provides the ability to add customized signers to a [`Wallet`](super::Wallet)
//! through the [`Wallet::add_signer`](super::Wallet::add_signer) function.
//!
//! ```
//! # use alloc::sync::Arc;
//! # use core::str::FromStr;
//! # use bitcoin::secp256k1::{Secp256k1, All};
//! # use bitcoin::*;
//! # use bdk_wallet::signer::*;
//! # use bdk_wallet::*;
//! # #[derive(Debug)]
//! # struct CustomHSM;
//! # impl CustomHSM {
//! #     fn hsm_sign_input(&self, _psbt: &mut Psbt, _input: usize) -> Result<(), SignerError> {
//! #         Ok(())
//! #     }
//! #     fn connect() -> Self {
//! #         CustomHSM
//! #     }
//! #     fn get_id(&self) -> SignerId {
//! #         SignerId::Dummy(0)
//! #     }
//! # }
//! #[derive(Debug)]
//! struct CustomSigner {
//!     device: CustomHSM,
//! }
//!
//! impl CustomSigner {
//!     fn connect() -> Self {
//!         CustomSigner { device: CustomHSM::connect() }
//!     }
//! }
//!
//! impl SignerCommon for CustomSigner {
//!     fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
//!         self.device.get_id()
//!     }
//! }
//!
//! impl InputSigner for CustomSigner {
//!     fn sign_input(
//!         &self,
//!         psbt: &mut Psbt,
//!         input_index: usize,
//!         _sign_options: &SignOptions,
//!         _secp: &Secp256k1<All>,
//!     ) -> Result<(), SignerError> {
//!         self.device.hsm_sign_input(psbt, input_index)?;
//!
//!         Ok(())
//!     }
//! }
//!
//! let custom_signer = CustomSigner::connect();
//!
//! let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/0/*)";
//! let change_descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/1/*)";
//! let mut wallet = Wallet::create(descriptor, change_descriptor)
//!     .network(Network::Testnet)
//!     .create_wallet_no_persist()?;
//! wallet.add_signer(
//!     KeychainKind::External,
//!     SignerOrdering(200),
//!     Arc::new(custom_signer)
//! );
//!
//! # Ok::<_, anyhow::Error>(())
//! ```

use crate::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitcoin::psbt::{GetKey, GetKeyError};
use core::cmp::Ordering;
use core::fmt;
use core::ops::{Bound::Included, Deref};
use std::string::ToString;

use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::hash160;
use bitcoin::secp256k1;
use bitcoin::PrivateKey;
use bitcoin::{psbt, sighash, taproot};

use miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorSecretKey, KeyMap};
use miniscript::{SigType, ToPublicKey};

use super::utils::SecpCtx;
use crate::descriptor::XKeyUtils;
use crate::wallet::error::MiniscriptPsbtError;

/// Identifier of a signer in the `SignersContainers`. Used as a key to find the right signer among
/// multiple of them
#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Hash)]
pub enum SignerId {
    /// Bitcoin HASH160 (RIPEMD160 after SHA256) hash of an ECDSA public key
    PkHash(hash160::Hash),
    /// The fingerprint of a BIP32 extended key
    Fingerprint(Fingerprint),
    /// Dummy identifier
    Dummy(u64),
}

impl From<hash160::Hash> for SignerId {
    fn from(hash: hash160::Hash) -> SignerId {
        SignerId::PkHash(hash)
    }
}

impl From<Fingerprint> for SignerId {
    fn from(fing: Fingerprint) -> SignerId {
        SignerId::Fingerprint(fing)
    }
}

/// Signing error
#[derive(Debug)]
pub enum SignerError {
    /// The private key is missing for the required public key
    MissingKey,
    /// The private key in use has the right fingerprint but derives differently than expected
    InvalidKey,
    /// The user canceled the operation
    UserCanceled,
    /// Input index is out of range
    InputIndexOutOfRange,
    /// The `non_witness_utxo` field of the transaction is required to sign this input
    MissingNonWitnessUtxo,
    /// The `non_witness_utxo` specified is invalid
    InvalidNonWitnessUtxo,
    /// The `witness_utxo` field of the transaction is required to sign this input
    MissingWitnessUtxo,
    /// The `witness_script` field of the transaction is required to sign this input
    MissingWitnessScript,
    /// The fingerprint and derivation path are missing from the psbt input
    MissingHdKeypath,
    /// The psbt contains a non-`SIGHASH_ALL` sighash in one of its input and the user hasn't
    /// explicitly allowed them
    ///
    /// To enable signing transactions with non-standard sighashes set
    /// [`SignOptions::allow_all_sighashes`] to `true`.
    NonStandardSighash,
    /// Invalid SIGHASH for the signing context in use
    InvalidSighash,
    /// Error while computing the hash to sign a Taproot input.
    SighashTaproot(sighash::TaprootError),
    /// PSBT sign error.
    Psbt(psbt::SignError),
    /// Miniscript PSBT error
    MiniscriptPsbt(MiniscriptPsbtError),
    /// To be used only by external libraries implementing [`InputSigner`] or
    /// [`TransactionSigner`], so that they can return their own custom errors, without having to
    /// modify [`SignerError`] in BDK.
    External(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey => write!(f, "Missing private key"),
            Self::InvalidKey => write!(f, "The private key in use has the right fingerprint but derives differently than expected"),
            Self::UserCanceled => write!(f, "The user canceled the operation"),
            Self::InputIndexOutOfRange => write!(f, "Input index out of range"),
            Self::MissingNonWitnessUtxo => write!(f, "Missing non-witness UTXO"),
            Self::InvalidNonWitnessUtxo => write!(f, "Invalid non-witness UTXO"),
            Self::MissingWitnessUtxo => write!(f, "Missing witness UTXO"),
            Self::MissingWitnessScript => write!(f, "Missing witness script"),
            Self::MissingHdKeypath => write!(f, "Missing fingerprint and derivation path"),
            Self::NonStandardSighash => write!(f, "The psbt contains a non standard sighash"),
            Self::InvalidSighash => write!(f, "Invalid SIGHASH for the signing context in use"),
            Self::SighashTaproot(err) => write!(f, "Error while computing the hash to sign a Taproot input: {}", err),
            Self::Psbt(err) => write!(f, "Error computing the sighash: {}", err),
            Self::MiniscriptPsbt(err) => write!(f, "Miniscript PSBT error: {}", err),
            Self::External(err) => write!(f, "{}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignerError {}

/// Signing context
///
/// Used by our software signers to determine the type of signatures to make
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerContext {
    /// Legacy context
    Legacy,
    /// Segwit v0 context (BIP 143)
    Segwitv0,
    /// Taproot context (BIP 340)
    Tap {
        /// Whether the signer can sign for the internal key or not
        is_internal_key: bool,
    },
}

/// Wrapper to pair a signer with its context
#[derive(Debug, Clone)]
pub struct SignerWrapper<S: Sized + fmt::Debug + Clone> {
    signer: S,
}

impl<S: Sized + fmt::Debug + Clone> SignerWrapper<S> {
    /// Create a wrapped signer from a signer and a context
    pub fn new(signer: S) -> Self {
        SignerWrapper { signer }
    }
}

impl<S: Sized + fmt::Debug + Clone> Deref for SignerWrapper<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.signer
    }
}

impl GetKey for SignerWrapper<KeyMap> {
    type Error = GetKeyError;

    fn get_key<C: secp256k1::Signing>(
        &self,
        key_request: psbt::KeyRequest,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        // eprintln!("keymap: {:#?}", self);

        for (descriptor_pk, descriptor_sk) in self.clone().iter() {
            match descriptor_sk {
                DescriptorSecretKey::Single(single_priv) => match key_request {
                    psbt::KeyRequest::Pubkey(public_key) => {
                        match single_priv.key.public_key(secp).eq(&public_key) {
                            true => return Ok(Some(single_priv.key)),
                            false => return Ok(None),
                        }
                    }
                    // FIXME: (@leonardo) Is this right ?
                    psbt::KeyRequest::Bip32(_) => return Err(GetKeyError::NotSupported),
                    psbt::KeyRequest::XOnlyPubkey(xonly_public_key) => {
                        let pubkey_even = bitcoin::PublicKey::new(
                            xonly_public_key.public_key(secp256k1::Parity::Even),
                        );
                        let key = match single_priv.key.public_key(secp) == pubkey_even {
                            true => Some(single_priv.key),
                            false => None,
                        };

                        // let key = self.get(&pubkey_even).cloned();

                        if key.is_some() {
                            return Ok(key);
                        }

                        let pubkey_odd = bitcoin::PublicKey::new(
                            xonly_public_key.public_key(secp256k1::Parity::Odd),
                        );

                        match single_priv.key.public_key(secp) == pubkey_odd {
                            true => {
                                let negated_priv_key = single_priv.key.negate();
                                return Ok(Some(negated_priv_key));
                            }
                            false => return Ok(None),
                        };

                        // if let Some(priv_key) = self.get(&pubkey_odd).copied() {
                        //     let negated_priv_key = priv_key.negate();
                        //     return Ok(Some(negated_priv_key));
                        // }

                        // Ok(None);
                        // eprintln!("xonlypubkey");
                        // todo!()
                    }
                    _ => return Err(GetKeyError::NotSupported),
                },
                DescriptorSecretKey::XPrv(descriptor_xpriv) => match key_request {
                    psbt::KeyRequest::Pubkey(public_key) => match descriptor_pk {
                        DescriptorPublicKey::XPub(descriptor_xkey) => {
                            match public_key.inner.eq(&descriptor_xkey.xkey.public_key) {
                                true => {
                                    return Ok(Some(
                                        descriptor_xpriv
                                            .xkey
                                            .derive_priv(secp, &descriptor_xpriv.derivation_path)?
                                            .to_priv(),
                                    ));
                                }
                                false => return Ok(None),
                            }
                        }
                        _ => return Err(GetKeyError::NotSupported),
                    },
                    psbt::KeyRequest::Bip32(ref key_source) => {
                        match GetKey::get_key(&descriptor_xpriv.xkey, key_request.clone(), secp) {
                            Ok(private_key) => match private_key {
                                Some(private_key) => return Ok(Some(private_key)),
                                None => {
                                    match descriptor_xpriv.matches(&key_source, secp) {
                                        Some(derivation_path) => {
                                            let xpriv = match &descriptor_xpriv.origin {
                                                Some((fingerprint, origin_derivation_path)) => {
                                                    let derivation_path = &key_source.1
                                                        [origin_derivation_path.len()..];
                                                    descriptor_xpriv
                                                        .xkey
                                                        .derive_priv(secp, &derivation_path)?
                                                }
                                                None => descriptor_xpriv
                                                    .xkey
                                                    .derive_priv(secp, &key_source.1)?,
                                            };
                                            return Ok(Some(xpriv.to_priv()));
                                        }
                                        None => return Ok(None),
                                    };
                                }
                            },
                            Err(e) => return Err(e),
                        }
                    }
                    psbt::KeyRequest::XOnlyPubkey(xonly_public_key) => {
                        eprintln!("xonlypubkey");
                        todo!()
                    }
                    _ => todo!(),
                },
                DescriptorSecretKey::MultiXPrv(descriptor_multi_xkey) => todo!(),
            }
        }
        Ok(None)
    }
}

/// Defines the order in which signers are called
///
/// The default value is `100`. Signers with an ordering above that will be called later,
/// and they will thus see the partial signatures added to the transaction once they get to sign
/// themselves.
#[derive(Debug, Clone, PartialOrd, PartialEq, Ord, Eq)]
pub struct SignerOrdering(pub usize);

impl Default for SignerOrdering {
    fn default() -> Self {
        SignerOrdering(100)
    }
}

#[derive(Debug, Clone)]
struct SignersContainerKey {
    id: SignerId,
    ordering: SignerOrdering,
}

impl From<(SignerId, SignerOrdering)> for SignersContainerKey {
    fn from(tuple: (SignerId, SignerOrdering)) -> Self {
        SignersContainerKey {
            id: tuple.0,
            ordering: tuple.1,
        }
    }
}

/// Container for multiple signers
#[derive(Debug, Default, Clone)]
pub struct SignersContainer(BTreeMap<SignersContainerKey, Arc<SignerWrapper<KeyMap>>>);

impl SignersContainer {
    /// Create a map of public keys to secret keys
    pub fn as_key_map(&self, secp: &SecpCtx) -> KeyMap {
        self.0
            .values()
            .filter_map(|signer| {
                let keymap: BTreeMap<DescriptorPublicKey, DescriptorSecretKey> =
                    signer.signer.clone();
                Some(keymap)
            })
            .flatten() // flat_map flattens the iterators
            .collect()
    }

    /// Build a new signer container from a [`KeyMap`]
    ///
    /// Also looks at the corresponding descriptor to determine the [`SignerContext`] to attach to
    /// the signers
    pub fn build(
        keymap: KeyMap,
        descriptor: &Descriptor<DescriptorPublicKey>,
        secp: &SecpCtx,
    ) -> SignersContainer {
        let mut container = SignersContainer::new();

        // FIXME: (@leonardo) solve the usage of clone here.
        for (pubkey, secret) in keymap.clone() {
            let signer = Arc::new(SignerWrapper::new(keymap.clone()));

            match secret {
                DescriptorSecretKey::Single(private_key) => container.add_external(
                    SignerId::from(
                        private_key
                            .key
                            .public_key(secp)
                            .to_pubkeyhash(SigType::Ecdsa),
                    ),
                    SignerOrdering::default(),
                    signer,
                ),
                DescriptorSecretKey::XPrv(xprv) => container.add_external(
                    SignerId::from(xprv.root_fingerprint(secp)),
                    SignerOrdering::default(),
                    signer,
                ),
                DescriptorSecretKey::MultiXPrv(xprv) => container.add_external(
                    SignerId::from(xprv.root_fingerprint(secp)),
                    SignerOrdering::default(),
                    signer,
                ),
            };
        }

        container
    }
}

impl SignersContainer {
    /// Default constructor
    pub fn new() -> Self {
        SignersContainer(Default::default())
    }

    /// Adds an external signer to the container for the specified id. Optionally returns the
    /// signer that was previously in the container, if any
    pub fn add_external(
        &mut self,
        id: SignerId,
        ordering: SignerOrdering,
        signer: Arc<SignerWrapper<KeyMap>>,
    ) -> Option<Arc<SignerWrapper<KeyMap>>> {
        self.0.insert((id, ordering).into(), signer)
    }

    /// Removes a signer from the container and returns it
    pub fn remove(
        &mut self,
        id: SignerId,
        ordering: SignerOrdering,
    ) -> Option<Arc<SignerWrapper<KeyMap>>> {
        self.0.remove(&(id, ordering).into())
    }

    /// Returns the list of identifiers of all the signers in the container
    pub fn ids(&self) -> Vec<&SignerId> {
        self.0
            .keys()
            .map(|SignersContainerKey { id, .. }| id)
            .collect()
    }

    /// Returns the list of signers in the container, sorted by lowest to highest `ordering`
    pub fn signers(&self) -> Vec<&Arc<SignerWrapper<KeyMap>>> {
        self.0.values().collect()
    }

    /// Finds the signer with lowest ordering for a given id in the container.
    pub fn find(&self, id: SignerId) -> Option<&Arc<SignerWrapper<KeyMap>>> {
        self.0
            .range((
                Included(&(id.clone(), SignerOrdering(0)).into()),
                Included(&(id.clone(), SignerOrdering(usize::MAX)).into()),
            ))
            .filter(|(k, _)| k.id == id)
            .map(|(_, v)| v)
            .next()
    }
}

// TODO: (@leonardo) After fully updating to use rust-bitcoin PSBTs signing feature, it should be removed and wallet API updated accordingly.
/// Options for a software signer
///
/// Adjust the behavior of our software signers and the way a transaction is finalized
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Whether the signer should trust the `witness_utxo`, if the `non_witness_utxo` hasn't been
    /// provided
    ///
    /// Defaults to `false` to mitigate the "SegWit bug" which could trick the wallet into
    /// paying a fee larger than expected.
    ///
    /// Some wallets, especially if relatively old, might not provide the `non_witness_utxo` for
    /// SegWit transactions in the PSBT they generate: in those cases setting this to `true`
    /// should correctly produce a signature, at the expense of an increased trust in the creator
    /// of the PSBT.
    ///
    /// For more details see: <https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd>
    pub trust_witness_utxo: bool,

    /// Whether the wallet should assume a specific height has been reached when trying to finalize
    /// a transaction
    ///
    /// The wallet will only "use" a timelock to satisfy the spending policy of an input if the
    /// timelock height has already been reached. This option allows overriding the "current height" to let the
    /// wallet use timelocks in the future to spend a coin.
    pub assume_height: Option<u32>,

    /// Whether the signer should use the `sighash_type` set in the PSBT when signing, no matter
    /// what its value is
    ///
    /// Defaults to `false` which will only allow signing using `SIGHASH_ALL`.
    pub allow_all_sighashes: bool,

    /// Whether to try finalizing the PSBT after the inputs are signed.
    ///
    /// Defaults to `true` which will try finalizing PSBT after inputs are signed.
    pub try_finalize: bool,

    /// Specifies which Taproot script-spend leaves we should sign for. This option is
    /// ignored if we're signing a non-taproot PSBT.
    ///
    /// Defaults to All, i.e., the wallet will sign all the leaves it has a key for.
    pub tap_leaves_options: TapLeavesOptions,

    /// Whether we should try to sign a taproot transaction with the taproot internal key
    /// or not. This option is ignored if we're signing a non-taproot PSBT.
    ///
    /// Defaults to `true`, i.e., we always try to sign with the taproot internal key.
    pub sign_with_tap_internal_key: bool,

    /// Whether we should grind ECDSA signature to ensure signing with low r
    /// or not.
    /// Defaults to `true`, i.e., we always grind ECDSA signature to sign with low r.
    pub allow_grinding: bool,
}

// TODO: (@leonardo) After fully updating to use rust-bitcoin PSBTs signing feature, it should be removed and wallet API updated accordingly.
/// Customize which taproot script-path leaves the signer should sign.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum TapLeavesOptions {
    /// The signer will sign all the leaves it has a key for.
    #[default]
    All,
    /// The signer won't sign leaves other than the ones specified. Note that it could still ignore
    /// some of the specified leaves, if it doesn't have the right key to sign them.
    Include(Vec<taproot::TapLeafHash>),
    /// The signer won't sign the specified leaves.
    Exclude(Vec<taproot::TapLeafHash>),
    /// The signer won't sign any leaf.
    None,
}

impl Default for SignOptions {
    fn default() -> Self {
        SignOptions {
            trust_witness_utxo: false,
            assume_height: None,
            allow_all_sighashes: false,
            try_finalize: true,
            tap_leaves_options: TapLeavesOptions::default(),
            sign_with_tap_internal_key: true,
            allow_grinding: true,
        }
    }
}

impl PartialOrd for SignersContainerKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignersContainerKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ordering
            .cmp(&other.ordering)
            .then(self.id.cmp(&other.id))
    }
}

impl PartialEq for SignersContainerKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.ordering == other.ordering
    }
}

impl Eq for SignersContainerKey {}

// FIXME: (@leonardo) It should be either fixed to reflect the changes on signer behavior or removed with this module.
#[cfg(all(test, never))]
mod signers_container_tests {
    use super::*;
    use crate::descriptor;
    use crate::descriptor::IntoWalletDescriptor;
    use crate::keys::{DescriptorKey, IntoDescriptorKey};
    use assert_matches::assert_matches;
    use bitcoin::bip32;
    use bitcoin::secp256k1::{All, Secp256k1};
    use bitcoin::Network;
    use core::str::FromStr;
    use miniscript::ScriptContext;

    fn is_equal(this: &Arc<SignerWrapper<KeyMap>>, that: &Arc<DummySigner>) -> bool {
        let secp = Secp256k1::new();
        this.id(&secp) == that.id(&secp)
    }

    // Signers added with the same ordering (like `Ordering::default`) created from `KeyMap`
    // should be preserved and not overwritten.
    // This happens usually when a set of signers is created from a descriptor with private keys.
    #[test]
    fn signers_with_same_ordering() {
        let secp = Secp256k1::new();

        let (prvkey1, _, _) = setup_keys(TPRV0_STR);
        let (prvkey2, _, _) = setup_keys(TPRV1_STR);
        let desc = descriptor!(sh(multi(2, prvkey1, prvkey2))).unwrap();
        let (wallet_desc, keymap) = desc
            .into_wallet_descriptor(&secp, Network::Testnet)
            .unwrap();

        let signers = SignersContainer::build(keymap, &wallet_desc, &secp);
        assert_eq!(signers.ids().len(), 2);

        let signers = signers.signers();
        assert_eq!(signers.len(), 2);
    }

    #[test]
    fn signers_sorted_by_ordering() {
        let mut signers = SignersContainer::new();
        let signer1 = Arc::new(DummySigner { number: 1 });
        let signer2 = Arc::new(DummySigner { number: 2 });
        let signer3 = Arc::new(DummySigner { number: 3 });

        // Mixed order insertions verifies we are not inserting at head or tail.
        signers.add_external(SignerId::Dummy(2), SignerOrdering(2), signer2.clone());
        signers.add_external(SignerId::Dummy(1), SignerOrdering(1), signer1.clone());
        signers.add_external(SignerId::Dummy(3), SignerOrdering(3), signer3.clone());

        // Check that signers are sorted from lowest to highest ordering
        let signers = signers.signers();

        assert!(is_equal(signers[0], &signer1));
        assert!(is_equal(signers[1], &signer2));
        assert!(is_equal(signers[2], &signer3));
    }

    #[test]
    fn find_signer_by_id() {
        let mut signers = SignersContainer::new();
        let signer1 = Arc::new(DummySigner { number: 1 });
        let signer2 = Arc::new(DummySigner { number: 2 });
        let signer3 = Arc::new(DummySigner { number: 3 });
        let signer4 = Arc::new(DummySigner { number: 3 }); // Same ID as `signer3` but will use lower ordering.

        let id1 = SignerId::Dummy(1);
        let id2 = SignerId::Dummy(2);
        let id3 = SignerId::Dummy(3);
        let id_nonexistent = SignerId::Dummy(999);

        signers.add_external(id1.clone(), SignerOrdering(1), signer1.clone());
        signers.add_external(id2.clone(), SignerOrdering(2), signer2.clone());
        signers.add_external(id3.clone(), SignerOrdering(3), signer3.clone());

        assert_matches!(signers.find(id1), Some(signer) if is_equal(signer, &signer1));
        assert_matches!(signers.find(id2), Some(signer) if is_equal(signer, &signer2));
        assert_matches!(signers.find(id3.clone()), Some(signer) if is_equal(signer, &signer3));

        // The `signer4` has the same ID as `signer3` but lower ordering.
        // It should be found by `id3` instead of `signer3`.
        signers.add_external(id3.clone(), SignerOrdering(2), signer4.clone());
        assert_matches!(signers.find(id3), Some(signer) if is_equal(signer, &signer4));

        // Can't find anything with ID that doesn't exist
        assert_matches!(signers.find(id_nonexistent), None);
    }

    #[derive(Debug, Clone, Copy)]
    struct DummySigner {
        number: u64,
    }

    const TPRV0_STR:&str = "tprv8ZgxMBicQKsPdZXrcHNLf5JAJWFAoJ2TrstMRdSKtEggz6PddbuSkvHKM9oKJyFgZV1B7rw8oChspxyYbtmEXYyg1AjfWbL3ho3XHDpHRZf";
    const TPRV1_STR:&str = "tprv8ZgxMBicQKsPdpkqS7Eair4YxjcuuvDPNYmKX3sCniCf16tHEVrjjiSXEkFRnUH77yXc6ZcwHHcLNfjdi5qUvw3VDfgYiH5mNsj5izuiu2N";

    const PATH: &str = "m/44'/1'/0'/0";

    fn setup_keys<Ctx: ScriptContext>(
        tprv: &str,
    ) -> (DescriptorKey<Ctx>, DescriptorKey<Ctx>, Fingerprint) {
        let secp: Secp256k1<All> = Secp256k1::new();
        let path = bip32::DerivationPath::from_str(PATH).unwrap();
        let tprv = bip32::Xpriv::from_str(tprv).unwrap();
        let tpub = bip32::Xpub::from_priv(&secp, &tprv);
        let fingerprint = tprv.fingerprint(&secp);
        let prvkey = (tprv, path.clone()).into_descriptor_key().unwrap();
        let pubkey = (tpub, path).into_descriptor_key().unwrap();

        (prvkey, pubkey, fingerprint)
    }
}

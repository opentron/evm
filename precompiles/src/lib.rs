//! The precompiles.

use evm_core::{ExitError, ExitSucceed};

use primitive_types::{H160, H256, U256};
use ripemd160::Ripemd160;
use secp256k1::{Message, RecoveryId, Signature};
use sha3::{Digest, Keccak256};
use sha2::Sha256;
use std::convert::TryInto;

pub fn tron_precompile(
	address: H160,
	input: &[u8],
	_target_gas: Option<usize>,
) -> Option<Result<(ExitSucceed, Vec<u8>, usize), ExitError>> {
	match address {
		// 0000000000000000000000000000000000000000000000000000000000000001
		// ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address)
		_ if address == H160::from_low_u64_be(1) => {
			const COST: usize = 3000;
			println!("oh year! calling ecrecover");
			let ret = ecrecover(input).unwrap_or_default();
			Some(Ok((ExitSucceed::Returned, ret.as_bytes().to_vec(), COST)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000002
		// sha256(...) returns (bytes32)
		_ if address == H160::from_low_u64_be(2) => unimplemented!(),
		// 0000000000000000000000000000000000000000000000000000000000000003
		// ripemd160(...) returns (bytes20)
		_ if address == H160::from_low_u64_be(3) => unimplemented!(),
		// 0000000000000000000000000000000000000000000000000000000000000004
		// identity(...) returns (...)
		// The Identity function simply returns whatever its input is.
		_ if address == H160::from_low_u64_be(4) => {
			const COST: usize = 15;
			let cost = 3 * (input.len() + 31 / 32);
			Some(Ok((ExitSucceed::Returned, input.to_vec(), COST + cost)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000005
		// modExp:
		// Modular exponentiation
		_ if address == H160::from_low_u64_be(5) => unimplemented!(),
		// https://eips.ethereum.org/EIPS/eip-196
		// 0000000000000000000000000000000000000000000000000000000000000006
		// altBN128Add
		// alt_bn128 Addition
		_ if address == H160::from_low_u64_be(6) => unimplemented!(),
		// 0000000000000000000000000000000000000000000000000000000000000007
		// altBN128Mul
		// alt_bn128 Scalar Multiplication
		_ if address == H160::from_low_u64_be(7) => unimplemented!(),
		// 0000000000000000000000000000000000000000000000000000000000000008
		// altBN128Pairing: pairing check
		// alt_bn128 Pairing Checks
		_ if address == H160::from_low_u64_be(8) => unimplemented!(),
		// TRON 3.6 update
		// 0000000000000000000000000000000000000000000000000000000000000009
		// batchValidateSign
		_ if address == H160::from_low_u64_be(9) => unimplemented!(),
		// 000000000000000000000000000000000000000000000000000000000000000a
		// validateMultiSign
		_ if address == H160::from_low_u64_be(0x0a) => unimplemented!(),
		// TRON 4.0 update: shielded contracts
		// 0000000000000000000000000000000000000000000000000000000001000001
		// 0000000000000000000000000000000000000000000000000000000001000002
		// 0000000000000000000000000000000000000000000000000000000001000003
		// 0000000000000000000000000000000000000000000000000000000001000004
		_ => None,
	}
}

fn ecrecover(input: &[u8]) -> Option<H256> {
	// let hash = H256::from_slice(&input[0..32]);
	// let r = H256::from_slice(&input[64..96]);
	// let s = H256::from_slice(&input[96..128]);
	let v: u8 = U256::from_big_endian(&input[32..64]).try_into().ok()?;

	let msg = Message::parse_slice(&input[0..32]).ok()?;
	let sig = Signature::parse_slice(&input[64..128]).ok()?;
	// TRON: rec_id fix is same as EVM
	let rec_id = RecoveryId::parse(v.wrapping_sub(27)).ok()?;

	let pub_key = secp256k1::recover(&msg, &sig, &rec_id).ok()?;
	let raw_pub_key = pub_key.serialize();

	let mut hasher = Keccak256::new();
	hasher.input(&raw_pub_key[1..]); // skip [0], type byte
	let digest = hasher.result();

	let mut ret = H256::zero();
	ret.as_bytes_mut()[12..32].copy_from_slice(&digest[digest.len() - 20..]);
	Some(ret)
}

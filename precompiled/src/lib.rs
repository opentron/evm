//! The precompiles.

use evm_core::{ExitError, ExitSucceed};

use digest::Digest;
use num_bigint::BigUint;
use num_traits::Zero;
use primitive_types::{H160, U256};
use sha2::Sha256;
use std::convert::TryFrom;

mod alt_bn128;
mod tron;
// mod ztron;

const WORD_SISZE: usize = 32;

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
			let ret = tron::ecrecover(input).unwrap_or_default();
			Some(Ok((ExitSucceed::Returned, ret.as_bytes().to_vec(), COST)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000002
		// sha256(...) returns (bytes32)
		_ if address == H160::from_low_u64_be(2) => {
			const COST: usize = 60;
			let cost = COST + 12 * (input.len() + 31) / 32;

			let mut hasher = Sha256::new();
			hasher.input(input);
			let ret = hasher.result().to_vec();

			Some(Ok((ExitSucceed::Returned, ret, cost)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000003
		// ripemd160(...) returns (bytes20)
		_ if address == H160::from_low_u64_be(3) => {
			const COST: usize = 600;
			let cost = COST + 120 * (input.len() + 31) / 32;

			let mut hasher = Sha256::new();
			hasher.input(input);
			let orig = hasher.result().to_vec();

			let mut hasher = Sha256::new();
			hasher.input(&orig[..20]);
			let ret = hasher.result().to_vec();

			Some(Ok((ExitSucceed::Returned, ret, cost)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000004
		// identity(...) returns (...)
		// The Identity function simply returns whatever its input is.
		_ if address == H160::from_low_u64_be(4) => {
			const COST: usize = 15;
			let cost = COST + 3 * ((input.len() + 31) / 32);
			Some(Ok((ExitSucceed::Returned, input.to_vec(), cost)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000005
		// modexp: modular exponentiation on big numbers
		_ if address == H160::from_low_u64_be(5) => {
			let words: Vec<_> = input.chunks(32).take(3).collect();

			let base_len = i32::try_from(U256::from_big_endian(&words[0])).unwrap() as usize;
			let exp_len = i32::try_from(U256::from_big_endian(&words[1])).unwrap() as usize;
			let modulus_len = i32::try_from(U256::from_big_endian(&words[2])).unwrap() as usize;

			let mut offset = 32 * 3;
			let base = BigUint::from_bytes_be(&input[offset..offset + base_len]);
			offset += base_len;

			let exp = BigUint::from_bytes_be(&input[offset..offset + exp_len]);
			offset += exp_len;

			let modulus = BigUint::from_bytes_be(&input[offset..offset + modulus_len]);

			let max_len = base_len.max(modulus_len);
			let mul_complexity = if max_len <= 64 {
				max_len.pow(2)
			} else if max_len <= 1024 {
				max_len.pow(2) / 4 + 96 * max_len - 3072
			} else {
				max_len.pow(2) / 16 + 480 * max_len - 199680
			};
			let adj_exp_len = exp.bits() as usize;
			let cost = mul_complexity * adj_exp_len.max(1) / 20;

			if modulus == BigUint::zero() {
				return Some(Ok((ExitSucceed::Returned, vec![], cost)));
			}

			let ret = base.modpow(&exp, &modulus).to_bytes_be();
			let ret_with_leading_zeros = if ret.len() < modulus_len {
				let mut fixed = vec![0u8; modulus_len - ret.len()];
				fixed.extend_from_slice(&ret);
				fixed
			} else {
				ret
			};

			Some(Ok((ExitSucceed::Returned, ret_with_leading_zeros, cost)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000006
		// altBN128Add: alt_bn128 Addition
		_ if address == H160::from_low_u64_be(6) => {
			const COST: usize = 500;

			let ret = alt_bn128::ecadd(input).unwrap_or_default();
			Some(Ok((ExitSucceed::Returned, ret, COST)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000007
		// altBN128Mul: alt_bn128 Scalar Multiplication
		_ if address == H160::from_low_u64_be(7) => {
			const COST: usize = 40000;

			let ret = alt_bn128::ecmul(input).unwrap_or_default();
			Some(Ok((ExitSucceed::Returned, ret, COST)))
		}
		// 0000000000000000000000000000000000000000000000000000000000000008
		// altBN128Pairing: pairing check
		_ if address == H160::from_low_u64_be(8) => {
			const COST: usize = 100000;
			const PAIR_SIZE: usize = 192;

			let cost = COST + 80000 * (input.len() / PAIR_SIZE);
			let ret = alt_bn128::ecpairing(input).unwrap_or_default();

			Some(Ok((ExitSucceed::Returned, ret, cost)))
		}
		// TRON 3.6 update
		// 0000000000000000000000000000000000000000000000000000000000000009
		// batchvalidatesign(bytes32 hash, bytes[] signatures, address[] addresses) returns (bytes32)
		_ if address == H160::from_low_u64_be(9) => {
			const COST_PER_SIGN: usize = 1500;

			let cost = COST_PER_SIGN * (input.len() / WORD_SISZE - 5) / 6;

			let ret = tron::batchvalidatesign(input).unwrap_or_default();
			Some(Ok((ExitSucceed::Returned, ret, cost)))
		}
		// 000000000000000000000000000000000000000000000000000000000000000a
		// validatemultisign(address addr, uint256 permissionId, bytes32 hash, bytes[] signatures) returns (bool)
		_ if address == H160::from_low_u64_be(0x0a) => {
			const COST_PER_SIGN: usize = 1500;
			let _cost = COST_PER_SIGN * (input.len() / WORD_SISZE - 5) / 6;

			unimplemented!()
		}
		// TRON 4.0 update: shielded contracts
		// 0000000000000000000000000000000000000000000000000000000001000001 - verifymintproof
		// 0000000000000000000000000000000000000000000000000000000001000002 - verifytransferproof
		// 0000000000000000000000000000000000000000000000000000000001000003 - verifyburnproof
		// 0000000000000000000000000000000000000000000000000000000001000004 - merklehash
		_ => None,
	}
}

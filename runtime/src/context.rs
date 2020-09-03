use primitive_types::{H160, U256, H256};

/// Create scheme.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CreateScheme {
	/// Legacy create scheme of `CREATE`.
	Legacy {
		/// Nonce of current transaction.
		nonce: u64,
		/// Transaction root hash.
		transaction_root_hash: H256,
	},
	/// Create scheme of `CREATE2`.
	Create2 {
		/// Caller of the create.
		caller: H160,
		/// Code hash.
		code_hash: H256,
		/// Salt.
		salt: H256,
	},
	/// Create at a fixed location.
	Fixed(H160),
}

/// Call scheme.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CallScheme {
	/// `CALL`
	Call,
	/// `CALLCODE`
	CallCode,
	/// `DELEGATECALL`
	DelegateCall,
	/// `STATICCALL`
	StaticCall,
	/// `CALLTOKEN`
	CallToken,
}

/// Context of the runtime.
#[derive(Clone, Debug, Default)]
pub struct Context {
	/// Execution address.
	pub address: H160,
	/// Caller of the EVM.
	pub caller: H160,
	/// Apparent value of the EVM.
	pub call_value: U256,
	/// Call token id.
	pub call_token_id: U256,
	/// Call token value.
	pub call_token_value: U256,
}

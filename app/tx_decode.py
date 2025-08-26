import rlp


def is_hex_string(value: str) -> bool:
	if not isinstance(value, str):
		return False
	if value.startswith("0x"):
		value = value[2:]
	try:
		int(value, 16)
		return True
	except Exception:
		return False


def extract_to_address(raw_tx_hex: str):
	data = raw_tx_hex[2:] if raw_tx_hex.startswith("0x") else raw_tx_hex
	raw = bytes.fromhex(data)
	# Typed tx if first byte in {1,2}
	if len(raw) == 0:
		return None
	if raw[0] in (1, 2):
		fields = rlp.decode(raw[1:])
		# EIP-2930/1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList, ...]
		to_bytes = fields[5] if len(fields) > 5 else b""
	else:
		# Legacy: [nonce, gasPrice, gas, to, value, data, v, r, s]
		fields = rlp.decode(raw)
		to_bytes = fields[3] if len(fields) > 3 else b""
	if not to_bytes:
		return None
	return "0x" + to_bytes.hex()

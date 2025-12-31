extends Node

const ENCRYPTION_KEY = "ThisIsA32ByteEncryptionKey!!"
const SALT = "FNaFSL_CustomNight_Salt_2024"

func encrypt_data(data: Variant) -> PackedByteArray:
	var json_string = JSON.stringify(data)
	var bytes = (json_string + "|" + (json_string + SALT).sha256_text()).to_utf8_buffer()
	bytes.resize(int((bytes.size() + 15.0) / 16.0) * 16)
	
	var aes = AESContext.new()
	var key = ENCRYPTION_KEY.to_utf8_buffer()
	key.resize(32)
	aes.start(AESContext.MODE_ECB_ENCRYPT, key)
	
	var encrypted = aes.update(bytes)
	aes.finish()
	return encrypted

func decrypt_data(encrypted: PackedByteArray) -> Variant:
	var key = ENCRYPTION_KEY.to_utf8_buffer()
	key.resize(32)
	
	var aes = AESContext.new()
	aes.start(AESContext.MODE_ECB_DECRYPT, key)
	var decrypted_string = aes.update(encrypted).get_string_from_utf8().strip_edges()
	aes.finish()
	
	var separator_pos = decrypted_string.find("|")
	if separator_pos == -1:
		return null
	
	var json_string = decrypted_string.substr(0, separator_pos)
	if (json_string + SALT).sha256_text() != decrypted_string.substr(separator_pos + 1):
		return null
	
	return JSON.parse_string(json_string)
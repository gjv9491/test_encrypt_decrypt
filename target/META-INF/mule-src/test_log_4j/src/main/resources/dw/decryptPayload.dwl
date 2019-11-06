%dw 2.0
import * from dw::Core
import decryptMe from java!kms::EncryptionUtils
fun decrypt(encrypted_fields: Array, encrypted_key: String, payload) =
	payload mapObject(value, key) -> {
	   (key as String match  {
	    case str if (str == encrypted_key) -> 
	        (encrypted_fields map (decrypt) -> {
	        (decrypt mapObject ((value, key, index) -> {
	            (key):(decryptMe(value.decryption_credentials_path as String,
				value.decryption_key as String,
				value.encryption_context as String,
				value.encrypted_value as String)) default value
	        })
	        )})
	    else -> (key):value
	   })	
	}
/*
 * Pass in payload with encrypted_fields array return decrypted values and removes encrypted_fields array
 * decrypt(payload.encrypted_fields, "encrypted_fields", payload)
*/
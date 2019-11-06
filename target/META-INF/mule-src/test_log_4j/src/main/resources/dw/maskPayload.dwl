%dw 2.0
import * from dw::Core
fun mask(encrypted_fields: Array, encrypted_key: String, payload) =
	payload mapObject(value, key) -> {
	   (key as String match  {
	    case str if (str == encrypted_key) -> 
	        ((encrypted_fields) as Array map (decrypt) -> {
	        (decrypt mapObject ((value, key, index) -> {
	            (key): (value.encrypted_value as String) [0 to 4] replace  /./ with("*")
	        })
	        )})
	    else -> (key):value
	   })	
	}
/*
 * Pass in payload with encrypted_fields array return masked values
 * mask(payload.encrypted_fields, "encrypted_fields", payload)
*/
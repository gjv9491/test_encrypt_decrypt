package kms;

import java.util.Collections;
import java.util.Map;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.kms.*;
import com.amazonaws.services.kms.model.*;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.auth.*;
import com.amazonaws.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;


import static org.apache.commons.lang3.StringUtils.isEmpty;


class AWSVariables {
	public static final long DEFAULT_TIMEOUT_SECONDS = 900;
	public static final long DEFAULT_POLLING_FREQUENCY_SECONDS = 15;
	public static final String ROLE_SESSION_NAME = "AssumeRoleSession1";
	
}

public class EncryptionUtils {
	
	private static String encrypt(final AWSKMS kmsClient, final String keyId, final String data, final String encryptionContext) {
		String result = null;
		try {
			ByteBuffer plaintext = ByteBuffer.wrap(data.getBytes());
			EncryptRequest req = new EncryptRequest()
					.withKeyId(keyId)
					.withPlaintext(plaintext)
					.withEncryptionContext(getEncryptionContext(encryptionContext));
			
			ByteBuffer ciphertext = kmsClient.encrypt(req).getCiphertextBlob();
			byte[] base64EncodedValue = Base64.encode(ciphertext.array());
			result = new String(base64EncodedValue, Charset.forName("UTF-8"));
		} catch (AmazonServiceException ase) {
			ase.printStackTrace();
		} catch (AmazonClientException ace) {
	        }
	        return result;
	    }

	    private static String decrypt(final AWSKMS kmsClient, final String ciphertext, final String encryptionContext) {
	        String result=null;
	        try{
	            String cipherString = ciphertext;
	            byte[] cipherBytes = Base64.decode(cipherString);
	            ByteBuffer cipherBuffer = ByteBuffer.wrap(cipherBytes);
	            DecryptRequest req = new DecryptRequest()
	                    .withCiphertextBlob(cipherBuffer)
	                    .withEncryptionContext(getEncryptionContext(encryptionContext));
	            DecryptResult resp = kmsClient.decrypt(req);
	            result = new String(resp.getPlaintext().array(), Charset.forName("UTF-8"));
	        } catch (AmazonServiceException ase) {
	            ase.printStackTrace();
	        } catch (AmazonClientException ace) {
	            ace.printStackTrace();
	        }
	        return result;
	    }

	    private static AWSCredentials getCredentials(final String ROLE_IAM) {
	        if (isEmpty(ROLE_IAM)) return null;

	        int credsDuration = (int) (AWSVariables.DEFAULT_TIMEOUT_SECONDS
	                * AWSVariables.DEFAULT_POLLING_FREQUENCY_SECONDS);

	        if (credsDuration > 3600) {
	            credsDuration = 3600;
	        }

	        AssumeRoleRequest assumeRequest = new AssumeRoleRequest()
	                .withRoleArn(ROLE_IAM)
	                .withDurationSeconds(credsDuration)
	                .withRoleSessionName(AWSVariables.ROLE_SESSION_NAME);

	        AssumeRoleResult assumeResult = new AWSSecurityTokenServiceClient().assumeRole(assumeRequest);

	        BasicSessionCredentials credentials = new BasicSessionCredentials(
	                assumeResult.getCredentials().getAccessKeyId(),
	                assumeResult.getCredentials().getSecretAccessKey(),
	                assumeResult.getCredentials().getSessionToken());

	        return credentials;
	    }


	    private static Map<String, String> getEncryptionContext(final String encryptContext){
	        Map<String, String> map =Collections.emptyMap();
	        ObjectMapper mapper = new ObjectMapper();
	        try {

	            // convert JSON string to Map
	            map = mapper.readValue(encryptContext, Map.class);

	        } catch (IOException e) {
	            e.printStackTrace();
	        }
	        return map;
	    }


	    private static AWSKMS getKmsClient(final AWSCredentials creds, final String region) throws AWSKMSException {
	            final AWSKMS kmsClient = AWSKMSClientBuilder.standard()
	                    .withCredentials(new AWSStaticCredentialsProvider(creds))
	                    .withRegion(region).build();
	            return kmsClient;
	    }

	    public static String decryptMe(final String ROLE_IAM, final String ROLE_ARN,
	                                   final String encryptionContext, final String data ){
	    	String decrypted_value=null;
	    	try {
	        final String region= ROLE_ARN.split(":")[3];
	        final String keyId= ROLE_ARN.split("/")[1];
	        EncryptionUtils app = new EncryptionUtils();

	        AWSCredentials creds_temp = app.getCredentials(ROLE_IAM);
	        AWSKMS kmsClient = app.getKmsClient(creds_temp, region);
	        //String value = app.encrypt(kmsClient, keyId, data, encryptCntxt);
	        //System.out.println("encrypted value: " + value);
	        //System.out.println("decrypted value: " + devalue);
	        decrypted_value = app.decrypt(kmsClient, data, encryptionContext);
	    	} catch (Exception e) {
	            e.printStackTrace();
	    }
	 	   return decrypted_value;
	    }
	    
	    public static void main(String[] args) {
	        System.out.println();
	    }

	}
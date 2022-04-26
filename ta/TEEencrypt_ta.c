

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TA_TEEencrypt.h>

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */

const uint32_t rootkey =1;
int key=3;


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}


TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,TEE_Param __maybe_unused params[4],void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */


unsigned char rnd[16];

static TEE_Result TEE_GENERATEKEY(uint32_t param_types,TEE_Param params[4])
{
	uint32_t exp_param_types =
				TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	DMSG("has been called");
	if (param_types != exp_param_types)
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}		

	IMSG("Generating random data over %u bytes.", params[0].memref.size);

	TEE_GenerateRandom(rnd,sizeof(rnd));
	
	int a = rnd;
	int fixedrand  = ((a-1)%25)+1;
	key = fixedrand + rootkey;
	DMSG("\n\nvalue: %d\n\n",fixedrand );
	
	
	params[0].value.a = fixedrand;
	
	return TEE_SUCCESS;

}


static TEE_Result TEE_ENCRYPT(uint32_t param_types, TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [200]={0,};

	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}

	//DMSG("\n\n\ninlen:%d \nsent: %s \n\n\n",in_len, encrypted );

	DMSG ("Ciphertext :  %s", encrypted);
	memcpy(in, encrypted, in_len);

	return TEE_SUCCESS;
}


static TEE_Result TEE_SENDKEY(uint32_t param_types,TEE_Param params[4])
{
	DMSG("========================SENDING KEY...========================\n");

	DMSG("params: %d\n", params[0].value.a);
	key = params[0].value.a + rootkey;

	return TEE_SUCCESS;

}




static TEE_Result TEE_DECRYPT(uint32_t param_types,TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [200]={0,};

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	memcpy(decrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);



	return TEE_SUCCESS;
}




TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,uint32_t cmd_id,uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	

	switch (cmd_id) {
	
	case TA_TEEencrypt_GENERATEKEY:
			DMSG("BUILDING KEY...");
		return TEE_GENERATEKEY(param_types, params);

	case TA_TEEencrypt_ENCRYPT:
			DMSG("ENCRYPT COMMECNING...");
		return TEE_ENCRYPT(param_types, params);

	case TA_TEEencrypt_DECRYPT:
			DMSG("DECRYPT COMMENCING");
		return TEE_DECRYPT(param_types, params);

	case TA_TEEencrypt_SENDKEY:
			DMSG("KEY SENT");
		return TEE_SENDKEY(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

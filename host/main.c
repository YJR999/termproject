

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>



/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TA_TEEencrypt.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = {0};
	TEEC_Operation newop;
	TEEC_Operation decryptop;
	TEEC_Operation sendkeyop;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	int random_uuid[16] = { 0 };

	int randomkey;
		
	TEEC_Operation generatedkeyop={0};	
	char strNormal[200] = {0,};
	char strEncrypt[200] = {0,};
	char strDecrypt[200] = {0,};
	char strRead[200] = {0,};
	int sendKey ;
	int len =200;
	FILE *file;
	   
	if(argc!=3)
	{
		printf("error. put right arguments.\n");
	
	return 0;
	}

	if(  !(!strcmp(argv[1],"-d") || !strcmp(argv[1],"-e"))  )
	{
		printf("error put right orders.\n");
		return 0;
	}
	
	
	
	//printf("\n\n%s \n %d \n", decryptop.params[0].tmpref.buffer, strlen(argv[2]));
	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x %x origin 0x %x",res, err_origin);

	memset(&newop, 0, sizeof(newop));
	memset(&sendkeyop, 0, sizeof(sendkeyop));
	memset(&op, 0, sizeof(op));
	memset(&decryptop, 0, sizeof(decryptop));
	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,TEEC_NONE, TEEC_NONE, TEEC_NONE);
	decryptop.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	newop.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	sendkeyop.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);		


	op.params[0].tmpref.buffer = random_uuid;
	op.params[0].tmpref.size = sizeof(random_uuid);
	op.params[0].value.a = 0;
	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */

	if( !strcmp(argv[1],"-e") )
	{
		char file_buff[3];

		printf("===============ENCRYPTING...===================\n");
//random
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_GENERATEKEY, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_GENERATEKEY, &newop, &err_origin);
		//randomkey = (op.params[0].value.a-1)%25 +1; 
			randomkey = op.params[0].value.a;
			printf("\n\nval: %d \n\n",newop.params[0].value.a);
			
//random		

		strcpy(strNormal,argv[2]);
		
		decryptop.params[0].tmpref.buffer = strNormal;
		decryptop.params[0].tmpref.size = len;

		memcpy(decryptop.params[0].tmpref.buffer, strNormal, len);
			

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_ENCRYPT, &decryptop, &err_origin);


		memcpy(strEncrypt, decryptop.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", strEncrypt);// encrypted string


		printf("====Encrypt done. making file...====");
	
		file = fopen("TEEencrypted.txt","w+");
	


		if(file == NULL)//failed
		{
			printf("error. can't make file\n");
		}
		else//success
		{
			sprintf(file_buff,"%02d", randomkey);


			fputs(file_buff,file);
			
			fputs(strEncrypt,file);
			printf("file is built.\n");
		}

		fclose(file);

	}



	if( !strcmp(argv[1],"-d") )
	{
		const int extendedmax = 202;
		char stringsave[extendedmax];
		char substringsave[extendedmax];
	printf("======================DECRYPTING...======================\n");
		file = fopen("TEEencrypted.txt","r");

		if(file == NULL)//failed
		{
			printf("error. can't find file\n");
		}
		else//success
		{
 			char * stringans = fgets(stringsave, extendedmax, file);  

			strncpy(substringsave,stringsave+2,200); //cut for decrypt
			
			
			int sendkey=0;
		
			sendkey = (stringsave[0]-48)*10+stringsave[1]-48;
			sendkeyop.params[0].value.a = sendkey;
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_SENDKEY, &sendkeyop, &err_origin);

	//		printf("\n%d\n",sendkey);
		
    	//		 printf("%s\n%s\n",stringsave,substringsave);  //test

		decryptop.params[0].tmpref.buffer = substringsave; //final string
		decryptop.params[0].tmpref.size = len;
		memcpy(strEncrypt, decryptop.params[0].tmpref.buffer, len);

		fclose(file); 

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_DECRYPT, &decryptop, &err_origin);


		memcpy(strEncrypt, decryptop.params[0].tmpref.buffer, len);
		printf("Normaltext : %s\n", strEncrypt);// decrypted string
		file = fopen("TEEencrypted.txt","w");
			if(file!=NULL)//fix here if bug exists
			{
				fputs(strEncrypt,file);
				fclose(file); 
			}
		

		}

		 
	}


	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",res, err_origin);
	
	

	
	/*
	 * We're done with the TA, close the s3 ession and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
		

	return 0;
}

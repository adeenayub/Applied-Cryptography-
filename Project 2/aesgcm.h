#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

void HandleAllErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char *plaintxt, int plaintxt_len, unsigned char *additionalData, int additionalData_len, unsigned char *AESkey, unsigned char *IV, unsigned char *ciphertxt, unsigned char *tag)
{
	EVP_CIPHER_CTX *context = NULL;
	int len = 0;
	int cipher_len = 0;
	if(!(context = EVP_CIPHER_CTX_new())) 
	{
		HandleAllErrors();
	}

	if(EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 )
	{
        	HandleAllErrors();
	}

	if(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1)
        {
		HandleAllErrors();
	}
	
	if(1 != EVP_EncryptInit_ex(context, NULL, NULL, AESkey, IV))
	{
		HandleAllErrors();
	}
    
    	if(additionalData && additionalData_len > 0)
    	{
        	if(EVP_EncryptUpdate(context, NULL, &len, additionalData, additionalData_len) != 1 )
        	{
			HandleAllErrors();
	    	}
	}

	if(plaintxt)
	{
        	if(EVP_EncryptUpdate(context, ciphertxt, &len, plaintxt, plaintxt_len) != 1)
            	{
			HandleAllErrors();
		}
        	cipher_len = len;
    	}

	if(EVP_EncryptFinal_ex(context, ciphertxt + len, &len) != 1) 
	{
		HandleAllErrors();
	}
	cipher_len += len;

	if(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
	{
	        HandleAllErrors();
	}
	EVP_CIPHER_CTX_free(context);

	return cipher_len;
}

int decrypt(unsigned char *ciphertxt, int cipher_len, unsigned char *additionalData, int additionalData_len, unsigned char *tag, unsigned char *AESkey, unsigned char *IV, unsigned char *plaintxt)
{
	EVP_CIPHER_CTX *context = NULL;
	int len = 0;
	int plaintxt_len = 0;
	int val;

	if(!(context = EVP_CIPHER_CTX_new()))
	{
		HandleAllErrors();
	}

	if(!EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
		HandleAllErrors();
	}
 
	if(!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        {
		HandleAllErrors();
	}

	if(!EVP_DecryptInit_ex(context, NULL, NULL, AESkey, IV))
	{
		HandleAllErrors();
	}

	if(additionalData && additionalData_len > 0)
	{
        	if(!EVP_DecryptUpdate(context, NULL, &len, additionalData, additionalData_len))
            	{
			HandleAllErrors();
		}
	}
   
	if(ciphertxt)
	{
        	if(!EVP_DecryptUpdate(context, plaintxt, &len, ciphertxt, cipher_len))
		{
			HandleAllErrors();
		}
        	plaintxt_len = len;
    	}

	if(!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, tag))
        {
		HandleAllErrors();
	}
    
	val = EVP_DecryptFinal_ex(context, plaintxt + len, &len);

	EVP_CIPHER_CTX_free(context);

	if(val > 0)
	{
        	plaintxt_len += len;
        	return plaintxt_len;
	}
	else
	{
        	return -1;
    	}
}

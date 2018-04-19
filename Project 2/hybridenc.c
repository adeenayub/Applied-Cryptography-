#include "aesgcm.h"
#define BUFFSIZE 2048 
unsigned char key[256], IV[128];
//unsigned char plaintext[];
unsigned char ciphertext[128];
unsigned char decryptedtext[128];
unsigned char aad[] = "Some AAD data";
unsigned char tag[16];
int cipher_len = 0;

void GenerateSymmetricKey()
{
	
	if(!RAND_bytes(key, sizeof(key)))
	{
		printf("Could not generate the key\n");
	}
	if(!RAND_bytes(IV, sizeof(IV)))
	{
		printf("Could not generate the IV\n");
	}
	printf("key is %#x\n", key);
}

void Encrypt()
{
	unsigned char plaintext[] = "Alhamdulillah. Symmetric encryption is being done\n";	
	cipher_len = encrypt(plaintext, strlen(plaintext), aad, strlen(aad), key, IV, ciphertext, tag);
	printf("The ciphertext is:\n");
  	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	

}

void Decrypt()
{
	
	int decryptxt_len = decrypt(ciphertext, cipher_len, aad, strlen(aad), tag, key, IV, decryptedtext);

    if(decryptxt_len < 0)
    {
        printf("some error occured\n");
    }
    else
    {
	decryptedtext[decryptxt_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    }
}

void main()
{
	GenerateSymmetricKey();
	Encrypt();
	Decrypt();
	
}

#include <stdlib.h>
#include <openssl/err.h>
#include "aesgcm.h"
#include "RSA.h"

#define PORT 8080
#define BUFFSIZE 1024
#define KEYSIZE 32
#define BUFFY 10000
#define TAGIVSIZE 16
#define ENCRYPTEDKEYSIZE 256

unsigned char key[KEYSIZE];
unsigned char IV[TAGIVSIZE];
unsigned char ciphertext[BUFFY];
unsigned char decryptedtext[BUFFY];
unsigned char additionalData[] = "additional data";
unsigned char tag[TAGIVSIZE];
char enckey[ENCRYPTEDKEYSIZE];
int cipher_len = 0;


void GenerateSymmetricKey()
{
	if(!RAND_bytes(key, sizeof(key)))
	{
		printf("Could not generate the key\n");
	}
	//return key;
} 

void generateIV()
{
	if(!RAND_bytes(IV, sizeof(IV)))
	{
		printf("Could not generate the IV\n");
		
	}
}


void Encrypt()
{
	
	int plaintext_len = 0;
    	printf("Give a length of plaintext\n");
	scanf("%d", &plaintext_len);
	
	printf("Enter the plaintext\n");
	char *plaintext = malloc(plaintext_len);
	scanf(" %[^\t\n]%*c", plaintext);
  	//printf("Size is %d\n",(int)strlen(plaintext) );
	
	if(plaintext_len == (int)strlen(plaintext))
	{
	
		cipher_len = encrypt((unsigned char*)plaintext, strlen(plaintext), additionalData, strlen(additionalData), key,IV, ciphertext, tag);
		//printf("The ciphertext is:\n");
	  	//BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	}
	else
	{
		printf("Please enter the plaintext equal to the size you mentioned\n");
		printf("Program exited...\n");
		exit(1);
	}

}

void Decrypt()
{
	//PrintinHex(decryptedkey, sizeof(decryptedkey));
	//PrintinHex(ciphertext, sizeof(ciphertext));
	//PrintinHex(IV, sizeof(IV));
	int decryptxt_len = decrypt(ciphertext, (int)strlen(ciphertext), additionalData, strlen(additionalData), tag, decryptedkey, IV, decryptedtext);

    if(decryptxt_len < 0)
    {
        printf("some error occured\n");
    }
    else
    {
	decryptedtext[decryptxt_len] = '\0';

        printf("The decrypted text is:\n");
        printf("%s\n", decryptedtext);
	//printf("its length is %d", decryptxt_len);
    }
}

void main()
{
	//Bob generates a key//
	RSAKeyGenerator();
	//Alice generates symmetric key
	GenerateSymmetricKey();
	//Alice encrypts her message
	Encrypt();
	//Alice encrypts her key with Bob's public key//
	EncryptSymmetricKey(key);
	//Bob does the following//
	DecryptSymmetricKey();
	Decrypt();
}

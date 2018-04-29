#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#define RSAKEYLEN 2048
#define PUBLICXPONENT 3

RSA *keypair;
size_t priv_keylen;
size_t pub_keylen;
char *priv_key;
char *pub_key;
char *encryptedkey;
char *decryptedkey;
BIO *bp_public = NULL;
BIO *bp_private = NULL;
int enc;


void RSAKeyGenerator()
{	
	printf("\n.............Generating RSA KEY PAIR IA............\n");
	keypair = RSA_generate_key(RSAKEYLEN, PUBLICXPONENT, NULL, NULL);
	bp_public = BIO_new_file("public.pem", "w+");
    	PEM_write_bio_RSAPublicKey(bp_public, keypair);
	bp_private = BIO_new_file("private.pem", "w+");
    	PEM_write_bio_RSAPrivateKey(bp_private, keypair, NULL, NULL,0,NULL,NULL);
	priv_keylen = BIO_pending(bp_private);
	pub_keylen = BIO_pending(bp_public);
	priv_key = malloc(priv_keylen + 1);
	pub_key = malloc(pub_keylen + 1);
	BIO_read(bp_private, priv_key, priv_keylen);
	BIO_read(bp_public, pub_key, pub_keylen);
	priv_key[priv_keylen] = '\0';
	pub_key[pub_keylen] = '\0';
}

void free_var()
{
	
		RSA_free(keypair);
		BIO_free_all(bp_public);
    		BIO_free_all(bp_private);
		free(priv_key);
		free(pub_key);
		free(encryptedkey);
		free(decryptedkey);
}
void EncryptSymmetricKey(unsigned char * key1)
{	
	encryptedkey = malloc(RSA_size(keypair));
	enc = RSA_public_encrypt(32, key1, (unsigned char *)encryptedkey, keypair, RSA_PKCS1_OAEP_PADDING);
	if (enc == -1)
	{
		perror("Error in encryption\n");
		free_var();
	}
	//printf("The 256 bit AES key is \n");
	//PrinttinHex(key1, 32);
	//printf("size of encrypted text is %d\n", enc);
	//printf("The encrypted text is \n");
	//PrinttinHex(encryptedkey, enc); 
}

void DecryptSymmetricKey()
{	
	decryptedkey = malloc(enc);
	int dec = RSA_private_decrypt(enc,(unsigned char*)encryptedkey, (unsigned char *)decryptedkey, keypair, RSA_PKCS1_OAEP_PADDING);
    	if(dec == -1)
	{
		perror("error in decryption\n");
		free_var();
	}
	//printf("size of decr is %d\n", dec);
	//printf("The decrypted key is \n");
	//PrinttinHex(decryptedkey, enc);
}


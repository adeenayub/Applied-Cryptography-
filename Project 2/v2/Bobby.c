#include "aesgcm.h"
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define BUFFSIZE 1024
#define keySizeinBytes 32
#define BUFFY 10000
#define TAGIVSIZE 16

unsigned char key[keySizeinBytes];
unsigned char IV[TAGIVSIZE];
unsigned char ciphertext[BUFFY];
unsigned char decryptedtext[BUFFY];
unsigned char additionalData[] = "additional data";
unsigned char tag[TAGIVSIZE];
int cipher_len = 0;

void Decrypt()
{
	PrintinHex(key, sizeof(key));
	PrintinHex(ciphertext, sizeof(ciphertext));
	PrintinHex(IV, sizeof(IV));
	int decryptxt_len = decrypt(ciphertext, (int)strlen(ciphertext), additionalData, strlen(additionalData), tag, key, IV, decryptedtext);

    if(decryptxt_len < 0)
    {
        printf("some error occured\n");
    }
    else
    {
	decryptedtext[decryptxt_len] = '\0';

        printf("The decrypted text is:\n");
        printf("%s\n", decryptedtext);
	printf("its length is %d", decryptxt_len);
    }
}
void main()
{
	char *line = malloc(sizeof(char)*BUFFSIZE); 
	int len;
	printf("Assalamualaikum! I am Bob. I am waiting for Alice to send me a message\n");
	int skt = 0;
	struct sockaddr_in serv_address; /*datatype of sockets by Socket API*/
	/*Creating a TCP socket*/
	skt = socket(AF_INET,SOCK_STREAM ,0); /*Protocol set to default*/
	/*if Socket not created, error printed and program exits*/
	if(skt < 0)
	{
		perror("Socket not created\n");
		exit(1);
	}
	memset(&serv_address, '0', sizeof(serv_address));
	serv_address.sin_family = AF_INET; /*IP4*/
    	serv_address.sin_port = htons( PORT ); /*assigning port 8080 to the socket*/

	/*checking the address validity*/
	if(inet_pton(AF_INET, "127.0.0.1", &serv_address.sin_addr)<=0) 
    	{
		perror("The address is not valid \n");
		exit(1);
    	}
	/*Connecting to the server that's in the listening mode*/
	if (connect(skt, (struct sockaddr *)&serv_address, sizeof(serv_address)) < 0)
    	{
        	printf("The client has failed to connect to server \n");
        	exit(1);
    	}
		//printf("Enter a string containing alphabets and/or numbers  ");
		//fgets(line, BUFFSIZE, stdin);
		//printf("here");
		//len = strlen(line);
		//send(skt,line,strlen(line),0);	
		printf("oki");
		if(recv(skt, (char *)key, 32, 0) < 0)
		{
			;
		}
		else
		{
			if(recv(skt, (char *)IV, TAGIVSIZE, 0) < 0)
			{
				;
			}
			else
			{
				if(recv(skt, (char *)tag, TAGIVSIZE, 0) < 0)
				{
					;
				}
				else
				{
					if(recv(skt, (char *)ciphertext, BUFFY, 0) < 0) 					{
						;
					}
					else
					{					
						printf("\n%d is the len of cipher\n",(int) strlen(ciphertext));
						printf("cipher received ALhamdulillah\n"); 
						BIO_dump_fp (stdout, (const char *)ciphertext, (int)strlen(ciphertext));
						Decrypt();
					}
				}
			}
		}
	/*Closing the socket*/
	close(skt);
	
}

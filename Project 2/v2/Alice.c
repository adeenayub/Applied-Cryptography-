#include <sys/socket.h>
#include <unistd.h>  /*for closesocket*/
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "aesgcm.h"

#define PORT 8080
#define BUFFSIZE 1024
#define keySizeinBytes 32
#define BUFFY 10000 
int sockid, status, serv_accept, data_count, new_sock;
struct sockaddr_in serv_address, client_address;
socklen_t clientaddr_len;

unsigned char key[keySizeinBytes];
unsigned char IV[16];
unsigned char ciphertext[BUFFY];
unsigned char decryptedtext[BUFFY];
unsigned char additionalData[] = "additional data";
unsigned char tag[16];
int cipher_len = 0;



void GenerateSymmetricKey()
{
	
	if(!RAND_bytes(key, sizeof(key)))
	{
		printf("Could not generate the key\n");
	}
	
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
	//unsigned char plaintext[] = "Alhamdulillah. Symmetric encryption is being done\n";
	//size_t plaintext_len = 0;
	int plaintext_len = 0;
    	printf("Give a length of plaintext\n");
	scanf("%d", &plaintext_len);
	
	printf("Enter the plaintext\n");
	char *plaintext = malloc(plaintext_len);
	scanf(" %[^\t\n]%*c", plaintext);
  	printf("Size is %d\n",(int)strlen(plaintext) );
	
	if(plaintext_len == (int)strlen(plaintext))
	{
	
		cipher_len = encrypt((unsigned char*)plaintext, strlen(plaintext), additionalData, strlen(additionalData), key,IV, ciphertext, tag);
		printf("The ciphertext is:\n");
	  	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	}
	else
	{
		printf("Please enter the plaintext equal to the size you mentioned\n");
		printf("Program exited...\n");
		exit(1);
	}

}
 

/*Function to read file so that the server can output on screen*/
static void Readfile(const char * fname)
{
    FILE *f = fopen(fname, "r");    
    if(f != NULL)
    {
        int ch;

        while((ch = fgetc(f)) != EOF)     
        {
            putchar(ch);      
        }
        fclose(f);
    }
}


void main()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	FILE * myfile;
	int opt = 1; 
	printf("Assalamualaikum! I am Alice. Nice to see you! I'm gonna send a message to Bob IA. Dare not see. \n");
	/*Create a socket*/
	sockid = socket(AF_INET,SOCK_STREAM ,0);
	/*Print error if not created*/
	if(sockid == 0)
	{
		perror("Failed to create a socket");
		exit(1);
	}
	/*Allow socket options to be set*/
	if (setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
   	{
       		perror("setsockopt");
        	exit(EXIT_FAILURE);
    	}
	serv_address.sin_family = AF_INET;
    	serv_address.sin_addr.s_addr = INADDR_ANY;
    	serv_address.sin_port = htons( PORT );
	/*Reserve port for use by the socket*/
	if (bind(sockid, (struct sockaddr *)&serv_address,
					sizeof(serv_address))<0)
	{
		perror("Failed to bind the socket");
		exit(1);
	}
	/*Server enters the listening mode and prints an error condition if an error occurs*/
	if(listen(sockid, 1) < 0)
	{
		perror("The server has failed to listen on this port ");
		exit(1);
	}
	printf("The server is listening\n");
	
	clientaddr_len = sizeof(client_address);
	
	/*Accept client's connection request*/
	new_sock = accept(sockid, (struct sockaddr *)&client_address, 		
					&clientaddr_len);
	/*Print an error if connection not accepted*/
	if(new_sock < 0)
	{
		perror("Error in accepting. Connection not established.");
		exit(1);
	}
	else
	{
		printf("Estab");
	}
	
	
	//receive message from the client and if an error occurs do nothing*/
		/*if(recv(new_sock, line, BUFFSIZE, 0) < 0)
		{
			;
		}
		
		else
		{ */
			printf("RSA key received\n"); 
			GenerateSymmetricKey();
			generateIV();
			Encrypt();
			send(new_sock,(const char *)key,sizeof(key),0);
			PrintinHex(key,sizeof(key));
			send(new_sock,(const char *)IV, sizeof(IV),0);
			PrintinHex(IV, sizeof(IV));
			send(new_sock,(const char *)tag, sizeof(tag),0);		
			send(new_sock,(const char *)ciphertext,cipher_len,0);
			
			
		//}
	/*Closing the socket*/
	close(sockid);
	
}


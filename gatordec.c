/*                                      Gatorcrypt and Decrypt program                               */
/*                                      Submitted by Kamlesh Chhetty                                 */
/*                                              UFID - 04166911                                      */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "option.h"

//Initialize the cryptographic routines
int initializeGcryptRoutine();
int keyDerivation(char* password, char* salt, int numberOfIterations, int keyLength,
	      char** key);
int aesCounter  (char* key, int keyLength, char* inputFile, long fileLength, char*
initCounter, int blockLength,
              char** outFile);
int hmac     (char* key, int keyLength, char* outFile, long fileLength,
	      char** mac, int* macLength);

int readFile (char* fileName, 
	      long* fileLength, char** inputFile);
int writeFile(char* fileName, char* outFile, long fileLength, char* mac, int
	macLength, int opt);

int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port);
void checkErr(int err, char* msg);
void printKey(char* key, int keyLength);

int receiveFile(int port, 
	        char** inputFile, long* fileLength);
int verifyMac(char* key, int keyLength, char* inputFile, long fileLength, int
	macLength);
int recvAll(int socket, char* buff, long len);
char* USAGE_STR = "usage: gatordec < filename >  [-d < port >][-l] ";
int main(int argc, char** argv){
//define the files to be used
    char *fileName, *inputFile, *outFile;  
    int port;
    long fileLength=0;
    int opt, err;
    //add salt according to taste
    char *password, *salt = "NaCl";
    int keyLength = 32, macLength = 32, blockLength = 16;
    int numberOfIterations = 4096;
    char *initCounter;  
    char *key;

//parse the arguments and let the program decide the mode to be followed
    opt = parseArgs(argc, argv, &fileName, NULL, &port);
    checkErr(opt, USAGE_STR);

    if(D_DAEMON == opt){
	err = receiveFile(port, &inputFile, &fileLength);
	checkErr(err, "File receive error");
    
    } else if(L_LOCAL == opt){
	err = readFile(fileName, &fileLength, &inputFile );
	checkErr(err, "File read error");
    }
    password = getpass("Password:");

    initializeGcryptRoutine();
    err = keyDerivation(password, salt, numberOfIterations, keyLength, &key);
    checkErr(err, "Key derivation error");
    printKey(key, keyLength);

    err = verifyMac(key, keyLength, inputFile, fileLength, macLength);
    checkErr(err, "HMAC verification error");

    initCounter = (char*)(malloc(blockLength * sizeof(char)));

    memset((void *)initCounter, 0, (size_t)(blockLength * sizeof(char))); 

    err = aesCounter(key, keyLength, inputFile, fileLength - macLength, initCounter,
	    blockLength, &outFile);
    checkErr(err, "Decryption error");

    err = writeFile(fileName, outFile, fileLength - macLength, NULL, 1, opt);
    checkErr(err, "Error in output file operation");
    printf("%ld bytes written.\n", fileLength - macLength);

    return 0;
}
//check for the incoming file after waiting for a connection
int receiveFile(int port, 
	        char** inputFile, long* fileLength){
    int receiveSocket, acceptedSocket;
    int err, portStrlen;
    char *portStr;
    struct addrinfo *res, *curr;
    struct addrinfo hints;
    struct sockaddr incomingAddr;
    socklen_t incomingAddrSize = sizeof(incomingAddr);

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    portStrlen = ceil(log10((float)(port))) + 1;
    portStr = (char *)(malloc(portStrlen * sizeof(char)));
    sprintf(portStr, "%d", port);

    err = getaddrinfo(NULL,portStr, &hints, &res);
    if(err){return GETADDR_ERROR;}

    err = -1;
    curr = res;
    while(NULL != curr){
	receiveSocket = socket((*curr).ai_family, (*curr).ai_socktype,
			    (*curr).ai_protocol);
	if(-1 != receiveSocket){
	    err = bind(receiveSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	}
	if(-1 != err){
	    break;
	}

	close(receiveSocket);
	curr = (*curr).ai_next;
    }


    if(NULL == curr){
	return SOCKET_ABSENT_ERROR;
    }
    freeaddrinfo(res);
//start off the connection listening interface and wait for connections
    long amtReceived = 0;
    printf("Waiting for connections.\n");
    err = listen(receiveSocket, 1);
    if(err) {return ERROR;}
    acceptedSocket = accept(receiveSocket, &incomingAddr, &incomingAddrSize);
    if(-1 == acceptedSocket){return ERROR;}

    printf("Inbound file.\n");

    char * buff = (char*)(malloc(1 * sizeof(uint32_t)));
    recvAll(acceptedSocket, buff, 1*sizeof(uint32_t));
    *fileLength = ntohl(  *((long*)(buff)));
    *inputFile = (char*)(malloc( *fileLength *sizeof(char)));
    recvAll(acceptedSocket, *inputFile, *fileLength);

    return NONE;
}
//check for the file received.
int recvAll(int socket, char* buff, long len){
    long recvdAmt;
    long totalRecvd = 0;

    while(totalRecvd != len){
	recvdAmt = recv(socket, (buff+totalRecvd), len-totalRecvd, 0);
	if(-1 == recvdAmt ){
	    continue;
	}
	totalRecvd += recvdAmt;
    }
}
//check the MAC received from the received file and verify it
int verifyMac(char* key, int keyLength, char* inputFile, long fileLength, int
	macLength){
    int err;
    char* mac;

    err = hmac(key, keyLength, inputFile, fileLength - macLength,  &mac,
	    &macLength); checkErr(err, "HMAC computation error");
    if( 0 != memcmp(mac, inputFile+fileLength-macLength, macLength)){
	return VERIFY_MAC_ERROR;
    }
    return NONE;
}

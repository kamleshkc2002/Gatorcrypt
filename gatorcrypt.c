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

int sendFile(char* outFile, long fileLength, char* mac, int macLength, char*
	ipAddr, int port);
int sendAll(int socket, char* buff, long len);
char* USAGE_STR = "usage: gatorcrypt < input file > [-d < IP-addr:port >][-l ]";
int main(int argc, char** argv){

    char *fileName, *inputFile, *outFile, *mac, *ipAddr;  
    int port;
    long fileLength;
    int opt, err;
    //adding salt according to taste
    char *password, *salt = "NaCl";
    int keyLength = 32, macLength = 32, blockLength = 16;
    int numberOfIterations = 4096;
    char * initCounter;    char *key;

    opt = parseArgs(argc, argv, &fileName, &ipAddr, &port);
    checkErr(opt, USAGE_STR);

    password = getpass("Password:");

    initializeGcryptRoutine();
    err = keyDerivation(password, salt, numberOfIterations, keyLength, &key);
    checkErr(err, "Error in Key Derivation");
    printKey(key, keyLength);

    err = readFile(fileName, &fileLength, &inputFile);

    initCounter =  (char*)(malloc(blockLength * sizeof(char)));
    memset((void*)initCounter, 0, (size_t)(blockLength * sizeof(char)) ); 
    err = aesCounter(key, keyLength, inputFile, fileLength, initCounter, blockLength,
	    &outFile); checkErr(err, "Error in Encryption");

    err = hmac(key, keyLength, outFile, fileLength, &mac, &macLength);
    checkErr(err, "HMAC computation error");

    if(D_SEND == opt){
	err = sendFile(outFile, fileLength, mac, macLength, ipAddr, port);
	checkErr(err, "File send error");
	printf("%ld bytes sent.\n", fileLength+macLength);
    } else if(L_LOCAL == opt){
	err = writeFile(fileName, outFile, fileLength, mac, macLength, opt);
	checkErr(err, "Error in writing output File");
	printf("%ld bytes written.\n", fileLength+macLength);
    }
    
    return 0;
}


int sendFile(char* outFile, long fileLength, char* mac, int macLength, char*
	ipAddr, int port){ 

    int sendSocket;
    int err, portStrlen;
    char *portStr;
    struct addrinfo *res, *curr;
    struct addrinfo hints;
     
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM;
    
    portStrlen = ceil(log10((float)(port))) + 1; /* 1 for \0*/
    portStr = (char *)(malloc(portStrlen * sizeof(char)));
    sprintf(portStr, "%d", port);

    err = getaddrinfo(ipAddr,portStr, &hints, &res);
    if(err){return GETADDR_ERROR;}

    err = -1;
    curr = res;
    while(NULL != curr){
	sendSocket = socket((*curr).ai_family, (*curr).ai_socktype,
			    (*curr).ai_protocol);
	if(-1 != sendSocket){
	    //err = bind(sendSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	    err = connect(sendSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	}
	if(-1 != err){
	    break;
	}

	close(sendSocket);
	curr = (*curr).ai_next;
    }

    if(NULL == curr){
	return SOCKET_ABSENT_ERROR;
    }
    freeaddrinfo(res);

    uint32_t length = htonl(fileLength + macLength);
    sendAll(sendSocket, (char*)(&length), sizeof(length) );

    char ack = 0;
    sendAll(sendSocket, outFile, fileLength);
    sendAll(sendSocket, mac, macLength);

    close(sendSocket);
    
    return NONE;
}
int sendAll(int socket, char* buff, long len){
    long sentAmt;
    long totalSent = 0;

    while(totalSent != len){
	sentAmt = send(socket, (buff+totalSent), len-totalSent, 0);
	if(-1 == sentAmt ){
	    continue;
	}
	totalSent += sentAmt;
    }
}

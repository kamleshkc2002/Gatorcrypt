/*                                      Gatorcrypt and Decrypt program                               */
/*                                      Submitted by Kamlesh Chhetty                                 */
/*                                              UFID - 04166911                                      */
//common utils for the gatordec and gatorcrypt module to function
#include <stdio.h>
#include <stdlib.h>
#include "option.h"
#include <string.h>
#include <gcrypt.h>

//Initialize the cryptographic routines
int initializeGcryptRoutine(){
//Allocate 16 mb of secure memory after supressing the warnings. Once the memory is allocated the warnings are resumed
    const int MAX_SECURE_MEM = 16384;
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_INIT_SECMEM, MAX_SECURE_MEM, 0);
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int keyDerivation(char* password, char* salt, int numberOfIterations, int keyLength,
	      char** key){
    gpg_error_t err;
    size_t KEY_LENGTH = keyLength;
    *key = (char*)(malloc(KEY_LENGTH * sizeof(char)));

     err = gcry_kdf_derive(password, strlen(password), 
	    GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, strlen(salt),
	    numberOfIterations, KEY_LENGTH, *key);

    if(err){ return KEY_DERIVE_ERROR;}
    return NONE;
}

//initiate the AES encryption counter to start the encryption. We use the AES256 scheme for the encryption
int aesCounter  (char* key, int keyLength, char* inputFile, long fileLength, char*
	      initCounter, int blockLength,
              char** outFile){
    gcry_error_t err;
    gcry_cipher_hd_t aeshd;

    err = gcry_cipher_open(&aeshd, GCRY_CIPHER_AES256,
	                           GCRY_CIPHER_MODE_CTR,
	                           GCRY_CIPHER_SECURE);
    if(err){return CIPHER_OPEN_ERROR;}

    err = gcry_cipher_setkey(aeshd, key, keyLength);
    if(err){return CIPHER_SETKEY_ERROR;}
    
    err = gcry_cipher_setctr(aeshd, initCounter, blockLength);
    if(err){return CIPHER_SETCTR_ERROR;}

    *outFile = (char*)(malloc(fileLength * sizeof(char)));
    err = gcry_cipher_encrypt(aeshd, *outFile, fileLength, inputFile, fileLength);
    if(err){return CIPHER_ENCRYPT_ERROR;}

    gcry_cipher_close(aeshd);
    return NONE;
}
//initialize MAC routines
int hmac     (char* key, int keyLength, char* outFile, long fileLength,
	      char** mac, int* macLength ){
    gcry_error_t err;
    gcry_md_hd_t shahd;

//Using SHA512

    err = gcry_md_open(&shahd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
    if(err){ return MD_OPEN_ERROR;}

    err = gcry_md_setkey(shahd, key, keyLength);
    if(err){ return MD_SETKEY_ERROR;}

    gcry_md_write(shahd, outFile, fileLength);

    *macLength = 32;

    char* temp;
    temp = gcry_md_read(shahd, GCRY_MD_SHA512);

    *mac = (char*)(malloc(*macLength * sizeof(char)));
    memcpy(*mac, temp, *macLength);

    gcry_md_close(shahd);
    return NONE;
}

//Read the file for the encryption and decryption routines
int readFile (char* fileName,
	      long* fileLength, char** inputFile){
    FILE *in = fopen(fileName, "rb");
    if(NULL == in){
	return FOPEN_ERROR; 
    }
    fseek(in, 0, SEEK_END);
    *fileLength = ftell(in);
    fseek(in, 0, SEEK_SET);

    *inputFile = (char*)(malloc( (*fileLength) * sizeof(char)));
    fread(*inputFile, sizeof(char), *fileLength, in);

    fclose(in);
    
    return NONE;
}
int writeFile(char* fileName, char* outFile, long fileLength, char* mac, int
	macLength, int opt){
    int isGatorDec = (NULL == mac);
    char * extension = ".uf";
    char * outputFileName;
    int outputFileNameLength;

//GatorDec removes the extension, GatorCrypt adds the extension
//check if exists -> error code 33*
    if(isGatorDec && L_LOCAL == opt){
	outputFileNameLength = strlen(fileName) - strlen(extension) + 1; /*for null*/
	outputFileName = (char *)(malloc(outputFileNameLength*sizeof(char)));
	strncpy(outputFileName, fileName, outputFileNameLength-1);
	outputFileName[outputFileNameLength-1] = '\0';
    } else if(!isGatorDec) {
//return the file with the .uf extension
	outputFileNameLength = strlen(fileName) + strlen(extension) + 1; /*for null*/
	outputFileName = (char *)(malloc(outputFileNameLength*sizeof(char)));
	strncpy(outputFileName, fileName, strlen(fileName)+1);
	strcat(outputFileName, extension);
    }  else{
	outputFileName = fileName;
    }
	
//check if the output file exists.
    FILE *test = fopen(outputFileName, "r");
    if(NULL != test){  return OUTPUT_FILE_EXISTS;}

    FILE *out = fopen(outputFileName, "wb");
    if(NULL == out){ return FOPEN_ERROR;}

    fwrite(outFile, sizeof(char), fileLength, out);
    if(!isGatorDec){
	fwrite(mac, sizeof(char), macLength, out);
    } 
    fclose(out);
    return NONE;
}
//parse the arguments and the ip address associated with the network mode daemons
int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port){

    int isGatorDec = (ipAddress == NULL);
    int option;

    if( (argc <= 1) ||  (argc > 4)){
	return NUM_ARGS_ERROR;
    }

    *fileName = argv[1];

    if(argc >= 3){

        if(strcmp("-d", argv[2]) == 0){
	    option = ((isGatorDec) ? D_DAEMON : D_SEND);
	    if(argc == 4){ 
		if(!isGatorDec){
		    char* delimPos = strchr(argv[3], ':');
		    if(NULL == delimPos){ return STRCHR_ERROR;}
		    *delimPos = '\0';
		    *ipAddress = argv[3];
		    *port = atoi((delimPos+ 1));
		} else{
		    *port = atoi(argv[3]);
		}
		if(0 == *port){ return PORT_ERROR;}
	    } else{
		return MISSING_IPPORT_ERROR; 
	    }

//this is to let the program know that the local mode is to be selected
	} else if(strcmp("-l", argv[2]) == 0){
	    option = L_LOCAL;
	    if(argc != 3){
		return ERROR;
	    }
	} else{
	    return UNKNOWN_OPT_ERROR;
	}
    } else if(argc == 2){
	option = L_LOCAL;
    }

    return option;
}

//common method to parse the eror messages associated with the respective calls.
//has been used throughout the program to pass error messages.
void checkErr(int err, char* msg){
    if(NONE != err && L_LOCAL != err && D_DAEMON != err && D_SEND != err){
	printf("%s\n", msg);
	exit(err);
    }
}
//Print the key in hexadecimal
void printKey(char* key, int keyLength){

    int i;
    printf("Key:");
    for(i = 0; i < keyLength; i++){
	printf(" %02X", (unsigned char)(*(key+i)));
    }
    printf("\n");
}

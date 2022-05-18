//Author: Peter Kosorin (kosorpet)
#include <cstdio>
#include <cstring>
#include <openssl/evp.h>

typedef struct {
    unsigned char idlength;
    unsigned char colourmaptype;
    unsigned char datatypecode;
    uint16_t colourmaporigin;
    uint16_t colourmaplength;
    unsigned char colourmapdepth;
    uint16_t x_origin;
    uint16_t y_origin;
    uint16_t width;
    uint16_t height;
    unsigned char bitsperpixel;
    unsigned char imagedescriptor;
} HEADER;

int aesInit(EVP_CIPHER_CTX *e_ctx, char mode, const char * cypher) {
    unsigned char key[EVP_MAX_KEY_LENGTH] = "My secret key", iv[32] = "initialization vector";

    if(mode == 'e') {
        if(strcmp(cypher, "ecb") == 0) {
            EVP_EncryptInit_ex(e_ctx, EVP_aes_256_ecb(), NULL, key, iv);
        }
        else{
            EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
        }
    }
    else{
        if(strcmp(cypher, "ecb") == 0) {
            EVP_DecryptInit_ex(e_ctx, EVP_aes_256_ecb(), NULL, key, iv);
        }
        else{
            EVP_DecryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
        }
    }
    return 1;
}

void readHead(HEADER *header, FILE *input) {
    header->idlength = fgetc(input);
    header->colourmaptype = fgetc(input);
    header->datatypecode = fgetc(input);
    fread(&header->colourmaporigin, 2, 1, input);
    fread(&header->colourmaplength, 2, 1, input);
    header->colourmapdepth = fgetc(input);
    fread(&header->x_origin, 2, 1, input);
    fread(&header->y_origin, 2, 1, input);
    fread(&header->width, 2, 1, input);
    fread(&header->height, 2, 1, input);
    header->bitsperpixel = fgetc(input);
    header->imagedescriptor = fgetc(input);
}

void writeHead(HEADER header, FILE* output) {
    fputc(header.idlength, output);
    fputc(header.colourmaptype, output);
    fputc(header.datatypecode, output);
    fwrite(&header.colourmaporigin, 2, 1, output);
    fwrite(&header.colourmaplength, 2, 1, output);
    fputc(header.colourmapdepth, output);
    fwrite(&header.x_origin, 2, 1, output);
    fwrite(&header.y_origin, 2, 1, output);
    fwrite(&header.width, 2, 1, output);
    fwrite(&header.height, 2, 1, output);
    fputc(header.bitsperpixel, output);
    fputc(header.imagedescriptor, output);
}

int copyHead(FILE *input, FILE *output) {
    HEADER header;
    readHead(&header, input);
    writeHead(header, output);

    unsigned char * buff = (unsigned char*)malloc(sizeof (unsigned char) * (header.idlength + header.colourmaplength));
    int nread =  fread(buff, 1, header.idlength + header.colourmaplength, input);
    if(nread != header.idlength + header.colourmaplength){
        return 0;
    }
    int nwrite = fwrite(buff,1 , header.idlength + header.colourmaplength, output);
    if(nwrite != header.idlength + header.colourmaplength){
        return 0;
    }
    free(buff);
    return 1;
}

int encrypt( EVP_CIPHER_CTX *e_ctx, FILE* input, FILE* output){
    int inlen, outlen;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    for(;;){
        inlen = fread(inbuf, 1, 1024, input);
        if(inlen <= 0) break;
        if(!EVP_EncryptUpdate(e_ctx, outbuf, &outlen, inbuf, inlen)){
            return 0;
        }
        fwrite(outbuf, 1, outlen, output);
    }

    if(!EVP_EncryptFinal_ex(e_ctx, outbuf, &outlen)){
        return 0;
    }
    fwrite(outbuf, 1, outlen, output);
    return 1;
}

int decrypt( EVP_CIPHER_CTX *e_ctx, FILE* input, FILE* output){
    int inlen, outlen;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    for(;;){
        inlen = fread(inbuf, 1, 1024, input);
        if(inlen <= 0){
            break;
        }
        if(!EVP_DecryptUpdate(e_ctx, outbuf, &outlen, inbuf, inlen)){
            return 0;
        }
        fwrite(outbuf, 1, outlen, output);
    }

    if(!EVP_DecryptFinal_ex(e_ctx, outbuf, &outlen)){
        return 0;
    }
    fwrite(outbuf, 1, outlen, output);
    return 1;
}

FILE* openOutput(char* input, char mode, const char* cypher){
    char filename[NAME_MAX];
    strcpy(filename, strtok(input, "."));
    strcat(filename, "_");
    if(mode == 'e') {
        strcat(filename, cypher);
    }
    else{
        strcat(filename, "dec");
    }
    strcat(filename, ".tga");
    return fopen(filename, "wb");
}

int parseInput(int argc, char **argv, char* mode, char* cypher){
    if(argc != 4 ||
    !(strcmp(argv[2], "-e") == 0 || strcmp(argv[2], "-d") == 0) ||
    !(strcmp(argv[3], "cbc") == 0 || strcmp(argv[3], "ecb") == 0)){
        return 0;
    }
    *mode = argv[2][1];
    strcpy(cypher, argv[3]);
    return 1;
}

int main(int argc, char **argv) {
    char mode;
    char cypher[4];
    if(!parseInput(argc, argv, &mode, cypher)){
        printf("Usage: <filename> [-e | -d] [ecb | cbc]\n");
        return -1;
    }

    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) {
        printf("Unable to open file %s\n", argv[1]);
        return -2;
    }

    FILE *output = openOutput(argv[1], mode, cypher);
    if(output == NULL){
        printf("Unable to create output file.\n");
        return -2;
    }

    EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
    if (e_ctx == NULL) {
        printf("Error initializing encryption context\n");
        return -4;
    }

    if (!aesInit(e_ctx, mode, cypher)) {
        return -5;
    }

    if (!copyHead(input, output)) {
        printf("Problem with image header.\n");
        EVP_CIPHER_CTX_free(e_ctx);
        return -6;
    }

    if(mode == 'e'){
        if(!encrypt(e_ctx, input, output)){
            printf("Error encrypting image.\n");
            EVP_CIPHER_CTX_free(e_ctx);
            return -7;
        }
    }

    else{
        if(!decrypt(e_ctx, input, output)){
            printf("Error decrypting image.\n");
            EVP_CIPHER_CTX_free(e_ctx);
            return -8;
        }
    }

    fclose(input);
    fclose(output);
    EVP_CIPHER_CTX_free(e_ctx);
    return 0;
}

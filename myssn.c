/*
 * myssn.c
 *
 *  Created on: Feb 22, 2021
 *      Author: richa
 */

/*
 * *******************************************************************
 * Includes
 * *******************************************************************
 */
#include "myssn_interface.h"

/* AES data */
const uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
const uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


/*
 * *******************************************************************
 * Prototypes
 * *******************************************************************
 */

/*
 * Creates a myssn server socket.
 * 		Inputs: K64 IP Address.
 * 		Returns: the Socket handle.
 */
ssize_t server_create(const char *server_ip_address){
    ssize_t sock;
    struct sockaddr_in Serveraddr;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    Serveraddr.sin_family = AF_INET;
    Serveraddr.sin_port = htons(SERVER_PORT);
    inet_aton(server_ip_address, &Serveraddr.sin_addr.s_addr);
    bind(sock, (struct sockaddr*) &Serveraddr, sizeof(Serveraddr));
    PRINTF("myssn INFO: Create server on %s port %i\r\n",server_ip_address,SERVER_PORT);
    return sock;
}

/*
 * Accept a new connection on the myssn server socket.
 * 		Inputs: Sock Handler from sock creation.
 * 		Returns: 1 if connection is successful, -1 otherwise.
 */
ssize_t server_accept(ssize_t sock){
    ssize_t new_sock;
    size_t clilen;
    char* cli_ip_addr;
    //uint32_t d = (EXAMPLE_CLOCK_FREQ/1000000) * 20;
    struct sockaddr_in Cliaddr;
    PRINTF("Listening to connections\r\n");
    clilen = sizeof(Cliaddr);
    listen(sock,1);
    new_sock = accept(sock, (struct sockaddr *) &Cliaddr,  &clilen);
    cli_ip_addr = inet_ntoa(Cliaddr.sin_addr);
    if (new_sock < 0) PRINTF("ERROR on connection");
    else PRINTF("myssn INFO: connection from %s\r\n",cli_ip_addr);
    return new_sock;
}

/*
 * Receive data from socket.
 * 		Inputs: Socket Handler from new connection and buffer to store incoming message.
 * 		Returns: number of bytes read.
 */
ssize_t rec_cli(ssize_t sock, char* buffer){
    ssize_t msg = -1;
    ssize_t crc;
    msg = read(sock,buffer,255);
    if (msg < 0) PRINTF("ERROR reading from socket");
    else {
        crc = verify_checksum(buffer, msg);
        if(msg>0){
            PRINTF("Decrypted Message: ");
            for(int i=0; i<msg-4; i++) {
              PRINTF("%c", buffer[i]);
            }
            PRINTF("\r\n");
        }
        else PRINTF("CRC failed!: ");
    }
    return crc;
}

/*
 * Send data on socket.
 * 		Inputs: Socket Handler from new connection and buffer with message
 * 		Returns: 1 if data transmitted successfully, -1 otherwise.
 */
ssize_t send_ser(int sock, char* buffer){
    int bytes_written = -1;
    ssize_t padded_len;
    uint32_t checksum32;
    uint8_t padded_msg[512] = {0};
    memcpy(padded_msg, buffer, strlen(buffer));
    padded_len = encrypt_msg(padded_msg);
    checksum32 = apply_checksum(padded_msg,padded_len);
    //PRINTF("CRC-32: 0x%08x\r\n", checksum32);
    padded_msg[padded_len] = checksum32;
    padded_msg[padded_len+1] = checksum32 >> 8;
    padded_msg[padded_len+2] = checksum32 >> 16;
    padded_msg[padded_len+3] = checksum32 >> 24;
    bytes_written = write(sock, padded_msg, padded_len+4);
    if(bytes_written>0){
        PRINTF("Data successfully sent");
        return bytes_written;
    } else {
        PRINTF("Error sending data");
        return 0;
    }
}

/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
static void InitCrc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

/*
 * Verify checksum32 of a data frame.
 * 		Inputs: Buffer with message to validate CRC and length of said message.
 * 		Returns: 1 if CRC32 test passes, -1 otherwise.
 */
ssize_t verify_checksum(char* buffer, ssize_t msg_len){
    size_t buffer_string_len = msg_len-4;
    uint32_t rec_checksum32 = (uint32_t)buffer[msg_len-4] + (uint32_t)(buffer[msg_len-3] << 8) + (uint32_t)(buffer[msg_len-2] << 16) + (uint32_t)(buffer[msg_len-1] << 24);
    uint8_t padded_msg[512] = {0};
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    uint32_t checksum32;
    memcpy(padded_msg, buffer, buffer_string_len);
    checksum32 = apply_checksum(padded_msg, buffer_string_len);
    if(checksum32==rec_checksum32) {
        AES_CBC_decrypt_buffer(&ctx, padded_msg, buffer_string_len);
        memcpy(buffer, padded_msg, buffer_string_len);
        return 1;
    }
    else return -1;
    return 0;
}

/*
 * Calculate checksum32 of a data message.
 * 		Inputs: buffer with message and size of said message
 *		Outputs: calculated checksum
 */
int apply_checksum(uint8_t* buffer, size_t buf_size){
    /* CRC data */
    CRC_Type *base = CRC0;
    uint32_t checksum32;
    InitCrc32(base, 0xFFFFFFFFU);
    CRC_WriteData(base, (uint8_t *)&buffer[0], buf_size);
    checksum32 = CRC_Get32bitResult(base);
    PRINTF("CRC-32: 0x%08x\r\n", checksum32);
    return checksum32;
}

/*
 * Apply AES128 encryption to a message before transmition.
 * 		Inputs: buffer with message to be encrypted.
 * 		Returns the byte size of total message length.
 */
ssize_t encrypt_msg(char* buffer){
    struct AES_ctx ctx;
	ssize_t test_string_len, padded_len;
	uint8_t padded_msg[512] = {0};
	PRINTF("AES and CRC test task\r\n");
  	PRINTF("\nTesting AES128\r\n\n");
  	/* Init the AES context structure */
  	AES_init_ctx_iv(&ctx, key, iv);
  	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
  	test_string_len = strlen(buffer);
  	padded_len = test_string_len + (16 - (test_string_len%16) );
  	memcpy(padded_msg, buffer, test_string_len);
  	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);
  	PRINTF("Encrypted Message: ");
  	for(int i=0; i<padded_len; i++) {
  		PRINTF("0x%02x,", padded_msg[i]);
  	}
  	PRINTF("\r\n");
  	memcpy(buffer, padded_msg, padded_len);
  	return padded_len;
}

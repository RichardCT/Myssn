/*
 * myssn.h
 *
 *  Created on: Feb 18, 2021
 *      Author: richa
 */

#ifndef MYSSN_H_
#define MYSSN_H_

/*
 * ************************************************************************
 * Includes
 * ************************************************************************
 */
#include "sys/socket.h"
#include "aes.h"
#include "fsl_crc.h"

/*
 * ************************************************************************
 * Definitions
 * ************************************************************************
 */
#define SERVER_PORT 10000

/*
 * ************************************************************************
 * Prototypes
 * ************************************************************************
 */

static void InitCrc32(CRC_Type *base, uint32_t seed);

/*
 * Verify checksum32 of a data frame.
 * Returns 1 in case checksum is verified, -1 otherwise.
 */
ssize_t verify_checksum(char* buffer, ssize_t msg_len);

/*
 * Calculate checksum32 of a data message.
 */
int apply_checksum(uint8_t* buffer, size_t buf_size);

/*
 * Apply AES128 encryption to a message before transmition.
 * Returns the byte size of total message length.
 */
ssize_t encrypt_msg(char * buffer);


#endif /* MYSSN_H_ */

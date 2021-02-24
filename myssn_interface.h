/*
 * myssn_interface.h
 *
 *  Created on: Feb 22, 2021
 *      Author: richa
 */

#ifndef MYSSN_INTERFACE_H_
#define MYSSN_INTERFACE_H_

/*
 * *********************************************************************
 * Includes
 * *********************************************************************
 */
#include "myssn.h"

extern const uint8_t key[];
extern const uint8_t iv[];
#define SERVER_PORT 10000

/*
 * *********************************************************************
 * Prototypes
 * *********************************************************************
 */

/*
 * Creates a myssn server socket.
 * Returns the Socket handle.
 */
ssize_t server_create(const char *server_ip_address);

/*
 * Accept a new connection on the myssn server socket.
 * Returns 1 if connection is successful, -1 otherwise.
 */
ssize_t server_accept(ssize_t sock);

/*
 * Receive data from socket.
 * Returns the number of bytes read.
 */
ssize_t rec_cli(ssize_t sock, char* buffer);

/*
 * Send data on socket.
 * Returns 1 if data transmitted successfully, -1 otherwise.
 */
ssize_t send_ser(int sock, char* buffer);

#endif /* MYSSN_INTERFACE_H_ */

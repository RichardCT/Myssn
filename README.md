# Myssn
Library to exchange messages in a client-server model via TCP/IP

myssn.h has functions used internally in the API, so the user don't need to have access to it, nor modify it.

myssn_interface.h has the prototypes that the user has tu use in order to create a server and exchange messages with a client.

myssn.c is where the code of the API is implemented. The user may only modify AES information such as the key and iv. 

An example function to implement this is shown below:

void aescrc_test_task(void *arg)
{

    ssize_t socket, new_sock, msg;
    uint8_t padded_msg[512] = {0};

    socket = server_create("192.168.1.102");
    new_sock = server_accept(socket);
    while(1){
		msg = rec_cli(new_sock, padded_msg);
		for(int i=0; i<msg-4; i++) {
		  PRINTF("%c", padded_msg[i]);
		}
		PRINTF("\r\n");
		send_ser(new_sock, padded_msg);
    }

}

Three ssize_t variables need to be created, one for the server socket, one for the client-server connection socket, and one to store the size of the message sent by the client. 
Also a uint8_t buffer needs to be created to store the actual message from the client. 
Then the socket creation and client acceptance functions need to be called in that same order. To exchange messages indefinetly, a while(1) loop is implemented. Finally, 
the receive message and send message functions are called. 

The rest of the main function can be found in the following repository:
https://github.com/sansergio/mySafeAndSecureNetwork

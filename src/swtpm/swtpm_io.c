/********************************************************************************/
/*                                                                              */
/*                              TPM Host IO                                     */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_io.c 4564 2011-04-13 19:33:38Z stefanb $                */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010, 2019				*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* These are platform specific.  This version uses a TCP/IP socket interface.

   Environment variables are:

           TPM_PORT - the client and server socket port number
*/

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* BSD: sockaddr_in */
#include <sys/socket.h> /* BSD: accept() */
#include <sys/select.h> /* BSD: select() */
#include <sys/uio.h>

#include <openssl/aes.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_types.h>

#include "logging.h"
#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "tpmlib.h"
#include "utils.h"

/*
  global variables
*/

struct tpm_header {
	uint16_t tag;
	uint32_t length;
	uint32_t ordinal;
} __attribute__((packed));


#define FIXED_OUTPUT_SIZE 512 // 512 bits
#define AES_KEY_SIZE 32    // 256 bits
#define AES_BLOCK_SIZE 16

// 密钥
static const unsigned char key[AES_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static bool encryptable = false;

// 加密函数
void aes_encrypt(unsigned char *plaintext, int length) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 256, &enc_key);
    unsigned char *p = (unsigned char *)plaintext;
    
    for (int i = 0; i < length; i += 16) {
        // printf("encrypt \n");
        AES_encrypt(p, p, &enc_key);
        p += AES_BLOCK_SIZE;
    }
}

// 解密函数
void aes_decrypt(unsigned char *ciphertext, int length) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 256, &dec_key);
    unsigned char *c = ciphertext;
    for (int i = 0; i < length; i += 16) {
        AES_decrypt(c, c, &dec_key);
        c += AES_BLOCK_SIZE;
    }
    // printf("decrypt end\n");
}


/* platform dependent */

static int      sock_fd = -1;


/* SWTPM_IO_Read() reads a TPM command packet from the host

   Puts the result in 'buffer' up to 'bufferSize' bytes.

   On success, the number of bytes in the buffer is equal to 'bufferLength' bytes

   This function is intended to be platform independent.
*/

TPM_RESULT SWTPM_IO_Read(TPM_CONNECTION_FD *connection_fd,   /* read/write file descriptor */
                         unsigned char *buffer,   /* output: command stream */
                         uint32_t *bufferLength,  /* output: command stream length */
                         size_t bufferSize)       /* input: max size of output buffer */
{
    ssize_t             n;
    size_t              offset = 0;
    struct tpm_header *hdr;

    if (connection_fd->fd < 0) {
        TPM_DEBUG("SWTPM_IO_Read: Passed file descriptor is invalid\n");
        return TPM_IOERROR;
    }

    while (true) {
        n = read(connection_fd->fd, &buffer[offset], bufferSize - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n > 0) {
            offset += n;
            if (offset < sizeof(struct tpm_req_header))
                continue;
            break;
        } else {
           return TPM_IOERROR;
        }
    }

    *bufferLength = offset;
    // SWTPM_PrintAll(" SWTPM_IO_Read:before decrypt", " ", buffer, *bufferLength);

    if(buffer[0] == 0x80)
    {
         encryptable = false;
         return 0;
    }

    encryptable = true;
    aes_decrypt(buffer,*bufferLength);
    hdr = (struct tpm_header *)buffer;
    *bufferLength = be32toh(hdr->length); 
    


    SWTPM_PrintAll(" SWTPM_IO_Read:decrypt", " ", buffer, *bufferLength);


    return 0;
}


/* SWTPM_IO_SetSocketFD tells the IO layer that it's not necessary to open
   a server socket.
 */
TPM_RESULT SWTPM_IO_SetSocketFD(int fd)
{
    sock_fd = fd;
    return 0;
}

int SWTPM_IO_GetSocketFD(void)
{
    return sock_fd;
}


/* SWTPM_IO_Init initializes the TPM to host interface.

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Init(void)
{
    TPM_DEBUG(" SWTPM_IO_Init:\n");

    return 0;
}


/* SWTPM_IO_Connect() establishes a connection between the TPM server and the host client

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Connect(TPM_CONNECTION_FD *connection_fd,     /* read/write file descriptor */
                            int notify_fd)
{
    TPM_RESULT          rc = 0;
    socklen_t           cli_len;
    struct sockaddr_in  cli_addr;       /* Internet version of sockaddr */
    int                 max_fd = -1;
    fd_set              readfds;
    int                 n;

    while (rc == 0) {
        FD_ZERO(&readfds);

        FD_SET(sock_fd, &readfds);
        max_fd = sock_fd;

        FD_SET(notify_fd, &readfds);
        max_fd = (notify_fd > max_fd) ? notify_fd : max_fd;

        TPM_DEBUG("SWTPM_IO_Connect: Waiting for connections\n");

        n = select(max_fd + 1, &readfds, NULL, NULL, NULL);

        if (n > 0 && FD_ISSET(notify_fd, &readfds)) {
            rc = TPM_IOERROR;
            break;
        }

        if (n > 0 && FD_ISSET(sock_fd, &readfds)) {
            cli_len = sizeof(cli_addr);
            /* block until connection from client */
            TPM_DEBUG("\n SWTPM_IO_Connect: Accepting connection ...\n");
            connection_fd->fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len);
            if (connection_fd->fd < 0) {
                logprintf(STDERR_FILENO,
                          "SWTPM_IO_Connect: Error, accept() %d %s\n",
                          errno, strerror(errno));
                rc = TPM_IOERROR;
            }
            break;
        }
    }

    return rc;
}

/* SWTPM_IO_Write() writes 'buffer_length' bytes to the host.

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Write(TPM_CONNECTION_FD *connection_fd,       /* read/write file descriptor */
                          struct iovec *iovec,
                          int iovcnt)
{
    ssize_t     nwritten = 0;
    size_t      totlen = 0,send_len;
    int         i;
    struct tpm2_resp_prefix *respprefix;
    uint32_t *len_send = (uint32_t *) malloc (sizeof(uint32_t));

     /* test that connection is open to write */
    if (connection_fd->fd < 0) {
        logprintf(STDERR_FILENO,
       "SWTPM_IO_Write: Error, connection not open, fd %d\n",
        connection_fd->fd);
        return TPM_IOERROR;
    }
    SWTPM_PrintAll(" SWTPM_IO_Write:before encrypt", " ",
                    iovec[1].iov_base, iovec[1].iov_len);


    if(encryptable){

        send_len = ((iovec[1].iov_len /AES_BLOCK_SIZE )+1)*AES_BLOCK_SIZE ;
        respprefix = iovec[0].iov_base;
        *len_send = send_len;
        iovec[0].iov_base = len_send;
        iovec[0].iov_len = 4;

        iovec[1].iov_len = send_len;
        aes_encrypt(iovec[1].iov_base,send_len);
        // SWTPM_PrintAll(" SWTPM_IO_Write:encrypt", " ",
        //             iovec[1].iov_base, iovec[1].iov_len);
    }

       

    for (i = 0; i < iovcnt; i++)
        totlen += iovec[i].iov_len;

    nwritten = writev_full(connection_fd->fd, iovec, iovcnt);
    iovec[0].iov_base= respprefix;

  



   
    if (nwritten < 0) {
        logprintf(STDERR_FILENO, "SWTPM_IO_Write: Error, writev() %d %s\n",
                  errno, strerror(errno));
        return TPM_IOERROR;
    }
    if ((size_t)nwritten < totlen) {
        logprintf(STDERR_FILENO,
                  "SWTPM_IO_Write: Failed to write all bytes %zu != %zu\n",
                  nwritten, totlen);
        return TPM_IOERROR;
    }
    return 0;
}

/* SWTPM_IO_Disconnect() breaks the connection between the TPM server and the host client

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Disconnect(TPM_CONNECTION_FD *connection_fd)
{
    /* close the connection to the client */
    if (connection_fd->fd >= 0) {
        close(connection_fd->fd);
        connection_fd->fd = -1;     /* mark the connection closed */
    }

    return 0;
}

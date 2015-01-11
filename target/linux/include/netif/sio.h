#ifndef SIO_UNIX_H
#define SIO_UNIX_H

#include "lwip/sys.h"
#include "lwip/netif.h"
#include "netif/fifo.h"
/*#include "netif/pppif.h"*/
/* BAUDRATE is defined in sio.c as it is implementation specific */

typedef struct sio_status_t {
	int fd;
	fifo_t myfifo;
} sio_status_t;
#define sio_fd_t sio_status_t*
#define __sio_fd_t_defined

/** Baudrates */
typedef enum sioBaudrates {
	SIO_BAUD_9600,
	SIO_BAUD_19200,
	SIO_BAUD_38400,
	SIO_BAUD_57600,
	SIO_BAUD_115200
} sioBaudrates;

/**
* Read a char from incoming data stream, this call blocks until data has arrived
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
* @return 	char read from input stream
*/
u8_t sio_unix_recv( sio_status_t * siostat );
#define sio_recv sio_unix_recv

/**
* Poll for a new character from incoming data stream
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
* @return 	char read from input stream, or < 0 if no char was available
*/
s16_t sio_unix_poll(sio_status_t * siostat);

/**
*	Parse incoming characters until a string str is recieved, blocking call
* @param	str		zero terminated string to expect
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
*/
void sio_unix_expect_string(u8_t *str, sio_status_t * siostat);

/**
* Write a char to output data stream
* @param 	c		char to write to output stream
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
*/
void sio_unix_send( u8_t c, sio_status_t * siostat );

/**
* Write a char to output data stream
* @param 	str		pointer to a zero terminated string
* @param	siostat siostatus struct, contains sio instance data, given by sio_open
*/
void sio_unix_send_string(u8_t *str, sio_status_t * siostat);

/**
*	Flush outbuffer (send everything in buffer now), useful if some layer below is
*	holding on to data, waitng to fill a buffer
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
*/
void sio_unix_flush( sio_status_t * siostat );

/**
* Open serial port entry point from serial protocol (slipif, pppif)
* @param	devnum	the device number to use, i.e. ttySx, comx:, etc. there x = devnum
* @return 	siostatus struct, contains sio instance data, use when calling sio functions
*/
sio_status_t * sio_unix_open( int devnum );
#define sio_open sio_unix_open

/**
*	Change baudrate of port, may close and reopen port
* @param 	baud	new baudrate
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
*/
void sio_unix_change_baud( sioBaudrates baud, sio_status_t * siostat );

#if PPP_SUPPORT
/**
*	Write buffer to serial port
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
* @param 	buf	output buffer
* @param 	size	output buffer size
*/
u32_t sio_unix_write(sio_status_t * siostat, u8_t *buf, u32_t size);
#define sio_write sio_unix_write

/**
*	Read buffer from serial port
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
* @param 	buf	input buffer
* @param 	size	input buffer size
*/
u32_t sio_unix_read(sio_status_t * siostat, u8_t *buf, u32_t size);
#define sio_read sio_unix_read

/**
*	Flush serial port input buffer
* @param 	siostat siostatus struct, contains sio instance data, given by sio_open
*/
void sio_unix_read_abort(sio_status_t * siostat);
#define sio_read_abort sio_unix_read_abort
#endif /* PPP_SUPPORT */

#endif


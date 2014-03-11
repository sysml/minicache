/*
 * Glue code for httpd to read file from a mounted SHFS volume
 * Copyright(C) 2014 NEC Laboratories Europe Ltd.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */

#include <lwip/opt.h>
#include <lwip/def.h>
#include "httpd_opt.h"
#include "fs.h"
#include <string.h>
#include "shfs_fio.h"

#if LWIP_HTTPD_FILE_STATE
#else
#error "Please enable LWIP_HTTPD_FILE_STATE in httpd_opt.h"
#endif
#if LWIP_HTTPD_FS_ASYNC_READ
#error "LWIP_HTTPD_FS_ASYNC_READ is not supported yet"
#endif

#if !LWIP_HTTPD_DYNAMIC_HEADERS
int _fs_generate_hdr(SHFS_FD f, int flen, char *buf)
{
	char str_mime[128];
	size_t len, ret;
	char *ptr = buf;
	ret = 0;

	/* HTTP/1.0 200 OK */
	len = sprintf(ptr, "HTTP/1.0 200 OK\r\n");
	ret += len;
	ptr += len;

	/* Server Agent */
	len = sprintf(ptr, "Server: %s\r\n", HTTPD_SERVER_AGENT);
	ret += len;
	ptr += len;

	/* Content size */
	len = sprintf(ptr, "Content-Length: %d\r\n", flen);
	ret += len;
	ptr += len;

	/* Content Type */
	shfs_fio_mime(f, str_mime, sizeof(str_mime));
	if ( str_mime[0] == '\0' ) {
		/* default mime */
		len = sprintf(ptr, "Content-type: text/plain\r\n\r\n");
		ret += len;
		ptr += len;
	} else {
		/* mime provided by SHFS */
		len = sprintf(ptr, "Content-type: %s\r\n\r\n", str_mime);
		ret += len;
		ptr += len;
	}
	return ret;
}
#else
const char null_data[] = { '\0' };
#endif

int _fs_fsize(struct fs_file *file)
{
	SHFS_FD f = file->state;
	uint64_t fsize;
	int ret;

	shfs_fio_size(f, &fsize);
	/* FIXME: this workaround cuts the end of
	 * large files because they are not
	 * supported by httpd */
	ret = (int) min(fsize, (uint64_t) INT_MAX);
	if ((uint64_t) ret < fsize)
		printf("_fs_fsize(): WARNING: Shrinked file from %lu to %d bytes\n", fsize, ret);
	return ret;
}

err_t fs_open(struct fs_file *file, const char *name)
{
	SHFS_FD f;

	if ((file == NULL) || (name == NULL))
		return ERR_ARG;
	if (name[0] != '/')
		return ERR_VAL;

	f = shfs_fio_open(name + 1); /* removes leading '/' */
	if (!f)
		return ERR_VAL; /* file not found */

	file->state = f;
#if !LWIP_HTTPD_DYNAMIC_HEADERS
	file->data = malloc(1024); /* used to store the header */
	file->len = _fs_generate_hdr(f, _fs_fsize(file),
	                             (char *) file->data);
	            /* returns length of the header */
	file->index = 0; /* offset */
	file->http_header_included = 1;
#else
	file->data = null_data;
	file->len = 0; /* will let httpd_check_eof to read from disk */
	file->index = 0; /* offset */
	file->http_header_included = 0;
#endif
	file->pextension = NULL;
	file->is_custom_file = 1;
	return ERR_OK;
}

void fs_close(struct fs_file *file)
{
	SHFS_FD f = file->state;
#if !LWIP_HTTPD_DYNAMIC_HEADERS
	free((void *) file->data);
#endif
	shfs_fio_close(f);
}

#if LWIP_HTTPD_FS_ASYNC_READ
int fs_read_async(struct fs_file *file, char *buffer, int count, fs_wait_cb callback_fn, void *callback_arg)
{
	return 0;
}
#else

#include <hexdump.h>
int fs_read(struct fs_file *file, char *buffer, int count)
{
	SHFS_FD f = file->state;
	int nb_read;
	int ret;

	if (file->index < 0)
		file->index = 0;
	if (file->index >= _fs_fsize(file))
		return FS_READ_EOF;

	nb_read = _fs_fsize(file) - file->index;
	nb_read = min(nb_read, count);

	ret = shfs_fio_read(f, (uint64_t) file->index, buffer, nb_read);
	if (ret < 0) {
		printf("fs_read: read error: %d (%s) @ o=%d l=%\n", ret, strerror(-ret), file->index, nb_read);
		return FS_READ_EOF; /* a read error happened -> cancel request */
	}

	file->index += nb_read;
	return (nb_read);
}
#endif

int fs_bytes_left(struct fs_file *file)
{
	return _fs_fsize(file) - file->index;
}

void fs_getmime(struct fs_file *file, char *out, int outlen)
{
	SHFS_FD f = file->state;
	shfs_fio_mime(f, out, (size_t) outlen);
}

/* these functions are unused but prototypes are defined
 * when LWIP_HTTPD_FILE_STATE is enabled (see fs.h) */
void *fs_state_init(struct fs_file *file, const char *name) { return NULL; }
void fs_state_free(struct fs_file *file, void *state) { return; }

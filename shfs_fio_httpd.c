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

const char null_data[] = { '\0' };

int _fs_fsize(struct fs_file *file)
{
	SHFS_FD f = file->state;
	uint64_t fsize;

	shfs_fio_size(f, &fsize);
	/* FIXME: this workaround cuts the end of
	 * large files because they are not
	 * supported by httpd yet */
	return (int) min(fsize, (uint64_t) INT_MAX);
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
	file->len = 0; /* will let httpd_check_eof to read from disk */
	file->data = null_data;
	file->index = 0; /* offset */
	file->pextension = NULL;
	file->http_header_included = 0;
	file->is_custom_file = 1;
	return ERR_OK;
}

void fs_close(struct fs_file *file)
{
	SHFS_FD f = file->state;
	shfs_fio_close(f);
}

#if LWIP_HTTPD_FS_ASYNC_READ
int fs_read_async(struct fs_file *file, char *buffer, int count, fs_wait_cb callback_fn, void *callback_arg)
{
	return 0;
}
#else
int fs_read(struct fs_file *file, char *buffer, int count)
{
	int read;
	int ret;

	if (file->index >= _fs_fsize(file))
		return FS_READ_EOF;

	read = _fs_fsize(file) - file->index;
	read = min(read, count);

	ret = shfs_fio_read(file->state, (uint64_t) file->index, buffer, read);
	if (ret < 0)
		return 0;
		//		return FS_READ_EOF; /* a read error happened -> cancel request */

	file->index += read;
	return (read);
}
#endif

int fs_bytes_left(struct fs_file *file)
{
	return _fs_fsize(file) - file->index;
}

const char *fs_getmime(struct fs_file *file)
{
	return NULL;
}

/* these functions are unused but prototypes are defined
 * when LWIP_HTTPD_FILE_STATE is enabled (see fs.h) */
void *fs_state_init(struct fs_file *file, const char *name) { return NULL; }
void fs_state_free(struct fs_file *file, void *state) { return; }

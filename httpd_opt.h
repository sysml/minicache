#ifndef __HTTPD_OPT_H__
#define __HTTPD_OPT_H__

#define HTTPD_DEBUG LWIP_DBG_ON

#define LWIP_HTTPD_SSI_INCLUDE_TAG 0

/* Enables usage of SHFS for httpd
 * shfs_fio_httpd.c is providing the required functions,
 * the prototypes are defined in fs.h */
#define LWIP_HTTPD_DYNAMIC_HEADERS 0
#define LWIP_HTTPD_DYNAMIC_FILE_READ 1
#define LWIP_HTTPD_FILE_STATE 1
#define LWIP_HTTPD_CUSTOM_FILES 1

#if LWIP_HTTPD_DYNAMIC_HEADERS
#define LWIP_HTTPD_DYNAMIC_HEADERS_FS_HAS_MIME 1
#endif

#endif /* __HTTPD_OPT_H__ */

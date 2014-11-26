#ifndef _HTTP_DATA_H_
#define _HTTP_DATA_H_

static const char _http_sep[] = "\r\n";
static const size_t _http_sep_len = sizeof(_http_sep) - 1;

static const char __http_shdr00[] = "HTTP/0.9 200\r\n";
static const char __http_shdr01[] = "HTTP/0.9 206\r\n";
static const char __http_shdr02[] = "HTTP/0.9 400\r\n";
static const char __http_shdr03[] = "HTTP/0.9 404\r\n";
static const char __http_shdr04[] = "HTTP/0.9 416\r\n";
static const char __http_shdr05[] = "HTTP/0.9 500\r\n";
static const char __http_shdr06[] = "HTTP/0.9 501\r\n";
static const char __http_shdr07[] = "HTTP/0.9 503\r\n";
static const char __http_shdr08[] = "HTTP/1.0 200 OK\r\n";
static const char __http_shdr09[] = "HTTP/1.0 206 Partial content\r\n";
static const char __http_shdr10[] = "HTTP/1.0 400 Bad request\r\n";
static const char __http_shdr11[] = "HTTP/1.0 404 Element not found\r\n";
static const char __http_shdr12[] = "HTTP/1.0 416 Requested range not satisfiable\r\n";
static const char __http_shdr13[] = "HTTP/1.0 500 Internal server error\r\n";
static const char __http_shdr14[] = "HTTP/1.0 501 Not implemented\r\n";
static const char __http_shdr15[] = "HTTP/1.0 503 Service unavailable\r\n";
static const char __http_shdr16[] = "HTTP/1.1 200 OK\r\n";
static const char __http_shdr17[] = "HTTP/1.1 206 Partial content\r\n";
static const char __http_shdr18[] = "HTTP/1.1 400 Bad request\r\n";
static const char __http_shdr19[] = "HTTP/1.1 404 Element not found\r\n";
static const char __http_shdr20[] = "HTTP/1.1 416 Requested range not satisfiable\r\n";
static const char __http_shdr21[] = "HTTP/1.1 500 Internal server error\r\n";
static const char __http_shdr22[] = "HTTP/1.1 501 Not implemented\r\n";
static const char __http_shdr23[] = "HTTP/1.1 503 Service unavailable\r\n";
static const char __http_shdr24[] = "Content-type: text/plain\r\n";
static const char __http_shdr25[] = "Content-type: text/html\r\n";
static const char __http_shdr26[] = "Content-type: application/octet-stream\r\n";
static const char __http_shdr27[] = "Connection: close\r\n";
static const char __http_shdr28[] = "Connection: keep-alive\r\n";
static const char __http_shdr29[] = "Expires: Thu, 1 Jan 1970 00:00:00 GMT\r\nPragma: no-cache\r\n";
static const char __http_shdr30[] = "Server: "HTTP_SERVER_AGENT"\r\n";
static const char __http_shdr31[] = "Accept-ranges: bytes\r\n";
static const char __http_shdr32[] = "Transfer-encoding: chunked\r\n";

static const char * const _http_shdr[] = {
	__http_shdr00, __http_shdr01, __http_shdr02, __http_shdr03, __http_shdr04,
	__http_shdr05, __http_shdr06, __http_shdr07, __http_shdr08, __http_shdr09,
	__http_shdr10, __http_shdr11, __http_shdr12, __http_shdr13, __http_shdr14,
	__http_shdr15, __http_shdr16, __http_shdr17, __http_shdr18, __http_shdr19,
	__http_shdr20, __http_shdr21, __http_shdr22, __http_shdr23, __http_shdr24,
	__http_shdr25, __http_shdr26, __http_shdr27, __http_shdr28, __http_shdr29,
	__http_shdr30, __http_shdr31, __http_shdr32
};
static const size_t _http_shdr_len[] = {
	sizeof(__http_shdr00) - 1, sizeof(__http_shdr01) - 1,
	sizeof(__http_shdr02) - 1, sizeof(__http_shdr03) - 1,
	sizeof(__http_shdr04) - 1, sizeof(__http_shdr05) - 1,
	sizeof(__http_shdr06) - 1, sizeof(__http_shdr07) - 1,
	sizeof(__http_shdr08) - 1, sizeof(__http_shdr09) - 1,
	sizeof(__http_shdr10) - 1, sizeof(__http_shdr11) - 1,
	sizeof(__http_shdr12) - 1, sizeof(__http_shdr13) - 1,
	sizeof(__http_shdr14) - 1, sizeof(__http_shdr15) - 1,
	sizeof(__http_shdr16) - 1, sizeof(__http_shdr17) - 1,
	sizeof(__http_shdr18) - 1, sizeof(__http_shdr19) - 1,
	sizeof(__http_shdr20) - 1, sizeof(__http_shdr21) - 1,
	sizeof(__http_shdr22) - 1, sizeof(__http_shdr23) - 1,
	sizeof(__http_shdr24) - 1, sizeof(__http_shdr25) - 1,
	sizeof(__http_shdr26) - 1, sizeof(__http_shdr27) - 1,
	sizeof(__http_shdr28) - 1, sizeof(__http_shdr29) - 1,
	sizeof(__http_shdr30) - 1, sizeof(__http_shdr31) - 1,
	sizeof(__http_shdr32) - 1
};

/* Indexes into _http_shdr */
#define HTTP09_SHDR_200           0 /* 200 OK (HTTP/0.9) */
#define HTTP09_SHDR_206           1 /* 206 Partial content (HTTP/0.9) */
#define HTTP09_SHDR_400           2 /* 400 Bad request (HTTP/0.9) */
#define HTTP09_SHDR_404           3 /* 404 File not found (HTTP/0.9) */
#define HTTP09_SHDR_416           4 /* 416 Requested range not satisfiable (HTTP/0.9) */
#define HTTP09_SHDR_500           5 /* 500 Internal server error (HTTP/0.9) */
#define HTTP09_SHDR_501           6 /* 501 Not implemented (HTTP/0.9) */
#define HTTP09_SHDR_503           7 /* 503 Service unavailable (HTTP/0.9) */
#define HTTP10_SHDR_200           8 /* 200 OK (HTTP/1.0) */
#define HTTP10_SHDR_206           9 /* 206 Partial content (HTTP/1.0) */
#define HTTP10_SHDR_400          10 /* 400 Bad request (HTTP/1.0) */
#define HTTP10_SHDR_404          11 /* 404 Element not found (HTTP/1.0) */
#define HTTP10_SHDR_416          12 /* 416 Requested range not satisfiable (HTTP/1.0) */
#define HTTP10_SHDR_500          13 /* 500 Internal server error (HTTP/1.0) */
#define HTTP10_SHDR_501          14 /* 501 Not implemented (HTTP/1.0) */
#define HTTP10_SHDR_503          15 /* 503 Service unavailable (HTTP/1.0) */
#define HTTP11_SHDR_200          16 /* 200 OK (HTTP/1.1) */
#define HTTP11_SHDR_206          17 /* 206 Partial content (HTTP/1.1) */
#define HTTP11_SHDR_400          18 /* 400 Bad request (HTTP/1.1) */
#define HTTP11_SHDR_404          19 /* 404 Element not found (HTTP/1.1) */
#define HTTP11_SHDR_416          20 /* 416 Requested range not satisfiable (HTTP/1.1) */
#define HTTP11_SHDR_500          21 /* 500 Internal server error (HTTP/1.1) */
#define HTTP11_SHDR_501          22 /* 501 Not implemented (HTTP/1.1) */
#define HTTP11_SHDR_503          23 /* 503 Service unavailable (HTTP/1.1) */
#define HTTP_SHDR_PLAIN          24 /* text/plain */
#define HTTP_SHDR_HTML           25 /* text/html */
#define HTTP_SHDR_BINARY         26 /* application/octet-stream */
#define HTTP_SHDR_CONN_CLOSE     27 /* Connection: close */
#define HTTP_SHDR_CONN_KEEPALIVE 28 /* Connection: keep-alive */
#define HTTP_SHDR_NOCACHE        29 /* Pragma: no-cache */
#define HTTP_SHDR_SERVER         30 /* Server agent */
#define HTTP_SHDR_ACC_BYTERANGE  31 /* Accept-ranges: bytes */
#define HTTP_SHDR_ENC_CHUNKED    32 /* Transfer-Encoding: chunked */

#define HTTP_SHDR_DEFAULT_TYPE   HTTP_SHDR_PLAIN

#define HTTP_SHDR_OK(major, minor) HTTP_SHDR_200((major), (minor))
#define HTTP_SHDR_200(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_200 : (((minor) < 1) ? HTTP10_SHDR_200 : HTTP11_SHDR_200))
#define HTTP_SHDR_206(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_206 : (((minor) < 1) ? HTTP10_SHDR_206 : HTTP11_SHDR_206))
#define HTTP_SHDR_400(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_400 : (((minor) < 1) ? HTTP10_SHDR_400 : HTTP11_SHDR_400))
#define HTTP_SHDR_404(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_404 : (((minor) < 1) ? HTTP10_SHDR_404 : HTTP11_SHDR_404))
#define HTTP_SHDR_416(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_416 : (((minor) < 1) ? HTTP10_SHDR_416 : HTTP11_SHDR_416))
#define HTTP_SHDR_500(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_500 : (((minor) < 1) ? HTTP10_SHDR_500 : HTTP11_SHDR_500))
#define HTTP_SHDR_501(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_501 : (((minor) < 1) ? HTTP10_SHDR_501 : HTTP11_SHDR_501))
#define HTTP_SHDR_503(major, minor) \
	(((major) < 1) ? HTTP09_SHDR_503 : (((minor) < 1) ? HTTP10_SHDR_503 : HTTP11_SHDR_503))

static const char __http_dhdr00[] = "Content-type: ";
static const char __http_dhdr01[] = "Content-length: ";
static const char __http_dhdr02[] = "Content-range: bytes ";
static const char __http_dhdr03[] = "Retry-after: ";

static const char * const _http_dhdr[] = {
	__http_dhdr00, __http_dhdr01, __http_dhdr02, __http_dhdr03
};

#define HTTP_DHDR_MIME            0 /* content-type */
#define HTTP_DHDR_SIZE            1 /* content-length */
#define HTTP_DHDR_RANGE           2 /* content-range */
#define HTTP_DHDR_RETRY           3 /* retry-after */

static const char _http_err404p[] = \
	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
	"<html><head>\r\n"
	"<title>404 Element not found</title>\r\n"
	"</head><body>\r\n"
	"<h1>Element not found</h1>\r\n"
	"<p>The requested element could not be found.</p>\r\n"
	"</body></html>\r\n";
static const uint64_t _http_err404p_len = sizeof(_http_err404p) - 1;

static const char _http_err500p[] = \
	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
	"<html><head>\r\n"
	"<title>500 Internal server error</title>\r\n"
	"</head><body>\r\n"
	"<h1>Internal server error</h1>\r\n"
	"<p>An internal server error occured.</p>\r\n"
	"</body></html>\r\n";
static const uint64_t _http_err500p_len = sizeof(_http_err500p) - 1;

static const char _http_err501p[] = \
	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
	"<html><head>\r\n"
	"<title>501 Unsupported request</title>\r\n"
	"</head><body>\r\n"
	"<h1>Unsupported request</h1>\r\n"
	"<p>The request method is unsupported.</p>\r\n"
	"</body></html>\r\n";
static const uint64_t _http_err501p_len = sizeof(_http_err501p) - 1;

static const char _http_err503p[] = \
	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
	"<html><head>\r\n"
	"<title>503 Service unavailable</title>\r\n"
	"</head><body>\r\n"
	"<h1>Service unavailable</h1>\r\n"
	"<p>The service is temporarily unavailable.<br>Please try it again.</p>\r\n"
	"</body></html>\r\n";
static const uint64_t _http_err503p_len = sizeof(_http_err503p) - 1;

#ifdef HTTP_TESTFILE
static const char _http_testfile[] = \
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  /*   52 bytes */
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  /*  104 bytes */
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  /*  208 bytes */
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  /*  416 bytes */
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  /*  832 bytes */
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; /* 1456 bytes */
static const uint64_t _http_testfile_len = sizeof(_http_testfile) - 1;
#endif

#endif /* _HTTP_DATA_H_ */

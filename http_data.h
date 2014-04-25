#ifndef _HTTP_DATA_H_
#define _HTTP_DATA_H_

static const char __http_shdr00[] = "\r\n";
static const char __http_shdr01[] = "HTTP/0.9 200\r\n";
static const char __http_shdr02[] = "HTTP/0.9 206\r\n";
static const char __http_shdr03[] = "HTTP/0.9 400\r\n";
static const char __http_shdr04[] = "HTTP/0.9 404\r\n";
static const char __http_shdr05[] = "HTTP/0.9 416\r\n";
static const char __http_shdr06[] = "HTTP/0.9 500\r\n";
static const char __http_shdr07[] = "HTTP/0.9 501\r\n";
static const char __http_shdr08[] = "HTTP/1.0 200 OK\r\n";
static const char __http_shdr09[] = "HTTP/1.0 206 Partial content\r\n";
static const char __http_shdr10[] = "HTTP/1.0 400 Bad request\r\n";
static const char __http_shdr11[] = "HTTP/1.0 404 Element not found\r\n";
static const char __http_shdr12[] = "HTTP/1.0 416 Requested range not satisfiable\r\n";
static const char __http_shdr13[] = "HTTP/1.0 500 Internal server error\r\n";
static const char __http_shdr14[] = "HTTP/1.0 501 Not implemented\r\n";
static const char __http_shdr15[] = "HTTP/1.1 200 OK\r\n";
static const char __http_shdr16[] = "HTTP/1.1 206 Partial content\r\n";
static const char __http_shdr17[] = "HTTP/1.1 400 Bad request\r\n";
static const char __http_shdr18[] = "HTTP/1.1 404 Element not found\r\n";
static const char __http_shdr19[] = "HTTP/1.1 416 Requested range not satisfiable\r\n";
static const char __http_shdr20[] = "HTTP/1.1 500 Internal server error\r\n";
static const char __http_shdr21[] = "HTTP/1.1 501 Not implemented\r\n";
static const char __http_shdr22[] = "Content-type: text/plain\r\n";
static const char __http_shdr23[] = "Content-type: text/html\r\n";
static const char __http_shdr24[] = "Content-type: application/octet-stream\r\n";
static const char __http_shdr25[] = "Connection: close\r\n";
static const char __http_shdr26[] = "Connection: keep-alive\r\n";
static const char __http_shdr27[] = "Expires: Thu, 1 Jan 1970 00:00:00 GMT\r\nPragma: no-chache\r\n";
static const char __http_shdr28[] = "Server: "HTTPD_SERVER_AGENT"\r\n";
static const char __http_shdr29[] = "Accept-ranges: bytes\r\n";
static const char __http_shdr30[] = "Transfer-encoding: chunked\r\n";

static const char * const _http_shdr[] = {
	__http_shdr00, __http_shdr01, __http_shdr02, __http_shdr03, __http_shdr04,
	__http_shdr05, __http_shdr06, __http_shdr07, __http_shdr08, __http_shdr09,
	__http_shdr10, __http_shdr11, __http_shdr12, __http_shdr13, __http_shdr14,
	__http_shdr15, __http_shdr16, __http_shdr17, __http_shdr18, __http_shdr19,
	__http_shdr20, __http_shdr21, __http_shdr22, __http_shdr23, __http_shdr24,
	__http_shdr25, __http_shdr26, __http_shdr27, __http_shdr28, __http_shdr29,
	__http_shdr30
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
	sizeof(__http_shdr30) - 1
};

/* Indexes into _http_shdr */
#define HTTP_EOH                  0 /* end of header */
#define HTTP09_SHDR_OK            1 /* 200 OK (HTTP/0.9) */
#define HTTP09_SHDR_206           2 /* 206 Partial content (HTTP/0.9) */
#define HTTP09_SHDR_400           3 /* 400 Bad request (HTTP/0.9) */
#define HTTP09_SHDR_404           4 /* 404 File not found (HTTP/0.9) */
#define HTTP09_SHDR_416           5 /* 416 Requested range not satisfiable (HTTP/0.9) */
#define HTTP09_SHDR_500           6 /* 500 Internal server error (HTTP/0.9) */
#define HTTP09_SHDR_501           7 /* 501 Not implemented (HTTP/0.9) */
#define HTTP10_SHDR_OK            8 /* 200 OK (HTTP/1.0) */
#define HTTP10_SHDR_206           9 /* 206 Partial content (HTTP/1.0) */
#define HTTP10_SHDR_400          10 /* 400 Bad request (HTTP/1.0) */
#define HTTP10_SHDR_404          11 /* 404 Element not found (HTTP/1.0) */
#define HTTP10_SHDR_416          12 /* 416 Requested range not satisfiable (HTTP/1.0) */
#define HTTP10_SHDR_500          13 /* 500 Internal server error (HTTP/1.0) */
#define HTTP10_SHDR_501          14 /* 501 Not implemented (HTTP/1.0) */
#define HTTP11_SHDR_OK           15 /* 200 OK (HTTP/1.1) */
#define HTTP11_SHDR_206          16 /* 206 Partial content (HTTP/1.1) */
#define HTTP11_SHDR_400          17 /* 400 Bad request (HTTP/1.1) */
#define HTTP11_SHDR_404          18 /* 404 Element not found (HTTP/1.1) */
#define HTTP11_SHDR_416          19 /* 416 Requested range not satisfiable (HTTP/1.1) */
#define HTTP11_SHDR_500          20 /* 500 Internal server error (HTTP/1.1) */
#define HTTP11_SHDR_501          21 /* 501 Not implemented (HTTP/1.1) */
#define HTTP_SHDR_PLAIN          22 /* text/plain */
#define HTTP_SHDR_HTML           23 /* text/html */
#define HTTP_SHDR_BINARY         24 /* application/octet-stream */
#define HTTP_SHDR_CONN_CLOSE     25 /* Connection: close */
#define HTTP_SHDR_CONN_KEEPALIVE 26 /* Connection: keep-alive */
#define HTTP_SHDR_NOCACHE        27 /* Pragma: no-cache */
#define HTTP_SHDR_SERVER         28 /* Server agent */
#define HTTP_SHDR_ACC_BYTERANGE  29 /* Accept-ranges: bytes */
#define HTTP_SHDR_ENC_CHUNKED    30 /* Transfer-Encoding: chunked */

#define HTTP_SHDR_DEFAULT_TYPE   HTTP_SHDR_PLAIN

#define HTTP_SHDR_OK(major, minor) \
	(((major) < 1) ?  HTTP09_SHDR_OK : (((minor) < 1) ?  HTTP10_SHDR_OK :  HTTP11_SHDR_OK))
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

#define IS_HTTP_OK(shdr_code) \
	(((shdr_code) == HTTP09_SHDR_OK) || \
	 ((shdr_code) == HTTP10_SHDR_OK) || \
	 ((shdr_code) == HTTP11_SHDR_OK) || \
	 ((shdr_code) == HTTP09_SHDR_206) || \
	 ((shdr_code) == HTTP10_SHDR_206) || \
	 ((shdr_code) == HTTP11_SHDR_206))
#define IS_HTTP_400(shdr_code) \
	(((shdr_code) == HTTP09_SHDR_400) || \
	 ((shdr_code) == HTTP10_SHDR_400) || \
	 ((shdr_code) == HTTP11_SHDR_400))
#define IS_HTTP_404(shdr_code) \
	(((shdr_code) == HTTP09_SHDR_404) || \
	 ((shdr_code) == HTTP10_SHDR_404) || \
	 ((shdr_code) == HTTP11_SHDR_404))
#define IS_HTTP_416(shdr_code) \
	(((shdr_code) == HTTP09_SHDR_416) || \
	 ((shdr_code) == HTTP10_SHDR_416) || \
	 ((shdr_code) == HTTP11_SHDR_416))
#define IS_HTTP_500(shdr_code) \
	(((shdr_code) == HTTP09_SHDR_500) || \
	 ((shdr_code) == HTTP10_SHDR_500) || \
	 ((shdr_code) == HTTP11_SHDR_500))
#define IS_HTTP_501(shdr_code) \
	(((shdr_code) == HTTP09_SHDR_501) || \
	 ((shdr_code) == HTTP10_SHDR_501) || \
	 ((shdr_code) == HTTP11_SHDR_501))

static const char __http_dhdr00[] = "Content-type: ";
static const char __http_dhdr01[] = "Content-length: ";
static const char __http_dhdr02[] = "Content-range: bytes ";

static const char * const _http_dhdr[] = {
	__http_dhdr00, __http_dhdr01, __http_dhdr02,
};

#define HTTP_DHDR_MIME            0 /* content-type */
#define HTTP_DHDR_SIZE            1 /* content-length */
#define HTTP_DHDR_RANGE           2 /* content-range */

static const char _http_err404p[] = \
	"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"
	"<html>\n"
	"	<head>\n"
	"	<title>Error 404: Element not found</title>\n"
	"	</head>\n"
	"	\n"
	"	<body style=\"background-color:#212121; color:#FFFFFF; font-family:'Ubuntu Light','Ubuntu','HelveticaNeue-Light','Helvetica Neue Light','Helvetica Neue','Helvetica','Droid Sans','Verdana';\">\n"
	"	<table border=\"0\" height=\"100%\" width=\"100%\"><tr><td align=center valign=center>\n"
	"	<table border=\"0\">"
	"		<tr>\n"
	"			<td style=\"align:center; vertical-align:middle;\">\n"
	"				<div style=\"font-size:500%; color:#CC0000; text-shadow:#330000 3px 2px 5px; text-align:center;\">\n"
	"					<b>X</b>\n"
	"				</div>\n"
	"			</td>\n"
	"			<td>\n"
	"				&nbsp;&nbsp;&nbsp;\n"
	"		</td>\n"
	"			<td style=\"align:left; vertical-align:middle;\">\n"
	"				<div style=\"font-size:150%; text-shadow:#000000 3px 2px 5px;\">\n"
	"					Oops...\n"
	"				</div>\n"
	"				<br>\n"
	"				Sorry, element not found.<br>\n"
	"				Error: 404\n"
	"			</td>\n"
	"		</tr>\n"
	"	</table>\n"
	"	</td></tr></table>\n"
	"	</body>\n"
	"</html>\n";
static const size_t _http_err404p_len = sizeof(_http_err404p) - 1;

static const char _http_err500p[] = \
	"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"
	"<html>\n"
	"	<head>\n"
	"	<title>Error 500: Internal server error</title>\n"
	"	</head>\n"
	"	\n"
	"	<body style=\"background-color:#212121; color:#FFFFFF; font-family:'Ubuntu Light','Ubuntu','HelveticaNeue-Light','Helvetica Neue Light','Helvetica Neue','Helvetica','Droid Sans','Verdana';\">\n"
	"	<table border=\"0\" height=\"100%\" width=\"100%\"><tr><td align=center valign=center>\n"
	"	<table border=\"0\">"
	"		<tr>\n"
	"			<td style=\"align:center; vertical-align:middle;\">\n"
	"				<div style=\"font-size:500%; color:#CC0000; text-shadow:#330000 3px 2px 5px; text-align:center;\">\n"
	"					<b>X</b>\n"
	"				</div>\n"
	"			</td>\n"
	"			<td>\n"
	"				&nbsp;&nbsp;&nbsp;\n"
	"		</td>\n"
	"			<td style=\"align:left; vertical-align:middle;\">\n"
	"				<div style=\"font-size:150%; text-shadow:#000000 3px 2px 5px;\">\n"
	"					Oops...\n"
	"				</div>\n"
	"				<br>\n"
	"				An unexpected internal server error happend.<br>\n"
	"				Please try it again.<br>\n"
	"				Error: 500\n"
	"			</td>\n"
	"		</tr>\n"
	"	</table>\n"
	"	</td></tr></table>\n"
	"	</body>\n"
	"</html>\n";
static const size_t _http_err500p_len = sizeof(_http_err500p) - 1;

static const char _http_err501p[] = \
	"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"
	"<html>\n"
	"	<head>\n"
	"	<title>Error 501: Invalid request</title>\n"
	"	</head>\n"
	"	\n"
	"	<body style=\"background-color:#212121; color:#FFFFFF; font-family:'Ubuntu Light','Ubuntu','HelveticaNeue-Light','Helvetica Neue Light','Helvetica Neue','Helvetica','Droid Sans','Verdana';\">\n"
	"	<table border=\"0\" height=\"100%\" width=\"100%\"><tr><td align=center valign=center>\n"
	"	<table border=\"0\">"
	"		<tr>\n"
	"			<td style=\"align:center; vertical-align:middle;\">\n"
	"				<div style=\"font-size:500%; color:#CC0000; text-shadow:#330000 3px 2px 5px; text-align:center;\">\n"
	"					<b>X</b>\n"
	"				</div>\n"
	"			</td>\n"
	"			<td>\n"
	"				&nbsp;&nbsp;&nbsp;\n"
	"		</td>\n"
	"			<td style=\"align:left; vertical-align:middle;\">\n"
	"				<div style=\"font-size:150%; text-shadow:#000000 3px 2px 5px;\">\n"
	"					Oops...\n"
	"				</div>\n"
	"				<br>\n"
	"				Malformed request.<br>\n"
	"				Error: 501\n"
	"			</td>\n"
	"		</tr>\n"
	"	</table>\n"
	"	</td></tr></table>\n"
	"	</body>\n"
	"</html>\n";
static const size_t _http_err501p_len = sizeof(_http_err500p) - 1;

#endif /* _HTTP_DATA_H_ */

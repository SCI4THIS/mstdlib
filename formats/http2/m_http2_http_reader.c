#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>

M_http_error_t M_http2_http_reader_read(M_http_reader_t *httpr, const unsigned char *data, size_t data_len, size_t *len_read)
{
	(void)httpr;
	(void)data;
	(void)data_len;
	(void)len_read;
	/* Not yet implemented */
	return M_HTTP_ERROR_INVALIDUSE;
}

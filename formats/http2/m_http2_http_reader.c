#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>
#include "../http/m_http_reader_int.h"

static M_http_error_t M_http2_http_reader_frame_begin_func(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static M_http_error_t M_http2_http_reader_frame_end_func(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static M_http_error_t M_http2_http_reader_goaway_func(M_http2_goaway_t *goaway, void *thunk)
{
	(void)goaway;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static M_http_error_t M_http2_http_reader_data_func(M_http2_data_t *data, void *thunk)
{
	M_http_reader_t *hr      = thunk;
	M_http_error_t   h_error = hr->cbs.body_func(data->data, data->data_len, hr->thunk);
	return h_error;
}

static M_http_error_t M_http2_http_reader_settings_begin_func(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static M_http_error_t M_http2_http_reader_settings_end_func(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static M_http_error_t M_http2_http_reader_setting_func(M_http2_setting_t *setting, void *thunk)
{
	(void)setting;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static void M_http2_http_reader_error_func(M_http_error_t errcode, const char *errmsg)
{
	(void)errcode;
	(void)errmsg;
}

static M_http_error_t M_http2_http_reader_headers_begin_func(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}

static M_http_error_t M_http2_http_reader_headers_end_func(M_http2_framehdr_t *framehdr, void *thunk)
{
	M_http_reader_t *hr = thunk;
	M_http_error_t   h_error;
	(void)framehdr;
	h_error = hr->cbs.header_done_func(M_HTTP_DATA_FORMAT_CHUNKED, hr->thunk);
	return h_error;
}

static M_http_error_t M_http2_http_reader_header_priority_func(M_http2_header_priority_t *priority, void *thunk)
{
	(void)priority;
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}
static M_http_error_t M_http2_http_reader_header_func(M_http2_header_t *header, void *thunk)
{
	M_http_reader_t *hr          = thunk;
	M_http_error_t   h_error;

	if (M_str_eq(header->key, ":status")) {
		M_uint32 code = M_str_to_uint32(header->value);
		h_error = hr->cbs.start_func(M_HTTP_MESSAGE_TYPE_RESPONSE, M_HTTP_VERSION_2, M_HTTP_METHOD_UNKNOWN, NULL, code, "OK", hr->thunk);
	} else {
		hr->rstep = M_HTTP_READER_STEP_HEADER;
		h_error = M_http_reader_header_entry(hr, header->key, header->value);
	}

	return h_error;
}

static M_http_error_t M_http2_http_reader_pri_str_func(void *thunk)
{
	(void)thunk;
	return M_HTTP_ERROR_SUCCESS;
}


M_http_error_t M_http2_http_reader_read(M_http_reader_t *httpr, const unsigned char *data, size_t data_len, size_t *len_read)
{
	static const struct M_http2_reader_callbacks cbs = {
		M_http2_http_reader_frame_begin_func,
		M_http2_http_reader_frame_end_func,
		M_http2_http_reader_goaway_func,
		M_http2_http_reader_data_func,
		M_http2_http_reader_settings_begin_func,
		M_http2_http_reader_settings_end_func,
		M_http2_http_reader_setting_func,
		M_http2_http_reader_error_func,
		M_http2_http_reader_headers_begin_func,
		M_http2_http_reader_headers_end_func,
		M_http2_http_reader_header_priority_func,
		M_http2_http_reader_header_func,
		M_http2_http_reader_pri_str_func,
	};
	M_http2_reader_t *h2r      = M_http2_reader_create(&cbs, M_HTTP2_READER_NONE, httpr);
	M_http_error_t    h_error  = M_http2_reader_read(h2r, data, data_len, len_read);
	M_http2_reader_destroy(h2r);
	return h_error;
}

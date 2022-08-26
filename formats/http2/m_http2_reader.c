#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>

struct M_http2_reader {
	struct M_http2_reader_callbacks  cbs;
	M_uint32                         flags;
	void                            *thunk;
};

static M_http2_error_t M_http2_reader_frame_begin_func_default(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP2_ERROR_SUCCESS;
}
static M_http2_error_t M_http2_reader_frame_end_func_default(M_http2_framehdr_t *framehdr, void *thunk)
{
	(void)framehdr;
	(void)thunk;
	return M_HTTP2_ERROR_SUCCESS;
}


M_http2_reader_t *M_http2_reader_create(struct M_http2_reader_callbacks *cbs, M_uint32 flags, void *thunk)
{
	const struct M_http2_reader_callbacks default_cbs = {
		M_http2_reader_frame_begin_func_default,
		M_http2_reader_frame_end_func_default
	};

	M_http2_reader_t *h2r = M_malloc_zero(sizeof(*h2r));

	if (cbs == NULL) {
		M_mem_copy(&h2r->cbs, &default_cbs, sizeof(h2r->cbs));
	} else {
		h2r->cbs.frame_begin_func = cbs->frame_begin_func ? cbs->frame_begin_func : default_cbs.frame_begin_func;
		h2r->cbs.frame_end_func   = cbs->frame_end_func   ? cbs->frame_end_func   : default_cbs.frame_end_func;
	}

	h2r->flags = flags;
	h2r->thunk = thunk;

	return h2r;

}

void M_http2_reader_destroy(M_http2_reader_t *h2r)
{
	M_free(h2r);
}

static M_bool M_http2_frame_type_is_valid(M_http2_frame_type_t type)
{
	switch(type) {
		case M_HTTP2_FRAME_TYPE_DATA:
		case M_HTTP2_FRAME_TYPE_HEADERS:
		case M_HTTP2_FRAME_TYPE_PRIORITY:
		case M_HTTP2_FRAME_TYPE_RST_STREAM:
		case M_HTTP2_FRAME_TYPE_SETTINGS:
		case M_HTTP2_FRAME_TYPE_PUSH_PROMISE:
		case M_HTTP2_FRAME_TYPE_PING:
		case M_HTTP2_FRAME_TYPE_GOAWAY:
		case M_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
		case M_HTTP2_FRAME_TYPE_CONTINUATION:
			return M_TRUE;
		default:
			break;
	}
	return M_FALSE;
}

M_http2_error_t M_http2_reader_read(M_http2_reader_t *h2r, const unsigned char *data, size_t data_len, size_t *len_read)
{
	M_http2_error_t     res          = M_HTTP2_ERROR_INVALIDUSE;
	size_t              internal_len;
	M_http2_framehdr_t  framehdr;
	M_parser_t         *parser;

	if (h2r == NULL || data == NULL || data_len == 0)
		return M_HTTP2_ERROR_INVALIDUSE;

	if (len_read == NULL)
		len_read = &internal_len;

	*len_read = 0;

	parser = M_parser_create_const(data, data_len, M_PARSER_SPLIT_FLAG_NONE);
	while (M_http2_decode_framehdr(parser, &framehdr)) {
		if (!M_http2_frame_type_is_valid(framehdr.type)) {
			res = M_HTTP2_ERROR_INVALID_FRAME_TYPE;
			goto done;
		}
		h2r->cbs.frame_begin_func(&framehdr, h2r->thunk);
		M_parser_mark(parser);
		switch(framehdr.type) {
			case M_HTTP2_FRAME_TYPE_DATA:
			case M_HTTP2_FRAME_TYPE_HEADERS:
			case M_HTTP2_FRAME_TYPE_PRIORITY:
			case M_HTTP2_FRAME_TYPE_RST_STREAM:
			case M_HTTP2_FRAME_TYPE_SETTINGS:
			case M_HTTP2_FRAME_TYPE_PUSH_PROMISE:
			case M_HTTP2_FRAME_TYPE_PING:
			case M_HTTP2_FRAME_TYPE_GOAWAY:
			case M_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
			case M_HTTP2_FRAME_TYPE_CONTINUATION:
				break;
		}
		M_parser_mark_rewind(parser);
		M_parser_consume(parser, framehdr.len.u32);
		h2r->cbs.frame_end_func(&framehdr, h2r->thunk);
	}
	M_printf("M_http2_reader_read(%p,%p,%zu,%p)\n", h2r, data, data_len, len_read);
	/* Not yet implemented */
done:
	*len_read = data_len - M_parser_len(parser);
	M_parser_destroy(parser);
	return res;
}

M_http_error_t M_http2_http_reader_read(M_http_reader_t *httpr, const unsigned char *data, size_t data_len, size_t *len_read)
{
	M_printf("M_http2_http_reader_read(%p,%p,%zu,%p)\n", httpr, data, data_len, len_read);
	/* Not yet implemented */
	return M_HTTP_ERROR_INVALIDUSE;
}

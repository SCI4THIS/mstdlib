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

static M_http2_error_t M_http2_reader_goaway_func_default(M_http2_goaway_t *goaway, void *thunk)
{
	(void)goaway;
	(void)thunk;
	return M_HTTP2_ERROR_SUCCESS;
}

static M_http2_error_t M_http2_reader_data_func_default(M_http2_data_t *data, void *thunk)
{
	(void)data;
	(void)thunk;
	return M_HTTP2_ERROR_SUCCESS;
}


M_http2_reader_t *M_http2_reader_create(struct M_http2_reader_callbacks *cbs, M_uint32 flags, void *thunk)
{
	const struct M_http2_reader_callbacks default_cbs = {
		M_http2_reader_frame_begin_func_default,
		M_http2_reader_frame_end_func_default,
		M_http2_reader_goaway_func_default,
		M_http2_reader_data_func_default,
	};

	M_http2_reader_t *h2r = M_malloc_zero(sizeof(*h2r));

	if (cbs == NULL) {
		M_mem_copy(&h2r->cbs, &default_cbs, sizeof(h2r->cbs));
	} else {
		h2r->cbs.frame_begin_func = cbs->frame_begin_func ? cbs->frame_begin_func : default_cbs.frame_begin_func;
		h2r->cbs.frame_end_func   = cbs->frame_end_func   ? cbs->frame_end_func   : default_cbs.frame_end_func;
		h2r->cbs.goaway_func      = cbs->goaway_func      ? cbs->goaway_func      : default_cbs.goaway_func;
		h2r->cbs.data_func        = cbs->data_func        ? cbs->data_func        : default_cbs.data_func;
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

static M_bool M_parser_read_bytes_ntoh(M_parser_t *parser, M_uint8 *bytes, size_t len)
{
	for (; len-->0;) {
		if (!M_parser_read_byte(parser, &bytes[len]))
			return M_FALSE;
	}
	return M_TRUE;
}

static M_bool M_parser_read_stream(M_parser_t *parser, M_http2_stream_t *stream)
{
	M_uint8 byte;
	if (!M_parser_read_byte(parser, &byte))
		return M_FALSE;
	stream->is_R_set = (byte & 0x80) != 0;
	stream->id.u8[3] = byte & 0x7F;
	return M_parser_read_bytes_ntoh(parser, stream->id.u8, 3);
}

static M_http2_error_t M_http2_reader_read_data(M_http2_reader_t *h2r, M_http2_framehdr_t *framehdr, M_parser_t *parser)
{
	M_http2_data_t  data      = { 0 };
	M_http2_error_t errcode   = M_HTTP2_ERROR_SUCCESS;
	M_bool          is_padded = (framehdr->flags & 0x8) != 0;

	data.framehdr = framehdr;

	if (is_padded)
		M_parser_read_byte(parser, &data.pad_len); /* uint8 explicitly */

	data.data     = M_parser_peek(parser);
	data.data_len = framehdr->len.u32 - data.pad_len;

	if (is_padded)
		data.pad = &data.data[data.data_len];

	errcode = h2r->cbs.data_func(&data, h2r->thunk);
	return errcode;
}

static M_http2_error_t M_http2_reader_read_goaway(M_http2_reader_t *h2r, M_http2_framehdr_t *framehdr, M_parser_t *parser)
{
	M_http2_goaway_t goaway  = { 0 };
	M_http2_error_t  errcode = M_HTTP2_ERROR_SUCCESS;

	goaway.framehdr = framehdr;
	if (!M_parser_read_stream(parser, &goaway.stream))
		return M_HTTP2_ERROR_INTERNAL;

	if (!M_parser_read_bytes_ntoh(parser, goaway.errcode.u8, 4))
		return M_HTTP2_ERROR_INTERNAL;

	goaway.debug_data_len = framehdr->len.u32 - 8; /* minus stream and errcode */
	goaway.debug_data     = NULL;
	if (goaway.debug_data_len > 0)
		goaway.debug_data = M_parser_peek(parser);

	errcode = h2r->cbs.goaway_func(&goaway, h2r->thunk);

	if (goaway.debug_data_len > 0)
		M_parser_consume(parser, goaway.debug_data_len);

	return errcode;
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
		res = M_HTTP2_ERROR_SUCCESS;
		switch(framehdr.type) {
			case M_HTTP2_FRAME_TYPE_DATA:
				res = M_http2_reader_read_data(h2r, &framehdr, parser);
				break;
			case M_HTTP2_FRAME_TYPE_HEADERS:
			case M_HTTP2_FRAME_TYPE_PRIORITY:
			case M_HTTP2_FRAME_TYPE_RST_STREAM:
			case M_HTTP2_FRAME_TYPE_SETTINGS:
			case M_HTTP2_FRAME_TYPE_PUSH_PROMISE:
			case M_HTTP2_FRAME_TYPE_PING:
			case M_HTTP2_FRAME_TYPE_GOAWAY:
				res = M_http2_reader_read_goaway(h2r, &framehdr, parser);
				break;
			case M_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
			case M_HTTP2_FRAME_TYPE_CONTINUATION:
				break;
		}
		if (res != M_HTTP2_ERROR_SUCCESS)
			goto done;
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

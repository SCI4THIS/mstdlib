#ifndef __M_HTTP2_INT_H__
#define __M_HTTP2_INT_H__

#include <mstdlib/mstdlib.h>
#include <mstdlib/mstdlib_io.h>
#include <mstdlib/io/m_io_layer.h>
#include <mstdlib/net/m_http2.h>
#include "m_http2_nghttp2.h"

typedef enum {
	HTTP2_STATE_INIT          = 0,
	HTTP2_STATE_LISTENING     = 1,
	HTTP2_STATE_CONNECTING    = 2,
	HTTP2_STATE_CONNECTED     = 3,
	HTTP2_STATE_DISCONNECTING = 4,
	HTTP2_STATE_DISCONNECTED  = 5,
	HTTP2_STATE_ERROR         = 6,
} http2_state_t;

typedef enum {
	M_HTTP2_TYPE_SERVER = 0,
	M_HTTP2_TYPE_CLIENT = 1,
} M_http2_type_t;

struct M_http2_t {
	M_http2_type_t               type;
	M_http2_nghttp2_t           *ng;
	M_buf_t                     *out_buf;
	M_parser_t                  *in_parser;
	char                        *scheme;
	char                        *authority;
	M_io_handle_t               *handle;
	M_io_layer_t                *layer;
	M_http2_push_promise_mode_t  push_promise_mode;
	M_hash_u64vp_t              *streams;
};


void M_http2_stream_insert_request(M_http2_t *ht, M_int32 id, const char *key, const char *value);
void M_http2_stream_insert_response(M_http2_t *ht, M_int32 id, const char *key, const char *value);

M_http2_stream_t *M_http2_stream_create(M_int32 stream_id, M_hash_dict_t *request);

#endif

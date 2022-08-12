#ifndef __M_HTTP2_NGHTTP2_H__
#define __M_HTTP2_NGHTTP2_H__

#include <nghttp2/nghttp2.h>

typedef struct {
	nghttp2_session             *session;
	nghttp2_session_callbacks   *callbacks;
	nghttp2_option              *options;
} M_http2_nghttp2_t;

#include "m_http2_int.h"

M_http2_nghttp2_t *M_http2_nghttp2_create(M_http2_t *ht);
void               M_http2_nghttp2_destroy(M_http2_nghttp2_t *ng);
void               M_http2_nghttp2_mem_send(M_http2_t *ht);
size_t             M_http2_nghttp2_mem_recv(M_http2_t *ht);
M_int32            M_http2_nghttp2_client_submit_request(M_http2_t *ht, M_hash_dict_t *request);

#endif

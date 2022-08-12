#include "m_http2_int.h"

M_http2_stream_t *M_http2_stream_create(M_int32 stream_id, M_hash_dict_t *request)
{
	M_http2_stream_t *stream = M_malloc_zero(sizeof(*stream));

	stream->id               = stream_id;
	stream->response         = M_hash_dict_create(32, 75, M_HASH_DICT_NONE);
	stream->request          = request;
	stream->data             = M_parser_create(M_PARSER_SPLIT_FLAG_NONE);

	if (stream->request == NULL)
		stream->request = M_hash_dict_create(32, 75, M_HASH_DICT_NONE);

	return stream;
}

void M_http2_stream_destroy(M_http2_stream_t *stream)
{
	M_hash_dict_destroy(stream->request);
	M_hash_dict_destroy(stream->response);
	M_parser_destroy(stream->data);
	stream->request  = NULL;
	stream->response = NULL;
	stream->data     = NULL;
	M_free(stream);
}

static void M_http2_stream_destroy_cb(void *stream)
{
	M_http2_stream_destroy(stream);
}

void M_http2_stream_insert_request(M_http2_t *ht, M_int32 id, const char *key, const char *value)
{
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, (M_uint64)id);
	M_hash_dict_insert(stream->request, key, value);
}

void M_http2_stream_insert_response(M_http2_t *ht, M_int32 id, const char *key, const char *value)
{
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, (M_uint64)id);
	M_hash_dict_insert(stream->response, key, value);
}

static const char * M_http_reqtype_str(M_http2_request_t reqtype)
{
	switch (reqtype) {
		case M_HTTP2_REQUEST_GET:
			return "GET";
	}
}

static M_int32 M_http2_client_submit_request(M_http2_t *ht, M_hash_dict_t *request)
{
	return M_http2_nghttp2_client_submit_request(ht, request);
}

M_int32 M_http2_client_request(M_http2_t *ht, M_http2_request_t reqtype, const char *path)
{
	M_int32           id;
	M_hash_dict_t    *request;

	if (ht == NULL)
		return 0;

	request = M_hash_dict_create(8, 75, M_HASH_DICT_NONE);

	M_hash_dict_insert(request, ":method"   , M_http_reqtype_str(reqtype));
	M_hash_dict_insert(request, ":scheme"   , ht->scheme);
	M_hash_dict_insert(request, ":authority", ht->authority);
	M_hash_dict_insert(request, ":path"     , path);

	id = M_http2_client_submit_request(ht, request);

	M_hash_u64vp_insert(ht->streams, (M_uint64)id, M_http2_stream_create(id, request));

	return id;
}

M_http2_stream_t *M_http2_stream_take_by_id(M_http2_t *ht, M_int32 stream_id)
{
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, (M_uint64)stream_id);
	if (stream != NULL) {
		M_hash_u64vp_remove(ht->streams, (M_uint64)stream_id, M_FALSE);
	}
	return stream;
}

M_http2_t *M_http2_client_create(const char* scheme, const char *authority)
{
	M_http2_t                 *ht           = NULL;

	ht = M_malloc_zero(sizeof(*ht));
	ht->type = M_HTTP2_TYPE_CLIENT;
	ht->scheme = M_strdup(scheme);
	ht->authority = M_strdup(authority);
	ht->streams = M_hash_u64vp_create(32, 75, M_HASH_U64VP_NONE, M_http2_stream_destroy_cb);
	ht->ng = M_http2_nghttp2_create(ht);
	ht->out_buf = M_buf_create();
	ht->in_parser = M_parser_create(M_PARSER_FLAG_NONE);
	return ht;
}

void M_http2_destroy(M_http2_t *ht)
{
	M_http2_nghttp2_destroy(ht->ng);
	M_hash_u64vp_destroy(ht->streams, M_TRUE);
	M_free(ht->scheme);
	M_free(ht->authority);
	M_buf_cancel(ht->out_buf);
	M_parser_destroy(ht->in_parser);
	M_free(ht);
}

void M_http2_client_push_promise_mode(M_http2_t *ht, M_http2_push_promise_mode_t mode)
{
	ht->push_promise_mode = mode;
}

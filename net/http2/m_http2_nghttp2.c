#include "m_http2_nghttp2.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

static ssize_t ng_send_callback(nghttp2_session *session, const uint8_t *data, size_t length,
		int flags, void *user_data)
{
	M_printf("ng_send_callback(%p,%p,%zu,%d,%p)\n", session, data, length, flags, user_data);
	return 0;
}

static ssize_t ng_recv_callback(nghttp2_session *session, uint8_t *buf, size_t length,
		int flags, void *thunk)
{
	M_printf("ng_recv_callback(%p,%p,%zu,%d,%p)\n", session, buf, length, flags, thunk);
	return 0;
}

static const char *ng_frame_type_str(M_uint8 type)
{
	switch (type) {
		case NGHTTP2_DATA:
			return "DATA";
		case NGHTTP2_HEADERS:
			return "HEADERS";
		case NGHTTP2_PRIORITY:
			return "PRIORITY";
		case NGHTTP2_RST_STREAM:
			return "RST_STREAM";
		case NGHTTP2_SETTINGS:
			return "SETTINGS";
		case NGHTTP2_PUSH_PROMISE:
			return "PUSH_PROMISE";
		case NGHTTP2_PING:
			return "PING";
		case NGHTTP2_GOAWAY:
			return "GOAWAY";
		case NGHTTP2_WINDOW_UPDATE:
			return "UPDATE";
		case NGHTTP2_CONTINUATION:
			return "CONTINUATION";
		case NGHTTP2_ALTSVC:
			return "ALTSVC";
		case NGHTTP2_ORIGIN:
			return "ORIGIN";
		case NGHTTP2_PRIORITY_UPDATE:
			return "PRIORITY_UPDATE";
	}
	return "INVALID";
}

static int ng_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
		void *thunk)
{
	M_http2_t *ht = thunk;

	M_printf("ng_on_frame_recv_callback(%p,%p,%p): type=%s, stream_id=%d\n", session, frame, thunk, ng_frame_type_str(frame->hd.type), frame->hd.stream_id);
	if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
		M_int32 id = frame->push_promise.promised_stream_id;
		if (ht->push_promise_mode == M_HTTP2_PUSH_PROMISE_MODE_IGNORE) {
			M_printf("RST_STREAM PUSH_PROMISE (promised: %d)\n", id);
			nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, id, NGHTTP2_NO_ERROR);
		}
	}
	return 0;
}

static int ng_on_invalid_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
		int lib_error_code, void *user_data)
{
	M_printf("ng_on_invalid_frame_recv_callback(%p,%p,%d,%p)\n", session, frame, lib_error_code, user_data);
	return 0;
}

static int ng_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
		const uint8_t *data, size_t len, void *thunk)
{
	M_http2_t        *ht     = thunk;
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, (M_uint64)stream_id);
	(void)flags;
	(void)session;
	M_parser_append(stream->data, data, len);
	return 0;
}

static int ng_before_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
		void *user_data)
{
	M_printf("ng_before_frame_send_callback(%p,%p,%p)\n", session, frame, user_data);
	return 0;
}

static int ng_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
		void *user_data)
{
	size_t i;
	(void)user_data;
	M_printf("ng_on_frame_send_callback(%p,%p,%p): type=%s, stream_id=%d\n", session, frame, user_data, ng_frame_type_str(frame->hd.type), frame->hd.stream_id);

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
			const nghttp2_nv *nva = frame->headers.nva;
			printf("[INFO] C ----------------------------> S (HEADERS)\n");
			for (i = 0; i < frame->headers.nvlen; ++i) {
				fwrite(nva[i].name, 1, nva[i].namelen, stdout);
				printf(": ");
				fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
				printf("\n");
			}
		}
		break;
	case NGHTTP2_RST_STREAM:
		printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
		break;
	case NGHTTP2_GOAWAY:
		printf("[INFO] C ----------------------------> S (GOAWAY)\n");
		break;
	}
	return 0;
}

static int ng_on_frame_not_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
		int lib_error_code, void *user_data)
{
	M_printf("ng_on_frame_not_send_callback(%p,%p,%d,%p)\n", session, frame, lib_error_code, user_data);
	return 0;
}

static int ng_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
		void *thunk)
{
	M_http2_t        *ht = thunk;
	M_http2_stream_t *stream;
	M_printf("ng_on_stream_close_callback(%p,%d,%u,%p)\n", session, stream_id, error_code, thunk);
	stream = M_hash_u64vp_get_direct(ht->streams, (M_uint64)stream_id);
	M_printf("stream: %p\n", stream);
	if (stream != NULL) {
		M_io_layer_softevent_add(ht->layer, M_TRUE, M_EVENT_TYPE_READ, M_IO_ERROR_SUCCESS);
	}
	return 0;
}

static int ng_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame,
		void *thunk)
{
	M_http2_t *ht = thunk;
	if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
		M_int32 id = frame->push_promise.promised_stream_id;
		if (ht->push_promise_mode == M_HTTP2_PUSH_PROMISE_MODE_KEEP) {
			M_printf("Created stream for promised id: %d\n", id);
			M_hash_u64vp_insert(ht->streams, (M_uint64)id, M_http2_stream_create(id, NULL));
		}
	}
	M_printf("ng_on_begin_headers_callback(%p,%p,%p) type=%s\n", session, frame, thunk, ng_frame_type_str(frame->hd.type));
	return 0;
}

/*
static int ng_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                          const uint8_t *name, size_t namelen,
                                          const uint8_t *value, size_t valuelen,
                                          uint8_t flags, void *user_data)
{
	M_printf("ng_on_header_callback(%p,%p,%s,%zu,%s,%zu,%x,%p)\n", session, frame, name, namelen,
			value, valuelen, flags, user_data);
	return 0;
}
*/

static int ng_on_header_callback2(nghttp2_session *session,
                                           const nghttp2_frame *frame,
                                           nghttp2_rcbuf *rcbuf_key,
                                           nghttp2_rcbuf *rcbuf_value, uint8_t flags,
                                           void *thunk)
{
	M_http2_t  *ht        = thunk;
	M_int32    id         = frame->hd.stream_id;
	const char *key       = (const char *)nghttp2_rcbuf_get_buf(rcbuf_key).base;
	const char *value     = (const char *)nghttp2_rcbuf_get_buf(rcbuf_value).base;

	switch (frame->hd.type) {
		case NGHTTP2_PUSH_PROMISE:
			if (ht->push_promise_mode == M_HTTP2_PUSH_PROMISE_MODE_IGNORE)
				return 0;
			id = frame->push_promise.promised_stream_id;
			M_http2_stream_insert_request(ht, id, key, value);
			break;
		case NGHTTP2_HEADERS:
			M_http2_stream_insert_response(ht, id, key, value);
			break;
		default:
			M_printf("ng_on_header_callback2(%p,%p,%p,%p,%x,%p)\n", session, frame, rcbuf_key, rcbuf_value, flags, thunk);
			M_printf("Stream ID=%d, name: \"%s\", value: \"%s\", type=\"%s\"\n", id, key, value, ng_frame_type_str(frame->hd.type));
			break;
	}
	return 0;
}

/*
static int ng_on_invalid_header_callback(
    nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
    size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
    void *user_data)
{
	M_printf("ng_on_invalid_header_callback(%p,%p,%s,%zu,%s,%zu,%x,%p)\n", session, frame, name, namelen, value, valuelen, flags, user_data);
	return 0;
}
*/

static int ng_on_invalid_header_callback2(
    nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name,
    nghttp2_rcbuf *value, uint8_t flags, void *user_data)
{
	M_printf("ng_on_invalid_header_callback2(%p,%p,%p,%p,%x,%p)\n", session, frame, name, value, flags, user_data);
	return 0;
}

static ssize_t ng_select_padding_callback(nghttp2_session *session,
                                                   const nghttp2_frame *frame,
                                                   size_t max_payloadlen,
                                                   void *user_data)
{
	M_printf("ng_select_padding_callback(%p,%p,%zu,%p)\n", session, frame, max_payloadlen, user_data);
	return (ssize_t)frame->hd.length;
}

static ssize_t ng_data_source_read_length_callback(
    nghttp2_session *session, uint8_t frame_type, int32_t stream_id,
    int32_t session_remote_window_size, int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size, void *user_data)
{
	M_printf("ng_data_source_read_length_callback(%p,%x,%x,%d,%d,%u,%p)\n", session, frame_type, stream_id, session_remote_window_size, stream_remote_window_size, remote_max_frame_size, user_data);
	return 0;
}

static int ng_on_begin_frame_callback(nghttp2_session *session,
                                               const nghttp2_frame_hd *hd,
                                               void *user_data)
{
	M_printf("ng_on_begin_frame_callback(%p,%p,%p) type=%s, stream_id=%d\n", session, hd, user_data, ng_frame_type_str(hd->type), hd->stream_id);
	return 0;
}

static int ng_send_data_callback(nghttp2_session *session,
                                          nghttp2_frame *frame,
                                          const uint8_t *framehd, size_t length,
                                          nghttp2_data_source *source,
                                          void *user_data)
{
	M_printf("ng_send_data_callback(%p,%p,%s,%zu,%p,%p)\n", session, frame, framehd, length, source, user_data);
	return 0;
}

static ssize_t ng_pack_extension_callback(nghttp2_session *session,
                                                   uint8_t *buf, size_t len,
                                                   const nghttp2_frame *frame,
                                                   void *user_data)
{
	M_printf("ng_pack_extension_callback(%p,%p,%zu,%p,%p)\n", session, buf, len, frame, user_data);
	return 0;
}

static int ng_unpack_extension_callback(nghttp2_session *session,
                                                 void **payload,
                                                 const nghttp2_frame_hd *hd,
                                                 void *user_data)
{
	M_printf("ng_unpack_extension_callback(%p,%p,%p,%p)\n", session, payload, hd, user_data);
	return 0;
}

static int ng_on_extension_chunk_recv_callback(
    nghttp2_session *session, const nghttp2_frame_hd *hd, const uint8_t *data,
    size_t len, void *user_data)
{
	M_printf("ng_on_extension_chunk_recv_callback(%p,%p,%p,%zu,%p)\n", session, hd, data, len, user_data);
	return 0;
}


/*
static int ng_error_callback(nghttp2_session *session, const char *msg,
                                      size_t len, void *user_data)
{
	M_printf("ng_error_callback(%p,%s,%zu,%p)\n", session, msg, len, user_data);
	return 0;
}
*/

static int ng_error_callback2(nghttp2_session *session,
                                       int lib_error_code, const char *msg,
                                       size_t len, void *user_data)
{
	M_printf("ng_error_callback2(%p,%d,%s,%zu,%p)\n", session, lib_error_code, msg, len, user_data);
	return 0;
}

static void M_set_ng_callbacks(nghttp2_session_callbacks *ng_callbacks)
{
	nghttp2_session_callbacks_set_send_callback(ng_callbacks, ng_send_callback);
	nghttp2_session_callbacks_set_recv_callback(ng_callbacks, ng_recv_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(ng_callbacks, ng_on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(ng_callbacks, ng_on_invalid_frame_recv_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ng_callbacks, ng_on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_before_frame_send_callback(ng_callbacks, ng_before_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(ng_callbacks, ng_on_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_not_send_callback(ng_callbacks, ng_on_frame_not_send_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(ng_callbacks, ng_on_stream_close_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(ng_callbacks, ng_on_begin_headers_callback);
	/* If both are set only callback2 is called
	nghttp2_session_callbacks_set_on_header_callback(ng_callbacks, ng_on_header_callback);
	*/
	nghttp2_session_callbacks_set_on_header_callback2(ng_callbacks, ng_on_header_callback2);
	/* If both are set only callback2 is called
	nghttp2_session_callbacks_set_on_invalid_header_callback(ng_callbacks, ng_on_invalid_header_callback);
	*/
	nghttp2_session_callbacks_set_on_invalid_header_callback2(ng_callbacks, ng_on_invalid_header_callback2);
	nghttp2_session_callbacks_set_select_padding_callback(ng_callbacks, ng_select_padding_callback);
	nghttp2_session_callbacks_set_data_source_read_length_callback(ng_callbacks, ng_data_source_read_length_callback);
	nghttp2_session_callbacks_set_on_begin_frame_callback(ng_callbacks, ng_on_begin_frame_callback);
	nghttp2_session_callbacks_set_send_data_callback(ng_callbacks, ng_send_data_callback);
	nghttp2_session_callbacks_set_pack_extension_callback(ng_callbacks, ng_pack_extension_callback);
	nghttp2_session_callbacks_set_unpack_extension_callback(ng_callbacks, ng_unpack_extension_callback);
	nghttp2_session_callbacks_set_on_extension_chunk_recv_callback(ng_callbacks, ng_on_extension_chunk_recv_callback);
	/* If both are set only callback2 is called
	nghttp2_session_callbacks_set_error_callback(ng_callbacks, ng_error_callback);
	*/
	nghttp2_session_callbacks_set_error_callback2(ng_callbacks, ng_error_callback2);
}

/*
static void M_set_ng_callbacks_server(nghttp2_session_callbacks *ng_callbacks)
{
	M_set_ng_callbacks(ng_callbacks);
}
*/

static void M_set_ng_callbacks_client(nghttp2_session_callbacks *ng_callbacks)
{
	M_set_ng_callbacks(ng_callbacks);
}

static void M_set_ng_option(nghttp2_option *ng_options)
{
	nghttp2_option_set_builtin_recv_extension_type(ng_options, 0); /* (ignored) < 0x9 */
	nghttp2_option_set_max_deflate_dynamic_table_size(ng_options, 4096); /* default: 4096 */
	nghttp2_option_set_max_outbound_ack(ng_options, 1000); /* default: 1000 */
	nghttp2_option_set_max_send_header_block_length(ng_options, 65536); /* default: 65536 */
	nghttp2_option_set_max_settings(ng_options, 32); /* default: 32 */
	nghttp2_option_set_no_auto_ping_ack(ng_options, 0);
	nghttp2_option_set_no_auto_window_update(ng_options, 0); /* default: 0 */
	nghttp2_option_set_no_closed_streams(ng_options, 1);
	nghttp2_option_set_no_http_messaging(ng_options, 0);
	nghttp2_option_set_no_recv_client_magic(ng_options, 0);
	nghttp2_option_set_peer_max_concurrent_streams(ng_options, 100); /* default: 100 - overwritten byte initial SETTINGS frame*/
	nghttp2_option_set_user_recv_extension_type(ng_options, 0); /* (ignored) < 0x9 */
}

/*
static void M_set_ng_option_server(nghttp2_option *ng_options)
{
	M_set_ng_option(ng_options);
	nghttp2_option_set_server_fallback_rfc7540_priorities(ng_options, 1);
}
*/

static void M_set_ng_option_client(nghttp2_option *ng_options)
{
	M_set_ng_option(ng_options);
	nghttp2_option_set_max_reserved_remote_streams(ng_options, 200); /* default: 200 */
}

static void *ng_malloc_cb(size_t size, void *thunk)
{
	(void)thunk;
	return M_malloc(size);
}

static void ng_free_cb(void *ptr, void *thunk)
{
	(void)thunk;
	M_free(ptr);
}

static void *ng_calloc_cb(size_t nmemb, size_t size, void *thunk)
{
	(void)thunk;
	return M_malloc_zero(nmemb * size);
}

static void *ng_realloc_cb(void *ptr, size_t size, void *thunk)
{
	(void)thunk;
	return M_realloc(ptr, size);
}

M_http2_nghttp2_t *M_http2_nghttp2_create(M_http2_t *ht)
{
	int                        rc;
	M_http2_nghttp2_t         *ng     = NULL;
	nghttp2_settings_entry     iv[]   = {
		{ NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
		{ NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 0 },
	};
	nghttp2_mem                ng_mem = {
		NULL /* thunk */,
		ng_malloc_cb,
		ng_free_cb,
		ng_calloc_cb,
		ng_realloc_cb,
	};

	ng = M_malloc_zero(sizeof(*ng));

	rc = nghttp2_session_callbacks_new(&ng->callbacks);
	if (rc != 0) {
		goto fail;
	}
	rc = nghttp2_option_new(&ng->options);
	if (rc != 0) {
		goto fail;
	}
	M_set_ng_option_client(ng->options);
	M_set_ng_callbacks_client(ng->callbacks);
	nghttp2_session_client_new3(&ng->session, ng->callbacks, ht, ng->options, &ng_mem);
	rc = nghttp2_submit_settings(ng->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
	if (rc != 0) {
		goto fail;
	}
	return ng;
fail:
	M_http2_nghttp2_destroy(ng);
	return NULL;
}

void M_http2_nghttp2_destroy(M_http2_nghttp2_t *ng)
{
	if (ng->options != NULL) {
		nghttp2_option_del(ng->options);
		ng->options = NULL;
	}
	if (ng->callbacks != NULL) {
		nghttp2_session_callbacks_del(ng->callbacks);
		ng->callbacks = NULL;
	}
	if (ng->session != NULL) {
		nghttp2_session_del(ng->session);
		ng->session = NULL;
	}
	M_free(ng);
}

void M_http2_nghttp2_mem_send(M_http2_t *ht)
{
	const uint8_t *data;
	ssize_t        data_len;

	data_len = nghttp2_session_mem_send(ht->ng->session, &data);

	if (data_len > 0) {
		M_buf_add_bytes(ht->out_buf, data, (size_t)data_len);
	}
}

size_t M_http2_nghttp2_mem_recv(M_http2_t *ht)
{
	const M_uint8 *data     = M_parser_peek(ht->in_parser);
	size_t         data_len = M_parser_len(ht->in_parser);
	ssize_t        rv       = nghttp2_session_mem_recv(ht->ng->session, data, data_len);
	return (size_t)rv;
}

static void M_http2_client_set_hdr(nghttp2_nv *hdr, const char *name, const char *value, M_uint8 flags)
{
	hdr->name = (uint8_t*)name;
	hdr->value = (uint8_t*)value;
	hdr->namelen = M_str_len(name);
	hdr->valuelen = M_str_len(value);
	hdr->flags = flags;
}

M_int32 M_http2_nghttp2_client_submit_request(M_http2_t *ht, M_hash_dict_t *request)
{
	nghttp2_nv         *hdrs;
	const uint8_t      *data;
	ssize_t             data_len;
	M_hash_dict_enum_t *hashenum;
	size_t              num_headers;
	size_t              i;
	M_int32             stream_id;

	if (request == NULL || M_hash_dict_num_keys(request) == 0)
		return 0;

	num_headers = M_hash_dict_enumerate(request, &hashenum);
	hdrs = M_malloc_zero(sizeof(*hdrs) * num_headers);
	for (i = 0; i < num_headers; i++) {
		const char *key;
		const char *value;
		M_hash_dict_enumerate_next(request, hashenum, &key, &value);
		M_http2_client_set_hdr(&hdrs[i], key, value, NGHTTP2_NV_FLAG_NONE);
	}
	M_hash_dict_enumerate_free(hashenum);

	stream_id = nghttp2_submit_request(ht->ng->session, NULL, hdrs, num_headers, NULL, NULL);

	data_len = nghttp2_session_mem_send(ht->ng->session, &data);
	M_buf_add_bytes(ht->out_buf, data, (size_t)data_len);

	M_free(hdrs);

	return stream_id;
}

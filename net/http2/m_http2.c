#include <nghttp2/nghttp2.h>
#include <mstdlib/mstdlib.h>
#include <mstdlib/mstdlib_io.h>
#include <mstdlib/io/m_io_layer.h>
#include <mstdlib/net/m_http2.h>

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
	nghttp2_session             *ng_session;
	nghttp2_session_callbacks   *ng_callbacks;
	nghttp2_option              *ng_options;
	M_buf_t                     *out_buf;
	M_parser_t                  *in_parser;
	char                        *scheme;
	char                        *authority;
	M_io_handle_t               *handle;
	M_io_layer_t                *layer;
	M_http2_push_promise_mode_t  push_promise_mode;
	M_hash_u64vp_t              *streams;
};

struct M_io_handle {
	http2_state_t  state;
	M_http2_t     *ht;
	M_io_t        *io;
	M_io_meta_t   *meta;
	char           errmsg[256];
};

static M_http2_stream_t *M_http2_stream_create(M_int32 stream_id, M_hash_dict_t *request)
{
	M_http2_stream_t *stream = M_malloc_zero(sizeof(*stream));
	stream->id       = stream_id;
	stream->response = M_hash_dict_create(32, 75, M_HASH_DICT_NONE);
	stream->request  = request ? request : M_hash_dict_create(32, 75, M_HASH_DICT_NONE);
	stream->data     = M_parser_create(M_PARSER_SPLIT_FLAG_NONE);
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

static void M_http2_stream_insert_request(M_http2_t *ht, M_uint32 id, const char *key, const char *value)
{
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, id);
	M_hash_dict_insert(stream->request, key, value);
}

static void M_http2_stream_insert_response(M_http2_t *ht, M_uint32 id, const char *key, const char *value)
{
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, id);
	M_hash_dict_insert(stream->response, key, value);
}

static void M_http2_stream_destroy_cb(void *stream)
{
	M_http2_stream_destroy(stream);
}

static M_bool http2_init_cb(M_io_layer_t *layer)
{
	/* M_io_handle_t *handle = M_io_layer_get_handle(layer); */
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	return M_TRUE;
}

static M_io_error_t http2_accept_cb(M_io_t *new_conn, M_io_layer_t *orig_layer)
{
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	return M_IO_ERROR_SUCCESS;
}

static M_io_error_t http2_read_cb(M_io_layer_t *layer, unsigned char *buf, size_t *read_len, M_io_meta_t *meta)
{
	M_io_t *io        = M_io_layer_get_io(layer);
	size_t  layer_idx = M_io_layer_get_index(layer);

	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);

	return M_io_layer_read(io, layer_idx - 1, buf, read_len, meta);
}

static M_io_error_t http2_write_cb(M_io_layer_t *layer, const unsigned char *buf, size_t *write_len, M_io_meta_t *meta)
{
	M_io_t *io        = M_io_layer_get_io(layer);
	size_t  layer_idx = M_io_layer_get_index(layer);

	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);

	return M_io_layer_write(io, layer_idx - 1, buf, write_len, meta);
}

static M_bool http2_process_read(M_io_handle_t *handle, M_io_layer_t *layer)
{
	M_io_error_t ioerr;

	ioerr = M_io_read_into_parser(handle->io, handle->ht->in_parser);
	if (ioerr == M_IO_ERROR_WOULDBLOCK)
		return M_TRUE;

	if (ioerr == M_IO_ERROR_SUCCESS) {
		const M_uint8 *data     = M_parser_peek(handle->ht->in_parser);
		size_t         data_len = M_parser_len(handle->ht->in_parser);
		ssize_t        rv       = nghttp2_session_mem_recv(handle->ht->ng_session, data, data_len);
		if (rv < 0) {
			M_snprintf(handle->errmsg, sizeof(handle->errmsg), "HTTP2 session error num: %zu", rv);
			handle->state = HTTP2_STATE_ERROR;
			M_io_layer_softevent_add(layer, M_FALSE, M_EVENT_TYPE_ERROR, M_IO_ERROR_ERROR);
		} else {
			const uint8_t *data;
			size_t         data_len;
			data_len = nghttp2_session_mem_send(handle->ht->ng_session, &data);
			if (data_len > 0) {
				M_buf_add_bytes(handle->ht->out_buf, data, data_len);
				M_io_layer_softevent_add(layer, M_FALSE, M_EVENT_TYPE_WRITE, M_IO_ERROR_SUCCESS);
			}
			M_parser_consume(handle->ht->in_parser, rv);
		}
	}
	return M_TRUE; /* We only send soft READ events on stream completions */
}

static M_bool http2_process_write(M_io_handle_t *handle, M_io_layer_t *layer)
{
	M_io_error_t ioerr;
	size_t       nbytes;
	if (M_buf_len(handle->ht->out_buf) == 0)
		return M_FALSE; /* We don't have anything to write, maybe next layer does */

	nbytes = M_buf_len(handle->ht->out_buf);
	ioerr = M_io_write_from_buf(handle->io, handle->ht->out_buf);
	M_printf("%s:%d: M_io_write_from_buf(%p,%p): %s, WROTE %zu bytes\n", __FILE__, __LINE__, handle->io, handle->ht->out_buf, M_io_error_string(ioerr), nbytes - M_buf_len(handle->ht->out_buf));

	if (ioerr == M_IO_ERROR_SUCCESS) {
		const uint8_t *data;
		size_t         data_len;
		data_len = nghttp2_session_mem_send(handle->ht->ng_session, &data);
		if (data_len > 0) {
			M_buf_add_bytes(handle->ht->out_buf, data, data_len);
			M_io_layer_softevent_add(layer, M_FALSE, M_EVENT_TYPE_WRITE, M_IO_ERROR_SUCCESS);
		}
		if (M_buf_len(handle->ht->out_buf) > 0) {
			M_io_layer_softevent_add(layer, M_FALSE, M_EVENT_TYPE_WRITE, M_IO_ERROR_SUCCESS);
		}
		return M_TRUE; /* consume */
	}

	if (ioerr == M_IO_ERROR_WOULDBLOCK) {
		return M_TRUE; /* consume */
	}

	return M_FALSE;
}

static M_bool http2_process_cb(M_io_layer_t *layer, M_event_type_t *type)
{
	M_io_handle_t *handle     = M_io_layer_get_handle(layer);
	M_bool         is_consume = M_FALSE;

	M_printf("%s:%d: %s(<%s>)\n", __FILE__, __LINE__, __FUNCTION__, M_event_type_string(*type));

	switch (*type) {
		case M_EVENT_TYPE_CONNECTED:
			handle->state = HTTP2_STATE_CONNECTED;
			break;
		case M_EVENT_TYPE_ACCEPT:
			break;
		case M_EVENT_TYPE_READ:
			is_consume = http2_process_read(handle, layer);
			break;
		case M_EVENT_TYPE_DISCONNECTED:
			handle->state = HTTP2_STATE_DISCONNECTED;
			break;
		case M_EVENT_TYPE_ERROR:
			handle->state = HTTP2_STATE_ERROR;
			break;
		case M_EVENT_TYPE_WRITE:
			is_consume = http2_process_write(handle, layer);
			break;
		case M_EVENT_TYPE_OTHER:
			break;
	}
	return is_consume;
}

static void http2_unregister_cb(M_io_layer_t *layer)
{
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	return;
}

static M_bool http2_disconnect_cb(M_io_layer_t *layer)
{
	M_io_handle_t *handle = M_io_layer_get_handle(layer);
	M_http2_t     *ht     = handle->ht;
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	M_printf("session_terminate GO_AWAY\n");
	nghttp2_session_terminate_session(ht->ng_session, NGHTTP2_NO_ERROR);
	handle->state = HTTP2_STATE_DISCONNECTING;
	return M_FALSE;
}

static M_bool http2_reset_cb(M_io_layer_t *layer)
{
	M_io_handle_t *handle = M_io_layer_get_handle(layer);
	handle->state = HTTP2_STATE_INIT;
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	return M_TRUE;
}

static void http2_destroy_cb(M_io_layer_t *layer)
{
	M_io_handle_t *handle = M_io_layer_get_handle(layer);
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	M_io_meta_destroy(handle->meta);
	M_free(handle);
	return;
}

static M_io_state_t http2_state_cb(M_io_layer_t *layer)
{
	M_io_handle_t *handle = M_io_layer_get_handle(layer);
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	switch (handle->state) {
		case HTTP2_STATE_INIT:
			return M_IO_STATE_INIT;
		case HTTP2_STATE_LISTENING:
			return M_IO_STATE_LISTENING;
		case HTTP2_STATE_CONNECTING:
			return M_IO_STATE_CONNECTING;
		case HTTP2_STATE_CONNECTED:
			return M_IO_STATE_CONNECTED;
		case HTTP2_STATE_DISCONNECTING:
			return M_IO_STATE_DISCONNECTING;
		case HTTP2_STATE_DISCONNECTED:
			return M_IO_STATE_DISCONNECTED;
		case HTTP2_STATE_ERROR:
			break;
	}
	return M_IO_STATE_ERROR;
}

static M_bool http2_errormsg_cb(M_io_layer_t *layer, char *error, size_t err_len)
{
	M_io_handle_t *handle = M_io_layer_get_handle(layer);

	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);

	if (handle->state != HTTP2_STATE_ERROR)
		return M_FALSE;

	if (M_str_isempty(handle->errmsg))
		return M_FALSE;

	M_str_cpy(error, err_len, handle->errmsg);
	return M_TRUE;
}


M_io_error_t M_io_http2_add(M_io_t *io, M_http2_t *ht, size_t *layer_id)
{
	M_io_handle_t    *handle;
	M_io_layer_t     *layer;
	M_io_callbacks_t *callbacks;

	if (io == NULL)
		return M_IO_ERROR_INVALID;

	handle = M_malloc_zero(sizeof(*handle));
	handle->ht = ht;
	handle->io = io;

	handle->meta = M_io_meta_create();

	callbacks = M_io_callbacks_create();
	M_io_callbacks_reg_init(callbacks, http2_init_cb);
	M_io_callbacks_reg_read(callbacks, http2_read_cb);
	M_io_callbacks_reg_write(callbacks, http2_write_cb);
	M_io_callbacks_reg_accept(callbacks, http2_accept_cb);
	M_io_callbacks_reg_processevent(callbacks, http2_process_cb);
	M_io_callbacks_reg_unregister(callbacks, http2_unregister_cb);
	M_io_callbacks_reg_disconnect(callbacks, http2_disconnect_cb);
	M_io_callbacks_reg_reset(callbacks, http2_reset_cb);
	M_io_callbacks_reg_destroy(callbacks, http2_destroy_cb);
	M_io_callbacks_reg_state(callbacks, http2_state_cb);
	M_io_callbacks_reg_errormsg(callbacks, http2_errormsg_cb);
	layer = M_io_layer_add(io, "HTTP2", handle, callbacks);
	M_io_callbacks_destroy(callbacks);

	if (layer_id != NULL)
		*layer_id = M_io_layer_get_index(layer);

	ht->handle = handle;
	ht->layer  = layer;

	return M_IO_ERROR_SUCCESS;
}

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
		M_uint32 id = frame->push_promise.promised_stream_id;
		switch (ht->push_promise_mode) {
			case M_HTTP2_PUSH_PROMISE_MODE_IGNORE:
				M_printf("RST_STREAM PUSH_PROMISE (promised: %d)\n", id);
				nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, id, NGHTTP2_NO_ERROR);
				break;
			case M_HTTP2_PUSH_PROMISE_MODE_KEEP:
				M_hash_u64vp_insert(ht->streams, id, M_http2_stream_create(id, NULL));
				break;
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
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, stream_id);
	(void)flags;
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
	stream = M_hash_u64vp_get_direct(ht->streams, stream_id);
	M_printf("stream: %p\n", stream);
	if (stream != NULL) {
		M_io_layer_softevent_add(ht->layer, M_TRUE, M_EVENT_TYPE_READ, M_IO_ERROR_SUCCESS);
	}
	return 0;
}

static int ng_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame,
		void *user_data)
{
	M_printf("ng_on_begin_headers_callback(%p,%p,%p) type=%s\n", session, frame, user_data, ng_frame_type_str(frame->hd.type));
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
	return frame->hd.length;
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

static void M_set_ng_callbacks_server(nghttp2_session_callbacks *ng_callbacks)
{
	M_set_ng_callbacks(ng_callbacks);
}

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

static void M_set_ng_option_server(nghttp2_option *ng_options)
{
	M_set_ng_option(ng_options);
	nghttp2_option_set_server_fallback_rfc7540_priorities(ng_options, 1);
}

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

M_http2_t *M_http2_server_create()
{
	M_http2_t *ht     = NULL;
	int        rc;

	nghttp2_mem ng_mem = {
		NULL /* thunk */,
		ng_malloc_cb,
		ng_free_cb,
		ng_calloc_cb,
		ng_realloc_cb,
	};

	ht = M_malloc_zero(sizeof(*ht));
	ht->type = M_HTTP2_TYPE_SERVER;
	rc = nghttp2_session_callbacks_new(&ht->ng_callbacks);
	if (rc != 0) {
		M_printf("nghttp2_session_callbacks_new(%p): %d\n", &ht->ng_callbacks, rc);
		goto fail;
	}
	rc = nghttp2_option_new(&ht->ng_options);
	if (rc != 0) {
		M_printf("nghttp2_option_new(%p): %d\n", &ht->ng_options, rc);
		goto fail;
	}
	M_set_ng_option_server(ht->ng_options);
	M_set_ng_callbacks_server(ht->ng_callbacks);
	nghttp2_session_server_new3(&ht->ng_session, ht->ng_callbacks, ht, ht->ng_options, &ng_mem);
	return ht;
fail:
	M_free(ht);
	return NULL;
}

static void M_http2_client_set_hdr(nghttp2_nv *hdr, const char *name, const char *value, M_uint8 flags)
{
	hdr->name = (uint8_t*)name;
	hdr->value = (uint8_t*)value;
	hdr->namelen = M_str_len(name);
	hdr->valuelen = M_str_len(value);
	hdr->flags = flags;
}

static const char * M_http_reqtype_str(M_http2_request_t reqtype)
{
	switch (reqtype) {
		case M_HTTP2_REQUEST_GET:
			return "GET";
	}
}

static M_uint32 M_http2_client_submit_request(M_http2_t *ht, M_hash_dict_t *request)
{
	nghttp2_nv         *hdrs;
	const uint8_t      *data;
	size_t              data_len;
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

	stream_id = nghttp2_submit_request(ht->ng_session, NULL, hdrs, num_headers, NULL, NULL);

	data_len = nghttp2_session_mem_send(ht->ng_session, &data);
	M_buf_add_bytes(ht->out_buf, data, data_len);

	M_free(hdrs);

	return stream_id;
}

M_uint32 M_http2_client_request(M_http2_t *ht, M_http2_request_t reqtype, const char *path)
{
	M_uint32          id;
	M_hash_dict_t    *request;

	if (ht == NULL)
		return 0;

	request = M_hash_dict_create(8, 75, M_HASH_DICT_NONE);

	M_hash_dict_insert(request, ":method"   , M_http_reqtype_str(reqtype));
	M_hash_dict_insert(request, ":scheme"   , ht->scheme);
	M_hash_dict_insert(request, ":authority", ht->authority);
	M_hash_dict_insert(request, ":path"     , path);

	id = M_http2_client_submit_request(ht, request);

	M_hash_u64vp_insert(ht->streams, id, M_http2_stream_create(id, request));

	return id;
}

M_http2_stream_t *M_http2_stream_take_by_id(M_http2_t *ht, M_int32 stream_id)
{
	M_http2_stream_t *stream = M_hash_u64vp_get_direct(ht->streams, stream_id);
	if (stream != NULL) {
		M_hash_u64vp_remove(ht->streams, stream_id, M_FALSE);
	}
	return stream;
}

M_http2_t *M_http2_client_create(const char* scheme, const char *authority)
{
	int                        rc;
	M_http2_t                 *ht           = NULL;
	nghttp2_settings_entry     iv[]         = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
	};
	nghttp2_mem ng_mem = {
		NULL /* thunk */,
		ng_malloc_cb,
		ng_free_cb,
		ng_calloc_cb,
		ng_realloc_cb,
	};

	ht = M_malloc_zero(sizeof(*ht));
	ht->type = M_HTTP2_TYPE_CLIENT;
	ht->scheme = M_strdup(scheme);
	ht->authority = M_strdup(authority);
	ht->streams = M_hash_u64vp_create(32, 75, M_HASH_U64VP_NONE, M_http2_stream_destroy_cb);
	rc = nghttp2_session_callbacks_new(&ht->ng_callbacks);
	if (rc != 0) {
		M_printf("nghttp2_session_callbacks_new(%p): %d\n", &ht->ng_callbacks, rc);
		goto fail;
	}
	rc = nghttp2_option_new(&ht->ng_options);
	if (rc != 0) {
		M_printf("nghttp2_option_new(%p): %d\n", &ht->ng_options, rc);
		goto fail;
	}
	M_set_ng_option_client(ht->ng_options);
	M_set_ng_callbacks_client(ht->ng_callbacks);
	nghttp2_session_client_new3(&ht->ng_session, ht->ng_callbacks, ht, ht->ng_options, &ng_mem);
	rc = nghttp2_submit_settings(ht->ng_session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
	if (rc != 0) {
		M_printf("nghttps_submit_settings(%p, %d, %p, %zu): %d\n", ht->ng_session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv), rc);
		goto fail;
	}
	ht->out_buf = M_buf_create();
	ht->in_parser = M_parser_create(M_PARSER_FLAG_NONE);
	return ht;
fail:
	M_http2_destroy(ht);
	return NULL;
}

void M_http2_destroy(M_http2_t *ht)
{
	nghttp2_option_del(ht->ng_options);
	nghttp2_session_callbacks_del(ht->ng_callbacks);
	nghttp2_session_del(ht->ng_session);
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

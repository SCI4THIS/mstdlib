#include "m_http2_int.h"

struct M_io_handle {
	http2_state_t  state;
	M_http2_t     *ht;
	M_io_t        *io;
	M_io_meta_t   *meta;
	char           errmsg[256];
};

static M_bool http2_init_cb(M_io_layer_t *layer)
{
	(void)layer;
	/* M_io_handle_t *handle = M_io_layer_get_handle(layer); */
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	return M_TRUE;
}

static M_io_error_t http2_accept_cb(M_io_t *new_conn, M_io_layer_t *orig_layer)
{
	(void)new_conn;
	(void)orig_layer;
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
		size_t rv = M_http2_nghttp2_mem_recv(handle->ht);
		if (rv < 0) {
			M_snprintf(handle->errmsg, sizeof(handle->errmsg), "HTTP2 session error num: %zu", rv);
			handle->state = HTTP2_STATE_ERROR;
			M_io_layer_softevent_add(layer, M_FALSE, M_EVENT_TYPE_ERROR, M_IO_ERROR_ERROR);
		} else {
			M_http2_nghttp2_mem_send(handle->ht);
			if (M_buf_len(handle->ht->out_buf) > 0) {
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
		M_http2_nghttp2_mem_send(handle->ht);
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
	(void)layer;
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	return;
}

static M_bool http2_disconnect_cb(M_io_layer_t *layer)
{
	M_io_handle_t *handle = M_io_layer_get_handle(layer);
	M_http2_t     *ht     = handle->ht;
	M_printf("%s:%d: %s()\n", __FILE__, __LINE__, __FUNCTION__);
	M_printf("session_terminate GO_AWAY\n");
	nghttp2_session_terminate_session(ht->ng->session, NGHTTP2_NO_ERROR);
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

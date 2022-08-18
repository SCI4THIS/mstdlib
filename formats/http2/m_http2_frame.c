#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>

static const char M_http2_pri_str[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

typedef struct {
	size_t               len;
	M_http2_frame_type_t type;
	M_uint8              flags;
	M_bool               is_R_set;
	M_uint32             stream_id;
} M_http2_frame_header_t;

static void M_http2_frame_header_read(const char *data, size_t data_len, M_http2_frame_header_t *frame_header)
{
	M_uint32 frame_len  = 0;
	M_uint32 stream_id_R;

	if (data_len < 9)
		return;

	M_mem_copy(&frame_len, &data[0], 3);
	frame_header->type  = (M_uint8)data[3];
	frame_header->flags = (M_uint8)data[4];
	M_mem_copy(&stream_id_R, &data[5], 4);

	frame_header->len = M_ntoh32(frame_len) >> 8; /* M_ntoh24() */
	frame_header->stream_id = M_ntoh32(stream_id_R);

	if ((data[5] & 0x80) != 0) {
		frame_header->is_R_set = M_TRUE;
		frame_header->stream_id &= 0x7FFFFFFF;
	} else {
		frame_header->is_R_set = M_FALSE;
	}
}

static void M_http2_frame_header_write(M_buf_t *buf, M_http2_frame_header_t *frame_header)
{
	M_uint8  bytes[9];
	M_uint32 frame_len;
	M_uint32 stream_id_R;

	frame_len = M_hton32((M_uint32)frame_header->len) >> 8; /* M_hton24() */
	stream_id_R = M_hton32((M_uint32)frame_header->stream_id);
	M_mem_copy(&bytes[0], &frame_len, 3);
	bytes[3] = (M_uint8)frame_header->type;
	bytes[4] = frame_header->flags;
	M_mem_copy(&bytes[5], &stream_id_R, 4);
	if (frame_header->is_R_set) {
		bytes[5] |= 0x80;
	}

	M_buf_add_bytes(buf, bytes, 9);

}

static void M_http2_frame_write_setting(M_buf_t *buf, M_uint32 flags, M_http2_settings_id_t id, size_t val)
{
	M_uint8  bytes[6];
	M_uint16 n_id;
	M_uint32 n_val;

	if ((flags & (1 << id)) == 0)
		return;

	n_id  = M_hton16((M_uint16)id);
	n_val = M_hton32((M_uint32)val);

	M_mem_copy(&bytes[0], &n_id, 2);
	M_mem_copy(&bytes[2], &n_val, 4);

	M_buf_add_bytes(buf, bytes, 6);
}

void M_http2_frame_write_settings_ack(M_buf_t *buf)
{
	M_http2_frame_header_t frame_header = { 0, M_HTTP2_FRAME_TYPE_SETTINGS, 0x01, M_FALSE, 0 };
	M_http2_frame_header_write(buf, &frame_header);
}

M_bool M_http2_frame_write_settings(M_buf_t *buf, M_uint32 flags, M_http2_settings_t *settings)
{
	M_http2_frame_header_t frame_header;
	size_t                 num_settings;
	M_http2_settings_id_t  setting_id;
	const M_uint32         settings_id_mask =
		(1 << M_HTTP2_SETTINGS_HEADER_TABLE_SIZE)       |
		(1 << M_HTTP2_SETTINGS_ENABLE_PUSH)             |
		(1 << M_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)  |
		(1 << M_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE)     |
		(1 << M_HTTP2_SETTINGS_MAX_FRAME_SIZE)          |
		(1 << M_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE)    |
		(1 << M_HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) |
		(1 << M_HTTP2_SETTINGS_NO_RFC7540_PRIORITIES);

	if (settings == NULL)
		return M_FALSE;

	if ((flags & ~settings_id_mask) != 0)
		return M_FALSE;

	num_settings = M_uint64_popcount((M_uint64)flags);
	frame_header.len       = num_settings * 6;
	frame_header.type      = M_HTTP2_FRAME_TYPE_SETTINGS;
	frame_header.flags     = 0; /* Can only possibly be 0x01 ACK on SETTINGS frames */
	frame_header.is_R_set  = M_FALSE;
	frame_header.stream_id = 0; /* Global settings */

	M_http2_frame_header_write(buf, &frame_header);

	setting_id = M_HTTP2_SETTINGS_HEADER_TABLE_SIZE;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->header_table_size);
	setting_id = M_HTTP2_SETTINGS_ENABLE_PUSH;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->is_enable_push);
	setting_id = M_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->max_concurrent_streams);
	setting_id = M_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->initial_window_size);
	setting_id = M_HTTP2_SETTINGS_MAX_FRAME_SIZE;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->max_frame_size);
	setting_id = M_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->max_header_list_size);
	setting_id = M_HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->is_enable_connect_protocol);
	setting_id = M_HTTP2_SETTINGS_NO_RFC7540_PRIORITIES;
	M_http2_frame_write_setting(buf, flags, setting_id, settings->is_disable_rfc7540_priorities);

	return M_TRUE;
}

static void M_http2_frame_read_setting(const char *bytes, M_uint32 *flags, M_http2_settings_t *settings)
{
	M_http2_settings_id_t setting_id;
	M_uint16              n_id;
	M_uint32              n_val;

	M_mem_copy(&n_id, &bytes[0], 2);
	M_mem_copy(&n_val, &bytes[2], 4);

	setting_id  = M_ntoh16(n_id);

	*flags |= (1 << setting_id);

	switch (setting_id) {
		case M_HTTP2_SETTINGS_HEADER_TABLE_SIZE:
			settings->header_table_size = M_ntoh32(n_val);
			break;
		case M_HTTP2_SETTINGS_ENABLE_PUSH:
			settings->is_enable_push = (M_ntoh32(n_val) != 0);
			break;
		case M_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
			settings->max_concurrent_streams = M_ntoh32(n_val);
			break;
		case M_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
			settings->initial_window_size = M_ntoh32(n_val);
			break;
		case M_HTTP2_SETTINGS_MAX_FRAME_SIZE:
			settings->max_frame_size = M_ntoh32(n_val);
			break;
		case M_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
			settings->max_header_list_size = M_ntoh32(n_val);
			break;
		case M_HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
			settings->is_enable_connect_protocol = (M_ntoh32(n_val) != 0);
			break;
		case M_HTTP2_SETTINGS_NO_RFC7540_PRIORITIES:
			settings->is_disable_rfc7540_priorities = (M_ntoh32(n_val) != 0);
			break;
		case M_HTTP2_SETTINGS_ACK:
			/* Impossible */
			break;
	}
}

M_bool M_http2_frame_read_settings(const char *data, size_t data_len, M_uint32 *flags, M_http2_settings_t *settings)
{
	size_t                 pos;
	M_http2_frame_header_t frame_header;

	if (data_len < 9)
		return M_FALSE;

	M_http2_frame_header_read(data, data_len, &frame_header);
	if (frame_header.flags == 0x01) {
		*flags = (1u << M_HTTP2_SETTINGS_ACK);
		return M_TRUE;
	}
	if (data_len < (9 + frame_header.len))
		return M_FALSE;

	pos = 9;
	while (pos < (9 + frame_header.len)) {
		M_http2_frame_read_setting(&data[pos], flags, settings);
		pos += 6;
	}

	return M_TRUE;
}

M_bool M_http2_read_pri_str(const char *data, size_t data_len)
{
	static size_t len = sizeof(M_http2_pri_str) - 1;
	if (data_len < len)
		return M_FALSE;
	return M_mem_eq(data, M_http2_pri_str, len);
}

void M_http2_write_pri_str(M_buf_t *buf)
{
	M_buf_add_str(buf, M_http2_pri_str);
}

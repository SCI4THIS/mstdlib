#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>

const char *M_http2_pri_str = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

static void M_http2_frame_read_setting(const M_uint8 *bytes, M_uint32 *flags, M_http2_settings_t *settings)
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

typedef enum {
	M_HTTP2_HEADER_FRAME_FLAG_END_STREAM  = 0x01,
	M_HTTP2_HEADER_FRAME_FLAG_END_HEADERS = 0x04,
	M_HTTP2_HEADER_FRAME_FLAG_PADDED      = 0x08,
	M_HTTP2_HEADER_FRAME_FLAG_PRIORITY    = 0x20,
} M_http2_header_frame_flag_t;

#include "generated/m_http2_static_header_table.c"
/* m_http2_static_header_table.c initializes the following struct:
	* static struct {
	* 	const char *key;
	* 	const char *value;
 * } M_http2_header_table[];
 */

typedef enum {
	M_HTTP2_HEADER_ENTRY_TYPE_DYNAMIC_TABLE_SIZE_UPDATE,
	M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_NEW_NAME,
	M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME,
	M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_NEW_NAME,
	M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME,
	M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_NEW_NAME,
	M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME,
	M_HTTP2_HEADER_ENTRY_TYPE_INDEXED_FIELD,
	M_HTTP2_HEADER_ENTRY_TYPE_ERROR,
} M_http2_header_entry_type_t;

static M_http2_header_entry_type_t M_http2_frame_headers_entry_type(M_uint8 byte)
{
	/* See RFC7541 section 6.3 for more information */
	if ((byte & 0xE0) == 0x20)
		return M_HTTP2_HEADER_ENTRY_TYPE_DYNAMIC_TABLE_SIZE_UPDATE;
	if (byte == 0x10)
		return M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_NEW_NAME;
	if ((byte & 0xF0) == 0x10)
		return M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME;
	if (byte == 0x00)
		return M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_NEW_NAME;
	if ((byte & 0xF0) == 0x00)
		return M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME;
	if (byte == 0x40)
		return M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_NEW_NAME;
	if ((byte & 0xC0) == 0x40)
		return M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME;
	if ((byte & 0x80) == 0x80)
		return M_HTTP2_HEADER_ENTRY_TYPE_INDEXED_FIELD;

	return M_HTTP2_HEADER_ENTRY_TYPE_ERROR;
}


static size_t M_http2_frame_read_header_integer(const M_uint8 *data, M_uint64* val)
{
	size_t  pos = 0;
	M_uint8 byte;
	*val = 0;
	do {
		byte = data[pos++];
		*val = (*val * 0x80) + (byte & 0x7F);
	} while ((byte & 0x80) != 0);
	return pos;
}

static size_t M_http2_frame_read_header_string(const M_uint8* data, char **val)
{
	size_t pos                = 0;
	M_bool is_huffman_encoded = (data[pos] & 0x80) != 0;
	size_t len                = data[pos++] & 0x7F;

	if (len == 0x7F) {
		M_uint64 u64;
		pos += M_http2_frame_read_header_integer(&data[pos], &u64);
		len = u64 + 0x7F;
	}

	if (is_huffman_encoded) {
		M_buf_t *buf = M_buf_create();
		M_http2_huffman_decode(buf, &data[pos], len);
		*val = M_buf_finish_str(buf, NULL);
		return pos + len; /* data_len to advance, not the strlen */
	}

	*val = M_malloc(len + 1);
	M_mem_copy(*val, &data[pos], len);
	(*val)[len] = '\0';
	return pos + len;
}

M_hash_dict_t *M_http2_frame_read_headers(const M_uint8 *data, size_t data_len)
{
	M_hash_dict_t              *headers          = NULL;
	M_http2_frame_header_t      frame_header     = { 0 };
	size_t                      frame_pos        = 9;
	M_uint8                     pad_length       = 0;
	const char                 *key              = NULL;
	const char                 *value            = NULL;
	M_uint64                    u64              = 0;
	char                       *key_str          = NULL;
	char                       *value_str        = NULL;
	M_uint8                     mask;
	M_http2_header_entry_type_t entry_type;

	if (data_len < 9)
		return NULL;

	M_http2_frame_header_read(data, data_len, &frame_header);

	if (data_len < (9 + frame_header.len))
		return NULL;

	headers = M_hash_dict_create(32, 75, M_HASH_DICT_NONE);

	if (frame_header.flags & M_HTTP2_HEADER_FRAME_FLAG_PADDED) {
		pad_length = data[frame_pos++];
	}

	if (frame_header.flags & M_HTTP2_HEADER_FRAME_FLAG_PRIORITY) {
		struct {
			M_bool   exclusive;
			M_uint32 stream_dependency_id;
			M_uint8  weight;
		} priority = { 0 };
		M_uint32 stream_id;
		priority.exclusive = (data[frame_pos++] & 0x80) != 0;
		M_mem_copy(&stream_id, &data[frame_pos], sizeof(stream_id));
		priority.stream_dependency_id = M_hton32(stream_id);
		priority.stream_dependency_id &= 0x7FFFFFFF;
		frame_pos += 4;
		priority.weight = data[frame_pos++];
	}

	while (frame_pos + pad_length < frame_header.len) {
		entry_type = M_http2_frame_headers_entry_type(data[frame_pos]);
		switch (entry_type) {
			case M_HTTP2_HEADER_ENTRY_TYPE_INDEXED_FIELD:
				key = M_http2_header_table[data[frame_pos] & 0x7F].key;
				value = M_http2_header_table[data[frame_pos] & 0x7F].value;
				M_hash_dict_insert(headers, key, value);
				frame_pos++;
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_DYNAMIC_TABLE_SIZE_UPDATE:
			frame_pos++;
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME:
				if (entry_type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME) {
					mask = 0x0F;
				}
				if (entry_type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME) {
					mask = 0x0F;
				}
				if (entry_type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME) {
					mask = 0x3F;
				}
				if (data[frame_pos] == mask) {
					frame_pos++;
					frame_pos += M_http2_frame_read_header_integer(&data[frame_pos], &u64);
					u64 += mask;
					key = M_http2_header_table[u64].key;
				} else {
					key = M_http2_header_table[data[frame_pos++] & mask].key;
				}
				frame_pos += M_http2_frame_read_header_string(&data[frame_pos], &value_str);
				M_hash_dict_insert(headers, key, value_str);
				M_free(value_str);
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_NEW_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_NEW_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_NEW_NAME:
				frame_pos++;
				frame_pos += M_http2_frame_read_header_string(&data[frame_pos], &key_str);
				frame_pos += M_http2_frame_read_header_string(&data[frame_pos], &value_str);
				M_hash_dict_insert(headers, key_str, value_str);
				M_free(key_str);
				M_free(value_str);
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_ERROR:
				break;
		}
	}

	return headers;
}

static void M_http2_headers_frame_encode_keyval_match(M_uint8 idx, const char *key, const char *value, M_buf_t *buf)
{
	M_buf_add_byte(buf, 0x80 | i);
}

static void M_http2_headers_frame_encode_key_match(M_uint8 idx, const char *key, const char *value, M_buf_t *buf)
{
	if (idx < 0x0F) {
		M_buf_add_byte(buf, idx);
	} else {
		M_buf_add_byte(buf, 0x0F);
		M_http2_encode_number_chain(buf, idx - 0x0F);
	}
	M_http2_encode_string(buf, value);
}

static void M_http2_headers_frame_encode_no_match(const char *key, const char *value, M_buf_t *buf)
{
	M_buf_add_byte(buf, 0x00);
	M_http2_encode_string(buf, key);
	M_http2_encode_string(buf, value);
}

void M_http2_headers_frame_encode(const char *key, const char *value, M_buf_t *buf)
{
	M_uint8 i;
	for (i=1; i<sizeof(M_http2_header_table)/sizeof(M_http2_header_table[0]); i++) {
		if (M_str_eq(M_http2_header_table[i].key, key)) {
			if (M_https_header_table[i].value == NULL) {
				return M_http2_headers_frame_encode_key_match(i, key, value, buf);
			}
			if (M_str_eq(M_http2_header_table[i].value, value)) {
				return M_http2_headers_frame_encode_keyval_match(i, key, value, buf);
			}
		}
	}
	return M_http2_headers_frame_encode_no_match(key, value, buf);
}

size_t M_http2_decode_header(const M_uint8* data, size_t data_len, M_http_reader_header_full_func cb, void *thunk)
{
	size_t      pos         = 0;
	M_uint8     byte        = data[pos++];
	M_uint8     mask        = 0;
	const char *key_const   = NULL;
	const char *value_const = NULL;
	char       *key         = NULL;
	char       *value       = NULL;
	size_t      idx;

	M_http2_header_entry_type_t type = M_http2_frame_headers_entry_type(byte);
	switch (type) {
		case M_HTTP2_HEADER_ENTRY_TYPE_INDEXED_FIELD:
			idx = byte & 0x7F;
			key_const = M_http2_header_table[idx].key;
			value_const = M_http2_header_table[idx].value;
			cb(key_const, value_const, thunk);
			return pos;
		case M_HTTP2_HEADER_ENTRY_TYPE_DYNAMIC_TABLE_SIZE_UPDATE:
			return pos;
		case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME:
		case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME:
		case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME:
			mask = 0x0F;
			if (type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME)
				mask = 0x3F;
			if ((byte & mask) == mask) {
				idx  = mask;
				idx += M_http2_decode_number_chain(data, data_len, &pos);
			} else {
				idx  = byte & mask;
			}
			key_const = M_http2_header_table[idx].key;
			value = M_http2_decode_string_alloc(data, data_len, &pos);
			cb(key_const, value, thunk);
			M_free(value);
			return pos;
		case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_NEW_NAME:
		case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_NEW_NAME:
		case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_NEW_NAME:
			key   = M_http2_decode_string_alloc(data, data_len, &pos);
			value = M_http2_decode_string_alloc(data, data_len, &pos);
			cb(key, value, thunk);
			M_free(key);
			M_free(value);
			return pos;
		case M_HTTP2_HEADER_ENTRY_TYPE_ERROR:
			break;
	}
	return 0;
}

void M_http2_headers_frame_decode(const M_uint8* data, size_t data_len, M_http_reader_header_full_func entry_cb, void *thunk)
{
	M_http2_frame_header_t      frame_header     = { 0 };
	size_t                      frame_pos        = 9;
	M_uint8                     pad_length       = 0;
	const char                 *key              = NULL;
	const char                 *value            = NULL;
	M_uint64                    u64              = 0;
	char                       *key_str          = NULL;
	char                       *value_str        = NULL;
	M_uint8                     mask;
	M_http2_header_entry_type_t entry_type;

	if (data_len < 9)
		return;

	M_http2_frame_header_read(data, data_len, &frame_header);

	if (data_len < (9 + frame_header.len))
		return;

	if (frame_header.flags & M_HTTP2_HEADER_FRAME_FLAG_PADDED) {
		pad_length = data[frame_pos++];
	}

	if (frame_header.flags & M_HTTP2_HEADER_FRAME_FLAG_PRIORITY) {
		struct {
			M_bool   exclusive;
			M_uint32 stream_dependency_id;
			M_uint8  weight;
		} priority = { 0 };
		M_uint32 stream_id;
		priority.exclusive = (data[frame_pos++] & 0x80) != 0;
		M_mem_copy(&stream_id, &data[frame_pos], sizeof(stream_id));
		priority.stream_dependency_id = M_hton32(stream_id);
		priority.stream_dependency_id &= 0x7FFFFFFF;
		frame_pos += 4;
		priority.weight = data[frame_pos++];
	}

	while (frame_pos + pad_length < frame_header.len) {
		entry_type = M_http2_frame_headers_entry_type(data[frame_pos]);
		switch (entry_type) {
			case M_HTTP2_HEADER_ENTRY_TYPE_INDEXED_FIELD:
				key = M_http2_header_table[data[frame_pos] & 0x7F].key;
				value = M_http2_header_table[data[frame_pos] & 0x7F].value;
				entry_cb(key, value, thunk);
				frame_pos++;
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_DYNAMIC_TABLE_SIZE_UPDATE:
			frame_pos++;
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME:
				if (entry_type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_INDEX_NAME) {
					mask = 0x0F;
				}
				if (entry_type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_INDEX_NAME) {
					mask = 0x0F;
				}
				if (entry_type == M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_INDEX_NAME) {
					mask = 0x3F;
				}
				if (data[frame_pos] == mask) {
					frame_pos++;
					frame_pos += M_http2_frame_read_header_integer(&data[frame_pos], &u64);
					u64 += mask;
					key = M_http2_header_table[u64].key;
				} else {
					key = M_http2_header_table[data[frame_pos++] & mask].key;
				}
				frame_pos += M_http2_frame_read_header_string(&data[frame_pos], &value_str);
				entry_cb(key, value_str, thunk);
				M_free(value_str);
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_NEVER_INDEX_NEW_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_WITHOUT_INDEX_NEW_NAME:
			case M_HTTP2_HEADER_ENTRY_TYPE_LITERAL_FIELD_INCREMENTAL_INDEX_NEW_NAME:
				frame_pos++;
				frame_pos += M_http2_frame_read_header_string(&data[frame_pos], &key_str);
				frame_pos += M_http2_frame_read_header_string(&data[frame_pos], &value_str);
				entry_cb(key_str, value_str, thunk);
				M_free(key_str);
				M_free(value_str);
				break;
			case M_HTTP2_HEADER_ENTRY_TYPE_ERROR:
				break;
		}
	}
}

M_http2_goaway_t *M_http2_frame_read_goaway(const M_uint8 *data, size_t data_len)
{
	M_http2_frame_header_t  frame_header;
	M_http2_goaway_t       *goaway;
	M_uint32                stream_id;
	M_uint32                error_code;
	size_t                  pos        = 9;

	if (data_len < 9)
		return NULL;

	M_http2_frame_header_read(data, data_len, &frame_header);

	if (data_len < (9 + frame_header.len))
		return NULL;

	goaway = M_malloc_zero(sizeof(*goaway) + frame_header.len - 8);
	M_mem_copy(&stream_id, &data[pos], sizeof(stream_id));
	pos += sizeof(stream_id);
	goaway->is_reset_stream = (stream_id & 0x80) != 0;
	goaway->stream_id = M_ntoh32(stream_id) & 0x7FFFFFFF;
	M_mem_copy(&error_code, &data[pos], sizeof(error_code));
	pos += sizeof(error_code);
	goaway->error_code = M_ntoh32(error_code);
	goaway->debug_data_len = (frame_header.len - 8);
	if (goaway->debug_data_len > 0) {
		M_mem_copy(goaway->debug_data, &data[pos], goaway->debug_data_len);
	}
	return goaway;
}

typedef enum {
	M_HTTP2_DATA_FRAME_FLAG_END_STREAM  = 0x01,
	M_HTTP2_DATA_FRAME_FLAG_PADDED      = 0x08,
} M_http2_data_frame_flag_t;

M_bool M_http2_frame_read_data(const M_uint8 *data, size_t data_len, M_buf_t *buf)
{
	M_http2_frame_header_t frame_header;
	M_uint8                pad_len = 0;
	size_t                 pos     = 9;

	if (data_len < 9)
		return M_FALSE;

	M_http2_frame_header_read(data, data_len, &frame_header);

	if (data_len < (9 + frame_header.len))
		return M_FALSE;

	if ((frame_header.flags & M_HTTP2_DATA_FRAME_FLAG_PADDED) != 0) {
		pad_len = data[pos++];
	}

	M_buf_add_bytes(buf, &data[pos], frame_header.len - pad_len);

	return M_TRUE;
}

M_bool M_http2_frame_read_settings(const M_uint8 *data, size_t data_len, M_uint32 *flags, M_http2_settings_t *settings)
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

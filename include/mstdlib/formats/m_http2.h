/* The MIT License (MIT)
 *
 * Copyright (c) 2018 Monetra Technologies, LLC.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __M_HTTP2_H__
#define __M_HTTP2_H__

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#include <mstdlib/formats/m_http.h>

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

__BEGIN_DECLS

/*! \addtogroup m_http2 HTTP2
 *  \ingroup m_formats
 *
 * HTTP 2 message reading and writing.
 *
 * @{
 */

extern const char *M_http2_pri_str;

typedef enum {
	M_HTTP2_FRAME_TYPE_DATA          = 0x00,
	M_HTTP2_FRAME_TYPE_HEADERS       = 0x01,
	M_HTTP2_FRAME_TYPE_PRIORITY      = 0x02,
	M_HTTP2_FRAME_TYPE_RST_STREAM    = 0x03,
	M_HTTP2_FRAME_TYPE_SETTINGS      = 0x04,
	M_HTTP2_FRAME_TYPE_PUSH_PROMISE  = 0x05,
	M_HTTP2_FRAME_TYPE_PING          = 0x06,
	M_HTTP2_FRAME_TYPE_GOAWAY        = 0x07,
	M_HTTP2_FRAME_TYPE_WINDOW_UPDATE = 0x08,
	M_HTTP2_FRAME_TYPE_CONTINUATION  = 0x09,
} M_http2_frame_type_t;

typedef enum {
	M_HTTP2_SETTINGS_HEADER_TABLE_SIZE       = 0x01,
	M_HTTP2_SETTINGS_ENABLE_PUSH             = 0x02,
	M_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS  = 0x03,
	M_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE     = 0x04,
	M_HTTP2_SETTINGS_MAX_FRAME_SIZE          = 0x05,
	M_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE    = 0x06,
	M_HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08,
	M_HTTP2_SETTINGS_NO_RFC7540_PRIORITIES   = 0x09,
	M_HTTP2_SETTINGS_ACK                     = 31    /*!< signifies SETTINGS frame was an ACK */
} M_http2_settings_id_t;

typedef struct {
	size_t header_table_size;
	M_bool is_enable_push;
	size_t max_concurrent_streams;
	size_t initial_window_size;
	size_t max_frame_size;
	size_t max_header_list_size;
	M_bool is_enable_connect_protocol;
	M_bool is_disable_rfc7540_priorities;
} M_http2_settings_t;

typedef union {
	M_uint32 u32;
	M_uint8  u8[4];
} M_union_u32_u8;

typedef struct {
	M_bool         is_R_set;
	M_union_u32_u8 id;
} M_http2_stream_t;

typedef struct {
	M_union_u32_u8       len;
	M_http2_frame_type_t type;
	M_uint8              flags;
	M_http2_stream_t     stream;
} M_http2_framehdr_t;

typedef struct {
	M_http2_framehdr_t *framehdr;
	M_http2_stream_t    stream;
	M_union_u32_u8      errcode;
	const M_uint8      *debug_data;
	size_t              debug_data_len;
} M_http2_goaway_t;

typedef struct {
	M_http2_framehdr_t *framehdr;
	const M_uint8      *data;
	size_t              data_len;
	const M_uint8      *pad;
	M_uint8             pad_len;
} M_http2_data_t;


void              M_http2_encode_header(M_buf_t *buf, const char *key, const char *value);
size_t            M_http2_decode_header(const M_uint8* data, size_t data_len, M_http_reader_header_full_func entry_cb, void *thunk);
void              M_http2_headers_frame_decode(const M_uint8* data, size_t data_len, M_http_reader_header_full_func entry_cb, void *thunk);
void              M_http2_data_frame_decode(const M_uint8* data, size_t data_len, M_http_reader_body_func entry_cb, void *thunk);

void              M_http2_frame_write_settings_ack(M_buf_t *buf);
M_bool            M_http2_frame_write_settings(M_buf_t *buf, M_uint32 flags, M_http2_settings_t *settings);
M_bool            M_http2_frame_read_settings(const M_uint8 *data, size_t data_len, M_uint32 *flags, M_http2_settings_t *settings);
M_bool            M_http2_read_pri_str(const char *data, size_t data_len);
void              M_http2_write_pri_str(M_buf_t *buf);
M_bool            M_http2_huffman_decode(M_buf_t *buf, const M_uint8 *data, size_t data_len);
M_bool            M_http2_huffman_encode(M_buf_t *buf, const M_uint8 *data, size_t data_len);
M_hash_dict_t    *M_http2_frame_read_headers(const M_uint8 *data, size_t data_len);
M_bool            M_http2_frame_read_data(const M_uint8 *data, size_t data_len, M_buf_t *buf);
M_http2_goaway_t *M_http2_frame_read_goaway(const M_uint8 *data, size_t data_len);
size_t            M_http2_read_frame(const M_uint8 *data, size_t data_len);
/*
void              M_http2_frame_header_read(const M_uint8 *data, size_t data_len, M_http2_frame_header_t *frame_header);
*/
M_bool  M_http2_encode_huffman(const M_uint8 *data, size_t data_len, M_buf_t *buf);
void    M_http2_encode_number_chain(M_uint64 num, M_buf_t *buf);
void    M_http2_encode_string(const char *str, M_buf_t *buf);
M_bool  M_http2_encode_framehdr(M_http2_framehdr_t *framehdr, M_buf_t *buf);

M_bool  M_http2_decode_huffman(const M_uint8 *data, size_t data_len, M_buf_t *buf);
M_bool  M_http2_decode_number_chain(M_parser_t *parser, M_uint64 *num);
M_bool  M_http2_decode_string_length(M_parser_t *parser, M_uint64 *len, M_bool *is_huffman_encoded);
M_bool  M_http2_decode_string(M_parser_t *parser, M_buf_t *buf);
char   *M_http2_decode_string_alloc(M_parser_t *parser);
M_bool  M_http2_decode_framehdr(M_parser_t *parser, M_http2_framehdr_t *framehdr);

/*! @} */

/*! \addtogroup m_http2_reader HTTP2 Stream Reader
 *  \ingroup m_http2
 *
 * HTTP 2 message reading and writing.
 *
 * @{
 */

struct M_http2_reader;
typedef struct M_http2_reader M_http2_reader_t;

typedef enum {
	M_HTTP2_ERROR_SUCCESS = 0,                /*!< Success. Data fully parsed and all data is present. */
	M_HTTP2_ERROR_MOREDATA,                   /*!< Incomplete message, more data required. Not necessarily an error if parsing as data is streaming. */
	M_HTTP2_ERROR_STOP,                       /*!< Stop processing (Used by callback functions to indicate non-error but stop processing). */
	M_HTTP2_ERROR_INVALIDUSE,                 /*!< Invalid use. */
	M_HTTP2_ERROR_INVALID_FRAME_TYPE,
	M_HTTP2_ERROR_INTERNAL,
} M_http2_error_t;


/*! Flags controlling reader behavior. */
typedef enum {
	M_HTTP2_READER_NONE = 0,  /*!< Default operation. */
} M_http2_reader_flags_t;

typedef M_http2_error_t (*M_http2_reader_frame_begin_func)(M_http2_framehdr_t *framehdr, void *thunk);
typedef M_http2_error_t (*M_http2_reader_frame_end_func)(M_http2_framehdr_t *framehdr, void *thunk);
typedef M_http2_error_t (*M_http2_reader_goaway_func)(M_http2_goaway_t *goaway, void *thunk);
typedef M_http2_error_t (*M_http2_reader_data_func)(M_http2_data_t *data, void *thunk);

/*! Callbacks for various stages of parsing. */
struct M_http2_reader_callbacks {
	M_http2_reader_frame_begin_func frame_begin_func;
	M_http2_reader_frame_end_func   frame_end_func;
	M_http2_reader_goaway_func      goaway_func;
	M_http2_reader_data_func        data_func;
};

M_API M_http2_reader_t *M_http2_reader_create(struct M_http2_reader_callbacks *cbs, M_uint32 flags, void *thunk);
M_API void M_http2_reader_destroy(M_http2_reader_t *h2r);
M_API M_http2_error_t M_http2_reader_read(M_http2_reader_t *h2r, const unsigned char *data, size_t data_len, size_t *len_read);

M_API M_http_error_t M_http2_http_reader_read(M_http_reader_t *httpr, const unsigned char *data, size_t data_len, size_t *len_read);

/*! @} */

__END_DECLS

#endif

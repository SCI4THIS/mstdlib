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

#include <mstdlib/base/m_defs.h>
#include <mstdlib/base/m_types.h>
#include <mstdlib/base/m_list_str.h>
#include <mstdlib/base/m_hash_multi.h>
#include <mstdlib/base/m_parser.h>
#include <mstdlib/base/m_buf.h>
#include <mstdlib/text/m_textcodec.h>

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

__BEGIN_DECLS

/*! \addtogroup m_http2 HTTP2
 *  \ingroup m_formats
 *
 * HTTP 2 message reading and writing.
 *
 * @{
 */

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

M_bool M_http2_frame_write_settings(M_buf_t *buf, M_uint32 flags, M_http2_settings_t *settings);
M_bool M_http2_frame_read_settings(const char *data, size_t data_len, M_uint32 *flags, M_http2_settings_t *settings);

/*! @} */

__END_DECLS

#endif

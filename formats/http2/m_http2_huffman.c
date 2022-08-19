#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>

#include "m_http2_huffman_generated.c"

static M_http2_huffman_state_t M_http2_huffman_decode_byte(M_buf_t *buf, M_uint8 byte, M_http2_huffman_state_t state)
{
	M_uint32 charcode = 0;
	size_t   i;
	for (i=8; i-->0;) {
		M_bool bit = (byte & (1 << i)) != 0;
		state = M_http2_huffman(state, bit, &charcode);
		if (state == M_HTTP2_HUFFMAN_STATE_ERROR)
			return M_HTTP2_HUFFMAN_STATE_ERROR;
		if (state == M_HTTP2_HUFFMAN_STATE_) {
			/* state reset so emit character */
			if (charcode > 255)
				/* EOS is an error */
				return M_HTTP2_HUFFMAN_STATE_ERROR;
			M_buf_add_byte(buf, (M_uint8)charcode);
		}
	}
	return state;
}

M_bool M_http2_huffman_decode(M_buf_t *out_buf, const M_uint8 *data, size_t data_len)
{
	M_http2_huffman_state_t  state = M_HTTP2_HUFFMAN_STATE_;
	M_buf_t                 *buf   = M_buf_create();
	size_t                   i;
	for (i=0; i<data_len; i++) {
		state = M_http2_huffman_decode_byte(buf, data[i], state);
		if (state == M_HTTP2_HUFFMAN_STATE_ERROR) {
			M_buf_cancel(buf);
			return M_FALSE;
		}
	}
	M_buf_add_bytes(out_buf, M_buf_peek(buf), M_buf_len(buf));
	M_buf_cancel(buf);
	return M_TRUE;
}


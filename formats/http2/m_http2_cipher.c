#include <mstdlib/mstdlib.h>
#include <mstdlib/formats/m_http2.h>

#include "generated/m_http2_huffman_generated_encode.c"
/* Defines the following struct
 * struct {
 * 	M_uint8  len;
 * 	M_uint32 code;
 * } M_http2_huffman_encode_table[] = {
 * 	{ 13, 0x1ff8 },
 * 	{ 23, 0x7fffd8 },
 * 	...
 * 	{ 26, 0x3ffffee },
 * 	{ 30, 0x3fffffff },
 * };
 *
 * Which stores charcode indexed values specifying the bit length and value of static HTTP2 huffman codes.
 */

static M_uint8 M_http2_encode_huffman_character(M_buf_t *buf, M_uint8 encode_byte, size_t *encode_pos, M_uint8 len, M_uint32 charcode)
{
	size_t i;
	for (i=len; i-->0;) {
		M_bool bit = (charcode & (1 << i)) != 0;
		if (bit == M_FALSE)
			encode_byte &= ~(1u << *encode_pos);
		if (*encode_pos == 0) {
			M_buf_add_byte(buf, encode_byte);
			*encode_pos = 8;
			encode_byte = 0xFF;
		}
		(*encode_pos)--;
	}
	return encode_byte;
}

M_bool M_http2_encode_huffman(const M_uint8 *data, size_t data_len, M_buf_t *buf)
{
	size_t  i;
	M_uint8 encode_byte = 0xFF;
	size_t  encode_pos  = 7;
	for (i=0; i<data_len; i++) {
		M_uint8  byte     = data[i];
		M_uint8  len      = M_http2_huffman_encode_table[byte].len;
		M_uint32 charcode = M_http2_huffman_encode_table[byte].code;
		encode_byte       = M_http2_encode_huffman_character(buf, encode_byte, &encode_pos, len, charcode);
	}
	if (encode_pos < 7) {
		/* Add partial encoded byte to final output */
		M_buf_add_byte(buf, encode_byte);
	}
	return M_TRUE;
}

void M_http2_encode_number_chain(M_uint64 num, M_buf_t *buf)
{
	do {
		M_uint8 byte = num & 0x7F;
		num = num >> 7;
		if (num > 0) {
			M_buf_add_byte(buf, 0x80 | byte);
		} else {
			M_buf_add_byte(buf, byte);
		}
	} while (num > 0);
}

void M_http2_encode_string(const char *str, M_buf_t *buf)
{
	size_t len = M_str_len(str);
	M_uint8 byte;
	if (len < 0x7F) {
		byte = len & 0x7F;
		M_buf_add_byte(buf, 0x80 | byte);
	} else {
		M_buf_add_byte(buf, 0xFF);
		M_http2_encode_number_chain(len - 0x7F, buf);
	}
	M_http2_encode_huffman((M_uint8*)str, len, buf);
}

M_bool M_http2_encode_framehdr(M_http2_framehdr_t *framehdr, M_buf_t *buf)
{
	M_uint8 data[9];

	data[0] = framehdr->len.u8[2];
	data[1] = framehdr->len.u8[1];
	data[2] = framehdr->len.u8[0];
	data[3] = (M_uint8)framehdr->type;
	data[4] = framehdr->flags;
	data[5] = framehdr->stream.id.u8[3] | (framehdr->stream.is_R_set ? 0x80 : 0x00);
	data[6] = framehdr->stream.id.u8[2];
	data[7] = framehdr->stream.id.u8[1];
	data[8] = framehdr->stream.id.u8[0];

	M_buf_add_bytes(buf, data, sizeof(data));

	return M_TRUE;
}

/* Decoding */

#include "generated/m_http2_huffman_generated_decode.c"
/* Defines the following enum and function
 *
 * typedef enum {
 * 	M_HTTP2_HUFFMAN_STATE_,
 * 	M_HTTP2_HUFFMAN_STATE_0,
 * 	...
 * 	M_HTTP2_HUFFMAN_STATE_11111111111111111111111111111,
 * 	M_HTTP2_HUFFMAN_STATE_ERROR,
 * } M_http2_huffman_state_t;
 *
 * static M_http2_huffman_state_t M_http2_huffman(M_http2_huffman_state_t state, M_bool bit, M_uint32 *charcode);
 *
 * Which given a state and a bit and returns a new state.  On the detection of a huffman encoded value the state
 * will return to M_HTTP_HUFFMAN_STATE_ and charcode will be set to the detected charcode.
 */

static M_http2_huffman_state_t M_http2_decode_huffman_byte(M_buf_t *buf, M_uint8 byte, M_http2_huffman_state_t state)
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

M_bool M_http2_decode_huffman(const M_uint8 *data, size_t data_len, M_buf_t *out_buf)
{
	M_http2_huffman_state_t  state = M_HTTP2_HUFFMAN_STATE_;
	M_buf_t                 *buf   = M_buf_create();
	size_t                   i;
	for (i=0; i<data_len; i++) {
		state = M_http2_decode_huffman_byte(buf, data[i], state);
		if (state == M_HTTP2_HUFFMAN_STATE_ERROR) {
			M_buf_cancel(buf);
			return M_FALSE;
		}
	}
	M_buf_add_bytes(out_buf, M_buf_peek(buf), M_buf_len(buf));
	M_buf_cancel(buf);
	return M_TRUE;
}

M_bool M_http2_decode_number_chain(M_parser_t *parser, M_uint64 *num)
{
	M_uint8  byte;

	*num = 0;

	do {
		if (!M_parser_read_byte(parser, &byte))
			return M_FALSE;
		*num = (*num << 7) | (byte & 0x7F);
	} while((byte & 0x80) != 0);

	return M_TRUE;
}

M_bool M_http2_decode_string_length(M_parser_t *parser, M_uint64 *len, M_bool *is_huffman_encoded)
{
	static const M_uint8 mask = 0x7F;
	M_uint8              byte;

	if (!M_parser_read_byte(parser, &byte))
		return M_FALSE;

	*is_huffman_encoded = (byte & 0x80) != 0;

	byte = byte & mask;

	if (byte != mask) {
		*len = byte;
		return M_TRUE;
	}

	if (!M_http2_decode_number_chain(parser, len))
		return M_FALSE;

	*len += mask;
	return M_TRUE;
}

M_bool M_http2_decode_string(M_parser_t *parser, M_buf_t *buf)
{
	M_bool   is_huffman_encoded = M_FALSE;
	M_uint64 len                = 0;

	if (!M_http2_decode_string_length(parser, &len, &is_huffman_encoded))
		return M_FALSE;

	if (M_parser_len(parser) < len)
		return M_FALSE;

	if (is_huffman_encoded) {
		if (!M_http2_decode_huffman(M_parser_peek(parser), len, buf))
			return M_FALSE;
		M_parser_consume(parser, len);
		return M_TRUE;
	}
	M_buf_add_bytes(buf, M_parser_peek(parser), len);
	M_parser_consume(parser, len);
	return M_TRUE;
}

char *M_http2_decode_string_alloc(M_parser_t *parser)
{
	M_buf_t *buf = M_buf_create();
	if (!M_http2_decode_string(parser, buf)) {
		M_buf_cancel(buf);
		return NULL;
	}
	return M_buf_finish_str(buf, NULL);
}

M_bool M_http2_decode_framehdr(M_parser_t *parser, M_http2_framehdr_t *framehdr)
{
	const M_uint8 *data;

	if (M_parser_len(parser) < 9)
		return M_FALSE;

	data = M_parser_peek(parser);
	framehdr->len.u8[3]       = 0;
	framehdr->len.u8[2]       = data[0];
	framehdr->len.u8[1]       = data[1];
	framehdr->len.u8[0]       = data[2];
	framehdr->type            = data[3];
	framehdr->flags           = data[4];
	framehdr->stream.is_R_set = (data[5] & 0x80) != 0;
	framehdr->stream.id.u8[3] = data[5] & 0x7F;
	framehdr->stream.id.u8[2] = data[6];
	framehdr->stream.id.u8[1] = data[7];
	framehdr->stream.id.u8[0] = data[8];

	M_parser_consume(parser, 9);
	return M_TRUE;
}

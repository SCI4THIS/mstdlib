/* The MIT License (MIT)
 * 
 * Copyright (c) 2018 Main Street Softworks, Inc.
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

#include "m_config.h"

#include <mstdlib/mstdlib.h>

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static M_bool M_utf8_is_continue(unsigned char byte)
{
	if (byte >= 0x80 && byte <= 0xBF)
		return M_TRUE;
	return M_FALSE;
}

static size_t M_utf8_byte_width(unsigned char byte)
{
	if (byte <= 0x7F)
		return 1;

	/* Continue. */
	if (byte >= 0x80 && byte <= 0xBF)
		return 0;

	/* Doesn't start with 0xC0 because 0xC0-0xC1 are prohibited. */
	if (byte >= 0xC2 && byte <= 0xDF)
		return 2;

	if (byte >= 0xE0 && byte <= 0xEF)
		return 3;

	/* Doesn't end with 0xFF because 0xF7-0xFF are prohibited. */
	if (byte >= 0xF0 && byte <= 0xF4)
		return 4;

	/* Not valid. */
	return 0;
}

static size_t M_utf8_cp_width(M_uint32 cp)
{
	if (cp <= 0x7F)
		return 1;

	if (cp >= 0x80 && cp <= 0x7FF)
		return 2;

	if (cp >= 0x800 && cp <= 0xFFFF)
		return 3;

	if (cp >= 0x1000)
		return 4;

	return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

M_bool M_utf8_is_valid(const char *str)
{
	if (M_str_isempty(str))
		return M_TRUE;

	if (M_utf8_len(str) > 0)
		return M_TRUE;
	return M_FALSE;
}

M_bool M_utf8_is_valid_cp(M_uint32 cp)
{
	/* Max code point. */
	if (cp > 0x10FFFF)
		return M_FALSE;

	/* utf-16 surrogate pairs. */
	if (cp >= 0xD800 && cp <= 0xDFFF)
		return M_FALSE;

	return M_TRUE;
}

M_utf8_error_t M_utf8_to_cp(const char *str, M_uint32 *cp, const char **next)
{
	M_uint32 mycp;
	size_t   width = 0;
	size_t   len;
	size_t   i;

	if (str == NULL)
		return M_UTF8_ERROR_INVALID_PARAM;

	if (*str == '\0') {
		if (cp != NULL) {
			*cp = 0;
		}
		return M_UTF8_ERROR_SUCESS;
	}

	len   = M_str_len(str);
	width = M_utf8_byte_width((unsigned char)str[0]);
	if (width == 0)
		return M_UTF8_ERROR_BAD_START;

	if (width > len)
		return M_UTF8_ERROR_TRUNCATED;

	/* Single byte values are as is. */
	if (width == 1) {
		*cp = (M_uint32)str[0];
		return M_UTF8_ERROR_SUCESS;
	}

	/* Validate the next bytes in the sequence are continues. */
	for (i=1; i<width; i++) {
		if (!M_utf8_is_continue((unsigned char)str[i])) {
			return M_UTF8_ERROR_EXPECT_CONTINUE;
		}
	}

	/* Put it all together. */
	if (width == 2) {
 		mycp = (M_uint32)(((str[0] & 0x1F) << 6) | (str[1] & 0x3F));
	} else if (width == 3) {
 		mycp = (M_uint32)(((str[0] & 0x0F) << 12) | ((str[1] & 0x3F) << 6) | (str[2] & 0x3F));
	} else if (width == 4) {
 		mycp = (M_uint32)(((str[0] & 0x07) << 18) | ((str[1] & 0x3F) << 12) | ((str[2] & 0x3F) << 6) | (str[3] & 0x3F));
	} else {
		return M_UTF8_ERROR_BAD_CODE_POINT;
	}

	/* Validate code point is valid. */
	if (!M_utf8_is_valid_cp(mycp))
		return M_UTF8_ERROR_BAD_CODE_POINT;

	/* Detect overlong encoding by checking if the code point will use the same
 	 * width if convered back. */
	if (width != M_utf8_cp_width(mycp))
		return M_UTF8_ERROR_OVERLONG;

	if (cp != NULL)
		*cp = mycp;
	if (next != NULL)
		*next = str+width;
	return M_UTF8_ERROR_SUCESS;
}

M_utf8_error_t M_utf8_from_cp(char *buf, size_t buf_size, size_t *len, M_uint32 cp)
{
	size_t width;

	if (buf == NULL || len == NULL)
		return M_UTF8_ERROR_INVALID_PARAM;

	if (!M_utf8_is_valid_cp(cp))
		return M_UTF8_ERROR_BAD_CODE_POINT;

	width = M_utf8_cp_width(cp);
	if (width == 0)
		return M_UTF8_ERROR_BAD_CODE_POINT;

	if (width > buf_size)
		return M_UTF8_ERROR_TRUNCATED;

	if (width == 1) {
		M_mem_copy(buf, (char *)&cp, 1);
		return M_UTF8_ERROR_SUCESS;
	}

	if (width == 2) {
		buf[0] = (char)(0xC0 | ((cp >> 6) & 0x3F));
		buf[1] = (char)(0x80 | (cp & 0x3F));
	} else if (width == 3) {
		buf[0] = (char)(0xE0 | ((cp >> 12) & 0x3F));
		buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		buf[2] = (char)(0x80 | (cp & 0x3F));
	} else if (width == 4) {
		buf[0] = (char)(0xF0 | ((cp >> 18) & 0x3F));
		buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
		buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
		buf[3] = (char)(0x80 | (cp & 0x3F));
	} else {
		return M_UTF8_ERROR_BAD_CODE_POINT;
	}

	*len = width;
	return M_UTF8_ERROR_SUCESS;
}

M_utf8_error_t M_utf8_from_cp_buf(M_buf_t *buf, M_uint32 cp)
{
	char           mybuf[8] = { 0 };
	size_t         len;
	M_utf8_error_t res;

	res = M_utf8_from_cp(mybuf, sizeof(mybuf), &len, cp);
	if (res == M_UTF8_ERROR_SUCESS)
		M_buf_add_bytes(buf, mybuf, len);

	return res;
}

size_t M_utf8_len(const char *str)
{
	const char     *next = str;
	size_t          len  = 0;
	M_utf8_error_t  res  = M_UTF8_ERROR_SUCESS;

	if (M_str_isempty(str))
		return 0;

	while (*next != '\0' && res == M_UTF8_ERROR_SUCESS) {
		res = M_utf8_to_cp(str, NULL, &next);
		str = next;
		len++;
	}
	if (res != M_UTF8_ERROR_SUCESS)
		len = 0;

	return len;
}

M_utf8_error_t M_utf8_cp_at(const char *str, size_t idx, M_uint32 *cp)
{
	const char     *next = str;
	M_utf8_error_t  res  = M_UTF8_ERROR_SUCESS;
	size_t          i    = 0;

	if (M_str_isempty(str))
		return M_UTF8_ERROR_INVALID_PARAM;

	while (*next != '\0' && res == M_UTF8_ERROR_SUCESS) {
		res = M_utf8_to_cp(str, cp, &next);
		str = next;
		if (i == idx)
			break;
		i++;
	}
	if (res != M_UTF8_ERROR_SUCESS)
		return res;

	if (i != idx)
		return M_UTF8_ERROR_INVALID_PARAM;

	return M_UTF8_ERROR_SUCESS;
}

M_utf8_error_t M_utf8_chr_at(char *buf, size_t buf_size, size_t *len, const char *str, size_t idx)
{
	M_utf8_error_t res;
	M_uint32       cp;

	res = M_utf8_cp_at(str, idx, &cp);
	if (res != M_UTF8_ERROR_SUCESS)
		return res;

	return M_utf8_from_cp(buf, buf_size, len, cp);
}

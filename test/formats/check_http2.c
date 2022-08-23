#include "m_config.h"
#include <stdlib.h> /* EXIT_SUCCESS, EXIT_FAILURE, srand, rand */
#include <check.h>

#include <mstdlib/mstdlib.h>
#include <mstdlib/mstdlib_formats.h>

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#define add_test(SUITENAME, TESTNAME)\
do {\
	TCase *tc;\
	tc = tcase_create(#TESTNAME);\
	tcase_add_test(tc, TESTNAME);\
	suite_add_tcase(SUITENAME, tc);\
} while (0)

START_TEST(check_http2_frame_goaway)
{
	M_http2_goaway_t *goaway = NULL;
	const M_uint8 frame[]    = {
		0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00
	};
	goaway = M_http2_frame_read_goaway(frame, sizeof(frame));
	ck_assert_msg(goaway != NULL, "Should succeed");
	M_free(goaway);
}

START_TEST(check_http2_data)
{
	const M_uint8 frame[] = {
		0x00, 0x00, 0x57, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54,
		0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0a, 0x3c, 0x21, 0x2d, 0x2d, 0x5b, 0x69,
		0x66, 0x20, 0x49, 0x45, 0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x20, 0x37, 0x20, 0x5d, 0x3e, 0x3c,
		0x68, 0x74, 0x6d, 0x6c, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x6e, 0x6f, 0x2d, 0x6a,
		0x73, 0x20, 0x69, 0x65, 0x6d, 0x37, 0x22, 0x3e, 0x3c, 0x21, 0x5b, 0x65, 0x6e, 0x64, 0x69, 0x66,
		0x5d, 0x2d, 0x2d, 0x3e, 0x0a, 0x3c, 0x21, 0x2d, 0x2d, 0x5b, 0x69, 0x66, 0x20, 0x6c, 0x74, 0x20,
	};
	const char *frame_str =
		"\n<!DOCTYPE html>\n<!--[if IEMobile 7 ]><html class=\"no-js iem7\"><![endif]-->\n<!--[if lt ";
	M_buf_t *buf = M_buf_create();;
	char    *str = NULL;
	ck_assert_msg(M_http2_frame_read_data(frame, sizeof(frame), buf), "Should succeed");
	str = M_buf_finish_str(buf, NULL);
	ck_assert_msg(M_str_eq(str, frame_str), "Should have parsed correctly");
	M_free(str);
}

START_TEST(check_http2_huffman)
{
	char          *str           = NULL;
	size_t         str_len;
	const M_uint8  huffman_str[] = {
		0xaa, 0x69, 0xd2, 0x9a, 0xc4, 0xb9, 0xec, 0x9b
	};
	const char    *huffman_str_decoded = "nghttp2.org";
	const M_uint8  huffman_str2[] = {
	  0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b, 0x39, 0x60,
   0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36, 0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f, 0x95, 0x87,
   0x31, 0x60, 0x65, 0xc0, 0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07,
	};
	const char    *huffman_str2_decoded = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";
	/*11111111|00100001*/
	const M_uint8  huffman_str3[] = {
		0xff, 0x21
	};
	const char    *huffman_str3_decoded = "?A";
	M_buf_t *buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_decode(buf, huffman_str, sizeof(huffman_str)), "Should succeed");
	str = M_buf_finish_str(buf, NULL);
	ck_assert_msg(M_str_eq(str, huffman_str_decoded), "Should huffman decode to \"%s\" not \"%s\"", huffman_str_decoded, str);
	buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_encode(buf, (unsigned char *)str, M_str_len(str)), "Should succeed");
	M_free(str);
	str = M_buf_finish_str(buf, &str_len);
	ck_assert_msg(M_mem_eq(str, huffman_str, sizeof(huffman_str)), "Should huffman encode back");
	ck_assert_msg(str_len == sizeof(huffman_str), "Should be the same length");
	M_free(str);

	buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_decode(buf, huffman_str2, sizeof(huffman_str2)), "Should succeed");
	str = M_buf_finish_str(buf, NULL);
	ck_assert_msg(M_str_eq(str, huffman_str2_decoded), "Should huffman decode to \"%s\" not \"%s\"", huffman_str2_decoded, str);
	buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_encode(buf, (unsigned char *)str, M_str_len(str)), "Should succeed");
	M_free(str);
	str = M_buf_finish_str(buf, &str_len);
	ck_assert_msg(M_mem_eq(str, huffman_str2, sizeof(huffman_str2)), "Should huffman encode back");
	ck_assert_msg(str_len == sizeof(huffman_str2), "Should be the same length");
	M_free(str);

	buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_decode(buf, huffman_str3, sizeof(huffman_str3)), "Should succeed");
	str = M_buf_finish_str(buf, NULL);
	ck_assert_msg(M_str_eq(str, huffman_str3_decoded), "Should huffman decode to \"%s\" not \"%s\"", huffman_str3_decoded, str);
	buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_encode(buf, (unsigned char *)str, M_str_len(str)), "Should succeed");
	M_free(str);
	str = M_buf_finish_str(buf, &str_len);
	ck_assert_msg(M_mem_eq(str, huffman_str3, sizeof(huffman_str3)), "Should huffman encode back");
	ck_assert_msg(str_len == sizeof(huffman_str3), "Should be the same length");
	M_free(str);
}
END_TEST

START_TEST(check_http2_pri_str)
{
	M_buf_t *buf = M_buf_create();
	M_http2_write_pri_str(buf);
	ck_assert_msg(M_http2_read_pri_str(M_buf_peek(buf), M_buf_len(buf)), "Should succeed");
	M_buf_cancel(buf);
}
END_TEST

START_TEST(check_http2_frame_settings)
{
	M_http2_settings_t  settings;
	M_uint32            flags = 0;
	M_buf_t            *buf   = M_buf_create();

	const M_uint8 frame1[] = {
		0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64
	};

	ck_assert_msg(M_http2_frame_read_settings(frame1, sizeof(frame1), &flags, &settings), "Should succeed");
	ck_assert_msg(flags == (1 << M_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), "Should set max concurrent");
	ck_assert_msg(settings.max_concurrent_streams == 100, "Should set max concurrent to 100");

	ck_assert_msg(M_http2_frame_write_settings(buf, flags, &settings), "Should succeed");
	ck_assert_msg(M_buf_len(buf) == sizeof(frame1), "Should be same size as frame");
	ck_assert_msg(M_mem_eq(M_buf_peek(buf), frame1, sizeof(frame1)), "Should generate same as frame1");

	M_buf_drop(buf, M_buf_len(buf));

	M_http2_frame_write_settings_ack(buf);
	ck_assert_msg(M_http2_frame_read_settings((M_uint8*)M_buf_peek(buf), M_buf_len(buf), &flags, &settings), "Should succeed");
	ck_assert_msg(flags == (1u << M_HTTP2_SETTINGS_ACK), "Should set ACK flag");

	M_buf_cancel(buf);
}
END_TEST

/*
static void print_dict(M_hash_dict_t *dict)
{
	M_hash_dict_enum_t *hashenum;
	const char         *key;
	const char         *value;
	M_hash_dict_enumerate(dict, &hashenum);
	while (M_hash_dict_enumerate_next(dict, hashenum, &key, &value)) {
		M_printf("\"%s\" = \"%s\"\n", key, value);
	}
	M_hash_dict_enumerate_free(hashenum);
}
*/

START_TEST(check_http2_frame_headers)
{
	const M_uint8 frame[] = {
		0x00, 0x01, 0x05, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x20, 0x88, 0x0f, 0x12, 0x96, 0xe4, 0x59,
		0x3e, 0x94, 0x0b, 0xaa, 0x43, 0x6c, 0xca, 0x08, 0x02, 0x12, 0x81, 0x66, 0xe3, 0x4e, 0x5c, 0x65,
		0xe5, 0x31, 0x68, 0xdf, 0x0f, 0x10, 0x87, 0x49, 0x7c, 0xa5, 0x89, 0xd3, 0x4d, 0x1f, 0x0f, 0x1d,
		0x96, 0xdf, 0x69, 0x7e, 0x94, 0x03, 0x6a, 0x65, 0xb6, 0x85, 0x04, 0x01, 0x09, 0x40, 0x3f, 0x71,
		0xa6, 0x6e, 0x36, 0x25, 0x31, 0x68, 0xdf, 0x0f, 0x13, 0x8c, 0xfe, 0x5c, 0x11, 0x1a, 0x03, 0xb2,
		0x3c, 0xb0, 0x5e, 0x8d, 0xaf, 0xe7, 0x0f, 0x03, 0x84, 0x8f, 0xd2, 0x4a, 0x8f, 0x0f, 0x0d, 0x83,
		0x71, 0x91, 0x35, 0x00, 0x8f, 0xf2, 0xb4, 0x63, 0x27, 0x52, 0xd5, 0x22, 0xd3, 0x94, 0x72, 0x16,
		0xc5, 0xac, 0x4a, 0x7f, 0x86, 0x02, 0xe0, 0x03, 0x4f, 0x80, 0x5f, 0x0f, 0x29, 0x8c, 0xa4, 0x7e,
		0x56, 0x1c, 0xc5, 0x81, 0x90, 0xb6, 0xcb, 0x80, 0x00, 0x3f, 0x0f, 0x27, 0x86, 0xaa, 0x69, 0xd2,
		0x9a, 0xfc, 0xff, 0x00, 0x85, 0x1d, 0x09, 0x59, 0x1d, 0xc9, 0xa1, 0x9d, 0x98, 0x3f, 0x9b, 0x8d,
		0x34, 0xcf, 0xf3, 0xf6, 0xa5, 0x23, 0x81, 0x97, 0x00, 0x0f, 0xa5, 0x27, 0x65, 0x61, 0x3f, 0x07,
		0xf3, 0x71, 0xa6, 0x99, 0xfe, 0x7e, 0xd4, 0xa4, 0x70, 0x32, 0xe0, 0x01, 0x0f, 0x2d, 0x87, 0x12,
		0x95, 0x4d, 0x3a, 0x53, 0x5f, 0x9f, 0x00, 0x8b, 0xf2, 0xb4, 0xb6, 0x0e, 0x92, 0xac, 0x7a, 0xd2,
		0x63, 0xd4, 0x8f, 0x89, 0xdd, 0x0e, 0x8c, 0x1a, 0xb6, 0xe4, 0xc5, 0x93, 0x4f, 0x00, 0x8c, 0xf2,
		0xb7, 0x94, 0x21, 0x6a, 0xec, 0x3a, 0x4a, 0x44, 0x98, 0xf5, 0x7f, 0x8a, 0x0f, 0xda, 0x94, 0x9e,
		0x42, 0xc1, 0x1d, 0x07, 0x27, 0x5f, 0x00, 0x90, 0xf2, 0xb1, 0x0f, 0x52, 0x4b, 0x52, 0x56, 0x4f,
		0xaa, 0xca, 0xb1, 0xeb, 0x49, 0x8f, 0x52, 0x3f, 0x85, 0xa8, 0xe8, 0xa8, 0xd2, 0xcb,
	};
	const M_uint8 frame2[] = {
		0x00, 0x00, 0x0d, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x87, 0x84, 0x41, 0x88, 0xaa, 0x69,
		0xd2, 0x9a, 0xc4, 0xb9, 0xec, 0x9b,
	};

	const struct {
		const char *key;
		const char *val;
	} keyvals[] = {
		{ ":status", "200" },
		{ "x-content-type-options", "nosniff" },
		{ "last-modified", "Tue, 05 Jul 2022 09:43:52 GMT" },
		{ "etag", "\"62c407d8-18b4\"" },
		{ "x-xss-protection", "1; mode=block" },
		{ "server", "nghttpx" },
		{ "x-frame-options", "SAMEORIGIN" },
		{ "content-type", "text/html" },
		{ "date", "Wed, 17 Aug 2022 13:46:38 GMT" },
		{ "accept-ranges", "bytes" },
		{ "content-length", "6324" },
		{ "x-backend-header-rtt", "0.004902" },
		{ "strict-transport-security", "max-age=31536000" },
		{ "alt-svc", "h3=\":443\"; ma=3600, h3-29=\":443\"; ma=3600" },
		{ "via", "2 nghttpx" },
	};
	const struct {
		const char *key;
		const char *val;
	} keyvals2[] = {
		{ ":method", "GET" },
		{ ":scheme", "https" },
		{ ":path", "/" },
		{ ":authority", "nghttp2.org" },
	};
	const size_t        len      = (sizeof(keyvals) / sizeof(keyvals[0]));
	const size_t        len2     = (sizeof(keyvals2) / sizeof(keyvals2[0]));
	size_t              i;
	M_hash_dict_t      *headers  = M_http2_frame_read_headers(frame, sizeof(frame));
	ck_assert_msg(M_hash_dict_num_keys(headers) == len, "Should have read %zu header entries, not %zu", len, M_hash_dict_num_keys(headers));
	for (i=0; i<len; i++) {
		const char *val = M_hash_dict_get_direct(headers, keyvals[i].key);
		ck_assert_msg(M_str_eq(val, keyvals[i].val), "Should have \"%s\" = \"%s\", not \"%s\"", keyvals[i].key, keyvals[i].val, val);
	}
	M_hash_dict_destroy(headers);

	headers = M_http2_frame_read_headers(frame2, sizeof(frame2));
	ck_assert_msg(M_hash_dict_num_keys(headers) == len2, "Should have read %zu header entries, not %zu", len2, M_hash_dict_num_keys(headers));
	for (i=0; i<len2; i++) {
		const char *val = M_hash_dict_get_direct(headers, keyvals2[i].key);
		ck_assert_msg(M_str_eq(val, keyvals2[i].val), "Should have \"%s\" = \"%s\", not \"%s\"", keyvals2[i].key, keyvals2[i].val, val);
	}
	M_hash_dict_destroy(headers);
}
END_TEST

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

int main(void)
{
	Suite   *suite;
	SRunner *sr;
	int      nf;

	suite = suite_create("http2");

	add_test(suite, check_http2_frame_goaway);
	add_test(suite, check_http2_frame_settings);
	add_test(suite, check_http2_frame_headers);
	add_test(suite, check_http2_pri_str);
	add_test(suite, check_http2_huffman);
	add_test(suite, check_http2_data);

	sr = srunner_create(suite);
	if (getenv("CK_LOG_FILE_NAME")==NULL) srunner_set_log(sr, "check_http2.log");

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);

	return nf == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

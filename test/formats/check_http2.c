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

	const char frame1[] = {
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
	ck_assert_msg(M_http2_frame_read_settings(M_buf_peek(buf), M_buf_len(buf), &flags, &settings), "Should succeed");
	ck_assert_msg(flags == (1u << M_HTTP2_SETTINGS_ACK), "Should set ACK flag");

	M_buf_cancel(buf);
}
END_TEST

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

int main(void)
{
	Suite   *suite;
	SRunner *sr;
	int      nf;

	suite = suite_create("http2");

	add_test(suite, check_http2_frame_settings);
	add_test(suite, check_http2_pri_str);
	add_test(suite, check_http2_huffman);

	sr = srunner_create(suite);
	if (getenv("CK_LOG_FILE_NAME")==NULL) srunner_set_log(sr, "check_http2.log");

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);

	return nf == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

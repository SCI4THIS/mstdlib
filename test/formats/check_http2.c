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
	const M_uint8  huffman_str[] = {
		0xaa, 0x69, 0xd2, 0x9a, 0xc4, 0xb9, 0xec, 0x9b
	};
	M_buf_t *buf = M_buf_create();
	ck_assert_msg(M_http2_huffman_decode(buf, huffman_str, sizeof(huffman_str)), "Should succeed");
	str = M_buf_finish_str(buf, NULL);
	ck_assert_msg(M_str_eq(str, "nghttp2.org"), "Should huffman decode to \"nghttp2.org\"");
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

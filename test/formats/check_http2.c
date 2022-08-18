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

START_TEST(check_http2_frame_settings)
{
	M_http2_settings_t settings;
	M_uint32           flags = 0;

	const char frame1[] = {
		0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64
	};

	ck_assert_msg(M_http2_frame_read_settings(frame1, sizeof(frame1), &flags, &settings), "Should succeed");
	ck_assert_msg(flags == (1 << M_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), "Should set max concurrent");
	ck_assert_msg(settings.max_concurrent_streams == 100, "Should set max concurrent to 100");

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

	sr = srunner_create(suite);
	if (getenv("CK_LOG_FILE_NAME")==NULL) srunner_set_log(sr, "check_http2.log");

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);

	return nf == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

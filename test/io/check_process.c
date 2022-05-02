#include "m_config.h"
#include <stdlib.h>
#include <check.h>

#include <mstdlib/mstdlib.h>
#include <mstdlib/mstdlib_thread.h>
#include <mstdlib/mstdlib_io.h>

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#define DEBUG 1

#if defined(DEBUG) && DEBUG
#include <stdarg.h>

static void event_debug(const char *fmt, ...)
{
	va_list     ap;
	char        buf[1024];
	M_timeval_t tv;

	M_time_gettimeofday(&tv);
	va_start(ap, fmt);
	M_snprintf(buf, sizeof(buf), "%lld.%06lld: %s\n", tv.tv_sec, tv.tv_usec, fmt);
	M_vprintf(buf, ap);
	va_end(ap);
}
#else
static void event_debug(const char *fmt, ...)
{
	(void)fmt;
}
#endif

static const char *event_type_str(M_event_type_t type)
{
	switch (type) {
		case M_EVENT_TYPE_CONNECTED:
			return "CONNECTED";
		case M_EVENT_TYPE_ACCEPT:
			return "ACCEPT";
		case M_EVENT_TYPE_READ:
			return "READ";
		case M_EVENT_TYPE_WRITE:
			return "WRITE";
		case M_EVENT_TYPE_DISCONNECTED:
			return "DISCONNECT";
		case M_EVENT_TYPE_ERROR:
			return "ERROR";
		case M_EVENT_TYPE_OTHER:
			return "OTHER";
	}
	return "UNKNOWN";
}

/* We need proc_stdin as global as we cannot rely on receiving a disconnect event
 * when the process exits.  So we should close this endpoint when the process exits */
static M_io_t            *proc_stdin  = NULL;

/* Flags an error when trying to write to cat */
static M_bool             delay_cat_error_flag = M_FALSE;

static void process_cb(M_event_t *event, M_event_type_t type, M_io_t *io, void *data)
{
	char          error[256];
	M_buf_t      *buf;
	const char   *name = data;
	(void)event;
	(void)data;

	if (io != NULL) {
		event_debug("process %p %s event %s triggered", io, name, event_type_str(type));
	} else {
		event_debug("process %p event %s triggered (cat-delay)", io, event_type_str(type));
	}
	switch (type) {
		case M_EVENT_TYPE_CONNECTED:
			if (M_str_caseeq(name, "process")) {
				event_debug("process %p %s created with pid %d", io, name, M_io_process_get_pid(io));
			}
			break;
		case M_EVENT_TYPE_READ:
			buf = M_buf_create();
			M_io_read_into_buf(io, buf);
			event_debug("process %p %s read %zu bytes", io, name, M_buf_len(buf));
			M_buf_cancel(buf);
			break;
		case M_EVENT_TYPE_WRITE:
			break;
		case M_EVENT_TYPE_OTHER:
			if (proc_stdin != NULL) {
				size_t       written;
				M_io_error_t io_error;
				const char   str[] = "hello world!";
				io = proc_stdin;
				event_debug("(delay-cat) about to write");
				io_error = M_io_write(io, (const unsigned char *)str, sizeof(str), &written);
				event_debug("(delay-cat) write done");
				if (io_error != M_IO_ERROR_SUCCESS || written == 0) {
					event_debug("failed to write to stdin");
					return;
				}
				M_io_disconnect(io);
			} else {
				event_debug("Attempt to write to stdin, but it has been closed!");
				delay_cat_error_flag = M_TRUE;
			}
			break;
		case M_EVENT_TYPE_DISCONNECTED:
		case M_EVENT_TYPE_ERROR:
			M_io_get_error_string(io, error, sizeof(error));
			if (M_str_caseeq(name, "process")) {
				int return_code = 0;
				M_io_process_get_result_code(io, &return_code);
				event_debug("process %p %s ended with return code (%d), cleaning up: %s", io, name, return_code, error);
				if (proc_stdin)
					M_io_destroy(proc_stdin);
				proc_stdin = NULL;
			} else {
				event_debug("process %p %s ended, cleaning up: %s", io, name, error);
				/* On Linux/Mac we will be notified of stdin being disconnected, so mark as cleaned up already */
				if (io == proc_stdin)
					proc_stdin = NULL;
			}
			M_io_destroy(io);

			break;
		default:
			/* Ignore */
			break;
	}
}


static void process_trace_cb(void *cb_arg, M_io_trace_type_t type, M_event_type_t event_type, const unsigned char *data, size_t data_len)
{
	char *temp;
	(void)event_type;
	if (type == M_IO_TRACE_TYPE_READ) {
		M_printf("%s [READ]:\n", (const char *)cb_arg);
	} else if (type == M_IO_TRACE_TYPE_WRITE) {
		M_printf("%s [WRITE]:\n", (const char *)cb_arg);
	} else {
		M_printf("%s [%s]\n", (const char *)cb_arg, event_type_str(event_type));
		return;
	}

	temp = M_str_hexdump(M_STR_HEXDUMP_DECLEN|M_STR_HEXDUMP_HEADER, 0, NULL, data, data_len);
	M_printf("%s\n", temp);
	M_free(temp);
}

typedef enum {
	TEST_CASE_ECHO    = 1,
	TEST_CASE_TIMEOUT = 2,
	TEST_CASE_CAT     = 3,
} process_test_cases_t;

static M_bool process_test(process_test_cases_t test_case)
{
	M_event_t         *event   = M_event_create(M_EVENT_FLAG_EXITONEMPTY);
	M_io_t            *proc        = NULL;
	M_io_t            *proc_stdout = NULL;
	M_io_t            *proc_stderr = NULL;
	const char        *command;
	M_list_str_t      *args    = M_list_str_create(M_LIST_STR_NONE);

	switch (test_case) {
		case TEST_CASE_CAT:
#ifdef _WIN32
			command = "cmd.exe";
			M_list_str_insert(args, "/c");
			M_list_str_insert(args, "type");
#else
			command = "cat";
#endif
			break;
		case TEST_CASE_ECHO:
#ifdef _WIN32
			command = "cmd.exe";
			M_list_str_insert(args, "/c");
			M_list_str_insert(args, "echo");
			M_list_str_insert(args, "Hello World!");
#else
			command = "echo";
			M_list_str_insert(args, "Hello World!");
#endif
			break;
		case TEST_CASE_TIMEOUT:
#ifdef _WIN32
			command = "cmd.exe";
			M_list_str_insert(args, "/c");
			M_list_str_insert(args, "sleep");
			M_list_str_insert(args, "4");
#else
			command = "sleep";
			M_list_str_insert(args, "4");
#endif
			break;
	}

	event_debug("**** starting process test case %d", test_case);
	proc_stdin  = NULL;
	proc_stdout = NULL;
	proc_stderr = NULL;
	if (M_io_process_create(command, args, NULL, 2000, &proc, &proc_stdin, &proc_stdout, &proc_stderr) != M_IO_ERROR_SUCCESS) {
		event_debug("failed to create process %s", command);
		return M_FALSE;
	}
	M_list_str_destroy(args);

	M_io_add_trace(proc,        NULL, process_trace_cb, (void *)"process", NULL, NULL);
	M_io_add_trace(proc_stdin,  NULL, process_trace_cb, (void *)"stdin",   NULL, NULL);
	M_io_add_trace(proc_stdout, NULL, process_trace_cb, (void *)"stdout",  NULL, NULL);
	M_io_add_trace(proc_stderr, NULL, process_trace_cb, (void *)"stderr",  NULL, NULL);

	if (!M_event_add(event, proc, process_cb, (void *)"process")) {
		event_debug("failed to add process io handle");
		return M_FALSE;
	}
	if (!M_event_add(event, proc_stdin, process_cb, (void *)((test_case == TEST_CASE_CAT)?"stdin(cat)":"stdin"))) {
		event_debug("failed to add stdin io handle");
		return M_FALSE;
	}
	if (!M_event_add(event, proc_stdout, process_cb, (void *)"stdout")) {
		event_debug("failed to add stdout io handle");
		return M_FALSE;
	}
	if (!M_event_add(event, proc_stderr, process_cb, (void *)"stderr")) {
		event_debug("failed to add stderr io handle");
		return M_FALSE;
	}

	event_debug("entering loop");
	if (test_case == TEST_CASE_CAT) {
		M_event_timer_oneshot(event, 1000, M_TRUE, process_cb, proc_stdin);
	}
	if (M_event_loop(event, 5000) != M_EVENT_ERR_DONE) {
		event_debug("event loop did not return done");
		return M_FALSE;
	}
	event_debug("loop ended");

	if (delay_cat_error_flag) {
		return M_FALSE;
	}

	/* Cleanup */
	M_event_destroy(event);
	M_library_cleanup();
	event_debug("exited");
	return M_TRUE;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

START_TEST(check_process_echo)
{
	ck_assert(process_test(TEST_CASE_ECHO));
}
END_TEST

START_TEST(check_process_timeout)
{
	ck_assert(process_test(TEST_CASE_TIMEOUT));
}
END_TEST

START_TEST(check_process_cat)
{
	ck_assert(process_test(TEST_CASE_CAT));
}
END_TEST


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static Suite *process_suite(void)
{
	Suite *suite;
	TCase *tc;

	suite = suite_create("process");

	tc = tcase_create("process");
	tcase_add_test(tc, check_process_echo);
	tcase_add_test(tc, check_process_timeout);
	tcase_add_test(tc, check_process_cat);
	suite_add_tcase(suite, tc);


	return suite;
}

int main(int argc, char **argv)
{
	SRunner *sr;
	int      nf;

	(void)argc;
	(void)argv;

	sr = srunner_create(process_suite());
	if (getenv("CK_LOG_FILE_NAME")==NULL) srunner_set_log(sr, "check_process.log");

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);

	return nf == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

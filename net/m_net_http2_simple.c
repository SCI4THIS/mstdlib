/* The MIT License (MIT)
 *
 * Copyright (c) 2022 Monetra Technologies, LLC.
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

#include "m_net_int.h"

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

struct M_net_http2_simple {
	M_event_t                           *el;
	M_dns_t                             *dns;
	void                                *thunk;
	M_tls_clientctx_t                   *ctx;
	M_io_t                              *io;
	M_parser_t                          *read_parser;
	struct M_net_http2_simple_callbacks  cbs;
	char                                 errmsg[256];
};

static void M_net_http2_simple_error_cb_default(M_http_error_t error, const char *errmsg)
{
	(void)error;
	(void)errmsg;
}

static M_bool M_net_http2_simple_iocreate_cb_default(M_io_t *io, char *error, size_t errlen, void *thunk)
{
	(void)io;
	(void)error;
	(void)errlen;
	(void)thunk;
		return M_TRUE;
	
}

static void M_assign_cbs(void **dst_cbs, void *const*src_cbs, size_t len)
{
	size_t i;
	for (i=0; i<len; i++) {
		if (src_cbs[i] != NULL) {
			dst_cbs[i] = src_cbs[i];
		}
	}
}

M_API M_net_http2_simple_t *M_net_http2_simple_create(M_event_t *el, M_dns_t *dns, const struct M_net_http2_simple_callbacks *cbs, void *thunk)
{
	static const struct M_net_http2_simple_callbacks default_cbs = {
		M_net_http2_simple_iocreate_cb_default,
		M_net_http2_simple_error_cb_default,
	};

	M_net_http2_simple_t *h2 = NULL;

	if (el == NULL || dns == NULL)
		return NULL;

	h2 = M_malloc_zero(sizeof(*h2));

	M_mem_copy(&h2->cbs, &default_cbs, sizeof(default_cbs));
	if (cbs != NULL) {
		M_assign_cbs((void**)&h2->cbs, (void*const*)cbs, sizeof(default_cbs) / sizeof(void*));
	}

	h2->el    = el;
	h2->dns   = dns;
	h2->thunk = thunk;

	return h2;
}

M_API void M_net_http2_simple_destroy(M_net_http2_simple_t *h2)
{
	M_free(h2);
}

M_API void M_net_http2_simple_request(M_net_http2_simple_t *h2, const char *url, M_net_http2_simple_response_cb response_cb)
{
	(void)h2;
	(void)url;
	(void)response_cb;
}

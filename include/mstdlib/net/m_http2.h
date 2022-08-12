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

#ifndef __M_HTTP2_H__
#define __M_HTTP2_H__

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

__BEGIN_DECLS

/*! \addtogroup m_http2 HTTP2
 *  \ingroup m_net
 *
 * HTTP/2 message reading and writing.
 *
 * via libnghttp2
 *
 * Conforms to:
 *
 * - RFC 7540 Hypertext Transfer Protocol Version 2 (HTTP/2)
 * - RFC 7541 HPACK: Header Compression for HTTP/2
 *
 * In HTTP2 the major design concept is to open a single TCP
 * connection for all resource retrieval. The RFC has carve-outs
 * for non-encrypted communication, but in practice it is all done
 * over TLS.  This single connection eliminates all but one of handshakes,
 * reducing the communication overhead.
 *
 * Multiple data requests and responses are multiplexed through the
 * single communication SESSION.  An individual resource is broken into
 * data chunk FRAMES which are linked together by a STREAM id.  A
 * resource can be either client initiated via transmission of a HEADERS
 * frame (which assigns an odd numbered STREAM id to the request) or
 * server initiated via transmission of a PUSH_PROMISE frame (even numbered).
 *
 * This library is designed to be added as a layer to a M_io_t
 * stream.  It will manage the frame processing and propagate a
 * READ event up once a stream finishes to indicating a resource is
 * has finished transmitting and is available in local memory.
 *
 * Example application that demonstrates GET a webpage via HTTP2
 *
 * \code{.c}
 * #include <mstdlib/mstdlib.h>
 * #include <mstdlib/mstdlib_io.h>
 * #include <mstdlib/mstdlib_net.h>
 * #include <mstdlib/net/m_http2.h>
 *
 * struct {
 * 	const char *scheme;
 * 	const char *hostname;
 * 	M_uint16    port;
 * 	const char *path;
 * 	M_io_t     *io;
 * 	M_int32     stream_id;
 * 	size_t      tls_layer_idx;
 * } args = { "https", "nghttp2.org", (M_uint16)443, "/", NULL, 0, 0 };
 * 
 * static void print_headers(M_hash_dict_t *dict)
 * {
 * 	size_t              len;
 * 	size_t              i;
 * 	M_hash_dict_enum_t *hashenum;
 *
 * 	len = M_hash_dict_enumerate(dict, &hashenum);
 * 	for (i = 0; i < len; i++) {
 * 		const char *key;
 * 		const char *value;
 * 		M_hash_dict_enumerate_next(dict, hashenum, &key, &value);
 * 		M_printf("%s: %s\n", key, value);
 * 	}
 * 	M_hash_dict_enumerate_free(hashenum);
 * }
 *
 * static void print_stream(M_http2_stream_t *stream)
 * {
 * 	M_printf("[Request headers]\n");
 * 	print_headers(stream->request);
 * 	M_printf("[Response headers]\n");
 * 	print_headers(stream->response);
 * 	M_printf("[Data]\n");
 * 	M_printf("%.*s\n", (int)M_parser_len(stream->data), M_parser_peek(stream->data));
 * }
 *
 * static void process_cb(M_event_t *el, M_event_type_t evtype, M_io_t *io, void *thunk)
 * {
 * 	char             *application = NULL;
 * 	M_http2_stream_t *stream      = NULL;
 * 	M_http2_t        *ht          = thunk;
 * 	char              errmsg[256] = { 0 };
 *
 * 	switch (evtype) {
 * 		case M_EVENT_TYPE_CONNECTED:
 * 			application = M_tls_get_application(io, args.tls_layer_idx);
 * 			M_printf("CONNECTED to %s with application: %s\n", args.hostname, application);
 * 			M_free(application);
 * 			break;
 * 		case M_EVENT_TYPE_READ:
 * 			stream = M_http2_stream_take_by_id(ht, args.stream_id);
 * 			if (stream == NULL)
 * 				return;
 * 			print_stream(stream);
 * 			M_http2_stream_destroy(stream);
 * 			M_io_disconnect(args.io);
 * 			break;
 * 		case M_EVENT_TYPE_DISCONNECTED:
 * 			M_io_destroy(args.io);
 * 			args.io = NULL;
 * 			M_event_done(el);
 * 			break;
 * 		case M_EVENT_TYPE_ERROR:
 * 			M_io_get_error_string(args.io, errmsg, sizeof(errmsg));
 * 			M_printf("Error: %s: %s\n", M_io_error_string(M_io_get_error(args.io)), errmsg);
 * 			M_event_done_with_disconnect(el, 0, 1000);
 * 			break;
 * 		default:
 * 			break;
 * 	}
 * }
 *
 * int main(int argc, char **argv)
 * {
 * 	M_event_t         *el      = M_event_create(M_EVENT_FLAG_NONE);
 * 	M_dns_t           *dns     = M_dns_create(el);
 * 	M_http2_t         *ht      = M_http2_client_create(args.scheme, args.hostname);
 * 	M_tls_clientctx_t *ctx     = M_tls_clientctx_create();
 * 	M_list_str_t      *applist = M_list_str_create(M_LIST_STR_NONE);
 *
 * 	M_http2_client_push_promise_mode(ht, M_HTTP2_PUSH_PROMISE_MODE_IGNORE);
 * 	M_io_net_client_create(&args.io, dns, args.hostname, args.port, M_IO_NET_ANY);
 *
 * 	M_list_str_insert(applist, "h2");
 * 	M_tls_clientctx_set_default_trust(ctx);
 * 	M_tls_clientctx_set_applications(ctx, applist);
 *
 * 	M_io_tls_client_add(args.io, ctx, args.hostname, &args.tls_layer_idx);
 * 	M_io_http2_add(args.io, ht, NULL);
 *
 * 	args.stream_id = M_http2_client_request(ht, M_HTTP2_REQUEST_GET, args.path);
 *
 * 	M_event_add(el, args.io, process_cb, ht);
 * 	M_event_loop(el, M_TIMEOUT_INF);
 *
 * 	M_io_destroy(args.io);
 * 	M_list_str_destroy(applist);
 * 	M_tls_clientctx_destroy(ctx);
 * 	M_http2_destroy(ht);
 * 	M_dns_destroy(dns);
 * 	M_event_destroy(el);
 *
 * 	return 0;
 *}
 * \endcode
 *
 * @{
 */

struct M_http2_t;
typedef struct M_http2_t M_http2_t;

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/*! */
typedef enum {
	M_HTTP2_REQUEST_GET = 1, /*!< Retrieve URI with ":method" "GET". Similar to HTTP/1.1 GET. */
} M_http2_request_t;

/*! */
typedef enum {
	M_HTTP2_PUSH_PROMISE_MODE_IGNORE = 1, /*!< RST_STREAM and ignore PUSH_PROMISE from server. */
	M_HTTP2_PUSH_PROMISE_MODE_KEEP,       /*!< Treat a PUSH_PROMISE like a client request. */
} M_http2_push_promise_mode_t;

/*! */
typedef struct {
	M_uint32       id;       /*!< Stream id */
	M_parser_t    *data;     /*!< Full content of data stream */
	M_hash_dict_t *request;  /*!< Request headers */
	M_hash_dict_t *response; /*!< Response headers */
} M_http2_stream_t;

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/*! Create a HTTP2 client object
 *
 * \param[in] scheme most often "https".
 * \param[in] authority for example "nghttp2.org".
 *
 * \return newly created http2 object
 */
M_API M_http2_t *M_http2_client_create(const char *scheme, const char *authority);

/*! Destroy a HTTP2 object
 *
 * \param[in] ht object
 */
M_API void M_http2_destroy(M_http2_t *ht);

/*! Request resource
 *
 * \param[in] ht
 * \param[in] reqtype for example M_HTTP2_REQUEST_GET, for "GET"
 * \param[in] path for example "/".
 *
 * \return newly created http2 object
 */
M_API M_uint32 M_http2_client_request(M_http2_t *ht, M_http2_request_t reqtype, const char *path);

/*! Change handling of PUSH_PROMISE frames
 *
 * \param[in] ht
 * \param[in] mode
 */
M_API void M_http2_client_push_promise_mode(M_http2_t *ht, M_http2_push_promise_mode_t mode);

/*! Take completed stream object identified by stream_id
 * Internal reference is removed caller is responsible for destroying
 * \see M_http2_stream_destroy()
 *
 * \param[in] ht
 * \param[in] stream_id
 *
 * \return stream object or NULL if it doesn't exist
 */
M_API M_http2_stream_t *M_http2_stream_take_by_id(M_http2_t *ht, M_int32 stream_id);

/*! Destroy stream object
 *
 * \param[in] stream object to destroy
 */
M_API void M_http2_stream_destroy(M_http2_stream_t *stream);

/*! Add http2 layer to io
 *
 * \param[in] io M_io_t to add HTTP2 support to
 * \param[in] ht HTTP2 object
 * \param[out] layer_id the assigned layer_idx
 *
 * \return result
 */
M_io_error_t      M_io_http2_add(M_io_t *io, M_http2_t *ht, size_t *layer_id);

/*! @} */

__END_DECLS

#endif /* __M_HTTP_H__ */

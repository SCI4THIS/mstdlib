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

#include "m_flow.h"

typedef enum {
	STATE_CONNECTING = 1,
	STATE_OPENING_RESPONSE,
	STATE_EHLO,
	STATE_STARTTLS,
	STATE_AUTH,
	STATE_SENDMSG,
	STATE_QUIT,
	STATE_QUIT_ACK,
	STATE_DISCONNECTING,
} m_state_ids;

static M_state_machine_status_t M_state_connecting(void *data, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot = data;

	if ((slot->connection_mask & M_NET_SMTP_CONNECTION_MASK_IO) != 0u) {
		*next = STATE_OPENING_RESPONSE;
		return M_STATE_MACHINE_STATUS_NEXT;
	}
	return M_STATE_MACHINE_STATUS_WAIT;
}

static M_state_machine_status_t M_opening_response_post_cb(void *data, M_state_machine_status_t sub_status,
		M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot           = data;
	M_state_machine_status_t    machine_status = M_STATE_MACHINE_STATUS_ERROR_STATE;

	if (sub_status == M_STATE_MACHINE_STATUS_ERROR_STATE)
		goto done;

	if (slot->smtp_response_code != 220) {
		const char *line = M_list_str_last(slot->smtp_response);
		/* Classify as connect failure so endpoint can get removed */
		slot->is_connect_fail = M_TRUE;
		slot->net_error = M_NET_ERROR_PROTOFORMAT;
		M_snprintf(slot->errmsg, sizeof(slot->errmsg), "Expected 220 opening statement, got: %s", line);
		goto done;
	}

	if (!M_str_caseeq(slot->address, "localhost")) {
		const char *first_line = M_list_str_at(slot->smtp_response, 0);
		if (M_str_casecmpsort_max(slot->address, &first_line[4], slot->str_len_address) != 0) {
			M_snprintf(slot->errmsg, sizeof(slot->errmsg), "Domain mismatch \"%s\" != \"%s\"", slot->address, &first_line[4]);
			goto done;
		}
	}
	*next = STATE_EHLO;
	machine_status = M_STATE_MACHINE_STATUS_NEXT;

done:
	return M_net_smtp_flow_tcp_smtp_response_post_cb(data, machine_status, NULL);
}

static M_bool M_ehlo_pre_cb(void *data, M_state_machine_status_t *status, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot    = data;
	const char                 *address = NULL;
	const char                 *domain  = NULL;
	(void)status;
	(void)next;

	if (!M_email_from(slot->email, NULL, NULL, &address)) {
		return M_FALSE;
	}

	if (
		address == NULL                                ||
		(domain = M_str_chr(address, '@')) == NULL     ||
		(domain = &domain[1]) == NULL                  ||
		(slot->ehlo_domain = M_strdup(domain)) == NULL
	) {
		return M_FALSE;
	}

	return M_TRUE;
}

static M_state_machine_status_t M_ehlo_post_cb(void *data, M_state_machine_status_t sub_status, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot = data;

	M_free(slot->ehlo_domain);
	slot->ehlo_domain = NULL;

	if (sub_status == M_STATE_MACHINE_STATUS_ERROR_STATE)
		return sub_status;

	switch(slot->tls_state) {
		case M_NET_SMTP_TLS_NONE:
		case M_NET_SMTP_TLS_CONNECTED:
			*next = STATE_AUTH;
			break;
		case M_NET_SMTP_TLS_STARTTLS:
			if (slot->is_starttls_capable) {
				*next = STATE_STARTTLS;
				break;
			}
			/* Classify as connect failure so endpoint can get removed */
			slot->is_connect_fail = M_TRUE;
			slot->net_error = M_NET_ERROR_NOTPERM;
			M_snprintf(slot->errmsg, sizeof(slot->errmsg), "Server does not support STARTTLS");
			return M_STATE_MACHINE_STATUS_ERROR_STATE;
			break;
		case M_NET_SMTP_TLS_IMPLICIT:
		case M_NET_SMTP_TLS_STARTTLS_READY:
		case M_NET_SMTP_TLS_STARTTLS_ADDED:
			M_snprintf(slot->errmsg, sizeof(slot->errmsg), "Invalid TLS state.");
			return M_STATE_MACHINE_STATUS_ERROR_STATE;
			break;
	}
	return M_STATE_MACHINE_STATUS_NEXT;
}

static M_state_machine_status_t M_starttls_post_cb(void *data, M_state_machine_status_t sub_status, M_uint64 *next)
{
	(void)data;

	if (sub_status == M_STATE_MACHINE_STATUS_ERROR_STATE)
		return sub_status;

	*next = STATE_EHLO;
	return M_STATE_MACHINE_STATUS_NEXT;
}

static M_state_machine_status_t M_auth_post_cb(void *data, M_state_machine_status_t sub_status, M_uint64 *next)
{
	(void)data;

	if (sub_status == M_STATE_MACHINE_STATUS_ERROR_STATE)
		return sub_status;

	*next = STATE_SENDMSG;
	return M_STATE_MACHINE_STATUS_NEXT;
}

static M_bool M_sendmsg_pre_cb(void *data, M_state_machine_status_t *status, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot = data;
	(void)status;
	(void)next;

	slot->rcpt_i = 0;
	slot->rcpt_n = M_email_to_len(slot->email) + M_email_cc_len(slot->email) + M_email_bcc_len(slot->email);
	return M_TRUE;
}

static M_state_machine_status_t M_sendmsg_post_cb(void *data, M_state_machine_status_t sub_status, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot       = data;

	if (sub_status == M_STATE_MACHINE_STATUS_ERROR_STATE)
		return sub_status;

	slot->is_failure = M_FALSE; /* Success */

	*next = STATE_QUIT;
	return M_STATE_MACHINE_STATUS_NEXT;
}

static M_state_machine_status_t M_state_quit(void *data, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot = data;

	M_bprintf(slot->out_buf, "QUIT\r\n");
	*next = STATE_QUIT_ACK;
	return M_STATE_MACHINE_STATUS_NEXT;
}

static M_state_machine_status_t M_state_quit_ack(void *data, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot = data;

/* Although RFC 5321 calls for a 221 reply, if they don't send one we need to move on,
	* regardless of how upset John Klensin may get. */

	if (M_parser_consume_until(slot->in_parser, (const unsigned char *)"\r\n", 2, M_TRUE)) {
		*next = STATE_DISCONNECTING;
		return M_STATE_MACHINE_STATUS_NEXT;
	}
	return M_STATE_MACHINE_STATUS_WAIT;
}

static M_state_machine_status_t M_state_disconnecting(void *data, M_uint64 *next)
{
	M_net_smtp_endpoint_slot_t *slot      = data;
	(void)next;

	if ((slot->connection_mask & M_NET_SMTP_CONNECTION_MASK_IO) != 0u) {
		return M_STATE_MACHINE_STATUS_WAIT;
	}
	return M_STATE_MACHINE_STATUS_DONE;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

M_state_machine_t * M_net_smtp_flow_tcp()
{
	M_state_machine_t *m      = NULL;
	M_state_machine_t *sub_m  = NULL;

	m = M_state_machine_create(0, "SMTP-flow-tcp", M_STATE_MACHINE_NONE);
	M_state_machine_insert_state(m, STATE_CONNECTING, 0, NULL, M_state_connecting, NULL, NULL);

	sub_m = M_net_smtp_flow_tcp_smtp_response();
	M_state_machine_insert_sub_state_machine(m, STATE_OPENING_RESPONSE, 0, NULL, sub_m,
			M_net_smtp_flow_tcp_smtp_response_pre_cb, M_opening_response_post_cb, NULL, NULL);
	M_state_machine_destroy(sub_m);

	sub_m = M_net_smtp_flow_tcp_starttls();
	M_state_machine_insert_sub_state_machine(m, STATE_STARTTLS, 0, NULL, sub_m,
			NULL, M_starttls_post_cb, NULL, NULL);
	M_state_machine_destroy(sub_m);

	sub_m = M_net_smtp_flow_tcp_ehlo();
	M_state_machine_insert_sub_state_machine(m, STATE_EHLO, 0, NULL, sub_m,
			M_ehlo_pre_cb, M_ehlo_post_cb, NULL, NULL);
	M_state_machine_destroy(sub_m);

	sub_m = M_net_smtp_flow_tcp_auth();
	M_state_machine_insert_sub_state_machine(m, STATE_AUTH, 0, NULL, sub_m,
			NULL, M_auth_post_cb, NULL, NULL);
	M_state_machine_destroy(sub_m);

	sub_m = M_net_smtp_flow_tcp_sendmsg();
	M_state_machine_insert_sub_state_machine(m, STATE_SENDMSG, 0, NULL, sub_m,
			M_sendmsg_pre_cb, M_sendmsg_post_cb, NULL, NULL);
	M_state_machine_destroy(sub_m);

	M_state_machine_insert_state(m, STATE_QUIT, 0, NULL, M_state_quit, NULL, NULL);

	M_state_machine_insert_state(m, STATE_QUIT_ACK, 0, NULL, M_state_quit_ack, NULL, NULL);

	M_state_machine_insert_state(m, STATE_DISCONNECTING, 0, NULL, M_state_disconnecting, NULL, NULL);
	return m;
}

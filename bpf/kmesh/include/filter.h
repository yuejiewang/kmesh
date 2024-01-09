/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: nlgwcy
 * Create: 2022-02-14
 */
#ifndef __KMESH_FILTER_H__
#define __KMESH_FILTER_H__

#include "cluster.h"
#include "tcp_proxy.h"
#include "tail_call.h"
#include "bpf_log.h"
#include "kmesh_common.h"
#include "listener/listener.pb-c.h"
#include "filter/tcp_proxy.pb-c.h"
#include "filter/http_connection_manager.pb-c.h"

static inline int filter_match_check(const Listener__Filter *filter, const address_t *addr, const ctx_buff_t *ctx)
{
	int match = 0;
	switch (filter->config_type_case) {
		case LISTENER__FILTER__CONFIG_TYPE_HTTP_CONNECTION_MANAGER:
			match = 1;
			break;
		case LISTENER__FILTER__CONFIG_TYPE_TCP_PROXY:
			match = 1;
			break;
		default:
			break;
	}
	return match;
}

static inline int filter_chain_filter_match(const Listener__FilterChain *filter_chain,
											 const address_t *addr,
											 const ctx_buff_t *ctx,
											 Listener__Filter **filter_ptr,
											 __u64 *filter_ptr_idx)
{
	void *ptrs = NULL;
	Listener__Filter *filter = NULL;

	if (!filter_ptr || !filter_ptr_idx) {
		BPF_LOG(ERR, FILTERCHAIN, "invalid params\n");
		return -1;
	}

	if (filter_chain->n_filters == 0 || filter_chain->n_filters > KMESH_PER_FILTER_NUM) {
		BPF_LOG(ERR, FILTERCHAIN, "nfilter num(%d) invalid\n", filter_chain->n_filters);
		return -1;
	}
	
	/* filter match */
	ptrs = kmesh_get_ptr_val(filter_chain->filters);
	if (!ptrs) {
		BPF_LOG(ERR, FILTER, "failed to get filter ptrs\n");
		return -1;
	}

	/* limit loop cap to pass bpf verify */
	#pragma unroll
	for (unsigned int i = 0; i < KMESH_PER_FILTER_NUM; i++) {
		if (i >= filter_chain->n_filters) {
			break;
		}

		filter = (Listener__Filter *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!filter) {
			continue;
		}

		// FIXME: repeat on filter_manager
		if (filter_match_check(filter, addr, ctx)) {
			*filter_ptr = filter;
			*filter_ptr_idx = (__u64)*((__u64 *)ptrs + i);
			return 0;
		}
	}
	return -1;
}

static inline int handle_http_connection_manager(
		const Filter__HttpConnectionManager *http_conn, const address_t *addr,
		ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	int ret;
	char *route_name = NULL;
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};

	route_name = kmesh_get_ptr_val((http_conn->route_config_name));
	if (!route_name) {
		BPF_LOG(ERR, FILTER, "failed to get http conn route name\n");
		return -1;
	}

	KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_ROUTER_CONFIG, *addr);
	KMESH_TAIL_CALL_CTX_VALSTR(ctx_val, msg, route_name);

	KMESH_TAIL_CALL_WITH_CTX(KMESH_TAIL_CALL_ROUTER_CONFIG, ctx_key, ctx_val);
	return KMESH_TAIL_CALL_RET(ret);
}

SEC_TAIL(KMESH_PORG_CALLS, KMESH_TAIL_CALL_FILTER)
int filter_manager(ctx_buff_t *ctx)
{
	int ret = 0;
	ctx_key_t ctx_key = {0};
	ctx_val_t *ctx_val = NULL;
	Listener__Filter *filter = NULL;
	Filter__HttpConnectionManager *http_conn = NULL;
	Filter__TcpProxy *tcp_proxy = NULL;

	DECLARE_VAR_ADDRESS(ctx, addr);
	KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_FILTER, addr);
	ctx_val = kmesh_tail_lookup_ctx(&ctx_key);
	if (!ctx_val) {
		BPF_LOG(ERR, FILTER, "failed to lookup tail call val\n");
		return KMESH_TAIL_CALL_RET(-1);
	}

	filter = (Listener__Filter *)kmesh_get_ptr_val((void *)ctx_val->val);
	if (!filter) {
		BPF_LOG(ERR, FILTER, "failed to get filter\n");
		return KMESH_TAIL_CALL_RET(-1);
	}
	kmesh_tail_delete_ctx(&ctx_key);

	switch (filter->config_type_case) {
#ifndef CGROUP_SOCK_MANAGE
		case LISTENER__FILTER__CONFIG_TYPE_HTTP_CONNECTION_MANAGER:
			/* match and handle MAGIC string */
			
			ret = bpf_parse_header_msg(ctx_val->msg);

			if (GET_RET_PROTO_TYPE(ret) == PROTO_HTTP_1_1) {
				http_conn = kmesh_get_ptr_val(filter->http_connection_manager);
				
				if (!http_conn) {
					BPF_LOG(ERR, FILTER, "get http_conn failed\n");
					ret = -1;
					break;
				}
				ret = handle_http_connection_manager(http_conn, &addr, ctx, ctx_val->msg);
			} else if (GET_RET_PROTO_TYPE(ret) == PROTO_HTTP_2_0) {
				char key_type[6] = {'_', 'T', 'Y', 'P', 'E', '\0'};
				struct bpf_mem_ptr *frame_type_ptr = NULL;
				unsigned char frame_type;
				frame_type_ptr = (struct bpf_mem_ptr *)bpf_get_msg_header_element(key_type);
				frame_type = *(unsigned char *)(frame_type_ptr->ptr);

				switch (frame_type) {
				case 0:  /* DATA frame */
					BPF_LOG(DEBUG, FILTER, "http2.0 recv data frame");
					Core__SocketAddress *sock_addr = NULL;
					char key_id[11] = {'_', 'S', 'T', 'R', 'E', 'A', 'M', '_', 'I', 'D', '\0'};
					struct bpf_mem_ptr *stream_id_ptr = NULL;
					unsigned int stream_id;
					stream_id_ptr = (struct bpf_mem_ptr *)bpf_get_msg_header_element(key_id);
					if (!stream_id_ptr) {
						BPF_LOG(ERR, FILTER, "http2.0 data frame get stream_id failed\n");
						ret = -1;
						break;
					}
					stream_id = *(unsigned int *)(stream_id_ptr->ptr);
					sock_addr = kmesh_map_lookup_elem(&map_of_id2ep, (void *)&stream_id);
					if (!sock_addr) {
						BPF_LOG(ERR, FILTER, "http2.0 data frame get sock addr failed\n");
						ret = -EAGAIN;
						break;
					}

					BPF_LOG(INFO, FILTER, "loadbalance to addr=[%u:%u]\n",
							sock_addr->ipv4, sock_addr->port);
					SET_CTX_ADDRESS(ctx, sock_addr);

					break;
				
				case 1:  /* HEADERS frame */
					BPF_LOG(DEBUG, FILTER, "http2.0 recv headers frame");

					http_conn = kmesh_get_ptr_val(filter->http_connection_manager);

					if (!http_conn) {
						BPF_LOG(ERR, FILTER, "get http_conn failed\n");
						ret = -1;
						break;
					}
					ret = handle_http_connection_manager(http_conn, &addr, ctx, ctx_val->msg);

					break;
				
				default: /* control frames */
					BPF_LOG(DEBUG, FILTER, "http2.0 receive control frame");
					break;
				}
			} else {
				BPF_LOG(DEBUG, FILTER, "http filter manager, only support http1.1/http2.0 this version");
				break;
			}
			
			break;
#endif
		case LISTENER__FILTER__CONFIG_TYPE_TCP_PROXY:
			tcp_proxy = kmesh_get_ptr_val(filter->tcp_proxy);
			if (!tcp_proxy) {
				BPF_LOG(ERR, FILTER, "get tcp_prxoy failed\n");
				ret = -1;
				break;
			}
			ret = tcp_proxy_manager(tcp_proxy, ctx);
			break;
		default:
			break;
	}
	return KMESH_TAIL_CALL_RET(ret);
}

SEC_TAIL(KMESH_PORG_CALLS, KMESH_TAIL_CALL_FILTER_CHAIN)
int filter_chain_manager(ctx_buff_t *ctx)
{
	int ret = 0;
	__u64 filter_idx = 0;
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};
	ctx_val_t *ctx_val_ptr = NULL;
	Listener__FilterChain *filter_chain = NULL;
	Listener__Filter *filter = NULL;

	DECLARE_VAR_ADDRESS(ctx, addr);

	KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_FILTER_CHAIN, addr);
	ctx_val_ptr = kmesh_tail_lookup_ctx(&ctx_key);
	if (!ctx_val_ptr) {
		BPF_LOG(ERR, FILTERCHAIN, "failed to lookup tail ctx\n");
		return KMESH_TAIL_CALL_RET(-1);
	}
	kmesh_tail_delete_ctx(&ctx_key);

	filter_chain = (Listener__FilterChain *)kmesh_get_ptr_val((void *)ctx_val_ptr->val);
	if (filter_chain == NULL) {
		return KMESH_TAIL_CALL_RET(-1);
	}
	/* filter match */
	ret = filter_chain_filter_match(filter_chain, &addr, ctx, &filter, &filter_idx);
	if (ret != 0) {
		BPF_LOG(ERR, FILTERCHAIN, "no match filter, addr=%u\n", addr.ipv4);
		return KMESH_TAIL_CALL_RET(-1);
	}

	// FIXME: when filter_manager unsuccessful,
	// we should skip back and handle next filter, rather than exit.

	KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_FILTER, addr);
	KMESH_TAIL_CALL_CTX_VAL(ctx_val, ctx_val_ptr->msg, filter_idx);

	KMESH_TAIL_CALL_WITH_CTX(KMESH_TAIL_CALL_FILTER, ctx_key, ctx_val);
	return KMESH_TAIL_CALL_RET(ret);
}


#endif

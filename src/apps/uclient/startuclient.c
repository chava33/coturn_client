/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <unistd.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "startuclient.h"
#include "ns_turn_msg.h"
#include "uclient.h"
#include "session.h"

#include <openssl/err.h>

/////////////////////////////////////////

#define MAX_CONNECT_EFFORTS (77)
#define DTLS_MAX_CONNECT_TIMEOUT (30)
#define MAX_TLS_CYCLES (32)
#define EXTRA_CREATE_PERMS (25)

static uint64_t current_reservation_token = 0;
//static int allocate_rtcp = 0;
static const int never_allocate_rtcp = 0;

#if ALPN_SUPPORTED
static const unsigned char kALPNProtos[] = "\x08http/1.1\x09stun.turn\x12stun.nat-discovery";
static const size_t kALPNProtosLen = sizeof(kALPNProtos) - 1;
#endif

int clnet_connect(uint16_t clnet_remote_port, const char *remote_address,
		const unsigned char* ifname, const char *local_address, app_ur_conn_info *clnet_info)
{
	ioa_addr local_addr;
	evutil_socket_t clnet_fd = -1;
	int connect_err = 0;
	ioa_addr remote_addr;

	ns_bzero(&remote_addr, sizeof(ioa_addr));
	if (make_ioa_addr((const u08bits*) remote_address, clnet_remote_port,
			&remote_addr) < 0)
		return -1;

	ns_bzero(&local_addr, sizeof(ioa_addr));

	clnet_fd = socket(remote_addr.ss.sa_family, CLIENT_STREAM_SOCKET_TYPE, CLIENT_STREAM_SOCKET_PROTOCOL);
	if (clnet_fd < 0) {
		perror("socket");
		exit(-1);
	}

	if (sock_bind_to_device(clnet_fd, ifname) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"Cannot bind client socket to device %s\n", ifname);
	}

	set_sock_buf_size(clnet_fd, UR_CLIENT_SOCK_BUF_SIZE);
	set_raw_socket_tos(clnet_fd, remote_addr.ss.sa_family, 0x22);
	set_raw_socket_ttl(clnet_fd, remote_addr.ss.sa_family, 47);
    if (addr_connect(clnet_fd, &remote_addr, &connect_err) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot connect to remote addr: %d\n", __FUNCTION__, connect_err);
        return -1;
    }

    addr_cpy(&(clnet_info->remote_addr), &remote_addr);
    addr_cpy(&(clnet_info->local_addr), &local_addr);
    clnet_info->fd = clnet_fd;
    addr_get_from_sock(clnet_fd, &(clnet_info->local_addr));
    STRCPY(clnet_info->lsaddr,local_address);
    STRCPY(clnet_info->rsaddr,remote_address);
    STRCPY(clnet_info->ifname,(const char*)ifname);

    addr_debug_print(1, &(clnet_info->local_addr), "Connected from");
    addr_debug_print(1, &remote_addr, "Connected to");

	usleep(500);
	return 0;
}

int clnet_allocate(app_ur_conn_info *clnet_info, ioa_addr *relay_addr, int af, char *turn_addr, u16bits *turn_port)
{
    int len;
    int af4 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4);
    int af6 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6);
	stun_buffer request_message, response_message;

    stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME, af4, af6, relay_transport, mobility, NULL, -1);
    stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));
    if ((len = send_buffer(clnet_info, &request_message, 0, 0)) < 0) {
        perror("send_buffer");
        return -1;
    }

    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "allocate sent\n");
    if ((len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message)) < 0) {
        perror("recv_buffer");
        return -1;
    }

    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "allocate response received: \n");
    response_message.len = len;
    if (!stun_is_success_response(&response_message)) {
        perror("clnet_allocate");
        return -1;
    }

    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
    stun_attr_ref sar = stun_attr_get_first(&response_message);
    if (stun_attr_get_addr(&response_message, sar, relay_addr, NULL) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: !!!: relay addr cannot be received (1)\n", __FUNCTION__);
        return -1;
    }

    char addrbuf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &relay_addr->s4.sin_addr, addrbuf, INET6_ADDRSTRLEN);
    int port = nswap16(relay_addr->s4.sin_port);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IPv4. Received relay addr %s:%d\n", addrbuf, port);
    addr_cpy(&(clnet_info->relay_addr), relay_addr);

    stun_attr_ref rt_sar = stun_attr_get_first_by_type( &response_message, STUN_ATTRIBUTE_RESERVATION_TOKEN);
    uint64_t rtv = stun_attr_get_reservation_token_value(rt_sar);
    current_reservation_token = rtv;
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: rtv=%llu\n", __FUNCTION__, (long long unsigned int)rtv);

	return 0;
}

int turn_create_permission(app_ur_conn_info *clnet_info, ioa_addr *peer_addr, int addrnum)
{
	if(no_permissions || (addrnum<1))
		return 0;

	char saddr[129]="\0";
    addr_to_string(peer_addr,(u08bits*)saddr);
	stun_buffer request_message, response_message;
	{
		int cp_sent = 0;
		stun_init_request(STUN_METHOD_CREATE_PERMISSION, &request_message);
		{
			int addrindex;
			for(addrindex=0;addrindex<addrnum;++addrindex) {
				stun_attr_add_addr(&request_message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr+addrindex);
			}
		}

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));
		while (!cp_sent) {
			int len = send_buffer(clnet_info, &request_message, 0,0);
			if (len <= 0) {
				perror("send");
				exit(1);
            }

            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "create perm sent: %s\n",saddr);
            cp_sent = 1;
		}
	}

	////////////<<==create permission send
	////////create permission response==>>

	{
		int cp_received = 0;
		while (!cp_received) {
			int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);
            if (len <= 0) {
				perror("recv");
				exit(-1);
            }

            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "cp response received: \n");
            if (stun_is_success_response(&response_message)) {
                cp_received = 1;
                TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
            } else {
                TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown create permission response\n");
                /* Try again ? */
            }
		}
	}

	return 0;
}

int start_c2c_connection
(
    uint16_t clnet_remote_port0,
    const char *remote_address0,
    const unsigned char* ifname,
    const char *local_address,
    app_ur_conn_info *clnet_info_probe,
    app_ur_conn_info *clnet_info1,
    uint16_t *chn1,
    app_ur_conn_info *clnet_info1_rtcp,
    uint16_t *chn1_rtcp,
    app_ur_conn_info *clnet_info2,
    uint16_t *chn2,
    app_ur_conn_info *clnet_info2_rtcp,
    uint16_t *chn2_rtcp
) {

	ioa_addr relay_addr1;
	ioa_addr relay_addr2;

	uint16_t clnet_remote_port = clnet_remote_port0;
	char remote_address[1025];
	STRCPY(remote_address,remote_address0);

	/* Real: */
    /* hit2 */

	if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, clnet_info1) < 0) {
		exit(-1);
	}

	if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address, clnet_info2) < 0) {
		exit(-1);
	}

	if (clnet_allocate(clnet_info1, &relay_addr1, default_address_family, NULL, NULL) < 0) {
	    exit(-1);
    }

    if (clnet_allocate(clnet_info2, &relay_addr2, default_address_family, NULL, NULL) < 0) {
          exit(-1);
    }

    if (turn_create_permission(clnet_info1, &relay_addr2, 1) < 0) {
        exit(-1);
    }

    if (turn_create_permission(clnet_info2, &relay_addr1, 1) < 0) {
        exit(-1);
    }

	addr_cpy(&(clnet_info1->peer_addr), &relay_addr2);
	addr_cpy(&(clnet_info2->peer_addr), &relay_addr1);

	return 0;
}

//////////// RFC 6062 ///////////////

int turn_tcp_connect(app_ur_conn_info *clnet_info, ioa_addr *peer_addr) {
    int cp_sent = 0;

    stun_buffer message;

    stun_init_request(STUN_METHOD_CONNECT, &message);
    stun_attr_add_addr(&message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr);

    stun_attr_add_fingerprint_str(message.buf,(size_t*)&(message.len));
    while (!cp_sent) {
        int len = send_buffer(clnet_info, &message, 0,0);
        if (len <= 0) {
            perror("send");
            exit(1);
        }

        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "tcp connect sent\n");
        cp_sent = 1;
    }

	return 0;
}

static int turn_tcp_connection_bind(app_ur_conn_info *clnet_info, app_tcp_conn_info *atc)
{
	stun_buffer request_message, response_message;
	{
		int cb_sent = 0;
		u32bits cid = atc->cid;
		stun_init_request(STUN_METHOD_CONNECTION_BIND, &request_message);
		stun_attr_add(&request_message, STUN_ATTRIBUTE_CONNECTION_ID, (const s08bits*)&cid,4);
		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));
		while (!cb_sent) {
			int len = send_buffer(clnet_info, &request_message, 1, atc);
			if (len <= 0) {
				perror("send");
				exit(1);
            }

            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "connection bind sent\n");
            cb_sent = 1;
		}
	}

	////////////<<==connection bind send
	////////connection bind response==>>
	{
		int cb_received = 0;
		while (!cb_received) {
			int len = recv_buffer(clnet_info, &response_message, 1, 1, atc, &request_message);
            if (len <= 0) {
				perror("recv");
				exit(-1);
            }

            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "connect bind response received: \n");
            if (stun_is_success_response(&response_message)) {
                if(stun_get_method(&response_message) != STUN_METHOD_CONNECTION_BIND)
                    continue;

                cb_received = 1;
                TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
                atc->tcp_data_bound = 1;
            } else {
                TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown connection bind response\n");
                /* Try again ? */
            }
		}
	}

	return 0;
}

void tcp_data_connect(app_ur_session *elem, u32bits cid)
{
	int clnet_fd;

	clnet_fd = socket(elem->pinfo.remote_addr.ss.sa_family, CLIENT_STREAM_SOCKET_TYPE, CLIENT_STREAM_SOCKET_PROTOCOL);
	if (clnet_fd < 0) {
		perror("socket");
		exit(-1);
	}

	if (sock_bind_to_device(clnet_fd, client_ifname) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"Cannot bind client socket to device %s\n", client_ifname);
	}
	set_sock_buf_size(clnet_fd, (UR_CLIENT_SOCK_BUF_SIZE<<2));

	++elem->pinfo.tcp_conn_number;
	int i = (int)(elem->pinfo.tcp_conn_number-1);
	elem->pinfo.tcp_conn=(app_tcp_conn_info**)turn_realloc(elem->pinfo.tcp_conn,0,elem->pinfo.tcp_conn_number*sizeof(app_tcp_conn_info*));
	elem->pinfo.tcp_conn[i]=(app_tcp_conn_info*)turn_malloc(sizeof(app_tcp_conn_info));
	ns_bzero(elem->pinfo.tcp_conn[i],sizeof(app_tcp_conn_info));

	elem->pinfo.tcp_conn[i]->tcp_data_fd = clnet_fd;
	elem->pinfo.tcp_conn[i]->cid = cid;

	addr_cpy(&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr), &(elem->pinfo.local_addr));
	addr_set_port(&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr), 0);
	addr_bind(clnet_fd, &(elem->pinfo.tcp_conn[i]->tcp_data_local_addr), 1, 1, TCP_SOCKET);
	addr_get_from_sock(clnet_fd,&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr));

    int err;
    if (addr_connect(clnet_fd, &(elem->pinfo.remote_addr), &err) < 0) {
        perror("tcp_data_connect");
	}

	if (turn_tcp_connection_bind(&(elem->pinfo), elem->pinfo.tcp_conn[i]) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot BIND to tcp connection\n", __FUNCTION__);
        return;
	}

    socket_set_nonblocking(clnet_fd);
    addr_debug_print(clnet_verbose, &(elem->pinfo.remote_addr), "TCP data network connected to");
}




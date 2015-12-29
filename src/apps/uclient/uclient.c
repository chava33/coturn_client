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

#include "apputils.h"
#include "uclient.h"
#include "startuclient.h"
#include "ns_turn_utils.h"
#include "session.h"

#include <unistd.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/select.h>

//static int verbose_packets=0;

static size_t current_clients_number = 0;

static u32bits tot_messages=0;
static u32bits tot_send_messages=0;
static u64bits tot_send_bytes = 0;
static u32bits tot_recv_messages=0;
static u64bits tot_recv_bytes = 0;
static u64bits tot_send_dropped = 0;

static int client_write(app_ur_session *elem);
static int client_shutdown(app_ur_session *elem);

static u64bits current_time = 0;
static u64bits current_mstime = 0;

static char buffer_to_send[65536]="\0";

static int total_clients = 0;

/* Patch for unlimited number of clients provided by ucudbm@gmail.com */
#define SLEEP_INTERVAL (234)

#define MAX_LISTENING_CYCLE_NUMBER (7)
#define MAXIMUM(a, b)  ((a) > (b) ? (a) : (b))
#define MINIMUM(a, b)  ((a) < (b) ? (a) : (b))

int RTP_PACKET_INTERVAL = 20;

static inline s64bits time_minus(u64bits t1, u64bits t2) {
	return ( (s64bits)t1 - (s64bits)t2 );
}

static u64bits total_loss = 0;
static u64bits total_jitter = 0;
static u64bits total_latency = 0;

static u64bits min_latency = 0xFFFFFFFF;
static u64bits max_latency = 0;
static u64bits min_jitter = 0xFFFFFFFF;
static u64bits max_jitter = 0;


static int show_statistics = 0;

///////////////////////////////////////////////////////////////////////////////

static void __turn_getMSTime(void) {
  static u64bits start_sec = 0;
  struct timespec tp={0,0};
#if defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, &tp);
#else
  tp.tv_sec = time(NULL);
#endif
  if(!start_sec)
    start_sec = tp.tv_sec;
  if(current_time != (u64bits)((u64bits)(tp.tv_sec)-start_sec))
    show_statistics = 1;
  current_time = (u64bits)((u64bits)(tp.tv_sec)-start_sec);
  current_mstime = (u64bits)((current_time * 1000) + (tp.tv_nsec/1000000));
}

static app_ur_session* init_app_session(app_ur_session *ss)
{
  if(ss) {
    ns_bzero(ss,sizeof(app_ur_session));
    ss->pinfo.fd=-1;
  }
  return ss;
}

static app_ur_session* create_new_ss(void)
{
	++current_clients_number;
	return init_app_session((app_ur_session*) turn_malloc(sizeof(app_ur_session)));
}

static void uc_delete_session_elem_data(app_ur_session* cdi)
{
    EVENT_DEL(cdi->input_ev);
    EVENT_DEL(cdi->input_tcp_data_ev);

    cdi->pinfo.tcp_conn_number = 0;
    cdi->pinfo.tcp_conn = NULL;
    turn_free(cdi->pinfo.tcp_conn, 111);
    socket_closesocket(cdi->pinfo.fd);
    cdi->pinfo.fd = -1;
    current_clients_number--;
}

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer* message, int data_connection, app_tcp_conn_info *atc)
{

	int rc = 0;
	int ret = -1;
	char *buffer = (char*) (message->buf);

	ioa_socket_raw fd = clnet_info->fd;
	if (data_connection) {
	  if (atc) {
	    fd = atc->tcp_data_fd;
	  } else if (is_TCP_relay()){
	    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
			  "trying to send tcp data buffer over unready connection: size=%d\n",(int)(message->len));
	    return -1;
	  }
	}

    size_t left = (size_t) (message->len);
    while (left > 0) {
        do {
            rc = send(fd, buffer, left, 0);
        } while (rc < 0 && ((errno == EINTR) || (errno == ENOBUFS)));
        if (rc > 0) {
            left -= (size_t) rc;
            buffer += rc;
        } else {
            tot_send_dropped+=1;
            break;
        }
    }

    if (left > 0)
        return -1;

    ret = (int) message->len;
	return ret;
}

int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer* message, int sync, int data_connection, app_tcp_conn_info *atc, stun_buffer* request_message)
{
	int rc = 0;
	stun_tid tid;
	if(request_message) {
		stun_tid_from_message(request_message, &tid);
	}

	ioa_socket_raw fd = clnet_info->fd;
	if (atc)
		fd = atc->tcp_data_fd;
    /* Plain TCP */
    do {
        rc = recv(fd, message->buf, sizeof(message->buf) - 1, MSG_PEEK);
        if ((rc < 0) && (errno == EAGAIN) && sync) {
            errno = EINTR;
        }
       // printf("\nReceived message %s\n",message->buf);    
} while (rc < 0 && (errno == EINTR));

    if (rc <= 0)
        return rc;

    int mlen = rc;
    size_t app_msg_len = (size_t) rc;
    if (!atc) {
        mlen = stun_get_message_len_str(message->buf, rc, 1, &app_msg_len);
    } else {
        if (!sync)
            mlen = clmessage_length;

        if (mlen > clmessage_length)
            mlen = clmessage_length;

        app_msg_len = (size_t) mlen;
    }

    int rcr = 0;
    int rsf = 0;
    int cycle = 0;
    while (rsf < mlen && cycle++ < 128) {
        do {
            rcr = recv(fd, message->buf + rsf, (size_t) mlen - (size_t) rsf, 0);
            if (rcr < 0 && errno == EAGAIN && sync)
                errno = EINTR;
        } while (rcr < 0 && (errno == EINTR));

        if (rcr > 0)
            rsf += rcr;

    }
    if (rsf < 1)
        return -1;
    if (rsf < (int) app_msg_len) {
        if ((size_t) (app_msg_len / (size_t) rsf) * ((size_t) (rsf)) != app_msg_len) {
            return -1;
        }
    }
    message->len = app_msg_len;
    rc = app_msg_len;

	return rc;
}

static int client_read(app_ur_session *elem, int is_tcp_data, app_tcp_conn_info *atc)
{

	elem->ctime = current_time;
	app_ur_conn_info *clnet_info = &(elem->pinfo);
	int rc = 0;

	rc = recv_buffer(clnet_info, &(elem->in_buffer), 0, is_tcp_data, atc, NULL);
    if (rc <= 0)
        return rc;

    elem->in_buffer.len = rc;
    const message_info *mi = NULL;
    size_t buffers = 1;
    if (is_tcp_data) {   // If the tcp bind is already there (then only tx and rx, no need to run tcp_data_connect)
        if ((int)elem->in_buffer.len == clmessage_length) {
            mi = (message_info*)(elem->in_buffer.buf);
        }
        if (mi->msgnum != elem->recvmsgnum + 1) {
            ++(elem->loss);
        } else {
            u64bits clatency = (u64bits)time_minus(current_mstime,mi->mstime);
            max_latency = MAXIMUM(clatency, max_latency);
            min_latency = MINIMUM(clatency, min_latency);
            elem->latency += clatency;

            if (elem->rmsgnum > 0) {
                u64bits cjitter = abs((int)(current_mstime-elem->recvtimems)-RTP_PACKET_INTERVAL);
                max_jitter = MAXIMUM(cjitter, max_jitter);
                min_jitter = MINIMUM(cjitter, min_jitter);
                elem->jitter += cjitter;
            }
        }
        elem->recvmsgnum = mi->msgnum;
        elem->rmsgnum += buffers;
        tot_recv_messages += buffers;
        tot_recv_bytes += elem->in_buffer.len;

        elem->recvtimems=current_mstime;
        elem->wait_cycles = 0;

    } else if (stun_is_indication(&(elem->in_buffer))) {
        stun_attr_ref sar = stun_attr_get_first(&(elem->in_buffer));
        u32bits cid = 0;
        while(sar) {
            int attr_type = stun_attr_get_type(sar);
            if (attr_type == STUN_ATTRIBUTE_CONNECTION_ID) {
                cid = *((const u32bits*)stun_attr_get_value(sar));
                break;
            }
            sar = stun_attr_get_next_str(elem->in_buffer.buf,elem->in_buffer.len,sar);
        }

        /* positive test */
        tcp_data_connect(elem, cid);

    } else if (stun_is_success_response(&(elem->in_buffer))) {
        stun_attr_ref sar = stun_attr_get_first(&(elem->in_buffer));
        u32bits cid = 0;
        while (sar) {
            int attr_type = stun_attr_get_type(sar);
            if (attr_type == STUN_ATTRIBUTE_CONNECTION_ID) {
               cid = *((const u32bits*)stun_attr_get_value(sar));
               break;
            }
            sar = stun_attr_get_next_str(elem->in_buffer.buf,elem->in_buffer.len,sar);
        }
        tcp_data_connect(elem, cid);
    } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: Unknown message received of size: %d\n",(int)(elem->in_buffer.len));
    }

	return rc;
}

static int client_shutdown(app_ur_session *elem)
{
  elem->state=UR_STATE_DONE;
  elem->ctime=current_time;
  uc_delete_session_elem_data(elem);
  
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"done, connection 0x%lx closed.\n",(long)elem);
  return 0;
}

static int client_write(app_ur_session *elem)
{

  if(!elem || elem->state!=UR_STATE_READY) return -1;
  elem->ctime = current_time;
  message_info *mi = (message_info*)buffer_to_send;
  //mi->msgnum = elem->wmsgnum;
  //mi->mstime = current_mstime;
  app_tcp_conn_info *atc=NULL;
  
  memcpy(elem->out_buffer.buf, buffer_to_send, clmessage_length);
  elem->out_buffer.len = clmessage_length;
  //elem->out_buffer.len = snprintf((char *)elem->out_buffer.buf, sizeof(elem->out_buffer.buf), "hello") + 1;
  if (!(elem->pinfo.tcp_conn) || !(elem->pinfo.tcp_conn_number)) {
      printf("didnt write any messages\n");
      return -1;
  }
  int i = (unsigned int)(random()) % elem->pinfo.tcp_conn_number;
  atc = elem->pinfo.tcp_conn[i];
  if(!atc->tcp_data_bound) {
      printf("%s: Uninitialized atc: i=%d, atc=0x%lx\n",__FUNCTION__,i,(long)atc);
	  return -1;
  }

  if (elem->out_buffer.len <= 0)
      return 0;
  int rc = send_buffer(&(elem->pinfo), &(elem->out_buffer), 1, atc);
  if (rc < 0)
      return -1;
  elem->wmsgnum++;
  elem->to_send_timems += RTP_PACKET_INTERVAL;
  tot_send_messages++;
  tot_send_bytes += clmessage_length;
  //printf("elem->wmsgnum = %d, bytes = %d\n", elem->wmsgnum, rc);

  return 0;
}

static void client_read_input(app_ur_session* elem)
{
  switch (elem->state) {
  case UR_STATE_READY:
      do {
        app_tcp_conn_info *atc = NULL;
        int is_tcp_data = 0, i, rc;
        for (i = 0; i< (int)elem->pinfo.tcp_conn_number; i++) {
            if (elem->pinfo.tcp_conn[i]->tcp_data_bound) {
                is_tcp_data = 1;
                atc = elem->pinfo.tcp_conn[i];
                break;
            }
        }
        rc = client_read(elem, is_tcp_data, atc);
        //printf("client_read called with is_tcp_data = %d, rc = %d\n", is_tcp_data, rc);

        if (rc <= 0)
            break;

      } while(1);

      break;
  default:
      break;
  }

}

static void set_buffer_to_send(int len, int idx)
{
   
    char buf[400];
	printf("enter message to send\n");
	getchar();
	if (fgets(buf,400,stdin) != NULL)
	{
		//printf("received_chr %s",buf);
//		memcpy(buffer_to_send,buf,sizeof(buf)+1);
		memcpy(buffer_to_send,"GET / HTTP/1.1\r\n\r\n",sizeof("GET / HTTP/1.1\r\n\r\n"));
	}
	
	
	
	
	int n;
	//memset(buffer_to_send, 0, 16);
	
    //n = snprintf(&buffer_to_send, sizeof(buf), "%s %d",buf, idx);
	//printf("n %d\n",n);
	
    /*
        buffer_to_send[16] = 'h';
        buffer_to_send[17] = 'e';
        buffer_to_send[18] = 'l';
        buffer_to_send[19] = 'l';
        buffer_to_send[20] = 'o';
    */
	//memset(&buffer_to_send[16+n+1], 0, len-16);
	//memset(&buffer_to_send[n+1], 0, len-16);
	//printf("buffer_to_send %s",buffer_to_send);

}

static int get_peer_relay(ioa_addr *relay)
{
    int port;
    const char *addrstr = "159.203.11.169";
    char buf[10];
    printf("Enter peer port:");
    fgets(buf, sizeof(buf), stdin);
    sscanf(buf, "%i" , &port);
    printf("peer_relay = %s:%d\n", addrstr, port);
    relay->s4.sin_family = AF_INET;
    relay->s4.sin_port = htons(port);
    inet_pton(AF_INET, addrstr, &relay->s4.sin_addr);
    
    return 0;
}

int socket_connect_another(char *host, in_port_t port){
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, sock;
	//host="localhost";
	if((hp = gethostbyname(host)) == NULL){
		herror("gethostbyname");
		exit(1);
	}
	const char *addrstr = "159.203.11.169";
	inet_pton(AF_INET, host, &addr.sin_addr);

	//bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if(sock == -1){
		perror("setsockopt");
		exit(1);
	}

	if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
		perror("connect");
		exit(1);

	}
	return sock;
}

static int refresh_channel(app_ur_session* elem, u16bits method, uint32_t lt)
{

	stun_buffer message;
	app_ur_conn_info *clnet_info = &(elem->pinfo);

	if(clnet_info->is_peer)
		return 0;

	if (!method || (method == STUN_METHOD_REFRESH)) {
		stun_init_request(STUN_METHOD_REFRESH, &message);
		lt = htonl(lt);
		stun_attr_add(&message, STUN_ATTRIBUTE_LIFETIME, (const char*) &lt, 4);
/*
		if(dual_allocation && !mobility) {
			int t = ((u08bits)random())%3;
			if(t) {
				u08bits field[4];
				field[0] = (t==1) ? (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 : (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
				field[1]=0;
				field[2]=0;
				field[3]=0;
				stun_attr_add(&message, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, (const char*) field, 4);
			}
		}
*/
//		add_origin(&message);
//		if(add_integrity(clnet_info, &message)<0) return -1;
//		if(use_fingerprints)
//			    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
		send_buffer(clnet_info, &message, 0,0);
	}
/*
	if (lt && !addr_any(&(elem->pinfo.peer_addr))) {

		if(!no_permissions) {
			if (!method || (method == STUN_METHOD_CREATE_PERMISSION)) {
				stun_init_request(STUN_METHOD_CREATE_PERMISSION, &message);
				stun_attr_add_addr(&message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
				add_origin(&message);
				if(add_integrity(clnet_info, &message)<0) return -1;
				if(use_fingerprints)
				    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message, 0,0);
			}
		}

		if (!method || (method == STUN_METHOD_CHANNEL_BIND)) {
			if (STUN_VALID_CHANNEL(elem->chnum)) {
				stun_set_channel_bind_request(&message, &(elem->pinfo.peer_addr), elem->chnum);
				add_origin(&message);
				if(add_integrity(clnet_info, &message)<0) return -1;
				if(use_fingerprints)
					    stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message,1,0);
			}
		}
	}
*/
	elem->refresh_time = current_mstime + 30*1000;

	return 0;
}

void dostuff(int); /* function prototype */
void error(const char *msg)
{
    perror(msg);
    exit(1);
}






int start_client(const char *rem_addr, int port, const unsigned char *ifname, const char *loc_addr, int maxmsgs, int idx)
{
    int i;
    app_ur_session session;
    app_ur_conn_info *clnet_info = &session.pinfo;
    ioa_addr self_relay, peer_relay;

    memset(&session, 0, sizeof(session));
    if (clnet_connect(port, rem_addr, ifname, loc_addr, clnet_info) < 0) {
        return -1;
    }

    if (clnet_allocate(clnet_info, &self_relay, default_address_family, NULL, NULL) < 0) {
        return -1;
    }

    if (get_peer_relay(&peer_relay) < 0) { 
        return -1;
    }

    if (turn_create_permission(clnet_info, &peer_relay, 1) < 0) {
        return -1;
    }

    socket_set_nonblocking(clnet_info->fd);
    session.state = UR_STATE_READY;
    session.tot_msgnum = maxmsgs;
    session.recvmsgnum =- 1;
    session.chnum = 0;

    printf("turn_tcp_connect: ready to tcp connect to peer\n");
    //getchar();
    if (turn_tcp_connect(clnet_info, &peer_relay) < 0) {
        return -1;
    }

    printf("client_read_input: enter when both clients are ready to establish tcp connection\n");
    getchar();
	//client_read_input-->client_read-->tcp_data_connect-->turn_tcp_connection_bind
    client_read_input(&session);
    while (1)
		{
	printf("set_buffer_to_send, client_write: enter when both clients are ready to send data\n");
    //getchar();
    set_buffer_to_send(clmessage_length, idx);
	client_write(&session);
    printf("client_read_input: enter when both clients are ready to receive data\n");
   // getchar();
	//
    client_read_input(&session);
	/*
    for (i = 0; i < (int)session.in_buffer.len - 16; i++) {
        printf("received byte = %c\n", (char)session.in_buffer.buf[i+16]);
    }
    */
    printf("received msg = %s\n", &session.in_buffer.buf);
    bzero(&session.in_buffer.buf,MAX_STUN_MESSAGE_SIZE);
    time_t t = time(NULL);
    struct tm tm = *localtime(&t); 
    printf("now: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    refresh_channel(&session, 0, 6000);
    //getchar();
		}
    return 0;
}

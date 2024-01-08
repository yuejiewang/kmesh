#include "kmesh_parse_http_2_0.h"
#include "huffman.h"

u32 parse_http_2_0_request(const struct bpf_mem_ptr *msg) {
  return 1;
}

u32 parse_http_2_0_response(const struct bpf_mem_ptr *msg) {
  return 1;
}

static struct msg_protocol http_2_0_request = {
	.parse_protocol_msg = parse_http_2_0_request,
};

static struct msg_protocol http_2_0_response = {
	.parse_protocol_msg = parse_http_2_0_response,
};

static void register_http_2_0_request(void)
{
	list_add_tail(&http_2_0_request.list, &g_protocol_list_head);
}

static void register_http_2_0_response(void)
{
	list_add_tail(&http_2_0_response.list, &g_protocol_list_head);
}

int __init kmesh_register_http_2_0_init(void)
{
	register_http_2_0_request();
	register_http_2_0_response();

	return 0;
}

int kmesh_parse_recv(hd_inflater* inflater, const uint8_t *in, size_t inlen) {
	return 1;
}

/* init the decoder for a new session */
int hd_inflate_new(hd_inflater **inflater_ptr, void *mem_user_data) {
	return 1;
}

/* decode a header field into a name-value pair */
ssize_t hd_inflate_hd_nv(hd_inflater *inflater, hd_nv *nv_out,
                         int *inflate_flags, const uint8_t *in, size_t inlen,
                         int in_final) {
	return 1;
}

/* decode header block fragment */
ssize_t inflate_hd_block(hd_inflater* inflater, const uint8_t *in,
                         size_t inlen) {
	return 1;
}

static inline int memeq(const void *s1, const void *s2, size_t n) {
  return memcmp(s1, s2, n) == 0;
}

static int32_t lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {
  case 2:
    switch (name[1]) {
    case 'e':
      if (memeq("t", name, 1)) {
        return TOKEN_TE;
      }
      break;
    }
    break;
  case 3:
    switch (name[2]) {
    case 'a':
      if (memeq("vi", name, 2)) {
        return TOKEN_VIA;
      }
      break;
    case 'e':
      if (memeq("ag", name, 2)) {
        return TOKEN_AGE;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'e':
      if (memeq("dat", name, 3)) {
        return TOKEN_DATE;
      }
      break;
    case 'g':
      if (memeq("eta", name, 3)) {
        return TOKEN_ETAG;
      }
      break;
    case 'k':
      if (memeq("lin", name, 3)) {
        return TOKEN_LINK;
      }
      break;
    case 'm':
      if (memeq("fro", name, 3)) {
        return TOKEN_FROM;
      }
      break;
    case 't':
      if (memeq("hos", name, 3)) {
        return TOKEN_HOST;
      }
      break;
    case 'y':
      if (memeq("var", name, 3)) {
        return TOKEN_VARY;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'e':
      if (memeq("rang", name, 4)) {
        return TOKEN_RANGE;
      }
      break;
    case 'h':
      if (memeq(":pat", name, 4)) {
        return TOKEN__PATH;
      }
      break;
    case 'w':
      if (memeq("allo", name, 4)) {
        return TOKEN_ALLOW;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'e':
      if (memeq("cooki", name, 5)) {
        return TOKEN_COOKIE;
      }
      break;
    case 'r':
      if (memeq("serve", name, 5)) {
        return TOKEN_SERVER;
      }
      break;
    case 't':
      if (memeq("accep", name, 5)) {
        return TOKEN_ACCEPT;
      }
      if (memeq("expec", name, 5)) {
        return TOKEN_EXPECT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'd':
      if (memeq(":metho", name, 6)) {
        return TOKEN__METHOD;
      }
      break;
    case 'e':
      if (memeq(":schem", name, 6)) {
        return TOKEN__SCHEME;
      }
      if (memeq("upgrad", name, 6)) {
        return TOKEN_UPGRADE;
      }
      break;
    case 'h':
      if (memeq("refres", name, 6)) {
        return TOKEN_REFRESH;
      }
      break;
    case 'r':
      if (memeq("refere", name, 6)) {
        return TOKEN_REFERER;
      }
      break;
    case 's':
      if (memeq(":statu", name, 6)) {
        return TOKEN__STATUS;
      }
      if (memeq("expire", name, 6)) {
        return TOKEN_EXPIRES;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'e':
      if (memeq("if-rang", name, 7)) {
        return TOKEN_IF_RANGE;
      }
      break;
    case 'h':
      if (memeq("if-matc", name, 7)) {
        return TOKEN_IF_MATCH;
      }
      break;
    case 'n':
      if (memeq("locatio", name, 7)) {
        return TOKEN_LOCATION;
      }
      break;
    case 'y':
      if (memeq("priorit", name, 7)) {
        return TOKEN_PRIORITY;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'l':
      if (memeq(":protoco", name, 8)) {
        return TOKEN__PROTOCOL;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'e':
      if (memeq("keep-aliv", name, 9)) {
        return TOKEN_KEEP_ALIVE;
      }
      if (memeq("set-cooki", name, 9)) {
        return TOKEN_SET_COOKIE;
      }
      break;
    case 'n':
      if (memeq("connectio", name, 9)) {
        return TOKEN_CONNECTION;
      }
      break;
    case 't':
      if (memeq("user-agen", name, 9)) {
        return TOKEN_USER_AGENT;
      }
      break;
    case 'y':
      if (memeq(":authorit", name, 9)) {
        return TOKEN__AUTHORITY;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'r':
      if (memeq("retry-afte", name, 10)) {
        return TOKEN_RETRY_AFTER;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case 'e':
      if (memeq("content-typ", name, 11)) {
        return TOKEN_CONTENT_TYPE;
      }
      break;
    case 's':
      if (memeq("max-forward", name, 11)) {
        return TOKEN_MAX_FORWARDS;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'd':
      if (memeq("last-modifie", name, 12)) {
        return TOKEN_LAST_MODIFIED;
      }
      break;
    case 'e':
      if (memeq("content-rang", name, 12)) {
        return TOKEN_CONTENT_RANGE;
      }
      break;
    case 'h':
      if (memeq("if-none-matc", name, 12)) {
        return TOKEN_IF_NONE_MATCH;
      }
      break;
    case 'l':
      if (memeq("cache-contro", name, 12)) {
        return TOKEN_CACHE_CONTROL;
      }
      break;
    case 'n':
      if (memeq("authorizatio", name, 12)) {
        return TOKEN_AUTHORIZATION;
      }
      break;
    case 's':
      if (memeq("accept-range", name, 12)) {
        return TOKEN_ACCEPT_RANGES;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'h':
      if (memeq("content-lengt", name, 13)) {
        return TOKEN_CONTENT_LENGTH;
      }
      break;
    case 't':
      if (memeq("accept-charse", name, 13)) {
        return TOKEN_ACCEPT_CHARSET;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (memeq("accept-languag", name, 14)) {
        return TOKEN_ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (memeq("accept-encodin", name, 14)) {
        return TOKEN_ACCEPT_ENCODING;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'e':
      if (memeq("content-languag", name, 15)) {
        return TOKEN_CONTENT_LANGUAGE;
      }
      if (memeq("www-authenticat", name, 15)) {
        return TOKEN_WWW_AUTHENTICATE;
      }
      break;
    case 'g':
      if (memeq("content-encodin", name, 15)) {
        return TOKEN_CONTENT_ENCODING;
      }
      break;
    case 'n':
      if (memeq("content-locatio", name, 15)) {
        return TOKEN_CONTENT_LOCATION;
      }
      if (memeq("proxy-connectio", name, 15)) {
        return TOKEN_PROXY_CONNECTION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (memeq("if-modified-sinc", name, 16)) {
        return TOKEN_IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (memeq("transfer-encodin", name, 16)) {
        return TOKEN_TRANSFER_ENCODING;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'e':
      if (memeq("proxy-authenticat", name, 17)) {
        return TOKEN_PROXY_AUTHENTICATE;
      }
      break;
    }
    break;
  case 19:
    switch (name[18]) {
    case 'e':
      if (memeq("if-unmodified-sinc", name, 18)) {
        return TOKEN_IF_UNMODIFIED_SINCE;
      }
      break;
    case 'n':
      if (memeq("content-dispositio", name, 18)) {
        return TOKEN_CONTENT_DISPOSITION;
      }
      if (memeq("proxy-authorizatio", name, 18)) {
        return TOKEN_PROXY_AUTHORIZATION;
      }
      break;
    }
    break;
  case 25:
    switch (name[24]) {
    case 'y':
      if (memeq("strict-transport-securit", name, 24)) {
        return TOKEN_STRICT_TRANSPORT_SECURITY;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case 'n':
      if (memeq("access-control-allow-origi", name, 26)) {
        return TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN;
      }
      break;
    }
    break;
  }
  return -1;
}

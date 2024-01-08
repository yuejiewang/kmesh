#ifndef KMESH_REGISTER_HTTP_2_0_H
#define KMESH_REGISTER_HTTP_2_0_H

#include "kmesh_parse_protocol_data.h"
#include "huffman.h"

typedef struct
{
  /* The pointer to the underlying buffer */
  u8 *base;
  /* Size of buffer pointed by |base|. */
  size_t len;
  /* Reference count */
  int32_t ref;
} rcbuf;  // nghttp2_rcbuf.h

/**
 * @struct
 *
 * The name/value pair, which mainly used to represent header fields.
 */
typedef struct {
  
  u8 *name;
  
  u8 *value;
  
  size_t namelen;
  
  size_t valuelen;
  
  u8 flags;
} nv;  // nghttp2.h

#define HD_ENTRY_OVERHEAD 32
#define HD_MAP_SIZE 128

#define INDEX_RANGE_VALID(context, idx)                                        \
  ((idx) < (context)->hd_table.len + STATIC_TABLE_LENGTH)

#define FRAME_HDLEN 9

#define CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define CLIENT_MAGIC_LEN 24

/* The number of bytes for each SETTINGS entry */
#define FRAME_SETTINGS_ENTRY_LENGTH 6

/* Length of priority related fields in HEADERS/PRIORITY frames */
#define PRIORITY_SPECLEN 5

#define STREAM_ID_MASK ((1u << 31) - 1)
#define PRI_GROUP_ID_MASK ((1u << 31) - 1)
#define PRIORITY_MASK ((1u << 31) - 1)
#define WINDOW_SIZE_INCREMENT_MASK ((1u << 31) - 1)
#define SETTINGS_ID_MASK ((1 << 24) - 1)

u32 parse_http_2_0_request(const struct bpf_mem_ptr *msg);
u32 parse_http_2_0_response(const struct bpf_mem_ptr *msg);

int __init kmesh_register_http_2_0_init(void);

/* Make scalar initialization form of hd_entry */
#define MAKE_STATIC_ENT(N, V, T, H)                                            \
  {                                                                            \
    {(u8 *)(N), sizeof((N)) - 1, -1},                                          \
    {(u8 *)(V), sizeof((V)) - 1, -1},                                          \
    {(u8 *)(N), (u8 *)(V), sizeof((N)) - 1, sizeof((V)) - 1, 0},               \
    T, H                                                                       \
  }

static const hd_static_entry static_table[] = {
    MAKE_STATIC_ENT(":authority", "", 0, 3153725150u),
    MAKE_STATIC_ENT(":method", "GET", 1, 695666056u),
    MAKE_STATIC_ENT(":method", "POST", 1, 695666056u),
    MAKE_STATIC_ENT(":path", "/", 3, 3292848686u),
    MAKE_STATIC_ENT(":path", "/index.html", 3, 3292848686u),
    MAKE_STATIC_ENT(":scheme", "http", 5, 2510477674u),
    MAKE_STATIC_ENT(":scheme", "https", 5, 2510477674u),
    MAKE_STATIC_ENT(":status", "200", 7, 4000288983u),
    MAKE_STATIC_ENT(":status", "204", 7, 4000288983u),
    MAKE_STATIC_ENT(":status", "206", 7, 4000288983u),
    MAKE_STATIC_ENT(":status", "304", 7, 4000288983u),
    MAKE_STATIC_ENT(":status", "400", 7, 4000288983u),
    MAKE_STATIC_ENT(":status", "404", 7, 4000288983u),
    MAKE_STATIC_ENT(":status", "500", 7, 4000288983u),
    MAKE_STATIC_ENT("accept-charset", "", 14, 3664010344u),
    MAKE_STATIC_ENT("accept-encoding", "gzip, deflate", 15, 3379649177u),
    MAKE_STATIC_ENT("accept-language", "", 16, 1979086614u),
    MAKE_STATIC_ENT("accept-ranges", "", 17, 1713753958u),
    MAKE_STATIC_ENT("accept", "", 18, 136609321u),
    MAKE_STATIC_ENT("access-control-allow-origin", "", 19, 2710797292u),
    MAKE_STATIC_ENT("age", "", 20, 742476188u),
    MAKE_STATIC_ENT("allow", "", 21, 2930878514u),
    MAKE_STATIC_ENT("authorization", "", 22, 2436257726u),
    MAKE_STATIC_ENT("cache-control", "", 23, 1355326669u),
    MAKE_STATIC_ENT("content-disposition", "", 24, 3889184348u),
    MAKE_STATIC_ENT("content-encoding", "", 25, 65203592u),
    MAKE_STATIC_ENT("content-language", "", 26, 24973587u),
    MAKE_STATIC_ENT("content-length", "", 27, 1308181789u),
    MAKE_STATIC_ENT("content-location", "", 28, 2302364718u),
    MAKE_STATIC_ENT("content-range", "", 29, 3555523146u),
    MAKE_STATIC_ENT("content-type", "", 30, 4244048277u),
    MAKE_STATIC_ENT("cookie", "", 31, 2007449791u),
    MAKE_STATIC_ENT("date", "", 32, 3564297305u),
    MAKE_STATIC_ENT("etag", "", 33, 113792960u),
    MAKE_STATIC_ENT("expect", "", 34, 2530896728u),
    MAKE_STATIC_ENT("expires", "", 35, 1049544579u),
    MAKE_STATIC_ENT("from", "", 36, 2513272949u),
    MAKE_STATIC_ENT("host", "", 37, 2952701295u),
    MAKE_STATIC_ENT("if-match", "", 38, 3597694698u),
    MAKE_STATIC_ENT("if-modified-since", "", 39, 2213050793u),
    MAKE_STATIC_ENT("if-none-match", "", 40, 2536202615u),
    MAKE_STATIC_ENT("if-range", "", 41, 2340978238u),
    MAKE_STATIC_ENT("if-unmodified-since", "", 42, 3794814858u),
    MAKE_STATIC_ENT("last-modified", "", 43, 3226950251u),
    MAKE_STATIC_ENT("link", "", 44, 232457833u),
    MAKE_STATIC_ENT("location", "", 45, 200649126u),
    MAKE_STATIC_ENT("max-forwards", "", 46, 1826162134u),
    MAKE_STATIC_ENT("proxy-authenticate", "", 47, 2709445359u),
    MAKE_STATIC_ENT("proxy-authorization", "", 48, 2686392507u),
    MAKE_STATIC_ENT("range", "", 49, 4208725202u),
    MAKE_STATIC_ENT("referer", "", 50, 3969579366u),
    MAKE_STATIC_ENT("refresh", "", 51, 3572655668u),
    MAKE_STATIC_ENT("retry-after", "", 52, 3336180598u),
    MAKE_STATIC_ENT("server", "", 53, 1085029842u),
    MAKE_STATIC_ENT("set-cookie", "", 54, 1848371000u),
    MAKE_STATIC_ENT("strict-transport-security", "", 55, 4138147361u),
    MAKE_STATIC_ENT("transfer-encoding", "", 56, 3719590988u),
    MAKE_STATIC_ENT("user-agent", "", 57, 606444526u),
    MAKE_STATIC_ENT("vary", "", 58, 1085005381u),
    MAKE_STATIC_ENT("via", "", 59, 1762798611u),
    MAKE_STATIC_ENT("www-authenticate", "", 60, 779865858u),
};

typedef enum {
  TOKEN__AUTHORITY = 0,
  TOKEN__METHOD = 1,
  TOKEN__PATH = 3,
  TOKEN__SCHEME = 5,
  TOKEN__STATUS = 7,
  TOKEN_ACCEPT_CHARSET = 14,
  TOKEN_ACCEPT_ENCODING = 15,
  TOKEN_ACCEPT_LANGUAGE = 16,
  TOKEN_ACCEPT_RANGES = 17,
  TOKEN_ACCEPT = 18,
  TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN = 19,
  TOKEN_AGE = 20,
  TOKEN_ALLOW = 21,
  TOKEN_AUTHORIZATION = 22,
  TOKEN_CACHE_CONTROL = 23,
  TOKEN_CONTENT_DISPOSITION = 24,
  TOKEN_CONTENT_ENCODING = 25,
  TOKEN_CONTENT_LANGUAGE = 26,
  TOKEN_CONTENT_LENGTH = 27,
  TOKEN_CONTENT_LOCATION = 28,
  TOKEN_CONTENT_RANGE = 29,
  TOKEN_CONTENT_TYPE = 30,
  TOKEN_COOKIE = 31,
  TOKEN_DATE = 32,
  TOKEN_ETAG = 33,
  TOKEN_EXPECT = 34,
  TOKEN_EXPIRES = 35,
  TOKEN_FROM = 36,
  TOKEN_HOST = 37,
  TOKEN_IF_MATCH = 38,
  TOKEN_IF_MODIFIED_SINCE = 39,
  TOKEN_IF_NONE_MATCH = 40,
  TOKEN_IF_RANGE = 41,
  TOKEN_IF_UNMODIFIED_SINCE = 42,
  TOKEN_LAST_MODIFIED = 43,
  TOKEN_LINK = 44,
  TOKEN_LOCATION = 45,
  TOKEN_MAX_FORWARDS = 46,
  TOKEN_PROXY_AUTHENTICATE = 47,
  TOKEN_PROXY_AUTHORIZATION = 48,
  TOKEN_RANGE = 49,
  TOKEN_REFERER = 50,
  TOKEN_REFRESH = 51,
  TOKEN_RETRY_AFTER = 52,
  TOKEN_SERVER = 53,
  TOKEN_SET_COOKIE = 54,
  TOKEN_STRICT_TRANSPORT_SECURITY = 55,
  TOKEN_TRANSFER_ENCODING = 56,
  TOKEN_USER_AGENT = 57,
  TOKEN_VARY = 58,
  TOKEN_VIA = 59,
  TOKEN_WWW_AUTHENTICATE = 60,
  TOKEN_TE,
  TOKEN_CONNECTION,
  TOKEN_KEEP_ALIVE,
  TOKEN_PROXY_CONNECTION,
  TOKEN_UPGRADE,
  TOKEN__PROTOCOL,
  TOKEN_PRIORITY,
} token;

int kmesh_parse_recv(hd_inflater* inflater, const uint8_t *in, size_t inlen);

int hd_inflate_new(hd_inflater **inflater_ptr, void *mem_user_data);

static inline int memeq(const void *s1, const void *s2, size_t n);

static int32_t lookup_token(const uint8_t *name, size_t namelen);

#endif /* KMESH_REGISTER_HTTP_2_0_H */

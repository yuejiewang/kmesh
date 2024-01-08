#ifndef KMESH_REGISTER_HTTP_2_0_H
#define KMESH_REGISTER_HTTP_2_0_H

#include "kmesh_parse_protocol_data.h"
#include "huffman.h"

int __init kmesh_register_http_2_0_init(void);

#define DEBUGF pr_info
#define BPF_MIN(A, B) ((A) < (B) ? (A) : (B))
#define BPF_MAX(A, B) ((A) > (B) ? (A) : (B))
#define bpf_memset(b, c, len) memset(b, c, len)

#define UINT32_MAX 4294967295

#define HD_ENTRY_OVERHEAD 32
#define HD_MAP_SIZE 128
#define HD_MAX_NV 65536
#define HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE (1 << 12)

#define STATIC_TABLE_LENGTH 61

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

#define INDEX_RANGE_VALID(context, idx)                                        \
  ((idx) < (context)->hd_table_len + STATIC_TABLE_LENGTH)
#define buf_avail(BUF) ((size_t)((BUF)->end - (BUF)->last))
#define bufs_cur_avail(BUFS) buf_avail(&(BUFS)->cur->buf)
#define buf_cap(BUF) ((size_t)((BUF)->end - (BUF)->begin))
#define buf_len(BUF) ((size_t)((BUF)->last - (BUF)->pos))
#define buf_shift_right(BUF, AMT)                                              \
  do {                                                                         \
    (BUF)->pos += AMT;                                                         \
    (BUF)->last += AMT;                                                        \
  } while (0)

#define buf_shift_left(BUF, AMT)                                               \
  do {                                                                         \
    (BUF)->pos -= AMT;                                                         \
    (BUF)->last -= AMT;                                                        \
  } while (0)

/* enum */

typedef enum {
  HD_OPCODE_NONE,
  HD_OPCODE_INDEXED,
  HD_OPCODE_NEWNAME,
  HD_OPCODE_INDNAME
} hd_opcode;

typedef enum {
  HD_STATE_EXPECT_TABLE_SIZE,
  HD_STATE_INFLATE_START,
  HD_STATE_OPCODE,
  HD_STATE_READ_TABLE_SIZE,
  HD_STATE_READ_INDEX,
  HD_STATE_NEWNAME_CHECK_NAMELEN,
  HD_STATE_NEWNAME_READ_NAMELEN,
  HD_STATE_NEWNAME_READ_NAMEHUFF,
  HD_STATE_NEWNAME_READ_NAME,
  HD_STATE_CHECK_VALUELEN,
  HD_STATE_READ_VALUELEN,
  HD_STATE_READ_VALUEHUFF,
  HD_STATE_READ_VALUE
} hd_inflate_state;

/**
 * @enum
 *
 * The flags for header field name/value pair.
 */
typedef enum {
  /**
   * No flag set.
   */
  NV_FLAG_NONE = 0,
  /**
   * Indicates that this name/value pair must not be indexed ("Literal
   * Header Field never Indexed" representation must be used in HPACK
   * encoding).  Other implementation calls this bit as "sensitive".
   */
  NV_FLAG_NO_INDEX = 0x01,
  /**
   * This flag is set solely by application.  If this flag is set, the
   * library does not make a copy of header field name.  This could
   * improve performance.
   */
  NV_FLAG_NO_COPY_NAME = 0x02,
  /**
   * This flag is set solely by application.  If this flag is set, the
   * library does not make a copy of header field value.  This could
   * improve performance.
   */
  NV_FLAG_NO_COPY_VALUE = 0x04
} nv_flag;

/**
 * @enum
 *
 * The flags for header inflation.
 */
typedef enum {
  /**
   * No flag set.
   */
  HD_INFLATE_NONE = 0,
  /**
   * Indicates all headers were inflated.
   */
  HD_INFLATE_FINAL = 0x01,
  /**
   * Indicates a header was emitted.
   */
  HD_INFLATE_EMIT = 0x02
} hd_inflate_flag;

/**
 * @enum
 *
 * The flags for HTTP/2 frames.  This enum defines all flags for all
 * frames.
 */
typedef enum {
  /**
   * No flag set.
   */
  FLAG_NONE = 0,
  /**
   * The END_STREAM flag.
   */
  FLAG_END_STREAM = 0x01,
  /**
   * The END_HEADERS flag.
   */
  FLAG_END_HEADERS = 0x04,
  /**
   * The ACK flag.
   */
  FLAG_ACK = 0x01,
  /**
   * The PADDED flag.
   */
  FLAG_PADDED = 0x08,
  /**
   * The PRIORITY flag.
   */
  FLAG_PRIORITY = 0x20
} flag;

/**
 * @enum
 *
 * The category of HEADERS, which indicates the role of the frame.  In
 * HTTP/2 spec, request, response, push response and other arbitrary
 * headers (e.g., trailer fields) are all called just HEADERS.  To
 * give the application the role of incoming HEADERS frame, we define
 * several categories.
 */
typedef enum {
  /**
   * The HEADERS frame is opening new stream, which is analogous to
   * SYN_STREAM in SPDY.
   */
  HCAT_REQUEST = 0,
  /**
   * The HEADERS frame is the first response headers, which is
   * analogous to SYN_REPLY in SPDY.
   */
  HCAT_RESPONSE = 1,
  /**
   * The HEADERS frame is the first headers sent against reserved
   * stream.
   */
  HCAT_PUSH_RESPONSE = 2,
  /**
   * The HEADERS frame which does not apply for the above categories,
   * which is analogous to HEADERS in SPDY.  If non-final response
   * (e.g., status 1xx) is used, final response HEADERS frame will be
   * categorized here.
   */
  HCAT_HEADERS = 3
} headers_category;

/* Internal state when receiving incoming frame */
typedef enum {
  /* Receiving frame header */
  IB_READ_CLIENT_MAGIC,
  IB_READ_FIRST_SETTINGS,
  IB_READ_HEAD,
  IB_READ_NBYTE,
  IB_READ_HEADER_BLOCK,
  IB_IGN_HEADER_BLOCK,
  IB_IGN_PAYLOAD,
  IB_FRAME_SIZE_ERROR,
  IB_READ_SETTINGS,
  IB_READ_GOAWAY_DEBUG,
  IB_EXPECT_CONTINUATION,
  IB_IGN_CONTINUATION,
  IB_READ_PAD_DATA,
  IB_READ_DATA,
  IB_IGN_DATA,
  IB_IGN_ALL,
  IB_READ_ALTSVC_PAYLOAD,
  IB_READ_ORIGIN_PAYLOAD,
  IB_READ_EXTENSION_PAYLOAD
} inbound_state;

/**
 * @enum
 *
 * The frame types in HTTP/2 specification.
 */
typedef enum {
  /**
   * The DATA frame.
   */
  DATA = 0,
  /**
   * The HEADERS frame.
   */
  HEADERS = 0x01,
  /**
   * The PRIORITY frame.
   */
  PRIORITY = 0x02,
  /**
   * The RST_STREAM frame.
   */
  RST_STREAM = 0x03,
  /**
   * The SETTINGS frame.
   */
  SETTINGS = 0x04,
  /**
   * The PUSH_PROMISE frame.
   */
  PUSH_PROMISE = 0x05,
  /**
   * The PING frame.
   */
  PING = 0x06,
  /**
   * The GOAWAY frame.
   */
  GOAWAY = 0x07,
  /**
   * The WINDOW_UPDATE frame.
   */
  WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.  This frame type won't be passed to any
   * callbacks because the library processes this frame type and its
   * preceding HEADERS/PUSH_PROMISE as a single frame.
   */
  CONTINUATION = 0x09,
  /**
   * The ALTSVC frame, which is defined in `RFC 7383
   * <https://tools.ietf.org/html/rfc7838#section-4>`_.
   */
  ALTSVC = 0x0a,
  /**
   * The ORIGIN frame, which is defined by `RFC 8336
   * <https://tools.ietf.org/html/rfc8336>`_.
   */
  ORIGIN = 0x0c,
  /**
   * The PRIORITY_UPDATE frame, which is defined by :rfc:`9218`.
   */
  PRIORITY_UPDATE = 0x10
} frame_type;

/* structures */

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

/* The entry used for static header table. */
typedef struct {
  rcbuf name;
  rcbuf value;
  nv cnv;
  int32_t token;
  u32 hash;
} hd_static_entry;

typedef struct {
  /* dynamic header table */
  size_t hd_table_len;
  /* Abstract buffer size of hd_table as described in the spec. This
     is the sum of length of name/value in hd_table +
     HD_ENTRY_OVERHEAD bytes overhead per each entry. */
  size_t hd_table_bufsize;
  /* The effective header table size. */
  size_t hd_table_bufsize_max;
  /* Next sequence number for hd_entry */
  u32 next_seq;
  /* If inflate/deflate error occurred, this value is set to 1 and
     further invocation of inflate/deflate will fail with
     ERR_HEADER_COMP. */
  u8 bad;
} hd_context;

struct hd_entry;
typedef struct hd_entry hd_entry;

typedef struct {
  rcbuf *name;
  rcbuf *value;
  int32_t token;
  u8 flags;
} hd_nv;

struct hd_entry {
  /* The header field name/value pair */
  hd_nv nv;
  /* This is solely for hd_{deflate,inflate}_get_table_entry
     APIs to keep backward compatibility. */
  nv cnv;
  /* The next entry which shares same bucket in hash table. */
  hd_entry *next;
  /* The sequence number.  We will increment it by one whenever we
     store hd_entry to dynamic header table. */
  u32 seq;
  /* The hash value for header name (nv.name). */
  u32 hash;
};

typedef struct {
  hd_context ctx;
  /* Stores current state of huffman decoding */
  hd_huff_decode_context huff_decode_ctx;
  /* header buffer */
  buf namebuf, valuebuf;
  rcbuf *namercbuf, *valuercbuf;
  /* Pointer to the name/value pair which are used in the current
     header emission. */
  rcbuf *nv_name_keep, *nv_value_keep;
  /* The number of bytes to read */
  size_t left;
  /* The index in indexed repr or indexed name */
  size_t index;
  /* The maximum header table size the inflater supports. This is the
     same value transmitted in SETTINGS_HEADER_TABLE_SIZE */
  size_t settings_hd_table_bufsize_max;
  /* Minimum header table size set by hd_inflate_change_table_size */
  size_t min_hd_table_bufsize_max;
  /* The number of next shift to decode integer */
  size_t shift;
  hd_opcode opcode;
  hd_inflate_state state;
  /* nonzero if string is huffman encoded */
  u8 huffman_encoded;
  /* nonzero if deflater requires that current entry is indexed */
  u8 index_required;
  /* nonzero if deflater requires that current entry must not be
     indexed */
  u8 no_index;
} hd_inflater;

/**
 * @struct
 * The frame header.
 */
typedef struct {
  /**
   * The length field of this frame, excluding frame header.
   */
  size_t length;
  /**
   * The stream identifier (aka, stream ID)
   */
  int32_t stream_id;
  /**
   * The type of this frame.  See `frame_type`.
   */
  u8 type;
  /**
   * The flags.
   */
  u8 flags;
  /**
   * Reserved bit in frame header.  Currently, this is always set to 0
   * and application should not expect something useful in here.
   */
  u8 reserved;
} frame_hd;

/**
 * @struct
 *
 * The DATA frame.  The received data is delivered via
 * :type:`on_data_chunk_recv_callback`.
 */
typedef struct {
  frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
} data_frame;

/**
 * @struct
 *
 * The HEADERS frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The name/value pairs.
   */
  nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The category of this HEADERS frame.
   */
  headers_category cat;
} headers_frame;

/* union of other frame types */
typedef struct {
  frame_hd hd;
  size_t payloadlen;
} control_frame;

/**
 * @union
 *
 * This union includes all frames to pass them to various function
 * calls as frame type.  The CONTINUATION frame is omitted
 * from here because the library deals with it internally.
 */
typedef union {
  /**
   * The frame header, which is convenient to inspect frame header.
   */
  frame_hd hd;
  /**
   * The DATA frame.
   */
  data_frame data;
  /**
   * The HEADERS frame.
   */
  headers_frame headers;
  /**
   * Other frame types.
   */
  control_frame ctrl;
} http2_frame;

/* function declarations */

u32 parse_http_2_0_request(const struct bpf_mem_ptr *msg);
u32 parse_http_2_0_response(const struct bpf_mem_ptr *msg);


inline void buf_init(buf *buf);
inline int buf_init2(buf *buf, size_t initial);
inline int buf_reserve(buf *buf, size_t new_cap);
inline void buf_wrap_init(buf *buf, u8 *begin, size_t len);

int32_t lookup_token(const u8 *name, size_t namelen);

hd_nv hd_table_get(hd_context *context, size_t idx);

ssize_t inflate_hd_block(hd_inflater* inflater, const u8 *in,
                         size_t inlen);

int hd_inflate_new(hd_inflater **inflater_ptr);

void hd_inflate_keep_free(hd_inflater *inflater);

int kmesh_parse_recv(hd_inflater* inflater, const u8 *in, size_t inlen);

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

#endif /* KMESH_REGISTER_HTTP_2_0_H */

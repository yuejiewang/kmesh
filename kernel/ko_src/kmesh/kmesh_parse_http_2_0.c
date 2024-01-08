#include "kmesh_parse_http_2_0.h"

u32 parse_http_2_0_request(hd_inflater *inflater,
                           const struct bpf_mem_ptr *msg) {
  return kmesh_parse_recv(inflater, msg->ptr, msg->size);
}

u32 parse_http_2_0_response(hd_inflater *inflater,
                            const struct bpf_mem_ptr *msg) {
  return kmesh_parse_recv(inflater, msg->ptr, msg->size);
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

static inline uint16_t get_uint16(const uint8_t *data) {
  uint16_t n;
  memcpy(&n, data, sizeof(uint16_t));
  return ntohs(n);
}

static inline uint32_t get_uint32(const uint8_t *data) {
  uint32_t n;
  memcpy(&n, data, sizeof(uint32_t));
  return ntohl(n);
}

static inline void *default_malloc(size_t size) {
  return kmalloc(size);
}

static inline void default_free(void *ptr) {
  kvfree(ptr);
}

static inline void *default_calloc(size_t nmemb, size_t size) {
  return kcalloc(nmemb, size);
}

static inline void *default_realloc(void *ptr, size_t size) {
  return krealloc(ptr, size);
}

/*
 * Frees |rcbuf| itself, regardless of its reference cout.
 */
static inline void rcbuf_del(rcbuf *rcbuf) {
  default_free(rcbuf, rcbuf->base);
}

static inline void rcbuf_incref(rcbuf *rcbuf) {
  if (rcbuf->ref == -1) {
    return;
  }

  ++rcbuf->ref;
}

static inline void rcbuf_decref(rcbuf *rcbuf) {
  if (rcbuf == NULL || rcbuf->ref == -1) {
    return;
  }

  assert(rcbuf->ref > 0);

  if (--rcbuf->ref == 0) {
    rcbuf_del(rcbuf);
  }
}

static inline void buf_init(buf *buf) {
  buf->begin = NULL;
  buf->end = NULL;
  buf->pos = NULL;
  buf->last = NULL;
  buf->mark = NULL;
}

static inline int buf_init2(buf *buf, size_t initial) {
  buf_init(buf);
  return buf_reserve(buf, initial);
}

static inline int buf_reserve(buf *buf, size_t new_cap) {
  uint8_t *ptr;
  size_t cap;

  cap = buf_cap(buf);

  if (cap >= new_cap) {
    return 0;
  }

  new_cap = BPF_MAX(new_cap, cap * 2);

  ptr = default_realloc(buf->begin, new_cap);

  if (ptr == NULL) {
    return ERR_NOMEM;
  }

  buf->pos = ptr + (buf->pos - buf->begin);
  buf->last = ptr + (buf->last - buf->begin);
  buf->mark = ptr + (buf->mark - buf->begin);
  buf->begin = ptr;
  buf->end = ptr + new_cap;

  return 0;
}

static inline void buf_wrap_init(buf *buf, uint8_t *begin, size_t len) {
  buf->begin = buf->pos = buf->last = buf->mark = buf->end = begin;
  if (len) {
    buf->end += len;
  }
}

static inline int buf_chain_new(buf_chain **chain, size_t chunk_length) {
  int rv;

  *chain = default_malloc(sizeof(buf_chain));

  if (*chain == NULL) {
    return ERR_NOMEM;
  }

  (*chain)->next = NULL;

  rv = buf_init2(&(*chain)->buf, chunk_length);
  if (rv != 0) {
    default_free(*chain);
    return ERR_NOMEM;
  }

  return 0;
}

static inline int bufs_alloc_chain(bufs *bufs) {
  int rv;
  buf_chain *chain;

  if (bufs->cur->next) {
    bufs->cur = bufs->cur->next;

    return 0;
  }

  if (bufs->max_chunk == bufs->chunk_used) {
    return ERR_BUFFER_ERROR;
  }

  rv = buf_chain_new(&chain, bufs->chunk_length);
  if (rv != 0) {
    return rv;
  }

  DEBUGF("new buffer %zu bytes allocated for bufs %p, used %zu\n",
         bufs->chunk_length, bufs, bufs->chunk_used);

  ++bufs->chunk_used;

  bufs->cur->next = chain;
  bufs->cur = chain;

  buf_shift_right(&bufs->cur->buf, bufs->offset);

  return 0;
}

static inline int bufs_ensure_addb(bufs *bufs) {
  int rv;
  buf *buf;

  buf = &bufs->cur->buf;

  if (buf_avail(buf) > 0) {
    return 0;
  }

  rv = bufs_alloc_chain(bufs);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

int bufs_addb(bufs *bufs, uint8_t b) {
  int rv;

  rv = bufs_ensure_addb(bufs);
  if (rv != 0) {
    return rv;
  }

  *bufs->cur->buf.last++ = b;

  return 0;
}

ssize_t hd_huff_decode(hd_huff_decode_context *ctx,
                       buf *buf, const uint8_t *src,
                       size_t srclen, int final) {
  const uint8_t *end = src + srclen;
  huff_decode node = {ctx->fstate, 0};
  const huff_decode *t = &node;
  uint8_t c;

  /* We use the decoding algorithm described in
     http://graphics.ics.uci.edu/pub/Prefix.pdf */
  for (; src != end;) {
    c = *src++;
    t = &huff_decode_table[t->fstate & 0x1ff][c >> 4];
    if (t->fstate & HUFF_SYM) {
      *buf->last++ = t->sym;
    }

    t = &huff_decode_table[t->fstate & 0x1ff][c & 0xf];
    if (t->fstate & HUFF_SYM) {
      *buf->last++ = t->sym;
    }
  }

  ctx->fstate = t->fstate;

  if (final && !(ctx->fstate & HUFF_ACCEPTED)) {
    return ERR_HEADER_COMP;
  }

  return (ssize_t)srclen;
}

int hd_huff_decode_failure_state(hd_huff_decode_context *ctx) {
  return ctx->fstate == 0x100;
}

void hd_inflate_keep_free(hd_inflater *inflater) {
  rcbuf_decref(inflater->nv_value_keep);
  rcbuf_decref(inflater->nv_name_keep);

  inflater->nv_value_keep = NULL;
  inflater->nv_name_keep = NULL;
}

/*
 * Decodes |prefix| prefixed integer stored from |in|.  The |last|
 * represents the 1 beyond the last of the valid contiguous memory
 * region from |in|.  The decoded integer must be less than or equal
 * to UINT32_MAX.
 *
 * If the |initial| is nonzero, it is used as a initial value, this
 * function assumes the |in| starts with intermediate data.
 *
 * An entire integer is decoded successfully, decoded, the |*fin| is
 * set to nonzero.
 *
 * This function stores the decoded integer in |*res| if it succeed,
 * including partial decoding (in this case, number of shift to make
 * in the next call will be stored in |*shift_ptr|) and returns number
 * of bytes processed, or returns -1, indicating decoding error.
 */
static ssize_t decode_length(uint32_t *res, size_t *shift_ptr, int *fin,
                             uint32_t initial, size_t shift, const uint8_t *in,
                             const uint8_t *last, size_t prefix) {
  uint32_t k = (uint8_t)((1 << prefix) - 1);
  uint32_t n = initial;
  const uint8_t *start = in;

  *shift_ptr = 0;
  *fin = 0;

  if (n == 0) {
    if ((*in & k) != k) {
      *res = (*in) & k;
      *fin = 1;
      return 1;
    }

    n = k;

    if (++in == last) {
      *res = n;
      return (ssize_t)(in - start);
    }
  }

  for (; in != last; ++in, shift += 7) {
    uint32_t add = *in & 0x7f;

    if (shift >= 32) {
      DEBUGF("inflate: shift exponent overflow\n");
      return -1;
    }

    if ((UINT32_MAX >> shift) < add) {
      DEBUGF("inflate: integer overflow on shift\n");
      return -1;
    }

    add <<= shift;

    if (UINT32_MAX - add < n) {
      DEBUGF("inflate: integer overflow on addition\n");
      return -1;
    }

    n += add;

    if ((*in & (1 << 7)) == 0) {
      break;
    }
  }

  *shift_ptr = shift;

  if (in == last) {
    *res = n;
    return (ssize_t)(in - start);
  }

  *res = n;
  *fin = 1;
  return (ssize_t)(in + 1 - start);
}

/*
 * Decodes the integer from the range [in, last).  The result is
 * assigned to |inflater->left|.  If the |inflater->left| is 0, then
 * it performs variable integer decoding from scratch. Otherwise, it
 * uses the |inflater->left| as the initial value and continues to
 * decode assuming that [in, last) begins with intermediary sequence.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * ERR_HEADER_COMP
 *   Integer decoding failed
 */
static ssize_t hd_inflate_read_len(hd_inflater *inflater, int *rfin,
                                   const uint8_t *in, const uint8_t *last,
                                   size_t prefix, size_t maxlen) {
  ssize_t rv;
  uint32_t out;

  *rfin = 0;

  rv = decode_length(&out, &inflater->shift, rfin, (uint32_t)inflater->left,
                     inflater->shift, in, last, prefix);

  if (rv == -1) {
    DEBUGF("inflatehd: integer decoding failed\n");
    return ERR_HEADER_COMP;
  }

  if (out > maxlen) {
    DEBUGF("inflatehd: integer exceeded the maximum value %u, %zu\n",
           out, maxlen);
    return ERR_HEADER_COMP;
  }

  inflater->left = out;

  DEBUGF("inflatehd: decoded integer is %u\n", out);

  return rv;
}

hd_nv hd_table_get(hd_context *context, size_t idx) {
  assert(INDEX_RANGE_VALID(context, idx));
  if (idx >= STATIC_TABLE_LENGTH) {
    DEBUGF("\tWARN: Index out of static table range, using dynamic table.\n");
    return hd_table_get(context, 1);
    // return hd_ringbuf_get(&context->hd_table, idx - STATIC_TABLE_LENGTH)->nv;
  } else {
    const hd_static_entry *ent = &static_table[idx];
    hd_nv nv = {(rcbuf *)&ent->name,
                (rcbuf *)&ent->value, ent->token,
                NV_FLAG_NONE};
    return nv;
  }
}

/*
 * Finalize indexed header representation reception.  The referenced
 * header is always emitted, and |*nv_out| is filled with that value.
 */
static void hd_inflate_commit_indexed(hd_inflater *inflater,
                                      hd_nv *nv_out) {
  hd_nv nv = hd_table_get(&inflater->ctx, inflater->index);

  DEBUGF("inflatehd: header emission: %s: %s\n", nv.name->base,
         nv.value->base);
  *nv_out = nv;
}

int rcbuf_new(rcbuf **rcbuf_ptr, size_t size) {
  uint8_t *p;

  p = default_malloc(sizeof(rcbuf) + size);

  if (p == NULL) {
    return ERR_NOMEM;
  }

  *rcbuf_ptr = (void *)p;

  (*rcbuf_ptr)->base = p + sizeof(rcbuf);
  (*rcbuf_ptr)->len = size;
  (*rcbuf_ptr)->ref = 1;

  return 0;
}

/*
 * Reads |inflater->left| bytes from the range [in, last) and performs
 * huffman decoding against them and pushes the result into the
 * |buffer|.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * ERR_NOMEM
 *   Out of memory
 * ERR_HEADER_COMP
 *   Huffman decoding failed
 */
static ssize_t hd_inflate_read_huff(hd_inflater *inflater,
                                    buf *buf, const uint8_t *in,
                                    const uint8_t *last) {
  ssize_t readlen;
  int fin = 0;
  if ((size_t)(last - in) >= inflater->left) {
    last = in + inflater->left;
    fin = 1;
  }
  readlen = hd_huff_decode(&inflater->huff_decode_ctx, buf, in,
                                   (size_t)(last - in), fin);

  if (readlen < 0) {
    DEBUGF("inflatehd: huffman decoding failed\n");
    return readlen;
  }
  if (hd_huff_decode_failure_state(&inflater->huff_decode_ctx)) {
    DEBUGF("inflatehd: huffman decoding failed\n");
    return ERR_HEADER_COMP;
  }

  inflater->left -= (size_t)readlen;
  return readlen;
}

/*
 * Reads |inflater->left| bytes from the range [in, last) and copies
 * them into the |buffer|.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * ERR_NOMEM
 *   Out of memory
 * ERR_HEADER_COMP
 *   Header decompression failed
 */
static ssize_t hd_inflate_read(hd_inflater *inflater, buf *buf,
                               const uint8_t *in, const uint8_t *last) {
  size_t len = BPF_MIN((size_t)(last - in), inflater->left);

	if (len > 0) {
		memcpy(buf->last, in, len);
	}
	buf->last += len;

  inflater->left -= len;
  return (ssize_t)len;
}

/*
 * Finalize literal header representation - new name- reception. If
 * header is emitted, |*nv_out| is filled with that value and 0 is
 * returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_newname(hd_inflater *inflater,
                                     hd_nv *nv_out) {
  hd_nv nv;
  int rv;

  if (inflater->no_index) {
    nv.flags = NV_FLAG_NO_INDEX;
  } else {
    nv.flags = NV_FLAG_NONE;
  }

  nv.name = inflater->namercbuf;
  nv.value = inflater->valuercbuf;
  nv.token = lookup_token(inflater->namercbuf->base, inflater->namercbuf->len);

  if (inflater->index_required) {
    DEBUGF("\tWARN: Incremental indexing ignored.\n");
  }

  DEBUGF("inflatehd: header emission: %s: %s\n", nv.name->base,
         nv.value->base);
  *nv_out = nv;

  inflater->nv_name_keep = nv.name;
  inflater->nv_value_keep = nv.value;

  inflater->namercbuf = NULL;
  inflater->valuercbuf = NULL;

  return 0;
}

/*
 * Finalize literal header representation - indexed name-
 * reception. If header is emitted, |*nv_out| is filled with that
 * value and 0 is returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_indname(hd_inflater *inflater,
                                     hd_nv *nv_out) {
  hd_nv nv;
  int rv;

  nv = hd_table_get(&inflater->ctx, inflater->index);

  if (inflater->no_index) {
    nv.flags = NV_FLAG_NO_INDEX;
  } else {
    nv.flags = NV_FLAG_NONE;
  }

  rcbuf_incref(nv.name);

  nv.value = inflater->valuercbuf;

  if (inflater->index_required) {
    DEBUGF("\tWARN: Incremental indexing ignored.\n");
  }

  DEBUGF("inflatehd: header emission: %s: %s\n", nv.name->base,
         nv.value->base);
  *nv_out = nv;

  inflater->nv_name_keep = nv.name;
  inflater->nv_value_keep = nv.value;

  inflater->valuercbuf = NULL;

  return 0;
}

static int hd_context_init(hd_context *context) {
  int rv;
  context->bad = 0;
  context->hd_table_bufsize_max = 1 << 12;  // HD_DEFAULT_MAX_BUFFER_SIZE;
	context->hd_table_len = 0;

  context->hd_table_bufsize = 0;
  context->next_seq = 0;

  return 0;
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

int hd_inflate_init(hd_inflater *inflater) {
  int rv;

  rv = hd_context_init(&inflater->ctx);
  if (rv != 0) {
    goto fail;
  }

  inflater->settings_hd_table_bufsize_max = 1 << 12;
  inflater->min_hd_table_bufsize_max = UINT32_MAX;

  inflater->nv_name_keep = NULL;
  inflater->nv_value_keep = NULL;

  inflater->opcode = HD_OPCODE_NONE;
  inflater->state = HD_STATE_INFLATE_START;

  buf_init(&inflater->namebuf);
  buf_init(&inflater->valuebuf);

  inflater->namercbuf = NULL;
  inflater->valuercbuf = NULL;

  inflater->huffman_encoded = 0;
  inflater->index = 0;
  inflater->left = 0;
  inflater->shift = 0;
  inflater->index_required = 0;
  inflater->no_index = 0;

  return 0;

fail:
  return rv;
}

int hd_inflate_new(hd_inflater **inflater_ptr) {
  int rv;
  hd_inflater *inflater;

  inflater = default_malloc(sizeof(hd_inflater));

  if (inflater == NULL) {
    return ERR_NOMEM;
  }

  rv = hd_inflate_init(inflater);

  if (rv != 0) {
    default_free(inflater);

    return rv;
  }

  *inflater_ptr = inflater;

  return 0;
}

ssize_t hd_inflate_hd_nv(hd_inflater *inflater, hd_nv *nv_out,
                         int *inflate_flags, const uint8_t *in, size_t inlen,
                         int in_final) {
  ssize_t rv = 0;
  const uint8_t *first = in;
  const uint8_t *last = in + inlen;
  int rfin = 0;
  int busy = 0;

  if (inflater->ctx.bad) {
    return ERR_HEADER_COMP;
  }

  DEBUGF("inflatehd: start state=%d\n", inflater->state);
  hd_inflate_keep_free(inflater);

  *inflate_flags = HD_INFLATE_NONE;
  for (; in != last || busy;) {
    busy = 0;
    switch (inflater->state) {
    case HD_STATE_EXPECT_TABLE_SIZE:
      if ((*in & 0xe0u) != 0x20u) {
        DEBUGF("inflatehd: header table size change was expected, but saw "
               "0x%02x as first byte",
               *in);
        rv = ERR_HEADER_COMP;
        goto fail;
      }
    /* fall through */
    case HD_STATE_INFLATE_START:
    case HD_STATE_OPCODE:
      if ((*in & 0xe0u) == 0x20u) {
        DEBUGF("inflatehd: header table size change\n");
        if (inflater->state == HD_STATE_OPCODE) {
          DEBUGF("inflatehd: header table size change must appear at the head "
                 "of header block\n");
          rv = ERR_HEADER_COMP;
          goto fail;
        }
        inflater->opcode = HD_OPCODE_INDEXED;
        inflater->state = HD_STATE_READ_TABLE_SIZE;
      } else if (*in & 0x80u) {
        DEBUGF("inflatehd: indexed repr\n");
        inflater->opcode = HD_OPCODE_INDEXED;
        inflater->state = HD_STATE_READ_INDEX;
      } else {
        if (*in == 0x40u || *in == 0 || *in == 0x10u) {
          DEBUGF("inflatehd: literal header repr - new name\n");
          inflater->opcode = HD_OPCODE_NEWNAME;
          inflater->state = HD_STATE_NEWNAME_CHECK_NAMELEN;
        } else {
          DEBUGF("inflatehd: literal header repr - indexed name\n");
          inflater->opcode = HD_OPCODE_INDNAME;
          inflater->state = HD_STATE_READ_INDEX;
        }
        inflater->index_required = (*in & 0x40) != 0;
        inflater->no_index = (*in & 0xf0u) == 0x10u;
        DEBUGF("inflatehd: indexing required=%d, no_index=%d\n",
               inflater->index_required, inflater->no_index);
        if (inflater->opcode == HD_OPCODE_NEWNAME) {
          ++in;
        }
      }
      inflater->left = 0;
      inflater->shift = 0;
      break;
    case HD_STATE_READ_TABLE_SIZE:
      rfin = 0;
      rv = hd_inflate_read_len(
          inflater, &rfin, in, last, 5,
          BPF_MIN(inflater->min_hd_table_bufsize_max,
                      inflater->settings_hd_table_bufsize_max));
      DEBUGF("inflatehd: read table size %zd bytes\n", rv);
      if (rv < 0) {
        goto fail;
      }
      in += rv;
      if (!rfin) {
        goto almost_ok;
      }
      DEBUGF("inflatehd: table_size=%zu\n", inflater->left);
      inflater->min_hd_table_bufsize_max = UINT32_MAX;
      inflater->ctx.hd_table_bufsize_max = inflater->left;
      DEBUGF("\tWARN: Shrink table size ignored.\n");
      // hd_context_shrink_table_size(&inflater->ctx, NULL);
      inflater->state = HD_STATE_INFLATE_START;
      break;
    case HD_STATE_READ_INDEX: {
      size_t prefixlen;

      if (inflater->opcode == HD_OPCODE_INDEXED) {
        prefixlen = 7;
      } else if (inflater->index_required) {
        prefixlen = 6;
      } else {
        prefixlen = 4;
      }

      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, prefixlen,
          (&inflater->ctx)->hd_table_len + STATIC_TABLE_LENGTH);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      if (!rfin) {
        goto almost_ok;
      }

      if (inflater->left == 0) {
        rv = ERR_HEADER_COMP;
        goto fail;
      }

      DEBUGF("inflatehd: index=%zu\n", inflater->left);
      if (inflater->opcode == HD_OPCODE_INDEXED) {
        inflater->index = inflater->left;
        --inflater->index;

        hd_inflate_commit_indexed(inflater, nv_out);

        inflater->state = HD_STATE_OPCODE;
        *inflate_flags |= HD_INFLATE_EMIT;
        return (ssize_t)(in - first);
      } else {
        inflater->index = inflater->left;
        --inflater->index;

        inflater->state = HD_STATE_CHECK_VALUELEN;
      }
      break;
    }
    case HD_STATE_NEWNAME_CHECK_NAMELEN:
      inflater->huffman_encoded = (*in & (1 << 7)) != 0;

      inflater->state = HD_STATE_NEWNAME_READ_NAMELEN;
      inflater->left = 0;
      inflater->shift = 0;
      DEBUGF("inflatehd: huffman encoded=%d\n", inflater->huffman_encoded != 0);
    /* Fall through */
    case HD_STATE_NEWNAME_READ_NAMELEN:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 7, HD_MAX_NV);
      if (rv < 0) {
        goto fail;
      }
      in += rv;
      if (!rfin) {
        DEBUGF("inflatehd: integer not fully decoded. current=%zu\n",
               inflater->left);

        goto almost_ok;
      }

      if (inflater->huffman_encoded) {
        (&inflater->huff_decode_ctx)->fstate = HUFF_ACCEPTED;

        inflater->state = HD_STATE_NEWNAME_READ_NAMEHUFF;

        rv = rcbuf_new(&inflater->namercbuf, inflater->left * 2 + 1);
      } else {
        inflater->state = HD_STATE_NEWNAME_READ_NAME;
        rv = rcbuf_new(&inflater->namercbuf, inflater->left + 1);
      }

      if (rv != 0) {
        goto fail;
      }

      buf_wrap_init(&inflater->namebuf, inflater->namercbuf->base,
                            inflater->namercbuf->len);

      break;
    case HD_STATE_NEWNAME_READ_NAMEHUFF:
      rv = hd_inflate_read_huff(inflater, &inflater->namebuf, in, last);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF("inflatehd: %zd bytes read\n", rv);

      if (inflater->left) {
        DEBUGF("inflatehd: still %zu bytes to go\n", inflater->left);

        goto almost_ok;
      }

      *inflater->namebuf.last = '\0';
      inflater->namercbuf->len = buf_len(&inflater->namebuf);

      inflater->state = HD_STATE_CHECK_VALUELEN;

      break;
    case HD_STATE_NEWNAME_READ_NAME:
      rv = hd_inflate_read(inflater, &inflater->namebuf, in, last);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF("inflatehd: %zd bytes read\n", rv);
      if (inflater->left) {
        DEBUGF("inflatehd: still %zu bytes to go\n", inflater->left);

        goto almost_ok;
      }

      *inflater->namebuf.last = '\0';
      inflater->namercbuf->len = buf_len(&inflater->namebuf);

      inflater->state = HD_STATE_CHECK_VALUELEN;

      break;
    case HD_STATE_CHECK_VALUELEN:
      // hd_inflate_set_huffman_encoded(inflater, in);
      inflater->huffman_encoded = (*in & (1 << 7)) != 0;

      inflater->state = HD_STATE_READ_VALUELEN;
      inflater->left = 0;
      inflater->shift = 0;
      DEBUGF("inflatehd: huffman encoded=%d\n", inflater->huffman_encoded != 0);
    /* Fall through */
    case HD_STATE_READ_VALUELEN:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 7, HD_MAX_NV);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      if (!rfin) {
        goto almost_ok;
      }

      DEBUGF("inflatehd: valuelen=%zu\n", inflater->left);

      if (inflater->huffman_encoded) {
        (&inflater->huff_decode_ctx)->fstate = HUFF_ACCEPTED;

        inflater->state = HD_STATE_READ_VALUEHUFF;

        rv = rcbuf_new(&inflater->valuercbuf, inflater->left * 2 + 1);
      } else {
        inflater->state = HD_STATE_READ_VALUE;

        rv = rcbuf_new(&inflater->valuercbuf, inflater->left + 1);
      }

      if (rv != 0) {
        goto fail;
      }

      buf_wrap_init(&inflater->valuebuf, inflater->valuercbuf->base,
                            inflater->valuercbuf->len);

      busy = 1;

      break;
    case HD_STATE_READ_VALUEHUFF:
      rv = hd_inflate_read_huff(inflater, &inflater->valuebuf, in, last);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF("inflatehd: %zd bytes read\n", rv);

      if (inflater->left) {
        DEBUGF("inflatehd: still %zu bytes to go\n", inflater->left);

        goto almost_ok;
      }

      *inflater->valuebuf.last = '\0';
      inflater->valuercbuf->len = buf_len(&inflater->valuebuf);

      if (inflater->opcode == HD_OPCODE_NEWNAME) {
        rv = hd_inflate_commit_newname(inflater, nv_out);
      } else {
        rv = hd_inflate_commit_indname(inflater, nv_out);
      }

      if (rv != 0) {
        goto fail;
      }

      inflater->state = HD_STATE_OPCODE;
      *inflate_flags |= HD_INFLATE_EMIT;

      return (ssize_t)(in - first);
    case HD_STATE_READ_VALUE:
      rv = hd_inflate_read(inflater, &inflater->valuebuf, in, last);
      if (rv < 0) {
        DEBUGF("inflatehd: value read failure %zd: %d\n", rv, (int)rv);
        goto fail;
      }

      in += rv;

      DEBUGF("inflatehd: %zd bytes read\n", rv);

      if (inflater->left) {
        DEBUGF("inflatehd: still %zu bytes to go\n", inflater->left);
        goto almost_ok;
      }

      *inflater->valuebuf.last = '\0';
      inflater->valuercbuf->len = buf_len(&inflater->valuebuf);

      if (inflater->opcode == HD_OPCODE_NEWNAME) {
        rv = hd_inflate_commit_newname(inflater, nv_out);
      } else {
        rv = hd_inflate_commit_indname(inflater, nv_out);
      }

      if (rv != 0) {
        goto fail;
      }

      inflater->state = HD_STATE_OPCODE;
      *inflate_flags |= HD_INFLATE_EMIT;

      return (ssize_t)(in - first);
    }
  }

  assert(in == last);

  DEBUGF("inflatehd: all input bytes were processed\n");

  if (in_final) {
    DEBUGF("inflatehd: in_final set\n");

    if (inflater->state != HD_STATE_OPCODE &&
        inflater->state != HD_STATE_INFLATE_START) {
      DEBUGF("inflatehd: unacceptable state=%d\n", inflater->state);
      rv = ERR_HEADER_COMP;

      goto fail;
    }
    *inflate_flags |= HD_INFLATE_FINAL;
  }
  return (ssize_t)(in - first);

almost_ok:
  if (in_final) {
    DEBUGF("inflatehd: input ended prematurely\n");

    rv = ERR_HEADER_COMP;

    goto fail;
  }
  return (ssize_t)(in - first);

fail:
  DEBUGF("inflatehd: error return %zd\n", rv);

  inflater->ctx.bad = 1;
  return rv;
}

ssize_t inflate_hd_block(hd_inflater* inflater, const uint8_t *in,
                         size_t inlen) {

  for (;;) {
    ssize_t rv;
    hd_nv nv;
    int inflate_flags = 0;
    size_t proclen;

    rv = hd_inflate_hd_nv(inflater, &nv, &inflate_flags, in, inlen, 1);

    if (rv < 0) {
      fprintf(stderr, "inflate failed with error code %zd", rv);
      return rv;
    }

    proclen = (size_t)rv;
    printf("proclen=%lu,inlen=%lu\n", proclen, inlen);

    in += proclen;
    inlen -= proclen;

    if (inlen == 0) {
      printf("dynamic table size: %zu\n", (&inflater->ctx)->hd_table_len);
    }

    if (inflate_flags & HD_INFLATE_EMIT) {
      fwrite(nv.name->base, 1, nv.name->len, stderr);
      fprintf(stderr, ": ");
      fwrite(nv.value->base, 1, nv.value->len, stderr);
      fprintf(stderr, "\n");
    }

    if (inflate_flags & HD_INFLATE_FINAL) {
      hd_inflate_keep_free(inflater);
      inflater->state = HD_STATE_INFLATE_START;
      break;
    }

    if ((inflate_flags & HD_INFLATE_EMIT) == 0 && inlen == 0) {
      break;
    }
  }

  return EXIT_SUCCESS;
}

int kmesh_parse_recv(hd_inflater* inflater, const uint8_t *in, size_t inlen) {
	/* WIP */
	return 1;
}

#include "kmesh_parse_http_2_0.h"

u32 parse_http_2_0_request(const struct bpf_mem_ptr *msg) {
	hd_inflater *inflater;
	int rv_inflater = hd_inflate_new(&inflater);
  if (rv_inflater != 0) {
    DEBUGF("hd_inflate_init failed with error: %d\n", rv_inflater);
    return 1;
  }
  return kmesh_parse_recv(inflater, msg->ptr, msg->size);
}

u32 parse_http_2_0_response(const struct bpf_mem_ptr *msg) {
  hd_inflater *inflater;
	int rv_inflater = hd_inflate_new(&inflater);
  if (rv_inflater != 0) {
    DEBUGF("hd_inflate_init failed with error: %d\n", rv_inflater);
    return 1;
  }
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

static inline u16 get_uint16(const u8 *data) {
  u16 n;
  memcpy(&n, data, sizeof(u16));
  return ntohs(n);
}

static inline u32 get_uint32(const u8 *data) {
  u32 n;
  memcpy(&n, data, sizeof(u32));
  return ntohl(n);
}

static inline void *default_malloc(size_t size) {
  return kmalloc(size, GFP_KERNEL);
}

static inline void default_free(void *ptr) {
  kfree(ptr);
}

static inline void *default_calloc(size_t nmemb, size_t size) {
  return kcalloc(nmemb, size, GFP_KERNEL);
}

static inline void *default_realloc(void *ptr, size_t size) {
  return krealloc(ptr, size, GFP_KERNEL);
}

/*
 * Frees |rcbuf| itself, regardless of its reference cout.
 */
inline void rcbuf_del(rcbuf *rcbuf) {
  default_free(rcbuf);
}

inline void rcbuf_incref(rcbuf *rcbuf) {
  if (rcbuf->ref == -1) {
    return;
  }

  ++rcbuf->ref;
}

inline void rcbuf_decref(rcbuf *rcbuf) {
  if (rcbuf == NULL || rcbuf->ref == -1) {
    return;
  }

  // assert(rcbuf->ref > 0);
	if (rcbuf->ref <= 0) {
		DEBUGF("\tWARN: rcbuf reference count <= 0\n");
	}

  if (--rcbuf->ref == 0) {
    rcbuf_del(rcbuf);
  }
}

inline void buf_init(buf *buf) {
  buf->begin = NULL;
  buf->end = NULL;
  buf->pos = NULL;
  buf->last = NULL;
  buf->mark = NULL;
}

inline int buf_init2(buf *buf, size_t initial) {
  buf_init(buf);
  return buf_reserve(buf, initial);
}

inline int buf_reserve(buf *buf, size_t new_cap) {
  u8 *ptr;
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

inline void buf_wrap_init(buf *buf, u8 *begin, size_t len) {
  buf->begin = buf->pos = buf->last = buf->mark = buf->end = begin;
  if (len) {
    buf->end += len;
  }
}

inline int buf_chain_new(buf_chain **chain, size_t chunk_length) {
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

inline int bufs_alloc_chain(bufs *bufs) {
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

inline int bufs_ensure_addb(bufs *bufs) {
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

int bufs_addb(bufs *bufs, u8 b) {
  int rv;

  rv = bufs_ensure_addb(bufs);
  if (rv != 0) {
    return rv;
  }

  *bufs->cur->buf.last++ = b;

  return 0;
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
static ssize_t decode_length(u32 *res, size_t *shift_ptr, int *fin,
                             u32 initial, size_t shift, const u8 *in,
                             const u8 *last, size_t prefix) {
  u32 k = (u8)((1 << prefix) - 1);
  u32 n = initial;
  const u8 *start = in;

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
    u32 add = *in & 0x7f;

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
                                   const u8 *in, const u8 *last,
                                   size_t prefix, size_t maxlen) {
  ssize_t rv;
  u32 out;

  *rfin = 0;

  rv = decode_length(&out, &inflater->shift, rfin, (u32)inflater->left,
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
  // assert(INDEX_RANGE_VALID(context, idx));
	if (!INDEX_RANGE_VALID(context, idx)) {
		DEBUGF("\tWARN: invalid index range.\n");
	}
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
                                    buf *buf, const u8 *in,
                                    const u8 *last) {
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
                               const u8 *in, const u8 *last) {
  size_t len = BPF_MIN((size_t)(last - in), inflater->left);

	if (len > 0) {
		memcpy(buf->last, in, len);
	}
	buf->last += len;

  inflater->left -= len;
  return (ssize_t)len;
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
  u8 *p;

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
  context->bad = 0;
  context->hd_table_bufsize_max = 1 << 12;  // HD_DEFAULT_MAX_BUFFER_SIZE;
	context->hd_table_len = 0;

  context->hd_table_bufsize = 0;
  context->next_seq = 0;

  return 0;
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
                         int *inflate_flags, const u8 *in, size_t inlen,
                         int in_final) {
  ssize_t rv = 0;
  const u8 *first = in;
  const u8 *last = in + inlen;
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

  // assert(in == last);

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

ssize_t inflate_hd_block(hd_inflater* inflater, const u8 *in,
                         size_t inlen) {

  for (;;) {
    ssize_t rv;
    hd_nv nv;
    int inflate_flags = 0;
    size_t proclen;

    rv = hd_inflate_hd_nv(inflater, &nv, &inflate_flags, in, inlen, 1);

    if (rv < 0) {
      DEBUGF("inflate failed with error code %zd", rv);
      return rv;
    }

    proclen = (size_t)rv;
    DEBUGF("proclen=%lu,inlen=%lu\n", proclen, inlen);

    in += proclen;
    inlen -= proclen;

    if (inlen == 0) {
      DEBUGF("dynamic table size: %zu\n", (&inflater->ctx)->hd_table_len);
    }

    if (inflate_flags & HD_INFLATE_EMIT) {
      DEBUGF("name=%s, namelen=%lu, value=%s, valuelen=%lu",
			       nv.name->base, nv.name->len, nv.value->base, nv.value->len);
    }

		/* add header field to rbtree */
		struct kmesh_data_node *node = new_kmesh_data_node(nv.name->len);
		node->value.ptr = nv.value->base;
		node->value.size = nv.value->len;
		(void)strncpy(node->keystring, nv.name->base, nv.name->len);
    if (!kmesh_protocol_data_insert(node))
      delete_kmesh_data_node(&node);

    if (inflate_flags & HD_INFLATE_FINAL) {
      hd_inflate_keep_free(inflater);
      inflater->state = HD_STATE_INFLATE_START;
      break;
    }

    if ((inflate_flags & HD_INFLATE_EMIT) == 0 && inlen == 0) {
      break;
    }
  }

  return 0;
}

static const u8 static_in[] = {0};

int kmesh_parse_recv(hd_inflater* inflater, const u8 *in, size_t inlen) {
  http2_frame frame;
	/* todo: deal with client magic */
  inbound_state frame_state = IB_READ_HEAD;
  bpf_memset(&frame, 0, sizeof(http2_frame));

  size_t payloadleft;
  size_t padlen;

  const u8 *first, *last;
  size_t readlen;
  int rv;
  int busy;
	payloadleft = 0;
	padlen = 0;
	rv = 0;
	busy = 0;

  if (in == NULL) {
    // assert(inlen == 0);
		if (inlen != 0) {
			DEBUGF("\tWARN: empty input\n");
		}
    in = static_in;
  }

  first = in;
  last = in + inlen;

  for (;;) {
    switch (frame_state) {
    case IB_READ_CLIENT_MAGIC:
      DEBUGF("recv: [IB_READ_CLIENT_MAGIC]\n");
      /* todo */
      break;

    case IB_READ_FIRST_SETTINGS:
      DEBUGF("recv: [IB_READ_FIRST_SETTINGS]\n");
      readlen = last - in;
      in += readlen;
			/* todo */
      break;

    /* Fall through */
    case IB_READ_HEAD: {
      DEBUGF("recv: [IB_READ_HEAD]\n");

      frame_hd *hd = &frame.hd;
			control_frame *ctrl = &frame.ctrl;

      // unpack frame header
      hd->length = get_uint32(&in[0]) >> 8;
      hd->type = in[3];
      hd->flags = in[4];
      hd->stream_id = get_uint32(&in[5]) & STREAM_ID_MASK;
      hd->reserved = 0;

      in += FRAME_HDLEN;

      // payload not including head, including Exclusive flag and stream dependency
      payloadleft = hd->length;
      DEBUGF("recv: payloadlen=%zu, type=%u, flags=0x%02x, stream_id=%d\n",
             hd->length, hd->type, hd->flags, hd->stream_id);

      // todo: deal with oversized header (if length > max_frame_size)

      switch (hd->type) {
      case DATA:
        DEBUGF("recv: DATA\n");
				in += payloadleft;
        /* todo */
        break;
      
      case HEADERS:
        DEBUGF("recv: HEADERS\n");
        hd->flags &=
            (FLAG_END_STREAM | FLAG_END_HEADERS |
             FLAG_PADDED | FLAG_PRIORITY);
        
        // padding
        if (hd->flags & FLAG_PADDED) {
          // todo: handle padding error
          frame_state = IB_READ_NBYTE;
          break;
        } else {
          DEBUGF("recv: no padding in payload\n");
        }

        busy = 1;

        frame_state = IB_READ_HEADER_BLOCK;

        break;
      
      case PRIORITY:
        DEBUGF("recv: PRIORITY\n");
				ctrl->payloadlen = hd->length;
				in += payloadleft;
        /* todo */
        break;

      case RST_STREAM:
        DEBUGF("recv: RST_STREAM\n");
      case WINDOW_UPDATE:
        DEBUGF("recv: WINDOW_UPDATE\n");
				ctrl->payloadlen = hd->length;
				in += payloadleft;
        /* todo */
        break;
      
      case SETTINGS:
        DEBUGF("recv: SETTINGS\n");
        hd->flags &= FLAG_ACK;
				ctrl->payloadlen = hd->length;

        frame_state = IB_READ_SETTINGS;

        busy = 1;

        break;

      case PUSH_PROMISE:
        DEBUGF("recv: PUSH_PROMISE\n");
				ctrl->payloadlen = hd->length;
        /* todo */
				in += payloadleft;
        break;
      
      case PING:
        DEBUGF("recv: PING\n");
				ctrl->payloadlen = hd->length;
        /* todo */
				in += payloadleft;
        break;
      
      case GOAWAY:
        DEBUGF("recv: GOAWAY\n");
				ctrl->payloadlen = hd->length;
        /* todo */
				in += payloadleft;
        break;
      
      case CONTINUATION:
        DEBUGF("recv: unexpected CONTINUATION\n");
        return (int)inlen;
      
      default:
        DEBUGF("recv: extension frame\n");
				ctrl->payloadlen = hd->length;
        /* todo */
				in += payloadleft;
        break;
      }
      break;
    }

    case IB_READ_NBYTE:
      DEBUGF("recv: [IB_READ_NBYTE]\n");

      readlen = last - in;
      /* todo: test buffer availability */

      DEBUGF("recv: readlen=%zu, payloadleft=%zu\n", readlen, payloadleft);

      switch (frame.hd.type) {
      case HEADERS:
        if (padlen == 0 && (frame.hd.flags & FLAG_PADDED)) {
          DEBUGF("\tWARN: padding ignored.\n");
        }
        busy = 1;

        if (frame_state == IB_IGN_ALL) {
          return (ssize_t)inlen;
        }

        frame_state = IB_READ_HEADER_BLOCK;

        break;
      
      default:
        break;
      }
      break;

    case IB_READ_HEADER_BLOCK:
      DEBUGF("recv: [IB_READ_HEADER_BLOCK]\n");
    case IB_IGN_HEADER_BLOCK:
      DEBUGF("recv: [IB_IGN_HEADER_BLOCK]\n");

      int final;

      readlen = BPF_MIN((size_t)(last - in), payloadleft);

      DEBUGF("recv: readlen=%zu, payloadleft=%zu\n", readlen,
             payloadleft - readlen);

      if (readlen == -1) {
        /* everything is padding */
        DEBUGF("recv: readlen = -1, everything is padding\n");
        readlen = 0;
      }

      final = (frame.hd.flags & FLAG_END_HEADERS) &&  payloadleft == readlen;

      if (readlen > 0 || (readlen == 0 && final)) {
        DEBUGF("recv: block final=%d\n", final);

        rv = inflate_hd_block(inflater, in, readlen);
        in += readlen;
        payloadleft -= readlen;
      } else {
        DEBUGF("recv: everything is padding\n");
        in += readlen;
        payloadleft -= readlen;
      }

      if (payloadleft) {
        break;
      }
      
      if ((frame.hd.flags & FLAG_END_HEADERS) == 0) {  // if END_HEADERS is set
        in = last;
        padlen = 0;
        if (frame_state == IB_READ_HEADER_BLOCK) {
          frame_state = IB_EXPECT_CONTINUATION;
        } else {
          frame_state = IB_IGN_CONTINUATION;
        }
      } else {
        if (frame_state == IB_READ_HEADER_BLOCK) {
          /* todo: more than 1 header frames */
        }
      }
      
      /* todo */
      break;
    
    case IB_IGN_PAYLOAD:
      DEBUGF("recv: [IB_IGN_PAYLOAD]\n");
      /* todo */
      break;

    case IB_FRAME_SIZE_ERROR:
      DEBUGF("recv: [IB_FRAME_SIZE_ERROR]\n");
      /* todo */
      return (int)inlen;
    
    case IB_READ_SETTINGS:
      DEBUGF("recv: [IB_READ_SETTINGS]\n");
      
      if (frame_state == IB_IGN_ALL) {
        return (ssize_t)inlen;
      }

			in += payloadleft;

      break;

    case IB_READ_GOAWAY_DEBUG:
      DEBUGF("recv: [IB_READ_GOAWAY_DEBUG]\n");
      /* todo */
      break;

    case IB_EXPECT_CONTINUATION:
      DEBUGF("recv: [IB_EXPECT_CONTINUATION]\n");
    case IB_IGN_CONTINUATION:
      DEBUGF("recv: [IB_IGN_CONTINUATION]\n");
      /* todo */
      break;

    case IB_READ_PAD_DATA:
      DEBUGF("recv: [IB_READ_PAD_DATA]\n");
      /* todo */
      break;
    
    case IB_READ_DATA:
      DEBUGF("recv: [IB_READ_DATA]\n");
      /* todo */
      break;
    
    case IB_IGN_DATA:
      DEBUGF("recv: [IB_IGN_DATA]\n");
      /* todo */
      break;
    
    case IB_IGN_ALL:
      DEBUGF("recv: [IB_IGN_ALL]\n");
      return (ssize_t)inlen;
    
    case IB_READ_EXTENSION_PAYLOAD:
      DEBUGF("recv: [IB_READ_EXTENSION_PAYLOAD]\n");
      /* todo */
      break;
    
    case IB_READ_ALTSVC_PAYLOAD:
      DEBUGF("recv: [IB_READ_ALTSVC_PAYLOAD]\n");
      /* todo */
      break;
    
    case IB_READ_ORIGIN_PAYLOAD:
      DEBUGF("recv: [IB_READ_ORIGIN_PAYLOAD]\n");
      /* todo */
      break;

    default:
      break;
    }  // switch (frame_state)

    if (!busy && in == last) {
      break;
    }

    busy = 0;
  }  // for (;;)

  return rv;

}

static inline int memeq(const void *s1, const void *s2, size_t n) {
  return memcmp(s1, s2, n) == 0;
}

int32_t lookup_token(const u8 *name, size_t namelen) {
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

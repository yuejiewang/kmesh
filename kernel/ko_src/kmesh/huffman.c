#include "huffman.h"

void hd_huff_decode_context_init(hd_huff_decode_context *ctx) {
  ctx->fstate = HUFF_ACCEPTED;
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

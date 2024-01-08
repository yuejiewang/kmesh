#ifndef HD_HUFFMAN_H
#define HD_HUFFMAN_H

#include "kmesh_http_2_0_data.h"

typedef enum {
  HUFF_ACCEPTED = 1 << 14,
  HUFF_SYM = 1 << 15,
} huff_decode_flag;

typedef struct {
  u16 fstate;
  u8 sym;
} huff_decode;

typedef huff_decode huff_decode_table_type[16];

typedef struct {
  /* fstate is the current huffman decoding state. */
  u16 fstate;
} hd_huff_decode_context;

typedef struct {
  /* The number of bits in this code */
  u32 nbits;
  /* Huffman code aligned to LSB */
  u32 code;
} huff_sym;

extern const huff_sym huff_sym_table[];
extern const huff_decode huff_decode_table[][16];

void hd_huff_decode_context_init(hd_huff_decode_context *ctx);
ssize_t hd_huff_decode(hd_huff_decode_context *ctx,
                       buf *buf, const u8 *src,
                       size_t srclen, int final);
int hd_huff_decode_failure_state(hd_huff_decode_context *ctx);

#endif /* HD_HUFFMAN_H */
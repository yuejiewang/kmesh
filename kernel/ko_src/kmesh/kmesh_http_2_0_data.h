#ifndef KMESH_HTTP_2_0_DATA_H
#define KMESH_HTTP_2_0_DATA_H

/* FIXME:
 * remove header files
 * fix int types
 */
#include <stdint.h>
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t
#define ssize_t int32_t
#define size_t uint32_t

typedef struct {
  /* This points to the beginning of the buffer. The effective range
     of buffer is [begin, end). */
  uint8_t *begin;
  /* This points to the memory one byte beyond the end of the
     buffer. */
  uint8_t *end;
  /* The position indicator for effective start of the buffer. pos <=
     last must be hold. */
  uint8_t *pos;
  /* The position indicator for effective one beyond of the end of the
     buffer. last <= end must be hold. */
  uint8_t *last;
  /* Mark arbitrary position in buffer [begin, end) */
  uint8_t *mark;
} buf;  // nghttp2_buf.h

/* Chains 2 buffers */
struct buf_chain {
  /* Points to the subsequent buffer. NULL if there is no such
     buffer. */
  struct buf_chain *next;
  buf buf;
};  // nghttp2_buf.h
typedef struct buf_chain buf_chain;

typedef struct {
  /* Points to the first buffer */
  buf_chain *head;
  /* Buffer pointer where write occurs. */
  buf_chain *cur;
  /* Memory allocator */
  void *mem_user_data;
  /* The buffer capacity of each buf.  This field may be 0 if
     bufs is initialized by bufs_wrap_init* family
     functions. */
  size_t chunk_length;
  /* The maximum number of buf_chain */
  size_t max_chunk;
  /* The number of buf_chain allocated */
  size_t chunk_used;
  /* The number of buf_chain to keep on reset */
  size_t chunk_keep;
  /* pos offset from begin in each buffers. On initialization and
     reset, buf->pos and buf->last are positioned at buf->begin +
     offset. */
  size_t offset;
} bufs;  // nghttp2_buf.h

/**
 * @enum
 *
 * Error codes used in this library.  The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  ERR_INVALID_ARGUMENT = -501,
  /**
   * Out of buffer space.
   */
  ERR_BUFFER_ERROR = -502,
  /**
   * The specified protocol version is not supported.
   */
  ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback`,
   * :type:`nghttp2_recv_callback` and
   * :type:`nghttp2_send_data_callback` to indicate that the operation
   * would block.
   */
  ERR_WOULDBLOCK = -504,
  /**
   * General protocol error
   */
  ERR_PROTO = -505,
  /**
   * The frame is invalid.
   */
  ERR_INVALID_FRAME = -506,
  /**
   * The peer performed a shutdown on the connection.
   */
  ERR_EOF = -507,
  /**
   * Used as a return value from
   * :func:`data_source_read_callback` to indicate that data
   * transfer is postponed.  See
   * :func:`data_source_read_callback` for details.
   */
  ERR_DEFERRED = -508,
  /**
   * Stream ID has reached the maximum value.  Therefore no stream ID
   * is available.
   */
  ERR_STREAM_ID_NOT_AVAILABLE = -509,
  /**
   * The stream is already closed; or the stream ID is invalid.
   */
  ERR_STREAM_CLOSED = -510,
  /**
   * RST_STREAM has been added to the outbound queue.  The stream is
   * in closing state.
   */
  ERR_STREAM_CLOSING = -511,
  /**
   * The transmission is not allowed for this stream (e.g., a frame
   * with END_STREAM flag set has already sent).
   */
  ERR_STREAM_SHUT_WR = -512,
  /**
   * The stream ID is invalid.
   */
  ERR_INVALID_STREAM_ID = -513,
  /**
   * The state of the stream is not valid (e.g., DATA cannot be sent
   * to the stream if response HEADERS has not been sent).
   */
  ERR_INVALID_STREAM_STATE = -514,
  /**
   * Another DATA frame has already been deferred.
   */
  ERR_DEFERRED_DATA_EXIST = -515,
  /**
   * Starting new stream is not allowed (e.g., GOAWAY has been sent
   * and/or received).
   */
  ERR_START_STREAM_NOT_ALLOWED = -516,
  /**
   * GOAWAY has already been sent.
   */
  ERR_GOAWAY_ALREADY_SENT = -517,
  /**
   * The received frame contains the invalid header block (e.g., There
   * are duplicate header names; or the header names are not encoded
   * in US-ASCII character set and not lower cased; or the header name
   * is zero-length string; or the header value contains multiple
   * in-sequence NUL bytes).
   */
  ERR_INVALID_HEADER_BLOCK = -518,
  /**
   * Indicates that the context is not suitable to perform the
   * requested operation.
   */
  ERR_INVALID_STATE = -519,
  /**
   * The user callback function failed due to the temporal error.
   */
  ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  /**
   * The length of the frame is invalid, either too large or too small.
   */
  ERR_FRAME_SIZE_ERROR = -522,
  /**
   * Header block inflate/deflate error.
   */
  ERR_HEADER_COMP = -523,
  /**
   * Flow control error
   */
  ERR_FLOW_CONTROL = -524,
  /**
   * Insufficient buffer size given to function.
   */
  ERR_INSUFF_BUFSIZE = -525,
  /**
   * Callback was paused by the application
   */
  ERR_PAUSE = -526,
  /**
   * There are too many in-flight SETTING frame and no more
   * transmission of SETTINGS is allowed.
   */
  ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
  /**
   * The server push is disabled.
   */
  ERR_PUSH_DISABLED = -528,
  /**
   * DATA or HEADERS frame for a given stream has been already
   * submitted and has not been fully processed yet.  Application
   * should wait for the transmission of the previously submitted
   * frame before submitting another.
   */
  ERR_DATA_EXIST = -529,
  /**
   * The current session is closing due to a connection error or
   * `session_terminate_session()` is called.
   */
  ERR_SESSION_CLOSING = -530,
  /**
   * Invalid HTTP header field was received and stream is going to be
   * closed.
   */
  ERR_HTTP_HEADER = -531,
  /**
   * Violation in HTTP messaging rule.
   */
  ERR_HTTP_MESSAGING = -532,
  /**
   * Stream was refused.
   */
  ERR_REFUSED_STREAM = -533,
  /**
   * Unexpected internal error, but recovered.
   */
  ERR_INTERNAL = -534,
  /**
   * Indicates that a processing was canceled.
   */
  ERR_CANCEL = -535,
  /**
   * When a local endpoint expects to receive SETTINGS frame, it
   * receives an other type of frame.
   */
  ERR_SETTINGS_EXPECTED = -536,
  /**
   * When a local endpoint receives too many settings entries
   * in a single SETTINGS frame.
   */
  ERR_TOO_MANY_SETTINGS = -537,
  /**
   * The errors < :enum:`error.ERR_FATAL` mean that
   * the library is under unexpected condition and processing was
   * terminated (e.g., out of memory).  If application receives this
   * error code, it must stop using that :type:`nghttp2_session`
   * object and only allowed operation for that object is deallocate
   * it using `nghttp2_session_del()`.
   */
  ERR_FATAL = -900,
  /**
   * Out of memory.  This is a fatal error.
   */
  ERR_NOMEM = -901,
  /**
   * The user callback function failed.  This is a fatal error.
   */
  ERR_CALLBACK_FAILURE = -902,
  /**
   * Invalid client magic (see :macro:`CLIENT_MAGIC`) was
   * received and further processing is not possible.
   */
  ERR_BAD_CLIENT_MAGIC = -903,
  /**
   * Possible flooding by peer was detected in this HTTP/2 session.
   * Flooding is measured by how many PING and SETTINGS frames with
   * ACK flag set are queued for transmission.  These frames are
   * response for the peer initiated frames, and peer can cause memory
   * exhaustion on server side to send these frames forever and does
   * not read network.
   */
  ERR_FLOODED = -904
} error;

#endif  /* KMESH_HTTP_2_0_DATA_H */
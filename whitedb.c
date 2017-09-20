#include <whitedb.h>
/* 
 * zlib/libpng license
 * Copyright (c) 2000-2004 mypapit
 * 
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the authors be held liable for any damages arising from the 
 * use of this software. 
 * 
 * Permission is granted to anyone to use this software for any purpose, including 
 * commercial applications, and to alter it and redistribute it freely, subject to 
 * the following restrictions:
 * 
 * 1. The origin of this software must not be misrepresented; you must not claim 
 * that you wrote the original software. If you use this software in a product, an 
 * acknowledgment in the product documentation would be appreciated but is not required.
 * 
 * 2. Altered source versions must be plainly marked as such, and must not be 
 * misrepresented as being the original software.
 * 
 * 3. This notice may not be removed or altered from any source distribution.
 */

 /** @file crc1.h
 *  CRC32 calculator from minicrc project.
 */

/* table of CRC-32's of all single-byte values (made by makecrc.c) */
gint32 crc_table[256] = {
  0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
  0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
  0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
  0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
  0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
  0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
  0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
  0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
  0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
  0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
  0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
  0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
  0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
  0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
  0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
  0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
  0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
  0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
  0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
  0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
  0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
  0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
  0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
  0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
  0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
  0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
  0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
  0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
  0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
  0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
  0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
  0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
  0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
  0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
  0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
  0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
  0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
  0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
  0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
  0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
  0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
  0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
  0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
  0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
  0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
  0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
  0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
  0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
  0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
  0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
  0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
  0x2d02ef8dL
};

static gint32 update_crc32(char *buf, gint n, gint32 crc) {
  register gint i;

  crc ^= 0xffffffff;
  for (i=0; i<n; i++)
    crc = crc_table[0xff & (buf[i] ^ crc)] ^ (crc >> 8);

  return crc ^= 0xffffffff;
}

/*
 * Copyright (c) 2007-2011, Lloyd Hilaiel <lloyd@hilaiel.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <math.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

//jl_api.h"
//jl_all.h"

#define YAJL_BUF_INIT_SIZE 2048

/* There seem to be some environments where long long is supported but
 * LLONG_MAX and LLONG_MIN are not defined. This is a safe workaround
 * (parsing large integers may break however).
 */
#ifndef LLONG_MAX
#define LLONG_MAX LONG_MAX
#define LLONG_MIN LONG_MIN
#endif

#ifdef _WIN32
#define snprintf(s, sz, f, ...) _snprintf_s(s, sz+1, sz, f, ## __VA_ARGS__)
#endif

struct yajl_buf_t {
    size_t len;
    size_t used;
    unsigned char * data;
    yajl_alloc_funcs * alloc;
};

typedef enum {
    yajl_gen_start,
    yajl_gen_map_start,
    yajl_gen_map_key,
    yajl_gen_map_val,
    yajl_gen_array_start,
    yajl_gen_in_array,
    yajl_gen_complete,
    yajl_gen_error
} yajl_gen_state;

struct yajl_gen_t
{
    unsigned int flags;
    unsigned int depth;
    const char * indentString;
    yajl_gen_state state[YAJL_MAX_DEPTH];
    yajl_print_t print;
    void * ctx; /* yajl_buf */
    /* memory allocation routines */
    yajl_alloc_funcs alloc;
};

struct yajl_lexer_t {
    /* the overal line and char offset into the data */
    size_t lineOff;
    size_t charOff;

    /* error */
    yajl_lex_error error;

    /* a input buffer to handle the case where a token is spread over
     * multiple chunks */
    yajl_buf buf;

    /* in the case where we have data in the lexBuf, bufOff holds
     * the current offset into the lexBuf. */
    size_t bufOff;

    /* are we using the lex buf? */
    unsigned int bufInUse;

    /* shall we allow comments? */
    unsigned int allowComments;

    /* shall we validate utf8 inside strings? */
    unsigned int validateUTF8;

    yajl_alloc_funcs * alloc;
};


static void * yajl_internal_malloc(void *ctx, size_t sz)
{
    (void)ctx;
    return malloc(sz);
}

static void * yajl_internal_realloc(void *ctx, void * previous,
                                    size_t sz)
{
    (void)ctx;
    return realloc(previous, sz);
}

static void yajl_internal_free(void *ctx, void * ptr)
{
    (void)ctx;
    free(ptr);
}

static void yajl_set_default_alloc_funcs(yajl_alloc_funcs * yaf)
{
    yaf->malloc = yajl_internal_malloc;
    yaf->free = yajl_internal_free;
    yaf->realloc = yajl_internal_realloc;
    yaf->ctx = NULL;
}

static
void yajl_buf_ensure_available(yajl_buf buf, size_t want)
{
    size_t need;

    assert(buf != NULL);

    /* first call */
    if (buf->data == NULL) {
        buf->len = YAJL_BUF_INIT_SIZE;
        buf->data = (unsigned char *) YA_MALLOC(buf->alloc, buf->len);
        buf->data[0] = 0;
    }

    need = buf->len;

    while (want >= (need - buf->used)) need <<= 1;

    if (need != buf->len) {
        buf->data = (unsigned char *) YA_REALLOC(buf->alloc, buf->data, need);
        buf->len = need;
    }
}

static yajl_buf yajl_buf_alloc(yajl_alloc_funcs * alloc)
{
    yajl_buf b = YA_MALLOC(alloc, sizeof(struct yajl_buf_t));
    memset((void *) b, 0, sizeof(struct yajl_buf_t));
    b->alloc = alloc;
    return b;
}

static void yajl_buf_free(yajl_buf buf)
{
    assert(buf != NULL);
    if (buf->data) YA_FREE(buf->alloc, buf->data);
    YA_FREE(buf->alloc, buf);
}

static void yajl_buf_append(yajl_buf buf, const void * data, size_t len)
{
    yajl_buf_ensure_available(buf, len);
    if (len > 0) {
        assert(data != NULL);
        memcpy(buf->data + buf->used, data, len);
        buf->used += len;
        buf->data[buf->used] = 0;
    }
}

static void yajl_buf_clear(yajl_buf buf)
{
    buf->used = 0;
    if (buf->data) buf->data[buf->used] = 0;
}

static const unsigned char * yajl_buf_data(yajl_buf buf)
{
    return buf->data;
}

static size_t yajl_buf_len(yajl_buf buf)
{
    return buf->used;
}

const char *
yajl_status_to_string(yajl_status stat)
{
    const char * statStr = "unknown";
    switch (stat) {
        case yajl_status_ok:
            statStr = "ok, no error";
            break;
        case yajl_status_client_canceled:
            statStr = "client canceled parse";
            break;
        case yajl_status_error:
            statStr = "parse error";
            break;
    }
    return statStr;
}

yajl_handle
yajl_alloc(const yajl_callbacks * callbacks,
           yajl_alloc_funcs * afs,
           void * ctx)
{
    yajl_handle hand = NULL;
    yajl_alloc_funcs afsBuffer;

    /* first order of business is to set up memory allocation routines */
    if (afs != NULL) {
        if (afs->malloc == NULL || afs->realloc == NULL || afs->free == NULL)
        {
            return NULL;
        }
    } else {
        yajl_set_default_alloc_funcs(&afsBuffer);
        afs = &afsBuffer;
    }

    hand = (yajl_handle) YA_MALLOC(afs, sizeof(struct yajl_handle_t));

    /* copy in pointers to allocation routines */
    memcpy((void *) &(hand->alloc), (void *) afs, sizeof(yajl_alloc_funcs));

    hand->callbacks = callbacks;
    hand->ctx = ctx;
    hand->lexer = NULL;
    hand->bytesConsumed = 0;
    hand->decodeBuf = yajl_buf_alloc(&(hand->alloc));
    hand->flags	    = 0;
    yajl_bs_init(hand->stateStack, &(hand->alloc));
    yajl_bs_push(hand->stateStack, yajl_state_start);

    return hand;
}

int
yajl_config(yajl_handle h, yajl_option opt, ...)
{
    int rv = 1;
    va_list ap;
    va_start(ap, opt);

    switch(opt) {
        case yajl_allow_comments:
        case yajl_dont_validate_strings:
        case yajl_allow_trailing_garbage:
        case yajl_allow_multiple_values:
        case yajl_allow_partial_values:
            if (va_arg(ap, int)) h->flags |= opt;
            else h->flags &= ~opt;
            break;
        default:
            rv = 0;
    }
    va_end(ap);

    return rv;
}

void
yajl_free(yajl_handle handle)
{
    yajl_bs_free(handle->stateStack);
    yajl_buf_free(handle->decodeBuf);
    if (handle->lexer) {
        yajl_lex_free(handle->lexer);
        handle->lexer = NULL;
    }
    YA_FREE(&(handle->alloc), handle);
}

yajl_status
yajl_parse(yajl_handle hand, const unsigned char * jsonText,
           size_t jsonTextLen)
{
    yajl_status status;

    /* lazy allocation of the lexer */
    if (hand->lexer == NULL) {
        hand->lexer = yajl_lex_alloc(&(hand->alloc),
                                     hand->flags & yajl_allow_comments,
                                     !(hand->flags & yajl_dont_validate_strings));
    }

    status = yajl_do_parse(hand, jsonText, jsonTextLen);
    return status;
}


yajl_status
yajl_complete_parse(yajl_handle hand)
{
    /* The lexer is lazy allocated in the first call to parse.  if parse is
     * never called, then no data was provided to parse at all.  This is a
     * "premature EOF" error unless yajl_allow_partial_values is specified.
     * allocating the lexer now is the simplest possible way to handle this
     * case while preserving all the other semantics of the parser
     * (multiple values, partial values, etc). */
    if (hand->lexer == NULL) {
        hand->lexer = yajl_lex_alloc(&(hand->alloc),
                                     hand->flags & yajl_allow_comments,
                                     !(hand->flags & yajl_dont_validate_strings));
    }

    return yajl_do_finish(hand);
}

unsigned char *
yajl_get_error(yajl_handle hand, int verbose,
               const unsigned char * jsonText, size_t jsonTextLen)
{
    return yajl_render_error_string(hand, jsonText, jsonTextLen, verbose);
}

size_t
yajl_get_bytes_consumed(yajl_handle hand)
{
    if (!hand) return 0;
    else return hand->bytesConsumed;
}


void
yajl_free_error(yajl_handle hand, unsigned char * str)
{
    /* use memory allocation functions if set */
    YA_FREE(&(hand->alloc), str);
}


static void CharToHex(unsigned char c, char * hexBuf)
{
    const char * hexchar = "0123456789ABCDEF";
    hexBuf[0] = hexchar[c >> 4];
    hexBuf[1] = hexchar[c & 0x0F];
}

static void
yajl_string_encode(const yajl_print_t print,
                   void * ctx,
                   const unsigned char * str,
                   size_t len,
                   int escape_solidus)
{
    size_t beg = 0;
    size_t end = 0;
    char hexBuf[7];
    hexBuf[0] = '\\'; hexBuf[1] = 'u'; hexBuf[2] = '0'; hexBuf[3] = '0';
    hexBuf[6] = 0;

    while (end < len) {
        const char * escaped = NULL;
        switch (str[end]) {
            case '\r': escaped = "\\r"; break;
            case '\n': escaped = "\\n"; break;
            case '\\': escaped = "\\\\"; break;
            /* it is not required to escape a solidus in JSON:
             * read sec. 2.5: http://www.ietf.org/rfc/rfc4627.txt
             * specifically, this production from the grammar:
             *   unescaped = %x20-21 / %x23-5B / %x5D-10FFFF
             */
            case '/': if (escape_solidus) escaped = "\\/"; break;
            case '"': escaped = "\\\""; break;
            case '\f': escaped = "\\f"; break;
            case '\b': escaped = "\\b"; break;
            case '\t': escaped = "\\t"; break;
            default:
                if ((unsigned char) str[end] < 32) {
                    CharToHex(str[end], hexBuf + 4);
                    escaped = hexBuf;
                }
                break;
        }
        if (escaped != NULL) {
            print(ctx, (const char *) (str + beg), end - beg);
            print(ctx, escaped, (unsigned int)strlen(escaped));
            beg = ++end;
        } else {
            ++end;
        }
    }
    print(ctx, (const char *) (str + beg), end - beg);
}

static void hexToDigit(unsigned int * val, const unsigned char * hex)
{
    unsigned int i;
    for (i=0;i<4;i++) {
        unsigned char c = hex[i];
        if (c >= 'A') c = (c & ~0x20) - 7;
        c -= '0';
        assert(!(c & 0xF0));
        *val = (*val << 4) | c;
    }
}

static void Utf32toUtf8(unsigned int codepoint, char * utf8Buf)
{
    if (codepoint < 0x80) {
        utf8Buf[0] = (char) codepoint;
        utf8Buf[1] = 0;
    } else if (codepoint < 0x0800) {
        utf8Buf[0] = (char) ((codepoint >> 6) | 0xC0);
        utf8Buf[1] = (char) ((codepoint & 0x3F) | 0x80);
        utf8Buf[2] = 0;
    } else if (codepoint < 0x10000) {
        utf8Buf[0] = (char) ((codepoint >> 12) | 0xE0);
        utf8Buf[1] = (char) (((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[2] = (char) ((codepoint & 0x3F) | 0x80);
        utf8Buf[3] = 0;
    } else if (codepoint < 0x200000) {
        utf8Buf[0] =(char)((codepoint >> 18) | 0xF0);
        utf8Buf[1] =(char)(((codepoint >> 12) & 0x3F) | 0x80);
        utf8Buf[2] =(char)(((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[3] =(char)((codepoint & 0x3F) | 0x80);
        utf8Buf[4] = 0;
    } else {
        utf8Buf[0] = '?';
        utf8Buf[1] = 0;
    }
}

static void yajl_string_decode(yajl_buf buf, const unsigned char * str,
                        size_t len)
{
    size_t beg = 0;
    size_t end = 0;

    while (end < len) {
        if (str[end] == '\\') {
            char utf8Buf[5];
            const char * unescaped = "?";
            yajl_buf_append(buf, str + beg, end - beg);
            switch (str[++end]) {
                case 'r': unescaped = "\r"; break;
                case 'n': unescaped = "\n"; break;
                case '\\': unescaped = "\\"; break;
                case '/': unescaped = "/"; break;
                case '"': unescaped = "\""; break;
                case 'f': unescaped = "\f"; break;
                case 'b': unescaped = "\b"; break;
                case 't': unescaped = "\t"; break;
                case 'u': {
                    unsigned int codepoint = 0;
                    hexToDigit(&codepoint, str + ++end);
                    end+=3;
                    /* check if this is a surrogate */
                    if ((codepoint & 0xFC00) == 0xD800) {
                        end++;
                        if (str[end] == '\\' && str[end + 1] == 'u') {
                            unsigned int surrogate = 0;
                            hexToDigit(&surrogate, str + end + 2);
                            codepoint =
                                (((codepoint & 0x3F) << 10) |
                                 ((((codepoint >> 6) & 0xF) + 1) << 16) |
                                 (surrogate & 0x3FF));
                            end += 5;
                        } else {
                            unescaped = "?";
                            break;
                        }
                    }

                    Utf32toUtf8(codepoint, utf8Buf);
                    unescaped = utf8Buf;

                    if (codepoint == 0) {
                        yajl_buf_append(buf, unescaped, 1);
                        beg = ++end;
                        continue;
                    }

                    break;
                }
                default:
                    assert("this should never happen" == NULL);
            }
            yajl_buf_append(buf, unescaped, (unsigned int)strlen(unescaped));
            beg = ++end;
        } else {
            end++;
        }
    }
    yajl_buf_append(buf, str + beg, end - beg);
}

#define ADV_PTR s++; if (!(len--)) return 0;

static int yajl_string_validate_utf8(const unsigned char * s, size_t len)
{
    if (!len) return 1;
    if (!s) return 0;

    while (len--) {
        /* single byte */
        if (*s <= 0x7f) {
            /* noop */
        }
        /* two byte */
        else if ((*s >> 5) == 0x6) {
            ADV_PTR;
            if (!((*s >> 6) == 0x2)) return 0;
        }
        /* three byte */
        else if ((*s >> 4) == 0x0e) {
            ADV_PTR;
            if (!((*s >> 6) == 0x2)) return 0;
            ADV_PTR;
            if (!((*s >> 6) == 0x2)) return 0;
        }
        /* four byte */
        else if ((*s >> 3) == 0x1e) {
            ADV_PTR;
            if (!((*s >> 6) == 0x2)) return 0;
            ADV_PTR;
            if (!((*s >> 6) == 0x2)) return 0;
            ADV_PTR;
            if (!((*s >> 6) == 0x2)) return 0;
        } else {
            return 0;
        }

        s++;
    }

    return 1;
}

int
yajl_gen_config(yajl_gen g, yajl_gen_option opt, ...)
{
    int rv = 1;
    va_list ap;
    va_start(ap, opt);

    switch(opt) {
        case yajl_gen_beautify:
        case yajl_gen_validate_utf8:
        case yajl_gen_escape_solidus:
            if (va_arg(ap, int)) g->flags |= opt;
            else g->flags &= ~opt;
            break;
        case yajl_gen_indent_string: {
            const char *indent = va_arg(ap, const char *);
            g->indentString = indent;
            for (; *indent; indent++) {
                if (*indent != '\n'
                    && *indent != '\v'
                    && *indent != '\f'
                    && *indent != '\t'
                    && *indent != '\r'
                    && *indent != ' ')
                {
                    g->indentString = NULL;
                    rv = 0;
                }
            }
            break;
        }
        case yajl_gen_print_callback:
            yajl_buf_free(g->ctx);
            g->print = va_arg(ap, const yajl_print_t);
            g->ctx = va_arg(ap, void *);
            break;
        default:
            rv = 0;
    }

    va_end(ap);

    return rv;
}



yajl_gen
yajl_gen_alloc(const yajl_alloc_funcs * afs)
{
    yajl_gen g = NULL;
    yajl_alloc_funcs afsBuffer;

    /* first order of business is to set up memory allocation routines */
    if (afs != NULL) {
        if (afs->malloc == NULL || afs->realloc == NULL || afs->free == NULL)
        {
            return NULL;
        }
    } else {
        yajl_set_default_alloc_funcs(&afsBuffer);
        afs = &afsBuffer;
    }

    g = (yajl_gen) YA_MALLOC(afs, sizeof(struct yajl_gen_t));
    if (!g) return NULL;

    memset((void *) g, 0, sizeof(struct yajl_gen_t));
    /* copy in pointers to allocation routines */
    memcpy((void *) &(g->alloc), (void *) afs, sizeof(yajl_alloc_funcs));

    g->print = (yajl_print_t)&yajl_buf_append;
    g->ctx = yajl_buf_alloc(&(g->alloc));
    g->indentString = "    ";

    return g;
}

void
yajl_gen_free(yajl_gen g)
{
    if (g->print == (yajl_print_t)&yajl_buf_append) yajl_buf_free((yajl_buf)g->ctx);
    YA_FREE(&(g->alloc), g);
}

#define INSERT_SEP \
    if (g->state[g->depth] == yajl_gen_map_key ||               \
        g->state[g->depth] == yajl_gen_in_array) {              \
        g->print(g->ctx, ",", 1);                               \
        if ((g->flags & yajl_gen_beautify)) g->print(g->ctx, "\n", 1);               \
    } else if (g->state[g->depth] == yajl_gen_map_val) {        \
        g->print(g->ctx, ":", 1);                               \
        if ((g->flags & yajl_gen_beautify)) g->print(g->ctx, " ", 1);                \
   }

#define INSERT_WHITESPACE                                               \
    if ((g->flags & yajl_gen_beautify)) {                                                    \
        if (g->state[g->depth] != yajl_gen_map_val) {                   \
            unsigned int _i;                                            \
            for (_i=0;_i<g->depth;_i++)                                 \
                g->print(g->ctx,                                        \
                         g->indentString,                               \
                         (unsigned int)strlen(g->indentString));        \
        }                                                               \
    }

#define ENSURE_NOT_KEY \
    if (g->state[g->depth] == yajl_gen_map_key ||       \
        g->state[g->depth] == yajl_gen_map_start)  {    \
        return yajl_gen_keys_must_be_strings;           \
    }                                                   \

/* check that we're not complete, or in error state.  in a valid state
 * to be generating */
#define ENSURE_VALID_STATE \
    if (g->state[g->depth] == yajl_gen_error) {   \
        return yajl_gen_in_error_state;\
    } else if (g->state[g->depth] == yajl_gen_complete) {   \
        return yajl_gen_generation_complete;                \
    }

#define INCREMENT_DEPTH \
    if (++(g->depth) >= YAJL_MAX_DEPTH) return yajl_max_depth_exceeded;

/* XXX: this is hairy. Shouldn't it check for 0? */
#define DECREMENT_DEPTH \
  if (--(g->depth) >= YAJL_MAX_DEPTH) return yajl_max_depth_exceeded;

#define APPENDED_ATOM \
    switch (g->state[g->depth]) {                   \
        case yajl_gen_start:                        \
            g->state[g->depth] = yajl_gen_complete; \
            break;                                  \
        case yajl_gen_map_start:                    \
        case yajl_gen_map_key:                      \
            g->state[g->depth] = yajl_gen_map_val;  \
            break;                                  \
        case yajl_gen_array_start:                  \
            g->state[g->depth] = yajl_gen_in_array; \
            break;                                  \
        case yajl_gen_map_val:                      \
            g->state[g->depth] = yajl_gen_map_key;  \
            break;                                  \
        default:                                    \
            break;                                  \
    }                                               \

#define FINAL_NEWLINE                                        \
    if ((g->flags & yajl_gen_beautify) && g->state[g->depth] == yajl_gen_complete) \
        g->print(g->ctx, "\n", 1);

yajl_gen_status
yajl_gen_integer(yajl_gen g, long long int number)
{
    char i[32];
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    snprintf(i, 31, "%lld", number);
    g->print(g->ctx, i, (unsigned int)strlen(i));
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

#if defined(_WIN32) || defined(WIN32)
#include <float.h>
#define isnan _isnan
#define isinf !_finite
#endif

yajl_gen_status
yajl_gen_double(yajl_gen g, double number)
{
    char i[32];
    ENSURE_VALID_STATE; ENSURE_NOT_KEY;
    if (isnan(number) || isinf(number)) return yajl_gen_invalid_number;
    INSERT_SEP; INSERT_WHITESPACE;
    snprintf(i, 31, "%.20g", number);
    if (strspn(i, "0123456789-") == strlen(i)) {
#ifdef _WIN32
        strcat_s(i, 32, ".0");
#else
        strcat(i, ".0");
#endif
    }
    g->print(g->ctx, i, (unsigned int)strlen(i));
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_number(yajl_gen g, const char * s, size_t l)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, s, l);
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_string(yajl_gen g, const unsigned char * str,
                size_t len)
{
    // if validation is enabled, check that the string is valid utf8
    // XXX: This checking could be done a little faster, in the same pass as
    // the string encoding
    if (g->flags & yajl_gen_validate_utf8) {
        if (!yajl_string_validate_utf8(str, len)) {
            return yajl_gen_invalid_string;
        }
    }
    ENSURE_VALID_STATE; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, "\"", 1);
    yajl_string_encode(g->print, g->ctx, str, len, g->flags & yajl_gen_escape_solidus);
    g->print(g->ctx, "\"", 1);
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_null(yajl_gen g)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, "null", strlen("null"));
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_bool(yajl_gen g, int boolean)
{
    const char * val = boolean ? "true" : "false";

	ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, val, (unsigned int)strlen(val));
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_map_open(yajl_gen g)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    INCREMENT_DEPTH;

    g->state[g->depth] = yajl_gen_map_start;
    g->print(g->ctx, "{", 1);
    if ((g->flags & yajl_gen_beautify)) g->print(g->ctx, "\n", 1);
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_map_close(yajl_gen g)
{
    ENSURE_VALID_STATE;
    DECREMENT_DEPTH;

    if ((g->flags & yajl_gen_beautify)) g->print(g->ctx, "\n", 1);
    APPENDED_ATOM;
    INSERT_WHITESPACE;
    g->print(g->ctx, "}", 1);
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_array_open(yajl_gen g)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    INCREMENT_DEPTH;
    g->state[g->depth] = yajl_gen_array_start;
    g->print(g->ctx, "[", 1);
    if ((g->flags & yajl_gen_beautify)) g->print(g->ctx, "\n", 1);
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_array_close(yajl_gen g)
{
    ENSURE_VALID_STATE;
    DECREMENT_DEPTH;
    if ((g->flags & yajl_gen_beautify)) g->print(g->ctx, "\n", 1);
    APPENDED_ATOM;
    INSERT_WHITESPACE;
    g->print(g->ctx, "]", 1);
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_get_buf(yajl_gen g, const unsigned char ** buf,
                 size_t * len)
{
    if (g->print != (yajl_print_t)&yajl_buf_append) return yajl_gen_no_buf;
    *buf = yajl_buf_data((yajl_buf)g->ctx);
    *len = yajl_buf_len((yajl_buf)g->ctx);
    return yajl_gen_status_ok;
}

void
yajl_gen_clear(yajl_gen g)
{
    if (g->print == (yajl_print_t)&yajl_buf_append) yajl_buf_clear((yajl_buf)g->ctx);
}

#ifdef YAJL_LEXER_DEBUG
static const char *
tokToStr(yajl_tok tok)
{
    switch (tok) {
        case yajl_tok_bool: return "bool";
        case yajl_tok_colon: return "colon";
        case yajl_tok_comma: return "comma";
        case yajl_tok_eof: return "eof";
        case yajl_tok_error: return "error";
        case yajl_tok_left_brace: return "brace";
        case yajl_tok_left_bracket: return "bracket";
        case yajl_tok_null: return "null";
        case yajl_tok_integer: return "integer";
        case yajl_tok_double: return "double";
        case yajl_tok_right_brace: return "brace";
        case yajl_tok_right_bracket: return "bracket";
        case yajl_tok_string: return "string";
        case yajl_tok_string_with_escapes: return "string_with_escapes";
    }
    return "unknown";
}
#endif

/* Impact of the stream parsing feature on the lexer:
 *
 * YAJL support stream parsing.  That is, the ability to parse the first
 * bits of a chunk of JSON before the last bits are available (still on
 * the network or disk).  This makes the lexer more complex.  The
 * responsibility of the lexer is to handle transparently the case where
 * a chunk boundary falls in the middle of a token.  This is
 * accomplished is via a buffer and a character reading abstraction.
 *
 * Overview of implementation
 *
 * When we lex to end of input string before end of token is hit, we
 * copy all of the input text composing the token into our lexBuf.
 *
 * Every time we read a character, we do so through the readChar function.
 * readChar's responsibility is to handle pulling all chars from the buffer
 * before pulling chars from input text
 */

#define readChar(lxr, txt, off)                      \
    (((lxr)->bufInUse && yajl_buf_len((lxr)->buf) && lxr->bufOff < yajl_buf_len((lxr)->buf)) ? \
     (*((const unsigned char *) yajl_buf_data((lxr)->buf) + ((lxr)->bufOff)++)) : \
     ((txt)[(*(off))++]))

#define unreadChar(lxr, off) ((*(off) > 0) ? (*(off))-- : ((lxr)->bufOff--))

static yajl_lexer
yajl_lex_alloc(yajl_alloc_funcs * alloc,
               unsigned int allowComments, unsigned int validateUTF8)
{
    yajl_lexer lxr = (yajl_lexer) YA_MALLOC(alloc, sizeof(struct yajl_lexer_t));
    memset((void *) lxr, 0, sizeof(struct yajl_lexer_t));
    lxr->buf = yajl_buf_alloc(alloc);
    lxr->allowComments = allowComments;
    lxr->validateUTF8 = validateUTF8;
    lxr->alloc = alloc;
    return lxr;
}

static void
yajl_lex_free(yajl_lexer lxr)
{
    yajl_buf_free(lxr->buf);
    YA_FREE(lxr->alloc, lxr);
    return;
}

/* a lookup table which lets us quickly determine three things:
 * VEC - valid escaped control char
 * note.  the solidus '/' may be escaped or not.
 * IJC - invalid json char
 * VHC - valid hex char
 * NFP - needs further processing (from a string scanning perspective)
 * NUC - needs utf8 checking when enabled (from a string scanning perspective)
 */
#define VEC 0x01
#define IJC 0x02
#define VHC 0x04
#define NFP 0x08
#define NUC 0x10

static const char charLookupTable[256] =
{
/*00*/ IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    ,
/*08*/ IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    ,
/*10*/ IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    ,
/*18*/ IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    , IJC    ,

/*20*/ 0      , 0      , NFP|VEC|IJC, 0      , 0      , 0      , 0      , 0      ,
/*28*/ 0      , 0      , 0      , 0      , 0      , 0      , 0      , VEC    ,
/*30*/ VHC    , VHC    , VHC    , VHC    , VHC    , VHC    , VHC    , VHC    ,
/*38*/ VHC    , VHC    , 0      , 0      , 0      , 0      , 0      , 0      ,

/*40*/ 0      , VHC    , VHC    , VHC    , VHC    , VHC    , VHC    , 0      ,
/*48*/ 0      , 0      , 0      , 0      , 0      , 0      , 0      , 0      ,
/*50*/ 0      , 0      , 0      , 0      , 0      , 0      , 0      , 0      ,
/*58*/ 0      , 0      , 0      , 0      , NFP|VEC|IJC, 0      , 0      , 0      ,

/*60*/ 0      , VHC    , VEC|VHC, VHC    , VHC    , VHC    , VEC|VHC, 0      ,
/*68*/ 0      , 0      , 0      , 0      , 0      , 0      , VEC    , 0      ,
/*70*/ 0      , 0      , VEC    , 0      , VEC    , 0      , 0      , 0      ,
/*78*/ 0      , 0      , 0      , 0      , 0      , 0      , 0      , 0      ,

       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,

       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,

       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,

       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    ,
       NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC    , NUC
};

/** process a variable length utf8 encoded codepoint.
 *
 *  returns:
 *    yajl_tok_string - if valid utf8 char was parsed and offset was
 *                      advanced
 *    yajl_tok_eof - if end of input was hit before validation could
 *                   complete
 *    yajl_tok_error - if invalid utf8 was encountered
 *
 *  NOTE: on error the offset will point to the first char of the
 *  invalid utf8 */
#define UTF8_CHECK_EOF if (*offset >= jsonTextLen) { return yajl_tok_eof; }

static yajl_tok
yajl_lex_utf8_char(yajl_lexer lexer, const unsigned char * jsonText,
                   size_t jsonTextLen, size_t * offset,
                   unsigned char curChar)
{
    if (curChar <= 0x7f) {
        /* single byte */
        return yajl_tok_string;
    } else if ((curChar >> 5) == 0x6) {
        /* two byte */
        UTF8_CHECK_EOF;
        curChar = readChar(lexer, jsonText, offset);
        if ((curChar >> 6) == 0x2) return yajl_tok_string;
    } else if ((curChar >> 4) == 0x0e) {
        /* three byte */
        UTF8_CHECK_EOF;
        curChar = readChar(lexer, jsonText, offset);
        if ((curChar >> 6) == 0x2) {
            UTF8_CHECK_EOF;
            curChar = readChar(lexer, jsonText, offset);
            if ((curChar >> 6) == 0x2) return yajl_tok_string;
        }
    } else if ((curChar >> 3) == 0x1e) {
        /* four byte */
        UTF8_CHECK_EOF;
        curChar = readChar(lexer, jsonText, offset);
        if ((curChar >> 6) == 0x2) {
            UTF8_CHECK_EOF;
            curChar = readChar(lexer, jsonText, offset);
            if ((curChar >> 6) == 0x2) {
                UTF8_CHECK_EOF;
                curChar = readChar(lexer, jsonText, offset);
                if ((curChar >> 6) == 0x2) return yajl_tok_string;
            }
        }
    }

    return yajl_tok_error;
}

/* lex a string.  input is the lexer, pointer to beginning of
 * json text, and start of string (offset).
 * a token is returned which has the following meanings:
 * yajl_tok_string: lex of string was successful.  offset points to
 *                  terminating '"'.
 * yajl_tok_eof: end of text was encountered before we could complete
 *               the lex.
 * yajl_tok_error: embedded in the string were unallowable chars.  offset
 *               points to the offending char
 */
#define STR_CHECK_EOF \
if (*offset >= jsonTextLen) { \
   tok = yajl_tok_eof; \
   goto finish_string_lex; \
}

/** scan a string for interesting characters that might need further
 *  review.  return the number of chars that are uninteresting and can
 *  be skipped.
 * (lth) hi world, any thoughts on how to make this routine faster? */
static size_t
yajl_string_scan(const unsigned char * buf, size_t len, int utf8check)
{
    unsigned char mask = IJC|NFP|(utf8check ? NUC : 0);
    size_t skip = 0;
    while (skip < len && !(charLookupTable[*buf] & mask))
    {
        skip++;
        buf++;
    }
    return skip;
}

static yajl_tok
yajl_lex_string(yajl_lexer lexer, const unsigned char * jsonText,
                size_t jsonTextLen, size_t * offset)
{
    yajl_tok tok = yajl_tok_error;
    int hasEscapes = 0;

    for (;;) {
        unsigned char curChar;

        /* now jump into a faster scanning routine to skip as much
         * of the buffers as possible */
        {
            const unsigned char * p;
            size_t len;

            if ((lexer->bufInUse && yajl_buf_len(lexer->buf) &&
                 lexer->bufOff < yajl_buf_len(lexer->buf)))
            {
                p = ((const unsigned char *) yajl_buf_data(lexer->buf) +
                     (lexer->bufOff));
                len = yajl_buf_len(lexer->buf) - lexer->bufOff;
                lexer->bufOff += yajl_string_scan(p, len, lexer->validateUTF8);
            }
            else if (*offset < jsonTextLen)
            {
                p = jsonText + *offset;
                len = jsonTextLen - *offset;
                *offset += yajl_string_scan(p, len, lexer->validateUTF8);
            }
        }

        STR_CHECK_EOF;

        curChar = readChar(lexer, jsonText, offset);

        /* quote terminates */
        if (curChar == '"') {
            tok = yajl_tok_string;
            break;
        }
        /* backslash escapes a set of control chars, */
        else if (curChar == '\\') {
            hasEscapes = 1;
            STR_CHECK_EOF;

            /* special case \u */
            curChar = readChar(lexer, jsonText, offset);
            if (curChar == 'u') {
                unsigned int i = 0;

                for (i=0;i<4;i++) {
                    STR_CHECK_EOF;
                    curChar = readChar(lexer, jsonText, offset);
                    if (!(charLookupTable[curChar] & VHC)) {
                        /* back up to offending char */
                        unreadChar(lexer, offset);
                        lexer->error = yajl_lex_string_invalid_hex_char;
                        goto finish_string_lex;
                    }
                }
            } else if (!(charLookupTable[curChar] & VEC)) {
                /* back up to offending char */
                unreadChar(lexer, offset);
                lexer->error = yajl_lex_string_invalid_escaped_char;
                goto finish_string_lex;
            }
        }
        /* when not validating UTF8 it's a simple table lookup to determine
         * if the present character is invalid */
        else if(charLookupTable[curChar] & IJC) {
            /* back up to offending char */
            unreadChar(lexer, offset);
            lexer->error = yajl_lex_string_invalid_json_char;
            goto finish_string_lex;
        }
        /* when in validate UTF8 mode we need to do some extra work */
        else if (lexer->validateUTF8) {
            yajl_tok t = yajl_lex_utf8_char(lexer, jsonText, jsonTextLen,
                                            offset, curChar);

            if (t == yajl_tok_eof) {
                tok = yajl_tok_eof;
                goto finish_string_lex;
            } else if (t == yajl_tok_error) {
                lexer->error = yajl_lex_string_invalid_utf8;
                goto finish_string_lex;
            }
        }
        /* accept it, and move on */
    }
  finish_string_lex:
    /* tell our buddy, the parser, wether he needs to process this string
     * again */
    if (hasEscapes && tok == yajl_tok_string) {
        tok = yajl_tok_string_with_escapes;
    }

    return tok;
}

#define RETURN_IF_EOF if (*offset >= jsonTextLen) return yajl_tok_eof;

static yajl_tok
yajl_lex_number(yajl_lexer lexer, const unsigned char * jsonText,
                size_t jsonTextLen, size_t * offset)
{
    /** XXX: numbers are the only entities in json that we must lex
     *       _beyond_ in order to know that they are complete.  There
     *       is an ambiguous case for integers at EOF. */

    unsigned char c;

    yajl_tok tok = yajl_tok_integer;

    RETURN_IF_EOF;
    c = readChar(lexer, jsonText, offset);

    /* optional leading minus */
    if (c == '-') {
        RETURN_IF_EOF;
        c = readChar(lexer, jsonText, offset);
    }

    /* a single zero, or a series of integers */
    if (c == '0') {
        RETURN_IF_EOF;
        c = readChar(lexer, jsonText, offset);
    } else if (c >= '1' && c <= '9') {
        do {
            RETURN_IF_EOF;
            c = readChar(lexer, jsonText, offset);
        } while (c >= '0' && c <= '9');
    } else {
        unreadChar(lexer, offset);
        lexer->error = yajl_lex_missing_integer_after_minus;
        return yajl_tok_error;
    }

    /* optional fraction (indicates this is floating point) */
    if (c == '.') {
        int numRd = 0;

        RETURN_IF_EOF;
        c = readChar(lexer, jsonText, offset);

        while (c >= '0' && c <= '9') {
            numRd++;
            RETURN_IF_EOF;
            c = readChar(lexer, jsonText, offset);
        }

        if (!numRd) {
            unreadChar(lexer, offset);
            lexer->error = yajl_lex_missing_integer_after_decimal;
            return yajl_tok_error;
        }
        tok = yajl_tok_double;
    }

    /* optional exponent (indicates this is floating point) */
    if (c == 'e' || c == 'E') {
        RETURN_IF_EOF;
        c = readChar(lexer, jsonText, offset);

        /* optional sign */
        if (c == '+' || c == '-') {
            RETURN_IF_EOF;
            c = readChar(lexer, jsonText, offset);
        }

        if (c >= '0' && c <= '9') {
            do {
                RETURN_IF_EOF;
                c = readChar(lexer, jsonText, offset);
            } while (c >= '0' && c <= '9');
        } else {
            unreadChar(lexer, offset);
            lexer->error = yajl_lex_missing_integer_after_exponent;
            return yajl_tok_error;
        }
        tok = yajl_tok_double;
    }

    /* we always go "one too far" */
    unreadChar(lexer, offset);

    return tok;
}

static yajl_tok
yajl_lex_comment(yajl_lexer lexer, const unsigned char * jsonText,
                 size_t jsonTextLen, size_t * offset)
{
    unsigned char c;

    yajl_tok tok = yajl_tok_comment;

    RETURN_IF_EOF;
    c = readChar(lexer, jsonText, offset);

    /* either slash or star expected */
    if (c == '/') {
        /* now we throw away until end of line */
        do {
            RETURN_IF_EOF;
            c = readChar(lexer, jsonText, offset);
        } while (c != '\n');
    } else if (c == '*') {
        /* now we throw away until end of comment */
        for (;;) {
            RETURN_IF_EOF;
            c = readChar(lexer, jsonText, offset);
            if (c == '*') {
                RETURN_IF_EOF;
                c = readChar(lexer, jsonText, offset);
                if (c == '/') {
                    break;
                } else {
                    unreadChar(lexer, offset);
                }
            }
        }
    } else {
        lexer->error = yajl_lex_invalid_char;
        tok = yajl_tok_error;
    }

    return tok;
}

static yajl_tok
yajl_lex_lex(yajl_lexer lexer, const unsigned char * jsonText,
             size_t jsonTextLen, size_t * offset,
             const unsigned char ** outBuf, size_t * outLen)
{
    yajl_tok tok = yajl_tok_error;
    unsigned char c;
    size_t startOffset = *offset;

    *outBuf = NULL;
    *outLen = 0;

    for (;;) {
        assert(*offset <= jsonTextLen);

        if (*offset >= jsonTextLen) {
            tok = yajl_tok_eof;
            goto lexed;
        }

        c = readChar(lexer, jsonText, offset);

        switch (c) {
            case '{':
                tok = yajl_tok_left_bracket;
                goto lexed;
            case '}':
                tok = yajl_tok_right_bracket;
                goto lexed;
            case '[':
                tok = yajl_tok_left_brace;
                goto lexed;
            case ']':
                tok = yajl_tok_right_brace;
                goto lexed;
            case ',':
                tok = yajl_tok_comma;
                goto lexed;
            case ':':
                tok = yajl_tok_colon;
                goto lexed;
            case '\t': case '\n': case '\v': case '\f': case '\r': case ' ':
                startOffset++;
                break;
            case 't': {
                const char * want = "rue";
                do {
                    if (*offset >= jsonTextLen) {
                        tok = yajl_tok_eof;
                        goto lexed;
                    }
                    c = readChar(lexer, jsonText, offset);
                    if (c != *want) {
                        unreadChar(lexer, offset);
                        lexer->error = yajl_lex_invalid_string;
                        tok = yajl_tok_error;
                        goto lexed;
                    }
                } while (*(++want));
                tok = yajl_tok_bool;
                goto lexed;
            }
            case 'f': {
                const char * want = "alse";
                do {
                    if (*offset >= jsonTextLen) {
                        tok = yajl_tok_eof;
                        goto lexed;
                    }
                    c = readChar(lexer, jsonText, offset);
                    if (c != *want) {
                        unreadChar(lexer, offset);
                        lexer->error = yajl_lex_invalid_string;
                        tok = yajl_tok_error;
                        goto lexed;
                    }
                } while (*(++want));
                tok = yajl_tok_bool;
                goto lexed;
            }
            case 'n': {
                const char * want = "ull";
                do {
                    if (*offset >= jsonTextLen) {
                        tok = yajl_tok_eof;
                        goto lexed;
                    }
                    c = readChar(lexer, jsonText, offset);
                    if (c != *want) {
                        unreadChar(lexer, offset);
                        lexer->error = yajl_lex_invalid_string;
                        tok = yajl_tok_error;
                        goto lexed;
                    }
                } while (*(++want));
                tok = yajl_tok_null;
                goto lexed;
            }
            case '"': {
                tok = yajl_lex_string(lexer, (const unsigned char *) jsonText,
                                      jsonTextLen, offset);
                goto lexed;
            }
            case '-':
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9': {
                /* integer parsing wants to start from the beginning */
                unreadChar(lexer, offset);
                tok = yajl_lex_number(lexer, (const unsigned char *) jsonText,
                                      jsonTextLen, offset);
                goto lexed;
            }
            case '/':
                /* hey, look, a probable comment!  If comments are disabled
                 * it's an error. */
                if (!lexer->allowComments) {
                    unreadChar(lexer, offset);
                    lexer->error = yajl_lex_unallowed_comment;
                    tok = yajl_tok_error;
                    goto lexed;
                }
                /* if comments are enabled, then we should try to lex
                 * the thing.  possible outcomes are
                 * - successful lex (tok_comment, which means continue),
                 * - malformed comment opening (slash not followed by
                 *   '*' or '/') (tok_error)
                 * - eof hit. (tok_eof) */
                tok = yajl_lex_comment(lexer, (const unsigned char *) jsonText,
                                       jsonTextLen, offset);
                if (tok == yajl_tok_comment) {
                    /* "error" is silly, but that's the initial
                     * state of tok.  guilty until proven innocent. */
                    tok = yajl_tok_error;
                    yajl_buf_clear(lexer->buf);
                    lexer->bufInUse = 0;
                    startOffset = *offset;
                    break;
                }
                /* hit error or eof, bail */
                goto lexed;
            default:
                lexer->error = yajl_lex_invalid_char;
                tok = yajl_tok_error;
                goto lexed;
        }
    }


  lexed:
    /* need to append to buffer if the buffer is in use or
     * if it's an EOF token */
    if (tok == yajl_tok_eof || lexer->bufInUse) {
        if (!lexer->bufInUse) yajl_buf_clear(lexer->buf);
        lexer->bufInUse = 1;
        yajl_buf_append(lexer->buf, jsonText + startOffset, *offset - startOffset);
        lexer->bufOff = 0;

        if (tok != yajl_tok_eof) {
            *outBuf = yajl_buf_data(lexer->buf);
            *outLen = yajl_buf_len(lexer->buf);
            lexer->bufInUse = 0;
        }
    } else if (tok != yajl_tok_error) {
        *outBuf = jsonText + startOffset;
        *outLen = *offset - startOffset;
    }

    /* special case for strings. skip the quotes. */
    if (tok == yajl_tok_string || tok == yajl_tok_string_with_escapes)
    {
        assert(*outLen >= 2);
        (*outBuf)++;
        *outLen -= 2;
    }


#ifdef YAJL_LEXER_DEBUG
    if (tok == yajl_tok_error) {
        printf("lexical error: %s\n",
               yajl_lex_error_to_string(yajl_lex_get_error(lexer)));
    } else if (tok == yajl_tok_eof) {
        printf("EOF hit\n");
    } else {
        printf("lexed %s: '", tokToStr(tok));
        fwrite(*outBuf, 1, *outLen, stdout);
        printf("'\n");
    }
#endif

    return tok;
}

static const char *
yajl_lex_error_to_string(yajl_lex_error error)
{
    switch (error) {
        case yajl_lex_e_ok:
            return "ok, no error";
        case yajl_lex_string_invalid_utf8:
            return "invalid bytes in UTF8 string.";
        case yajl_lex_string_invalid_escaped_char:
            return "inside a string, '\\' occurs before a character "
                   "which it may not.";
        case yajl_lex_string_invalid_json_char:
            return "invalid character inside string.";
        case yajl_lex_string_invalid_hex_char:
            return "invalid (non-hex) character occurs after '\\u' inside "
                   "string.";
        case yajl_lex_invalid_char:
            return "invalid char in json text.";
        case yajl_lex_invalid_string:
            return "invalid string in json text.";
        case yajl_lex_missing_integer_after_exponent:
            return "malformed number, a digit is required after the exponent.";
        case yajl_lex_missing_integer_after_decimal:
            return "malformed number, a digit is required after the "
                   "decimal point.";
        case yajl_lex_missing_integer_after_minus:
            return "malformed number, a digit is required after the "
                   "minus sign.";
        case yajl_lex_unallowed_comment:
            return "probable comment found in input text, comments are "
                   "not enabled.";
    }
    return "unknown error code";
}


/** allows access to more specific information about the lexical
 *  error when yajl_lex_lex returns yajl_tok_error. */
static yajl_lex_error
yajl_lex_get_error(yajl_lexer lexer)
{
    if (lexer == NULL) return (yajl_lex_error) -1;
    return lexer->error;
}

#define MAX_VALUE_TO_MULTIPLY ((LLONG_MAX / 10) + (LLONG_MAX % 10))

 /* same semantics as strtol */
static long long
yajl_parse_integer(const unsigned char *number, unsigned int length)
{
    long long ret  = 0;
    long sign = 1;
    const unsigned char *pos = number;
    if (*pos == '-') { pos++; sign = -1; }
    if (*pos == '+') { pos++; }

    while (pos < number + length) {
        if ( ret > MAX_VALUE_TO_MULTIPLY ) {
            errno = ERANGE;
            return sign == 1 ? LLONG_MAX : LLONG_MIN;
        }
        ret *= 10;
        if (LLONG_MAX - ret < (*pos - '0')) {
            errno = ERANGE;
            return sign == 1 ? LLONG_MAX : LLONG_MIN;
        }
        if (*pos < '0' || *pos > '9') {
            errno = ERANGE;
            return sign == 1 ? LLONG_MAX : LLONG_MIN;
        }
        ret += (*pos++ - '0');
    }

    return sign * ret;
}

static unsigned char *
yajl_render_error_string(yajl_handle hand, const unsigned char * jsonText,
                         size_t jsonTextLen, int verbose)
{
    size_t offset = hand->bytesConsumed;
    unsigned char * str;
    const char * errorType = NULL;
    const char * errorText = NULL;
    char text[72];
    const char * arrow = "                     (right here) ------^\n";

    if (yajl_bs_current(hand->stateStack) == yajl_state_parse_error) {
        errorType = "parse";
        errorText = hand->parseError;
    } else if (yajl_bs_current(hand->stateStack) == yajl_state_lexical_error) {
        errorType = "lexical";
        errorText = yajl_lex_error_to_string(yajl_lex_get_error(hand->lexer));
    } else {
        errorType = "unknown";
    }

    {
        size_t memneeded = 0;
        memneeded += strlen(errorType);
        memneeded += strlen(" error");
        if (errorText != NULL) {
            memneeded += strlen(": ");
            memneeded += strlen(errorText);
        }
        str = (unsigned char *) YA_MALLOC(&(hand->alloc), memneeded + 2);
        if (!str) return NULL;
        str[0] = 0;
#ifdef _WIN32
        strcat_s((char *) str, memneeded+2, errorType);
        strcat_s((char *) str, memneeded+2, " error");
#else
        strcat((char *) str, errorType);
        strcat((char *) str, " error");
#endif
        if (errorText != NULL) {
#ifdef _WIN32
            strcat_s((char *) str, memneeded+2, ": ");
            strcat_s((char *) str, memneeded+2, errorText);
#else
            strcat((char *) str, ": ");
            strcat((char *) str, errorText);
#endif
        }
#ifdef _WIN32
        strcat_s((char *) str, memneeded+2, "\n");
#else
        strcat((char *) str, "\n");
#endif
    }

    /* now we append as many spaces as needed to make sure the error
     * falls at char 41, if verbose was specified */
    if (verbose) {
        size_t start, end, i;
        size_t spacesNeeded;

        spacesNeeded = (offset < 30 ? 40 - offset : 10);
        start = (offset >= 30 ? offset - 30 : 0);
        end = (offset + 30 > jsonTextLen ? jsonTextLen : offset + 30);

        for (i=0;i<spacesNeeded;i++) text[i] = ' ';

        for (;start < end;start++, i++) {
            if (jsonText[start] != '\n' && jsonText[start] != '\r')
            {
                text[i] = jsonText[start];
            }
            else
            {
                text[i] = ' ';
            }
        }
        assert(i <= 71);
        text[i++] = '\n';
        text[i] = 0;
        {
            size_t memneeded = (unsigned int)(strlen((char *) str) +
                                                         strlen((char *) text) +
                                                         strlen(arrow) + 1);
            char * newStr = (char *) YA_MALLOC(&(hand->alloc), memneeded);
            if (newStr) {
                newStr[0] = 0;
#ifdef _WIN32
                strcat_s((char *) newStr, memneeded, (char *) str);
                strcat_s((char *) newStr, memneeded, text);
                strcat_s((char *) newStr, memneeded, arrow);
#else
                strcat((char *) newStr, (char *) str);
                strcat((char *) newStr, text);
                strcat((char *) newStr, arrow);
#endif
            }
            YA_FREE(&(hand->alloc), str);
            str = (unsigned char *) newStr;
        }
    }
    return str;
}

/* check for client cancelation */
#define _CC_CHK(x)                                                \
    if (!(x)) {                                                   \
        yajl_bs_set(hand->stateStack, yajl_state_parse_error);    \
        hand->parseError =                                        \
            "client cancelled parse via callback return value";   \
        return yajl_status_client_canceled;                       \
    }


static yajl_status
yajl_do_finish(yajl_handle hand)
{
    yajl_status stat;
    stat = yajl_do_parse(hand,(const unsigned char *) " ",1);

    if (stat != yajl_status_ok) return stat;

    switch(yajl_bs_current(hand->stateStack))
    {
        case yajl_state_parse_error:
        case yajl_state_lexical_error:
            return yajl_status_error;
        case yajl_state_got_value:
        case yajl_state_parse_complete:
            return yajl_status_ok;
        default:
            if (!(hand->flags & yajl_allow_partial_values))
            {
                yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                hand->parseError = "premature EOF";
                return yajl_status_error;
            }
            return yajl_status_ok;
    }
}

static yajl_status
yajl_do_parse(yajl_handle hand, const unsigned char * jsonText,
              size_t jsonTextLen)
{
    yajl_tok tok;
    const unsigned char * buf;
    size_t bufLen;
    size_t * offset = &(hand->bytesConsumed);

    *offset = 0;

  around_again:
    switch (yajl_bs_current(hand->stateStack)) {
        case yajl_state_parse_complete:
            if (hand->flags & yajl_allow_multiple_values) {
                yajl_bs_set(hand->stateStack, yajl_state_got_value);
                goto around_again;
            }
            if (!(hand->flags & yajl_allow_trailing_garbage)) {
                if (*offset != jsonTextLen) {
                    tok = yajl_lex_lex(hand->lexer, jsonText, jsonTextLen,
                                       offset, &buf, &bufLen);
                    if (tok != yajl_tok_eof) {
                        yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                        hand->parseError = "trailing garbage";
                    }
                    goto around_again;
                }
            }
            return yajl_status_ok;
        case yajl_state_lexical_error:
        case yajl_state_parse_error:
            return yajl_status_error;
        case yajl_state_start:
        case yajl_state_got_value:
        case yajl_state_map_need_val:
        case yajl_state_array_need_val:
        case yajl_state_array_start:  {
            /* for arrays and maps, we advance the state for this
             * depth, then push the state of the next depth.
             * If an error occurs during the parsing of the nesting
             * enitity, the state at this level will not matter.
             * a state that needs pushing will be anything other
             * than state_start */

            yajl_state stateToPush = yajl_state_start;

            tok = yajl_lex_lex(hand->lexer, jsonText, jsonTextLen,
                               offset, &buf, &bufLen);

            switch (tok) {
                case yajl_tok_eof:
                    return yajl_status_ok;
                case yajl_tok_error:
                    yajl_bs_set(hand->stateStack, yajl_state_lexical_error);
                    goto around_again;
                case yajl_tok_string:
                    if (hand->callbacks && hand->callbacks->yajl_string) {
                        _CC_CHK(hand->callbacks->yajl_string(hand->ctx,
                                                             buf, bufLen));
                    }
                    break;
                case yajl_tok_string_with_escapes:
                    if (hand->callbacks && hand->callbacks->yajl_string) {
                        yajl_buf_clear(hand->decodeBuf);
                        yajl_string_decode(hand->decodeBuf, buf, bufLen);
                        _CC_CHK(hand->callbacks->yajl_string(
                                    hand->ctx, yajl_buf_data(hand->decodeBuf),
                                    yajl_buf_len(hand->decodeBuf)));
                    }
                    break;
                case yajl_tok_bool:
                    if (hand->callbacks && hand->callbacks->yajl_boolean) {
                        _CC_CHK(hand->callbacks->yajl_boolean(hand->ctx,
                                                              *buf == 't'));
                    }
                    break;
                case yajl_tok_null:
                    if (hand->callbacks && hand->callbacks->yajl_null) {
                        _CC_CHK(hand->callbacks->yajl_null(hand->ctx));
                    }
                    break;
                case yajl_tok_left_bracket:
                    if (hand->callbacks && hand->callbacks->yajl_start_map) {
                        _CC_CHK(hand->callbacks->yajl_start_map(hand->ctx));
                    }
                    stateToPush = yajl_state_map_start;
                    break;
                case yajl_tok_left_brace:
                    if (hand->callbacks && hand->callbacks->yajl_start_array) {
                        _CC_CHK(hand->callbacks->yajl_start_array(hand->ctx));
                    }
                    stateToPush = yajl_state_array_start;
                    break;
                case yajl_tok_integer:
                    if (hand->callbacks) {
                        if (hand->callbacks->yajl_number) {
                            _CC_CHK(hand->callbacks->yajl_number(
                                        hand->ctx,(const char *) buf, bufLen));
                        } else if (hand->callbacks->yajl_integer) {
                            long long int i = 0;
                            errno = 0;
                            i = yajl_parse_integer(buf, bufLen);
                            if ((i == LLONG_MIN || i == LLONG_MAX) &&
                                errno == ERANGE)
                            {
                                yajl_bs_set(hand->stateStack,
                                            yajl_state_parse_error);
                                hand->parseError = "integer overflow" ;
                                /* try to restore error offset */
                                if (*offset >= bufLen) *offset -= bufLen;
                                else *offset = 0;
                                goto around_again;
                            }
                            _CC_CHK(hand->callbacks->yajl_integer(hand->ctx,
                                                                  i));
                        }
                    }
                    break;
                case yajl_tok_double:
                    if (hand->callbacks) {
                        if (hand->callbacks->yajl_number) {
                            _CC_CHK(hand->callbacks->yajl_number(
                                        hand->ctx, (const char *) buf, bufLen));
                        } else if (hand->callbacks->yajl_double) {
                            double d = 0.0;
                            yajl_buf_clear(hand->decodeBuf);
                            yajl_buf_append(hand->decodeBuf, buf, bufLen);
                            buf = yajl_buf_data(hand->decodeBuf);
                            errno = 0;
                            d = strtod((char *) buf, NULL);
                            if ((d == HUGE_VAL || d == -HUGE_VAL) &&
                                errno == ERANGE)
                            {
                                yajl_bs_set(hand->stateStack,
                                            yajl_state_parse_error);
                                hand->parseError = "numeric (floating point) "
                                    "overflow";
                                /* try to restore error offset */
                                if (*offset >= bufLen) *offset -= bufLen;
                                else *offset = 0;
                                goto around_again;
                            }
                            _CC_CHK(hand->callbacks->yajl_double(hand->ctx,
                                                                 d));
                        }
                    }
                    break;
                case yajl_tok_right_brace: {
                    if (yajl_bs_current(hand->stateStack) ==
                        yajl_state_array_start)
                    {
                        if (hand->callbacks &&
                            hand->callbacks->yajl_end_array)
                        {
                            _CC_CHK(hand->callbacks->yajl_end_array(hand->ctx));
                        }
                        yajl_bs_pop(hand->stateStack);
                        goto around_again;
                    }
                    /* intentional fall-through */
                }
                case yajl_tok_colon:
                case yajl_tok_comma:
                case yajl_tok_right_bracket:
                    yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                    hand->parseError =
                        "unallowed token at this point in JSON text";
                    goto around_again;
                default:
                    yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                    hand->parseError = "invalid token, internal error";
                    goto around_again;
            }
            /* got a value.  transition depends on the state we're in. */
            {
                yajl_state s = yajl_bs_current(hand->stateStack);
                if (s == yajl_state_start || s == yajl_state_got_value) {
                    yajl_bs_set(hand->stateStack, yajl_state_parse_complete);
                } else if (s == yajl_state_map_need_val) {
                    yajl_bs_set(hand->stateStack, yajl_state_map_got_val);
                } else {
                    yajl_bs_set(hand->stateStack, yajl_state_array_got_val);
                }
            }
            if (stateToPush != yajl_state_start) {
                yajl_bs_push(hand->stateStack, stateToPush);
            }

            goto around_again;
        }
        case yajl_state_map_start:
        case yajl_state_map_need_key: {
            /* only difference between these two states is that in
             * start '}' is valid, whereas in need_key, we've parsed
             * a comma, and a string key _must_ follow */
            tok = yajl_lex_lex(hand->lexer, jsonText, jsonTextLen,
                               offset, &buf, &bufLen);
            switch (tok) {
                case yajl_tok_eof:
                    return yajl_status_ok;
                case yajl_tok_error:
                    yajl_bs_set(hand->stateStack, yajl_state_lexical_error);
                    goto around_again;
                case yajl_tok_string_with_escapes:
                    if (hand->callbacks && hand->callbacks->yajl_map_key) {
                        yajl_buf_clear(hand->decodeBuf);
                        yajl_string_decode(hand->decodeBuf, buf, bufLen);
                        buf = yajl_buf_data(hand->decodeBuf);
                        bufLen = yajl_buf_len(hand->decodeBuf);
                    }
                    /* intentional fall-through */
                case yajl_tok_string:
                    if (hand->callbacks && hand->callbacks->yajl_map_key) {
                        _CC_CHK(hand->callbacks->yajl_map_key(hand->ctx, buf,
                                                              bufLen));
                    }
                    yajl_bs_set(hand->stateStack, yajl_state_map_sep);
                    goto around_again;
                case yajl_tok_right_bracket:
                    if (yajl_bs_current(hand->stateStack) ==
                        yajl_state_map_start)
                    {
                        if (hand->callbacks && hand->callbacks->yajl_end_map) {
                            _CC_CHK(hand->callbacks->yajl_end_map(hand->ctx));
                        }
                        yajl_bs_pop(hand->stateStack);
                        goto around_again;
                    }
                default:
                    yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                    hand->parseError =
                        "invalid object key (must be a string)";
                    goto around_again;
            }
        }
        case yajl_state_map_sep: {
            tok = yajl_lex_lex(hand->lexer, jsonText, jsonTextLen,
                               offset, &buf, &bufLen);
            switch (tok) {
                case yajl_tok_colon:
                    yajl_bs_set(hand->stateStack, yajl_state_map_need_val);
                    goto around_again;
                case yajl_tok_eof:
                    return yajl_status_ok;
                case yajl_tok_error:
                    yajl_bs_set(hand->stateStack, yajl_state_lexical_error);
                    goto around_again;
                default:
                    yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                    hand->parseError = "object key and value must "
                        "be separated by a colon (':')";
                    goto around_again;
            }
        }
        case yajl_state_map_got_val: {
            tok = yajl_lex_lex(hand->lexer, jsonText, jsonTextLen,
                               offset, &buf, &bufLen);
            switch (tok) {
                case yajl_tok_right_bracket:
                    if (hand->callbacks && hand->callbacks->yajl_end_map) {
                        _CC_CHK(hand->callbacks->yajl_end_map(hand->ctx));
                    }
                    yajl_bs_pop(hand->stateStack);
                    goto around_again;
                case yajl_tok_comma:
                    yajl_bs_set(hand->stateStack, yajl_state_map_need_key);
                    goto around_again;
                case yajl_tok_eof:
                    return yajl_status_ok;
                case yajl_tok_error:
                    yajl_bs_set(hand->stateStack, yajl_state_lexical_error);
                    goto around_again;
                default:
                    yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                    hand->parseError = "after key and value, inside map, "
                                       "I expect ',' or '}'";
                    /* try to restore error offset */
                    if (*offset >= bufLen) *offset -= bufLen;
                    else *offset = 0;
                    goto around_again;
            }
        }
        case yajl_state_array_got_val: {
            tok = yajl_lex_lex(hand->lexer, jsonText, jsonTextLen,
                               offset, &buf, &bufLen);
            switch (tok) {
                case yajl_tok_right_brace:
                    if (hand->callbacks && hand->callbacks->yajl_end_array) {
                        _CC_CHK(hand->callbacks->yajl_end_array(hand->ctx));
                    }
                    yajl_bs_pop(hand->stateStack);
                    goto around_again;
                case yajl_tok_comma:
                    yajl_bs_set(hand->stateStack, yajl_state_array_need_val);
                    goto around_again;
                case yajl_tok_eof:
                    return yajl_status_ok;
                case yajl_tok_error:
                    yajl_bs_set(hand->stateStack, yajl_state_lexical_error);
                    goto around_again;
                default:
                    yajl_bs_set(hand->stateStack, yajl_state_parse_error);
                    hand->parseError =
                        "after array element, I expect ',' or ']'";
                    goto around_again;
            }
        }
    }

    abort();
    return yajl_status_error;
}
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Tanel Tammet 2004,2005,2006,2007,2008,2009
* Copyright (c) Priit JÃ¤rv 2013,2014
*
* Contact: tanel.tammet@gmail.com
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbmem.c
 *  Allocating/detaching system memory: shared memory and allocated ordinary memory
 *
 */

/* ====== Includes =============== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/shm.h>
#include <sys/errno.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//features.h"
//mem.h"
//log.h"

/* ====== Private headers and defs ======== */

/* ======= Private protos ================ */

static int normalize_perms(int mode);
static void* link_shared_memory(int key, int *errcode);
static void* create_shared_memory(int key, gint size, int mode);
static int free_shared_memory(int key);

static int detach_shared_memory(void* shmptr);

#ifdef USE_DATABASE_HANDLE
static void *init_dbhandle(void);
static void free_dbhandle(void *dbhandle);
#endif

#ifndef _WIN32
static int memory_stats(void *db, struct shmid_ds *buf);
#endif

static gint show_memory_error(char *errmsg);
#ifdef _WIN32
static gint show_memory_error_nr(char* errmsg, int nr);
#endif

/* ====== Functions ============== */


/* ----------- dbase creation and deletion api funs ------------------ */

/* Check the header for compatibility.
 * XXX: this is not required for a fresh database. */
#define CHECK_SEGMENT(shmx) \
  if(shmx && dbmemsegh(shmx)) { \
    int err; \
    if((err = wg_check_header_compat(dbmemsegh(shmx)))) { \
      if(err < -1) { \
        show_memory_error("Existing segment header is incompatible"); \
        wg_print_code_version(); \
        wg_print_header_version(dbmemsegh(shmx), 1); \
      } \
      return NULL; \
    } \
  }

/** returns a pointer to the database, NULL if failure
 *
 * In case database with dbasename exists, the returned pointer
 * points to the existing database.
 *
 * If there exists no database with dbasename, a new database
 * is created in shared memory with size in bytes
 *
 * If size is not 0 and the database exists, the size of the
 * existing segment is required to be >= requested size,
 * otherwise the operation fails.
 *
 */


void* wg_attach_database(char* dbasename, gint size){
  void* shm = wg_attach_memsegment(dbasename, size, size, 1, 0, 0);
  CHECK_SEGMENT(shm)
  return shm;
}


/** returns a pointer to the existing database, NULL if
 *  there is no database with dbasename.
 *
 */

void* wg_attach_existing_database(char* dbasename){
  void* shm = wg_attach_memsegment(dbasename, 0, 0, 0, 0, 0);
  CHECK_SEGMENT(shm)
  return shm;
}

/**  returns a pointer to the database, NULL if failure
 *
 * Starts journal logging in the database.
 */

void* wg_attach_logged_database(char* dbasename, gint size){
  void* shm = wg_attach_memsegment(dbasename, size, size, 1, 1, 0);
  CHECK_SEGMENT(shm)
  return shm;
}

/**  returns a pointer to the database, NULL if failure
 *
 * Creates the database with given permission mode.
 * Otherwise performs like wg_attach_database().
 */

void* wg_attach_database_mode(char* dbasename, gint size, int mode){
  void* shm = wg_attach_memsegment(dbasename, size, size, 1, 0, mode);
  CHECK_SEGMENT(shm)
  return shm;
}

/**  returns a pointer to the database, NULL if failure
 *
 * Creates the database with given permission mode.
 * Otherwise performs like wg_attach_logged_database().
 */

void* wg_attach_logged_database_mode(char* dbasename, gint size, int mode){
  void* shm = wg_attach_memsegment(dbasename, size, size, 1, 1, mode);
  CHECK_SEGMENT(shm)
  return shm;
}


/** Normalize the mode for permissions.
 *
 */
static int normalize_perms(int mode) {
  /* Normalize the mode */
  mode &= 0666; /* kill the high bits and execute bits */
  mode |= 0600; /* owner can always read and write */
  /* group and others are either read-write or nothing */
  if((mode & 0060) != 0060)
    mode &= 0606;
  if((mode & 0006) != 0006)
    mode &= 0660;
  return mode;
}

/** Attach to shared memory segment.
 *  Normally called internally by wg_attach_database()
 *  May be called directly if the version compatibility of the
 *  memory image is not relevant (such as, when importing a dump
 *  file).
 */

void* wg_attach_memsegment(char* dbasename, gint minsize,
                               gint size, int create, int logging, int mode){
#ifdef USE_DATABASE_HANDLE
  void *dbhandle;
#endif
  void* shm;
  int err;
  int key=0;
#ifdef USE_DBLOG
  int omode;
#endif

#ifdef USE_DATABASE_HANDLE
  dbhandle = init_dbhandle();
  if(!dbhandle)
    return NULL;
#endif

  // default args handling
  if (dbasename!=NULL) key=strtol(dbasename,NULL,10);
  if (key<=0 || key==INT_MIN || key==INT_MAX) key=DEFAULT_MEMDBASE_KEY;
  if (minsize<0) minsize=0;
  if (size<minsize) size=minsize;

  // first try to link to already existing block with this key
  shm=link_shared_memory(key, &err);
  if (shm!=NULL) {
    /* managed to link to already existing shared memory block,
     * now check the header.
     */
    if(!dbcheckh(shm)) {
      show_memory_error("Existing segment header is invalid");
#ifdef USE_DATABASE_HANDLE
      free_dbhandle(dbhandle);
#endif
      return NULL;
    }
    if(minsize) {
      /* Check that the size of the segment is sufficient. We rely
       * on segment header being accurate. NOTE that shmget() also is capable
       * of checking the size, however under Windows the mapping size cannot
       * be checked accurately with system calls.
       */
      if(((db_memsegment_header *) shm)->size < minsize) {
        show_memory_error("Existing segment is too small");
#ifdef USE_DATABASE_HANDLE
        free_dbhandle(dbhandle);
#endif
        return NULL;
      }
    }
#ifdef USE_DATABASE_HANDLE
#ifdef USE_DBLOG
    if(logging) {
      /* If logging was requested and we're not initializing a new
       * segment, we should fail here if the existing database is
       * not actively logging.
       */
      if(!((db_memsegment_header *) shm)->logging.active) {
        show_memory_error("Existing memory segment has no journal");
        free_dbhandle(dbhandle);
        return NULL;
      }
    }
#endif
    ((db_handle *) dbhandle)->db = shm;
#ifdef USE_DBLOG
    /* Always set the umask for the logfile */
    omode = wg_memmode(dbhandle);
    if(omode == -1) {
      show_memory_error("Failed to get the access mode of the segment");
      free_dbhandle(dbhandle);
      return NULL;
    }
    wg_log_umask(dbhandle, ~omode);
#endif
#endif
#ifdef _WIN32
  } else if (!create) {
#else
  } else if (!create || err == EACCES) {
#endif
     /* linking to already existing block failed
        do not create a new base */
#ifdef USE_DATABASE_HANDLE
    free_dbhandle(dbhandle);
#endif
    return NULL;
  } else {
    /* linking to already existing block failed */
    /* create a new block if createnew_flag set
     *
     * When creating a new base, we have to select the size for the
     * memory segment. There are three possible scenarios:
     * - no size was requested. Use the default size.
     * - specific size was requested. Use it.
     * - a size and a minimum size were provided. First try the size
     *   given, if that fails fall back to minimum size.
     */
    if(!size) size = DEFAULT_MEMDBASE_SIZE;
    mode = normalize_perms(mode);
    shm = create_shared_memory(key, size, mode);
    if(!shm && minsize && minsize<size) {
      size = minsize;
      shm = create_shared_memory(key, size, mode);
    }

    if (shm==NULL) {
      show_memory_error("create_shared_memory failed");
#ifdef USE_DATABASE_HANDLE
      free_dbhandle(dbhandle);
#endif
      return NULL;
    } else {
#ifdef USE_DATABASE_HANDLE
      ((db_handle *) dbhandle)->db = shm;
      err=wg_init_db_memsegment(dbhandle, key, size);
#ifdef USE_DBLOG
      wg_log_umask(dbhandle, ~mode);
      if(!err && logging) {
        err = wg_start_logging(dbhandle);
      }
#endif
#else
      err=wg_init_db_memsegment(shm,key,size);
#endif
      if(err) {
        show_memory_error("Database initialization failed");
        free_shared_memory(key);
#ifdef USE_DATABASE_HANDLE
        free_dbhandle(dbhandle);
#endif
        return NULL;
      }
    }
  }
#ifdef USE_DATABASE_HANDLE
  return dbhandle;
#else
  return shm;
#endif
}


/** Detach database
 *
 * returns 0 if OK
 */
int wg_detach_database(void* dbase) {
  int err = detach_shared_memory(dbmemseg(dbase));
#ifdef USE_DATABASE_HANDLE
  if(!err) {
    free_dbhandle(dbase);
  }
#endif
  return err;
}


/** Delete a database
 *
 * returns 0 if OK
 */
int wg_delete_database(char* dbasename) {
  int key=0;

  // default args handling
  if (dbasename!=NULL) key=strtol(dbasename,NULL,10);
  if (key<=0 || key==INT_MIN || key==INT_MAX) key=DEFAULT_MEMDBASE_KEY;
  return free_shared_memory(key);
}



/* --------- local memory db creation and deleting ---------- */

/** Create a database in local memory
 * returns a pointer to the database, NULL if failure.
 */

void* wg_attach_local_database(gint size) {
  void* shm;
#ifdef USE_DATABASE_HANDLE
  void *dbhandle = init_dbhandle();
  if(!dbhandle)
    return NULL;
#endif

  if (size<=0) size=DEFAULT_MEMDBASE_SIZE;

  shm = (void *) malloc(size);
  if (shm==NULL) {
    show_memory_error("malloc failed");
    return NULL;
  } else {
    /* key=0 - no shared memory associated */
#ifdef USE_DATABASE_HANDLE
    ((db_handle *) dbhandle)->db = shm;
    if(wg_init_db_memsegment(dbhandle, 0, size)) {
#else
    if(wg_init_db_memsegment(shm, 0, size)) {
#endif
      show_memory_error("Database initialization failed");
      free(shm);
#ifdef USE_DATABASE_HANDLE
      free_dbhandle(dbhandle);
#endif
      return NULL;
    }
  }
#ifdef USE_DATABASE_HANDLE
  return dbhandle;
#else
  return shm;
#endif
}

/** Free a database in local memory
 * frees the allocated memory.
 */

void wg_delete_local_database(void* dbase) {
  if(dbase) {
    void *localmem = dbmemseg(dbase);
    if(localmem)
      free(localmem);
#ifdef USE_DATABASE_HANDLE
    free_dbhandle(dbase);
#endif
  }
}


/* -------------------- database handle management -------------------- */

#ifdef USE_DATABASE_HANDLE

static void *init_dbhandle() {
  void *dbhandle = malloc(sizeof(db_handle));
  if(!dbhandle) {
    show_memory_error("Failed to allocate the db handle");
    return NULL;
  } else {
    memset(dbhandle, 0, sizeof(db_handle));
  }
#ifdef USE_DBLOG
  if(wg_init_handle_logdata(dbhandle)) {
    free(dbhandle);
    return NULL;
  }
#endif
  return dbhandle;
}

static void free_dbhandle(void *dbhandle) {
#ifdef USE_DBLOG
  wg_cleanup_handle_logdata(dbhandle);
#endif
  free(dbhandle);
}

#endif

/* ----------------- memory image/dump compatibility ------------------ */

/** Check compatibility of memory image (or dump file) header
 *
 * Note: unlike API functions, this functions works directly on
 * the (db_memsegment_header *) pointer.
 *
 * returns 0 if header is compatible with current executable
 * returns -1 if header is not recognizable
 * returns -2 if header has wrong endianness
 * returns -3 if header version does not match
 * returns -4 if compile-time features do not match
 */
int wg_check_header_compat(db_memsegment_header *dbh) {
  /*
   * Check:
   * - magic marker (including endianness)
   * - version
   */

  if(!dbcheckh(dbh)) {
    gint32 magic = MEMSEGMENT_MAGIC_MARK;
    char *magic_bytes = (char *) &magic;
    char *header_bytes = (char *) dbh;

    if(magic_bytes[0]==header_bytes[3] && magic_bytes[1]==header_bytes[2] &&\
       magic_bytes[2]==header_bytes[1] && magic_bytes[3]==header_bytes[0]) {
      return -2; /* wrong endianness */
    }
    else {
      return -1; /* unknown marker (not a valid header) */
    }
  }
  if(dbh->version!=MEMSEGMENT_VERSION) {
    return -3;
  }
  if(dbh->features!=MEMSEGMENT_FEATURES) {
    return -4;
  }
  return 0;
}

void wg_print_code_version(void) {
  int i = 1;
  char *i_bytes = (char *) &i;

  printf("\nlibwgdb version: %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR,
    VERSION_REV);
  printf("byte order: %s endian\n", (i_bytes[0]==1 ? "little" : "big"));
  printf("compile-time features:\n"\
    "  64-bit encoded data: %s\n"\
    "  queued locks: %s\n"\
    "  chained nodes in T-tree: %s\n"\
    "  record backlinking: %s\n"\
    "  child databases: %s\n"\
    "  index templates: %s\n",
    (MEMSEGMENT_FEATURES & FEATURE_BITS_64BIT ? "yes" : "no"),
    (MEMSEGMENT_FEATURES & FEATURE_BITS_QUEUED_LOCKS ? "yes" : "no"),
    (MEMSEGMENT_FEATURES & FEATURE_BITS_TTREE_CHAINED ? "yes" : "no"),
    (MEMSEGMENT_FEATURES & FEATURE_BITS_BACKLINK ? "yes" : "no"),
    (MEMSEGMENT_FEATURES & FEATURE_BITS_CHILD_DB ? "yes" : "no"),
    (MEMSEGMENT_FEATURES & FEATURE_BITS_INDEX_TMPL ? "yes" : "no"));
}

void wg_print_header_version(db_memsegment_header *dbh, int verbose) {
  gint32 version, features;
  gint32 magic = MEMSEGMENT_MAGIC_MARK;
  char *magic_bytes = (char *) &magic;
  char *header_bytes = (char *) dbh;
  char magic_lsb = (char) (MEMSEGMENT_MAGIC_MARK & 0xff);

  /* Header might be incompatible, but to display version and feature
   * information, we still need to read it somehow, even if
   * it has wrong endianness.
   */
  if(magic_bytes[0]==header_bytes[3] && magic_bytes[1]==header_bytes[2] &&\
     magic_bytes[2]==header_bytes[1] && magic_bytes[3]==header_bytes[0]) {
    char *f1 = (char *) &(dbh->version);
    char *t1 = (char *) &version;
    char *f2 = (char *) &(dbh->features);
    char *t2 = (char *) &features;
    int i;
    for(i=0; i<4; i++) {
      t1[i] = f1[3-i];
      t2[i] = f2[3-i];
    }
  } else {
    version = dbh->version;
    features = dbh->features;
  }

  if(verbose) {
    printf("\nheader version: %d.%d.%d\n", (version & 0xff),
      ((version>>8) & 0xff), ((version>>16) & 0xff));
    printf("byte order: %s endian\n",
      (header_bytes[0]==magic_lsb ? "little" : "big"));
    printf("compile-time features:\n"\
      "  64-bit encoded data: %s\n"\
      "  queued locks: %s\n"\
      "  chained nodes in T-tree: %s\n"\
      "  record backlinking: %s\n"\
      "  child databases: %s\n"\
      "  index templates: %s\n",
      (features & FEATURE_BITS_64BIT ? "yes" : "no"),
      (features & FEATURE_BITS_QUEUED_LOCKS ? "yes" : "no"),
      (features & FEATURE_BITS_TTREE_CHAINED ? "yes" : "no"),
      (features & FEATURE_BITS_BACKLINK ? "yes" : "no"),
      (features & FEATURE_BITS_CHILD_DB ? "yes" : "no"),
      (features & FEATURE_BITS_INDEX_TMPL ? "yes" : "no"));
  } else {
    printf("%d.%d.%d%s\n",
      (version & 0xff), ((version>>8) & 0xff), ((version>>16) & 0xff),
      (features & FEATURE_BITS_64BIT ? " (64-bit)" : ""));
  }
}

/* --------------------  memory image stats --------------------------- */

#ifndef _WIN32
/** Get the shared memory stats structure.
 *  Returns 0 on success.
 *  Returns -1 if the database is local.
 *  Returns -2 on error.
 */
static int memory_stats(void *db, struct shmid_ds *buf) {
  db_memsegment_header* dbh = dbmemsegh(db);

  if(dbh->key) {
    int shmid = shmget((key_t) dbh->key, 0, 0);
    if(shmid < 0) {
      show_memory_error("memory_stats(): failed to get shmid");
      return -2;
    } else {
      int err;

      memset(buf, 0, sizeof(struct shmid_ds));
      err = shmctl(shmid, IPC_STAT, buf);
      if(err) {
        show_memory_error("memory_stats(): failed to stat shared memory");
        return -2;
      }
      return 0;
    }
  }
  return -1;
}
#endif

/** Return the mode bits of the shared memory permissions.
 *  Defaults to 0600 in cases where this does not apply directly.
 */
int wg_memmode(void *db) {
  int mode = 0600; /* default for local memory and Win32 */
#ifndef _WIN32
  struct shmid_ds buf;
  int err = memory_stats(db, &buf);
  if(!err) {
    mode = (int) buf.shm_perm.mode;
  } else if(err < -1) {
    return -1;
  }
#endif
  return mode;
}

/** Return the uid of the owner of the segment.
 *  returns -1 on error.
 */
int wg_memowner(void *db) {
#ifdef _WIN32
  int uid = 0;
#else
  int uid = getuid(); /* default for local memory */
  struct shmid_ds buf;
  int err = memory_stats(db, &buf);
  if(!err) {
    uid = (int) buf.shm_perm.uid;
  } else if(err < -1) {
    return -1;
  }
#endif
  return uid;
}

/** Return the gid of the owner of the segment.
 *  returns -1 on error.
 */
int wg_memgroup(void *db) {
#ifdef _WIN32
  int gid = 0;
#else
  int gid = getgid(); /* default for local memory */
  struct shmid_ds buf;
  int err = memory_stats(db, &buf);
  if(!err) {
    gid = (int) buf.shm_perm.gid;
  } else if(err < -1) {
    return -1;
  }
#endif
  return gid;
}

/* --------------- dbase create/delete ops not in api ----------------- */


static void* link_shared_memory(int key, int *errcode) {
  void *shm;

#ifdef _WIN32
  char fname[MAX_FILENAME_SIZE];
  HANDLE hmapfile;

  sprintf_s(fname,MAX_FILENAME_SIZE-1,"%d",key);
  hmapfile = OpenFileMapping(
                   FILE_MAP_ALL_ACCESS,   // read/write access
                   FALSE,                 // do not inherit the name
                   fname);               // name of mapping object
  errno = 0;
  *errcode = 0;
  if (hmapfile == NULL) {
      /* this is an expected error, message in most cases not wanted */
      return NULL;
   }
   shm = (void*) MapViewOfFile(hmapfile,   // handle to map object
                        FILE_MAP_ALL_ACCESS, // read/write permission
                        0,
                        0,
                        0);   // size of mapping
   if (shm == NULL)  {
      show_memory_error_nr("Could not map view of file",
        (int) GetLastError());
      CloseHandle(hmapfile);
      return NULL;
   }
   return shm;
#else
  int shmid; /* return value from shmget() */

  errno = 0;
  *errcode = 0;
  // Link to existing segment
  shmid=shmget((key_t)key, 0, 0);
  if (shmid < 0) {
    return NULL;
  }
  // Attach the segment to our data space
  shm=shmat(shmid,NULL,0);
  if (shm==(char *) -1) {
    *errcode = errno;
    if(*errcode == EACCES) {
      show_memory_error("cannot attach to shared memory (No permission)");
      return NULL;
    } else {
      show_memory_error("attaching shared memory segment failed");
      return NULL;
    }
  }
  return (void*) shm;
#endif
}



static void* create_shared_memory(int key, gint size, int mode) {
  void *shm;

#ifdef _WIN32
  char fname[MAX_FILENAME_SIZE];
  HANDLE hmapfile;

  sprintf_s(fname,MAX_FILENAME_SIZE-1,"%d",key);

  /* XXX: need to interpret the mode value here.
   * Right now the shared segment is created using the
   * default permissions, in the local namespace.
   */
  hmapfile = CreateFileMapping(
                 INVALID_HANDLE_VALUE,    // use paging file
                 NULL,                    // default security
                 PAGE_READWRITE,          // read/write access
                 0,                       // max. object size
                 size,                   // buffer size
                 fname);                 // name of mapping object
  errno = 0;
  if (hmapfile == NULL) {
      show_memory_error_nr("Could not create file mapping object",
        (int) GetLastError());
      return NULL;
   }
   shm = (void*) MapViewOfFile(hmapfile,   // handle to map object
                        FILE_MAP_ALL_ACCESS, // read/write permission
                        0,
                        0,
                        0);
   if (shm == NULL)  {
      show_memory_error_nr("Could not map view of file",
        (int) GetLastError());
      CloseHandle(hmapfile);
      return NULL;
   }
   return shm;
#else
  int shmflg; /* shmflg to be passed to shmget() */
  int shmid; /* return value from shmget() */

  // Create the segment
  shmflg=IPC_CREAT | IPC_EXCL | mode;
  shmid=shmget((key_t)key,size,shmflg);
  if (shmid < 0) {
    switch(errno) {
      case EEXIST:
        show_memory_error("creating shared memory segment: "\
          "Race condition detected when initializing");
        break;
      case EINVAL:
        show_memory_error("creating shared memory segment: "\
          "Specified segment size too large or too small");
        break;
      case ENOMEM:
        show_memory_error("creating shared memory segment: "\
          "Not enough physical memory");
        break;
      default:
        /* Generic error */
        show_memory_error("creating shared memory segment failed");
        break;
    }
    return NULL;
  }
  // Attach the segment to our data space
  shm=shmat(shmid,NULL,0);
  if (shm==(char *) -1) {
    show_memory_error("attaching shared memory segment failed");
    return NULL;
  }
  return (void*) shm;
#endif
}



static int free_shared_memory(int key) {
#ifdef _WIN32
  return 0;
#else
  int shmflg; /* shmflg to be passed to shmget() */
  int shmid; /* return value from shmget() */
  int tmp;

  errno = 0;
   // Link to existing segment
  shmflg=0666;
  shmid=shmget((key_t)key, 0, shmflg);
  if (shmid < 0) {
    switch(errno) {
      case EACCES:
        show_memory_error("linking to shared memory segment (for freeing): "\
          "Access denied");
        break;
      case ENOENT:
        show_memory_error("linking to shared memory segment (for freeing): "\
          "Segment does not exist");
        break;
      default:
        show_memory_error("linking to shared memory segment (for freeing) failed");
        break;
    }
    return -1;
  }
  // Free the segment
  tmp=shmctl(shmid, IPC_RMID, NULL);
  if (tmp==-1) {
    switch(errno) {
      case EPERM:
        show_memory_error("freeing shared memory segment: "\
          "Permission denied");
        break;
      default:
        show_memory_error("freeing shared memory segment failed");
        break;
    }
    return -2;
  }
  return 0;
#endif
}



static int detach_shared_memory(void* shmptr) {
#ifdef _WIN32
  return 0;
#else
  int tmp;

  // detach the segment
  tmp=shmdt(shmptr);
  if (tmp==-1) {
    show_memory_error("detaching shared memory segment failed");
    return -2;
  }
  return 0;
#endif
}


/* ------------ error handling ---------------- */

/** Handle memory error
 * since these errors mostly indicate a fatal error related to database
 * memory allocation, the db pointer is not very useful here and is
 * omitted.
 */
static gint show_memory_error(char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg memory error: %s.\n", errmsg);
#endif
  return -1;
}

#ifdef _WIN32
static gint show_memory_error_nr(char* errmsg, int nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"db memory allocation error: %s %d\n", errmsg, nr);
#endif
  return -1;
}
#endif

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Tanel Tammet 2004,2005,2006,2007,2008,2009
* Copyright (c) Priit Järv 2013
*
* Contact: tanel.tammet@gmail.com
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dballoc.c
 *  Database initialisation and common allocation/deallocation procedures:
 *  areas, subareas, objects, strings etc.
 *
 */

/* ====== Includes =============== */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//features.h"
//lock.h"
//index.h"

/* don't output 'segment does not have enough space' messages */
#define SUPPRESS_LOWLEVEL_ERR 1

/* ====== Private headers and defs ======== */

/* ======= Private protos ================ */

static gint init_db_subarea(void* db, void* area_header, gint index, gint size);
static gint alloc_db_segmentchunk(void* db, gint size); // allocates a next chunk from db memory segment
static gint init_syn_vars(void* db);
static gint init_extdb(void* db);
static gint init_db_index_area_header(void* db);
static gint init_logging(void* db);
static gint init_strhash_area(void* db, db_hash_area_header* areah);
static gint init_hash_subarea(void* db, db_hash_area_header* areah, gint arraylength);
static gint init_db_recptr_bitmap(void* db);
#ifdef USE_REASONER
static gint init_anonconst_table(void* db);
static gint intern_anonconst(void* db, char* str, gint enr);
#endif

static gint make_subarea_freelist(void* db, void* area_header, gint arrayindex);
static gint init_area_buckets(void* db, void* area_header);
static gint init_subarea_freespace(void* db, void* area_header, gint arrayindex);

static gint extend_fixedlen_area(void* db, void* area_header);

static gint split_free(void* db, void* area_header, gint nr, gint* freebuckets, gint i);
static gint extend_varlen_area(void* db, void* area_header, gint minbytes);

static gint show_dballoc_error_nr(void* db, char* errmsg, gint nr);
static gint show_dballoc_error(void* db, char* errmsg);


/* ====== Functions ============== */


/* -------- segment header initialisation ---------- */

/** starts and completes memsegment initialisation
*
* should be called after new memsegment is allocated
*/

gint wg_init_db_memsegment(void* db, gint key, gint size) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint tmp;
  gint free;
  gint i;

  // set main global values for db
  dbh->mark=(gint32) MEMSEGMENT_MAGIC_INIT;
  dbh->version=(gint32) MEMSEGMENT_VERSION;
  dbh->features=(gint32) MEMSEGMENT_FEATURES;
  dbh->checksum=0;
  dbh->size=size;
  dbh->initialadr=(gint)dbh; /* XXX: this assumes pointer size. Currently harmless
                             * because initialadr isn't used much. */
  dbh->key=key;  /* might be 0 if local memory used */

#ifdef CHECK
  if(((gint) dbh)%SUBAREA_ALIGNMENT_BYTES)
    show_dballoc_error(dbh,"db base pointer has bad alignment (ignoring)");
#endif

  // set correct alignment for free
  free=sizeof(db_memsegment_header);
  // set correct alignment for free
  i=SUBAREA_ALIGNMENT_BYTES-(free%SUBAREA_ALIGNMENT_BYTES);
  if (i==SUBAREA_ALIGNMENT_BYTES) i=0;
  dbh->free=free+i;

  // allocate and initialise subareas

  //datarec
  tmp=init_db_subarea(db,&(dbh->datarec_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create datarec area"); return -1; }
  (dbh->datarec_area_header).fixedlength=0;
  tmp=init_area_buckets(db,&(dbh->datarec_area_header)); // fill buckets with 0-s
  if (tmp) {  show_dballoc_error(db," cannot initialize datarec area buckets"); return -1; }
  tmp=init_subarea_freespace(db,&(dbh->datarec_area_header),0); // mark and store free space in subarea 0
  if (tmp) {  show_dballoc_error(db," cannot initialize datarec subarea 0"); return -1; }
  //longstr
  tmp=init_db_subarea(db,&(dbh->longstr_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create longstr area"); return -1; }
  (dbh->longstr_area_header).fixedlength=0;
  tmp=init_area_buckets(db,&(dbh->longstr_area_header)); // fill buckets with 0-s
  if (tmp) {  show_dballoc_error(db," cannot initialize longstr area buckets"); return -1; }
  tmp=init_subarea_freespace(db,&(dbh->longstr_area_header),0); // mark and store free space in subarea 0
  if (tmp) {  show_dballoc_error(db," cannot initialize longstr subarea 0"); return -1; }
  //listcell
  tmp=init_db_subarea(db,&(dbh->listcell_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create listcell area"); return -1; }
  (dbh->listcell_area_header).fixedlength=1;
  (dbh->listcell_area_header).objlength=sizeof(gcell);
  tmp=make_subarea_freelist(db,&(dbh->listcell_area_header),0); // freelist into subarray 0
  if (tmp) {  show_dballoc_error(db," cannot initialize listcell area"); return -1; }
  //shortstr
  tmp=init_db_subarea(db,&(dbh->shortstr_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create short string area"); return -1; }
  (dbh->shortstr_area_header).fixedlength=1;
  (dbh->shortstr_area_header).objlength=SHORTSTR_SIZE;
  tmp=make_subarea_freelist(db,&(dbh->shortstr_area_header),0); // freelist into subarray 0
  if (tmp) {  show_dballoc_error(db," cannot initialize shortstr area"); return -1; }
  //word
  tmp=init_db_subarea(db,&(dbh->word_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create word area"); return -1; }
  (dbh->word_area_header).fixedlength=1;
  (dbh->word_area_header).objlength=sizeof(gint);
  tmp=make_subarea_freelist(db,&(dbh->word_area_header),0); // freelist into subarray 0
  if (tmp) {  show_dballoc_error(db," cannot initialize word area"); return -1; }
  //doubleword
  tmp=init_db_subarea(db,&(dbh->doubleword_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create doubleword area"); return -1; }
  (dbh->doubleword_area_header).fixedlength=1;
  (dbh->doubleword_area_header).objlength=2*sizeof(gint);
  tmp=make_subarea_freelist(db,&(dbh->doubleword_area_header),0); // freelist into subarray 0
  if (tmp) {  show_dballoc_error(db," cannot initialize doubleword area"); return -1; }

  /* index structures also user fixlen object storage:
   *   tnode area - contains index nodes
   *   index header area - contains index headers
   *   index template area - contains template headers
   *   index hash area - varlen storage for hash buckets
   * index lookup data takes up relatively little space so we allocate
   * the smallest chunk allowed for the headers.
   */
  tmp=init_db_subarea(db,&(dbh->tnode_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create tnode area"); return -1; }
  (dbh->tnode_area_header).fixedlength=1;
  (dbh->tnode_area_header).objlength=sizeof(struct wg_tnode);
  tmp=make_subarea_freelist(db,&(dbh->tnode_area_header),0);
  if (tmp) {  show_dballoc_error(db," cannot initialize tnode area"); return -1; }

  tmp=init_db_subarea(db,&(dbh->indexhdr_area_header),0,MINIMAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create index header area"); return -1; }
  (dbh->indexhdr_area_header).fixedlength=1;
  (dbh->indexhdr_area_header).objlength=sizeof(wg_index_header);
  tmp=make_subarea_freelist(db,&(dbh->indexhdr_area_header),0);
  if (tmp) {  show_dballoc_error(db," cannot initialize index header area"); return -1; }

#ifdef USE_INDEX_TEMPLATE
  tmp=init_db_subarea(db,&(dbh->indextmpl_area_header),0,MINIMAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create index header area"); return -1; }
  (dbh->indextmpl_area_header).fixedlength=1;
  (dbh->indextmpl_area_header).objlength=sizeof(wg_index_template);
  tmp=make_subarea_freelist(db,&(dbh->indextmpl_area_header),0);
  if (tmp) {  show_dballoc_error(db," cannot initialize index header area"); return -1; }
#endif

  tmp=init_db_subarea(db,&(dbh->indexhash_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create indexhash area"); return -1; }
  (dbh->indexhash_area_header).fixedlength=0;
  tmp=init_area_buckets(db,&(dbh->indexhash_area_header)); // fill buckets with 0-s
  if (tmp) {  show_dballoc_error(db," cannot initialize indexhash area buckets"); return -1; }
  tmp=init_subarea_freespace(db,&(dbh->indexhash_area_header),0);
  if (tmp) {  show_dballoc_error(db," cannot initialize indexhash subarea 0"); return -1; }

  /* initialize other structures */

  /* initialize strhash array area */
  tmp=init_strhash_area(db,&(dbh->strhash_area_header));
  if (tmp) {  show_dballoc_error(db," cannot create strhash array area"); return -1; }


  /* initialize synchronization */
  tmp=init_syn_vars(db);
  if (tmp) { show_dballoc_error(db," cannot initialize synchronization area"); return -1; }

  /* initialize external database register */
  tmp=init_extdb(db);
  if (tmp) { show_dballoc_error(db," cannot initialize external db register"); return -1; }

  /* initialize index structures */
  tmp=init_db_index_area_header(db);
  if (tmp) { show_dballoc_error(db," cannot initialize index header area"); return -1; }

  /* initialize bitmap for record pointers: really allocated only if USE_RECPTR_BITMAP defined */
  tmp=init_db_recptr_bitmap(db);
  if (tmp) { show_dballoc_error(db," cannot initialize record pointer bitmap"); return -1; }

#ifdef USE_REASONER
  /* initialize anonconst table */
  tmp=init_anonconst_table(db);
  if (tmp) { show_dballoc_error(db," cannot initialize anonconst table"); return -1; }
#endif

  /* initialize logging structures */


  tmp=init_logging(db);
 /* tmp=init_db_subarea(db,&(dbh->logging_area_header),0,INITIAL_SUBAREA_SIZE);
  if (tmp) {  show_dballoc_error(db," cannot create logging area"); return -1; }
  (dbh->logging_area_header).fixedlength=0;
  tmp=init_area_buckets(db,&(dbh->logging_area_header)); // fill buckets with 0-s
  if (tmp) {  show_dballoc_error(db," cannot initialize logging area buckets"); return -1; }*/


  /* Database is initialized, mark it as valid */
  dbh->mark=(gint32) MEMSEGMENT_MAGIC_MARK;
  return 0;
}




/** initializes a subarea. subarea is used for actual data obs allocation
*
* returns 0 if ok, negative otherwise;
*
* called - several times - first by wg_init_db_memsegment, then as old subareas
* get filled up
*/

static gint init_db_subarea(void* db, void* area_header, gint index, gint size) {
  db_area_header* areah;
  gint segmentchunk;
  gint i;
  gint asize;

  //printf("init_db_subarea called with size %d \n",size);
  if (size<MINIMAL_SUBAREA_SIZE) return -1; // errcase
  segmentchunk=alloc_db_segmentchunk(db,size);
  if (!segmentchunk) return -2; // errcase
  areah=(db_area_header*)area_header;
  ((areah->subarea_array)[index]).size=size;
  ((areah->subarea_array)[index]).offset=segmentchunk;
  // set correct alignment for alignedoffset
  i=SUBAREA_ALIGNMENT_BYTES-(segmentchunk%SUBAREA_ALIGNMENT_BYTES);
  if (i==SUBAREA_ALIGNMENT_BYTES) i=0;
  ((areah->subarea_array)[index]).alignedoffset=segmentchunk+i;
  // set correct alignment for alignedsize
  asize=(size-i);
  i=asize-(asize%MIN_VARLENOBJ_SIZE);
  ((areah->subarea_array)[index]).alignedsize=i;
  // set last index and freelist
  areah->last_subarea_index=index;
  areah->freelist=0;
  return 0;
}

/** allocates a new segment chunk from the segment
*
* returns offset if successful, 0 if no more space available
* if 0 returned, no allocation performed: can try with a smaller value
* used for allocating all subareas
*
* Alignment is guaranteed to SUBAREA_ALIGNMENT_BYTES
*/

static gint alloc_db_segmentchunk(void* db, gint size) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint lastfree;
  gint nextfree;
  gint i;

  lastfree=dbh->free;
  nextfree=lastfree+size;
  if (nextfree<0) {
    show_dballoc_error_nr(db,"trying to allocate next segment exceeds positive int limit",size);
    return 0;
  }
  // set correct alignment for nextfree
  i=SUBAREA_ALIGNMENT_BYTES-(nextfree%SUBAREA_ALIGNMENT_BYTES);
  if (i==SUBAREA_ALIGNMENT_BYTES) i=0;
  nextfree=nextfree+i;
  if (nextfree>=(dbh->size)) {
#ifndef SUPPRESS_LOWLEVEL_ERR
    show_dballoc_error_nr(db,"segment does not have enough space for the required chunk of size",size);
#endif
    return 0;
  }
  dbh->free=nextfree;
  return lastfree;
}

/** initializes sync variable storage
*
* returns 0 if ok, negative otherwise;
* Note that a basic spinlock area is initialized even if locking
* is disabled, this is done for better memory image compatibility.
*/

static gint init_syn_vars(void* db) {

  db_memsegment_header* dbh = dbmemsegh(db);
  gint i;

#if !defined(LOCK_PROTO) || (LOCK_PROTO < 3) /* rpspin, wpspin */
  /* calculate aligned pointer */
  i = ((gint) (dbh->locks._storage) + SYN_VAR_PADDING - 1) & -SYN_VAR_PADDING;
  dbh->locks.global_lock = dbaddr(db, (void *) i);
  dbh->locks.writers = dbaddr(db, (void *) (i + SYN_VAR_PADDING));
#else
  i = alloc_db_segmentchunk(db, SYN_VAR_PADDING * (MAX_LOCKS+2));
  if(!i) return -1;
  /* re-align (SYN_VAR_PADDING <> SUBAREA_ALIGNMENT_BYTES) */
  i = (i + SYN_VAR_PADDING - 1) & -SYN_VAR_PADDING;
  dbh->locks.queue_lock = i;
  dbh->locks.storage = i + SYN_VAR_PADDING;
  dbh->locks.max_nodes = MAX_LOCKS;
  dbh->locks.freelist = dbh->locks.storage; /* dummy, wg_init_locks()
                                                will overwrite this */
#endif

  /* allocating space was successful, set the initial state */
  return wg_init_locks(db);
}

/** initializes external database register
*
* returns 0 if ok, negative otherwise;
*/

static gint init_extdb(void* db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  int i;

  dbh->extdbs.count = 0;
  for(i=0; i<MAX_EXTDB; i++) {
    dbh->extdbs.offset[i] = 0;
    dbh->extdbs.size[i] = 0;
  }
  return 0;
}

/** initializes main index area
* Currently this function only sets up an empty index table. The rest
* of the index storage is initialized by wg_init_db_memsegment().
* returns 0 if ok
*/
static gint init_db_index_area_header(void* db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  dbh->index_control_area_header.number_of_indexes=0;
  memset(dbh->index_control_area_header.index_table, 0,
    (MAX_INDEXED_FIELDNR+1)*sizeof(gint));
  dbh->index_control_area_header.index_list=0;
#ifdef USE_INDEX_TEMPLATE
  dbh->index_control_area_header.index_template_list=0;
  memset(dbh->index_control_area_header.index_template_table, 0,
    (MAX_INDEXED_FIELDNR+1)*sizeof(gint));
#endif
  return 0;
}

/** initializes logging area
*
*/
static gint init_logging(void* db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  dbh->logging.active = 0;
  dbh->logging.dirty = 0;
  dbh->logging.serial = 1; /* non-zero, so that zero value in db handle
                            * indicates uninitialized state. */
  return 0;
}

/** initializes strhash area
*
*/
static gint init_strhash_area(void* db, db_hash_area_header* areah) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint arraylength;

  if(STRHASH_SIZE > 0.01 && STRHASH_SIZE < 50) {
    arraylength = (gint) ((dbh->size+1) * (STRHASH_SIZE/100.0)) / sizeof(gint);
  } else {
    arraylength = DEFAULT_STRHASH_LENGTH;
  }
  return init_hash_subarea(db, areah, arraylength);
}

/** initializes hash area
*
*/
static gint init_hash_subarea(void* db, db_hash_area_header* areah, gint arraylength) {
  gint segmentchunk;
  gint i;
  gint asize;
  gint j;

  //printf("init_hash_subarea called with arraylength %d \n",arraylength);
  asize=((arraylength+1)*sizeof(gint))+(2*SUBAREA_ALIGNMENT_BYTES); // 2* just to be safe
  //printf("asize: %d \n",asize);
  //if (asize<100) return -1; // errcase to filter out stupid requests
  segmentchunk=alloc_db_segmentchunk(db,asize);
  //printf("segmentchunk: %d \n",segmentchunk);
  if (!segmentchunk) return -2; // errcase
  areah->offset=segmentchunk;
  areah->size=asize;
  areah->arraylength=arraylength;
  // set correct alignment for arraystart
  i=SUBAREA_ALIGNMENT_BYTES-(segmentchunk%SUBAREA_ALIGNMENT_BYTES);
  if (i==SUBAREA_ALIGNMENT_BYTES) i=0;
  areah->arraystart=segmentchunk+i;
  i=areah->arraystart;
  for(j=0;j<arraylength;j++) dbstore(db,i+(j*sizeof(gint)),0);
  //show_strhash(db);
  return 0;
}

static gint init_db_recptr_bitmap(void* db) {    
  db_memsegment_header* dbh = dbmemsegh(db);

#ifdef USE_RECPTR_BITMAP
  gint segmentchunk;
  gint asize;
  
  // recs minimal alignment 8 bytes, multiply by 8 bits in byte = 64
  asize=((dbh->size)/64)+16; 
  segmentchunk=alloc_db_segmentchunk(db,asize);
  if (!segmentchunk) return -2; // errcase
  dbh->recptr_bitmap.offset=segmentchunk;
  dbh->recptr_bitmap.size=asize;
  memset(offsettoptr(db,segmentchunk),0,asize);
  return 0;
#else  
  dbh->recptr_bitmap.offset=0;
  dbh->recptr_bitmap.size=0;  
  return 0;
#endif     
}


#ifdef USE_REASONER

/** initializes anonymous constants (special uris with attached funs)
*
*/
static gint init_anonconst_table(void* db) {
  int i;
  db_memsegment_header* dbh = dbmemsegh(db);

  dbh->anonconst.anonconst_nr=0;
  dbh->anonconst.anonconst_funs=0;
  // clearing is not really necessary
  for(i=0;i<ANONCONST_TABLE_SIZE;i++) {
    (dbh->anonconst.anonconst_table)[i]=0;
  }

  if (intern_anonconst(db,ACONST_TRUE_STR,ACONST_TRUE)) return 1;
  if (intern_anonconst(db,ACONST_FALSE_STR,ACONST_FALSE)) return 1;
  if (intern_anonconst(db,ACONST_IF_STR,ACONST_IF)) return 1;

  if (intern_anonconst(db,ACONST_NOT_STR,ACONST_NOT)) return 1;
  if (intern_anonconst(db,ACONST_AND_STR,ACONST_AND)) return 1;
  if (intern_anonconst(db,ACONST_OR_STR,ACONST_OR)) return 1;
  if (intern_anonconst(db,ACONST_IMPLIES_STR,ACONST_IMPLIES)) return 1;
  if (intern_anonconst(db,ACONST_XOR_STR,ACONST_XOR)) return 1;

  if (intern_anonconst(db,ACONST_LESS_STR,ACONST_LESS)) return 1;
  if (intern_anonconst(db,ACONST_EQUAL_STR,ACONST_EQUAL)) return 1;
  if (intern_anonconst(db,ACONST_GREATER_STR,ACONST_GREATER)) return 1;
  if (intern_anonconst(db,ACONST_LESSOREQUAL_STR,ACONST_LESSOREQUAL)) return 1;
  if (intern_anonconst(db,ACONST_GREATEROREQUAL_STR,ACONST_GREATEROREQUAL)) return 1;
  if (intern_anonconst(db,ACONST_ISZERO_STR,ACONST_ISZERO)) return 1;

  if (intern_anonconst(db,ACONST_ISEMPTYSTR_STR,ACONST_ISEMPTYSTR)) return 1;

  if (intern_anonconst(db,ACONST_PLUS_STR,ACONST_PLUS)) return 1;
  if (intern_anonconst(db,ACONST_MINUS_STR,ACONST_MINUS)) return 1;
  if (intern_anonconst(db,ACONST_MULTIPLY_STR,ACONST_MULTIPLY)) return 1;
  if (intern_anonconst(db,ACONST_DIVIDE_STR,ACONST_DIVIDE)) return 1;

  if (intern_anonconst(db,ACONST_STRCONTAINS_STR,ACONST_STRCONTAINS)) return 1;
  if (intern_anonconst(db,ACONST_STRCONTAINSICASE_STR,ACONST_STRCONTAINSICASE)) return 1;
  if (intern_anonconst(db,ACONST_SUBSTR_STR,ACONST_SUBSTR)) return 1;
  if (intern_anonconst(db,ACONST_STRLEN_STR,ACONST_STRLEN)) return 1;

  ++(dbh->anonconst.anonconst_nr); // max used slot + 1
  dbh->anonconst.anonconst_funs=dbh->anonconst.anonconst_nr;
  return 0;
}

/** internalizes new anonymous constants: used in init
*
*/
static gint intern_anonconst(void* db, char* str, gint enr) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint nr;
  gint uri;

  nr=decode_anonconst(enr);
  if (nr<0 || nr>=ANONCONST_TABLE_SIZE) {
    show_dballoc_error_nr(db,"inside intern_anonconst: nr given out of range: ", nr);
    return 1;
  }
  uri=wg_encode_unistr(db,str,NULL,WG_URITYPE);
  if (uri==WG_ILLEGAL) {
    show_dballoc_error_nr(db,"inside intern_anonconst: cannot create an uri of size ",strlen(str));
    return 1;
  }
  (dbh->anonconst.anonconst_table)[nr]=uri;
  if (dbh->anonconst.anonconst_nr<nr) (dbh->anonconst.anonconst_nr)=nr;
  return 0;
}

#endif

/* -------- freelists creation  ---------- */

/** create freelist for an area
*
* used for initialising (sub)areas used for fixed-size allocation
*
* returns 0 if ok
*
* speed stats:
*
* 10000 * creation of   100000 elems (1 000 000 000 or 1G ops) takes 1.2 sec on penryn
* 1000 * creation of  1000000 elems (1 000 000 000 or 1G ops) takes 3.4 sec on penryn
*
*/

static gint make_subarea_freelist(void* db, void* area_header, gint arrayindex) {
  db_area_header* areah;
  gint objlength;
  gint max;
  gint size;
  gint offset;
  gint i;

  // general area info
  areah=(db_area_header*)area_header;
  objlength=areah->objlength;

  //subarea info
  size=((areah->subarea_array)[arrayindex]).alignedsize;
  offset=((areah->subarea_array)[arrayindex]).alignedoffset;
  // create freelist
  max=(offset+size)-(2*objlength);
  for(i=offset;i<=max;i=i+objlength) {
    dbstore(db,i,i+objlength);
  }
  dbstore(db,i,0);
  (areah->freelist)=offset; //
  //printf("(areah->freelist) %d \n",(areah->freelist));
  return 0;
}




/* -------- buckets creation  ---------- */

/** fill bucket data for an area
*
* used for initialising areas used for variable-size allocation
*
* returns 0 if ok, not 0 if error
*
*/

gint init_area_buckets(void* db, void* area_header) {
  db_area_header* areah;
  gint* freebuckets;
  gint i;

  // general area info
  areah=(db_area_header*)area_header;
  freebuckets=areah->freebuckets;

  // empty all buckets
  for(i=0;i<EXACTBUCKETS_NR+VARBUCKETS_NR+CACHEBUCKETS_NR;i++) {
    freebuckets[i]=0;
  }
  return 0;
}

/** mark up beginning and end for a subarea, set free area as a new victim
*
* used for initialising new subareas used for variable-size allocation
*
* returns 0 if ok, not 0 if error
*
*/

gint init_subarea_freespace(void* db, void* area_header, gint arrayindex) {
  db_area_header* areah;
  gint* freebuckets;
  gint size;
  gint offset;
  gint dv;
  gint dvindex;
  gint dvsize;
  gint freelist;
  gint endmarkobj;
  gint freeoffset;
  gint freesize;
  //gint i;

  // general area info
  areah=(db_area_header*)area_header;
  freebuckets=areah->freebuckets;

  //subarea info
  size=((areah->subarea_array)[arrayindex]).alignedsize;
  offset=((areah->subarea_array)[arrayindex]).alignedoffset;

  // if the previous area exists, store current victim to freelist
  if (arrayindex>0) {
    dv=freebuckets[DVBUCKET];
    dvsize=freebuckets[DVSIZEBUCKET];
    if (dv!=0 && dvsize>=MIN_VARLENOBJ_SIZE) {
      dbstore(db,dv,makefreeobjectsize(dvsize)); // store new size with freebit to the second half of object
      dbstore(db,dv+dvsize-sizeof(gint),makefreeobjectsize(dvsize));
      dvindex=wg_freebuckets_index(db,dvsize);
      freelist=freebuckets[dvindex];
      if (freelist!=0) dbstore(db,freelist+2*sizeof(gint),dv); // update prev ptr
      dbstore(db,dv+sizeof(gint),freelist); // store previous freelist
      dbstore(db,dv+2*sizeof(gint),dbaddr(db,&freebuckets[dvindex])); // store ptr to previous
      freebuckets[dvindex]=dv; // store offset to correct bucket
      //printf("in init_subarea_freespace: \n PUSHED DV WITH SIZE %d TO FREELIST TO BUCKET %d:\n",
      //        dvsize,dvindex);
      //show_bucket_freeobjects(db,freebuckets[dvindex]);
    }
  }
  // create two minimal in-use objects never to be freed: marking beginning
  // and end of free area via in-use bits in size
  // beginning of free area
  dbstore(db,offset,makespecialusedobjectsize(MIN_VARLENOBJ_SIZE)); // lowest bit 0 means in use
  dbstore(db,offset+sizeof(gint),SPECIALGINT1START); // next ptr
  dbstore(db,offset+2*sizeof(gint),0); // prev ptr
  dbstore(db,offset+MIN_VARLENOBJ_SIZE-sizeof(gint),MIN_VARLENOBJ_SIZE); // len to end as well
  // end of free area
  endmarkobj=offset+size-MIN_VARLENOBJ_SIZE;
  dbstore(db,endmarkobj,makespecialusedobjectsize(MIN_VARLENOBJ_SIZE)); // lowest bit 0 means in use
  dbstore(db,endmarkobj+sizeof(gint),SPECIALGINT1END); // next ptr
  dbstore(db,endmarkobj+2*sizeof(gint),0); // prev ptr
  dbstore(db,endmarkobj+MIN_VARLENOBJ_SIZE-sizeof(gint),MIN_VARLENOBJ_SIZE); // len to end as well
  // calc where real free area starts and what is the size
  freeoffset=offset+MIN_VARLENOBJ_SIZE;
  freesize=size-2*MIN_VARLENOBJ_SIZE;
  // put whole free area into one free object
  // store the single free object as a designated victim
  dbstore(db,freeoffset,makespecialusedobjectsize(freesize)); // length without free bits: victim not marked free
  dbstore(db,freeoffset+sizeof(gint),SPECIALGINT1DV); // marks that it is a dv kind of special object
  freebuckets[DVBUCKET]=freeoffset;
  freebuckets[DVSIZEBUCKET]=freesize;
  // alternative: store the single free object to correct bucket
  /*
  dbstore(db,freeoffset,setcfree(freesize)); // size with free bits stored to beginning of object
  dbstore(db,freeoffset+sizeof(gint),0); // empty ptr to remaining obs stored after size
  i=freebuckets_index(db,freesize);
  if (i<0) {
    show_dballoc_error_nr(db,"initialising free object failed for ob size ",freesize);
    return -1;
  }
  dbstore(db,freeoffset+2*sizeof(gint),dbaddr(db,&freebuckets[i])); // ptr to previous stored
  freebuckets[i]=freeoffset;
  */
  return 0;
}



/* -------- fixed length object allocation and freeing ---------- */


/** allocate a new fixed-len object
*
* return offset if ok, 0 if allocation fails
*/

gint wg_alloc_fixlen_object(void* db, void* area_header) {
  db_area_header* areah;
  gint freelist;

  areah=(db_area_header*)area_header;
  freelist=areah->freelist;
  if (!freelist) {
    if(!extend_fixedlen_area(db,areah)) {
      show_dballoc_error_nr(db,"cannot extend fixed length object area for size ",areah->objlength);
      return 0;
    }
    freelist=areah->freelist;
    if (!freelist) {
      show_dballoc_error_nr(db,"no free fixed length objects available for size ",areah->objlength);
      return 0;
    } else {
      areah->freelist=dbfetch(db,freelist);
      return freelist;
    }
  } else {
    areah->freelist=dbfetch(db,freelist);
    return freelist;
  }
}

/** create and initialise a new subarea for fixed-len obs area
*
* returns allocated size if ok, 0 if failure
* used when the area has no more free space
*
*/

static gint extend_fixedlen_area(void* db, void* area_header) {
  gint i;
  gint tmp;
  gint size, newsize;
  db_area_header* areah;

  areah=(db_area_header*)area_header;
  i=areah->last_subarea_index;
  if (i+1>=SUBAREA_ARRAY_SIZE) {
    show_dballoc_error_nr(db,
      " no more subarea array elements available for fixedlen of size: ",areah->objlength);
    return 0; // no more subarea array elements available
  }
  size=((areah->subarea_array)[i]).size; // last allocated subarea size
  // make tmp power-of-two times larger
  newsize=size<<1;
  //printf("fixlen OLD SUBAREA SIZE WAS %d NEW SUBAREA SIZE SHOULD BE %d\n",size,newsize);

  while(newsize >= MINIMAL_SUBAREA_SIZE) {
    if(!init_db_subarea(db,areah,i+1,newsize)) {
      goto done;
    }
    /* fall back to smaller size */
    newsize>>=1;
    //printf("REQUIRED SPACE FAILED, TRYING %d\n",newsize);
  }
  show_dballoc_error_nr(db," cannot extend datarec area with a new subarea of size: ",newsize<<1);
  return 0;
done:
  // here we have successfully allocated a new subarea
  tmp=make_subarea_freelist(db,areah,i+1);  // fill with a freelist, store ptrs
  if (tmp) {  show_dballoc_error(db," cannot initialize new subarea"); return 0; }
  return newsize;
}



/** free an existing listcell
*
* the object is added to the freelist
*
*/

void wg_free_listcell(void* db, gint offset) {
  dbstore(db,offset,(dbmemsegh(db)->listcell_area_header).freelist);
  (dbmemsegh(db)->listcell_area_header).freelist=offset;
}


/** free an existing shortstr object
*
* the object is added to the freelist
*
*/

void wg_free_shortstr(void* db, gint offset) {
  dbstore(db,offset,(dbmemsegh(db)->shortstr_area_header).freelist);
  (dbmemsegh(db)->shortstr_area_header).freelist=offset;
}

/** free an existing word-len object
*
* the object is added to the freelist
*
*/

void wg_free_word(void* db, gint offset) {
  dbstore(db,offset,(dbmemsegh(db)->word_area_header).freelist);
  (dbmemsegh(db)->word_area_header).freelist=offset;
}



/** free an existing doubleword object
*
* the object is added to the freelist
*
*/

void wg_free_doubleword(void* db, gint offset) {
  dbstore(db,offset,(dbmemsegh(db)->doubleword_area_header).freelist); //bug fixed here
  (dbmemsegh(db)->doubleword_area_header).freelist=offset;
}

/** free an existing tnode object
*
* the object is added to the freelist
*
*/

void wg_free_tnode(void* db, gint offset) {
  dbstore(db,offset,(dbmemsegh(db)->tnode_area_header).freelist);
  (dbmemsegh(db)->tnode_area_header).freelist=offset;
}

/** free generic fixlen object
*
* the object is added to the freelist
*
*/

void wg_free_fixlen_object(void* db, db_area_header *hdr, gint offset) {
  dbstore(db,offset,hdr->freelist);
  hdr->freelist=offset;
}


/* -------- variable length object allocation and freeing ---------- */


/** allocate a new object of given length
*
* returns correct offset if ok, 0 in case of error
*
*/

gint wg_alloc_gints(void* db, void* area_header, gint nr) {
  gint wantedbytes;   // actually wanted size in bytes, stored in object header
  gint usedbytes;     // amount of bytes used: either wantedbytes or bytes+4 (obj must be 8 aligned)
  gint* freebuckets;
  gint res, nextobject;
  gint nextel;
  gint i;
  gint j;
  gint tmp;
  gint size;
  db_area_header* areah;

  areah=(db_area_header*)area_header;
  wantedbytes=nr*sizeof(gint); // object sizes are stored in bytes
  if (wantedbytes<0) return 0; // cannot allocate negative or zero sizes
  if (wantedbytes<=MIN_VARLENOBJ_SIZE) usedbytes=MIN_VARLENOBJ_SIZE;
  /* XXX: modifying the next line breaks encode_query_param_unistr().
   * Rewrite this using macros to reduce the chance of accidental breakage */
  else if (wantedbytes%8) usedbytes=wantedbytes+4;
  else usedbytes=wantedbytes;
  //printf("wg_alloc_gints called with nr %d and wantedbytes %d and usedbytes %d\n",nr,wantedbytes,usedbytes);
  // first find if suitable length free object is available
  freebuckets=areah->freebuckets;
  if (usedbytes<EXACTBUCKETS_NR && freebuckets[usedbytes]!=0) {
    res=freebuckets[usedbytes];  // first freelist element in that bucket
    nextel=dbfetch(db,res+sizeof(gint)); // next element in freelist of that bucket
    freebuckets[usedbytes]=nextel;
    // change prev ptr of next elem
    if (nextel!=0) dbstore(db,nextel+2*sizeof(gint),dbaddr(db,&freebuckets[usedbytes]));
    // prev elem cannot be free (no consecutive free elems)
    dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
    /* next object should be marked as "prev used" */
    nextobject=res+usedbytes;
    tmp=dbfetch(db,nextobject);
    if (isnormalusedobject(tmp)) dbstore(db,nextobject,makeusedobjectsizeprevused(tmp));
    return res;
  }
  // next try to find first free object in a few nearest exact-length buckets (shorter first)
  for(j=0,i=usedbytes+1;i<EXACTBUCKETS_NR && j<3;i++,j++) {
    if (freebuckets[i]!=0 &&
        getfreeobjectsize(dbfetch(db,freebuckets[i]))>=usedbytes+MIN_VARLENOBJ_SIZE) {
      // found one somewhat larger: now split and store the rest
      res=freebuckets[i];
      tmp=split_free(db,areah,usedbytes,freebuckets,i);
      if (tmp<0) return 0; // error case
      // prev elem cannot be free (no consecutive free elems)
      dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
      return res;
    }
  }
  // next try to use the cached designated victim for creating objects off beginning
  // designated victim is not marked free by header and is not present in any freelist
  size=freebuckets[DVSIZEBUCKET];
  if (usedbytes<=size && freebuckets[DVBUCKET]!=0) {
    res=freebuckets[DVBUCKET];
    if (usedbytes==size) {
      // found a designated victim of exactly right size, dv is used up and disappears
      freebuckets[DVBUCKET]=0;
      freebuckets[DVSIZEBUCKET]=0;
      // prev elem of dv cannot be free
      dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
      return res;
    } else if (usedbytes+MIN_VARLENOBJ_SIZE<=size) {
      // found a designated victim somewhat larger: take the first part and keep the rest as dv
      dbstore(db,res+usedbytes,makespecialusedobjectsize(size-usedbytes)); // store smaller size to victim, turn off free bits
      dbstore(db,res+usedbytes+sizeof(gint),SPECIALGINT1DV); // marks that it is a dv kind of special object
      freebuckets[DVBUCKET]=res+usedbytes; // point to rest of victim
      freebuckets[DVSIZEBUCKET]=size-usedbytes; // rest of victim becomes shorter
      // prev elem of dv cannot be free
      dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
      return res;
    }
  }
  // next try to find first free object in exact-length buckets (shorter first)
  for(i=usedbytes+1;i<EXACTBUCKETS_NR;i++) {
    if (freebuckets[i]!=0 &&
        getfreeobjectsize(dbfetch(db,freebuckets[i]))>=usedbytes+MIN_VARLENOBJ_SIZE) {
      // found one somewhat larger: now split and store the rest
      res=freebuckets[i];
      tmp=split_free(db,areah,usedbytes,freebuckets,i);
      if (tmp<0) return 0; // error case
      // prev elem cannot be free (no consecutive free elems)
      dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
      return res;
    }
  }
  // next try to find first free object in var-length buckets (shorter first)
  for(i=wg_freebuckets_index(db,usedbytes);i<EXACTBUCKETS_NR+VARBUCKETS_NR;i++) {
    if (freebuckets[i]!=0) {
      size=getfreeobjectsize(dbfetch(db,freebuckets[i]));
      if (size==usedbytes) {
        // found one of exactly right size
        res=freebuckets[i];  // first freelist element in that bucket
        nextel=dbfetch(db,res+sizeof(gint)); // next element in freelist of that bucket
        freebuckets[i]=nextel;
        // change prev ptr of next elem
        if (nextel!=0) dbstore(db,nextel+2*sizeof(gint),dbaddr(db,&freebuckets[i]));
        // prev elem cannot be free (no consecutive free elems)
        dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
        return res;
      } else if (size>=usedbytes+MIN_VARLENOBJ_SIZE) {
        // found one somewhat larger: now split and store the rest
        res=freebuckets[i];
        //printf("db %d,nr %d,freebuckets %d,i %d\n",db,(int)nr,(int)freebuckets,(int)i);
        tmp=split_free(db,areah,usedbytes,freebuckets,i);
        if (tmp<0) return 0; // error case
        // prev elem cannot be free (no consecutive free elems)
        dbstore(db,res,makeusedobjectsizeprevused(wantedbytes)); // store wanted size to the returned object
        return res;
      }
    }
  }
  // down here we have found no suitable dv or free object to use for allocation
  // try to get a new memory area
  //printf("ABOUT TO CREATE A NEW SUBAREA\n");
  tmp=extend_varlen_area(db,areah,usedbytes);
  if (!tmp) {  show_dballoc_error(db," cannot initialize new varlen subarea"); return 0; }
  // here we have successfully allocated a new subarea
  // call self recursively: this call will use the new free area
  tmp=wg_alloc_gints(db,areah,nr);
  //show_db_memsegment_header(db);
  return tmp;
}



/** create and initialise a new subarea for var-len obs area
*
* returns allocated size if ok, 0 if failure
* used when the area has no more free space
*
* bytes indicates the minimal required amount:
* could be extended much more, but not less than bytes
*
*/

static gint extend_varlen_area(void* db, void* area_header, gint minbytes) {
  gint i;
  gint tmp;
  gint size, minsize, newsize;
  db_area_header* areah;

  areah=(db_area_header*)area_header;
  i=areah->last_subarea_index;
  if (i+1>=SUBAREA_ARRAY_SIZE) {
    show_dballoc_error_nr(db," no more subarea array elements available for datarec: ",i);
    return 0; // no more subarea array elements available
  }
  size=((areah->subarea_array)[i]).size; // last allocated subarea size
  minsize=minbytes+SUBAREA_ALIGNMENT_BYTES+2*(MIN_VARLENOBJ_SIZE); // minimum allowed
#ifdef CHECK
  if(minsize<0) { /* sanity check */
    show_dballoc_error_nr(db, "invalid number of bytes requested: ", minbytes);
    return 0;
  }
#endif
  if(minsize<MINIMAL_SUBAREA_SIZE)
    minsize=MINIMAL_SUBAREA_SIZE;

  // make newsize power-of-two times larger so that it would be enough for required bytes
  for(newsize=size<<1; newsize>=0 && newsize<minsize; newsize<<=1);
  //printf("OLD SUBAREA SIZE WAS %d NEW SUBAREA SIZE SHOULD BE %d\n",size,newsize);

  while(newsize >= minsize) {
    if(!init_db_subarea(db,areah,i+1,newsize)) {
      goto done;
    }
    /* fall back to smaller size */
    newsize>>=1;
    //printf("REQUIRED SPACE FAILED, TRYING %d\n",newsize);
  }
  show_dballoc_error_nr(db," cannot extend datarec area with a new subarea of size: ",newsize<<1);
  return 0;
done:
  // here we have successfully allocated a new subarea
  tmp=init_subarea_freespace(db,areah,i+1); // mark beg and end, store new victim
  if (tmp) {  show_dballoc_error(db," cannot initialize new subarea"); return 0; }
  return newsize;
}



/** splits a free object into a smaller new object and the remainder, stores remainder to right list
*
* returns 0 if ok, negative nr in case of error
* we assume we always split the first elem in a bucket freelist
* we also assume the remainder is >=MIN_VARLENOBJ_SIZE
*
*/

static gint split_free(void* db, void* area_header, gint nr, gint* freebuckets, gint i) {
  gint object;
  gint oldsize;
  gint oldnextptr;
  gint splitsize;
  gint splitobject;
  gint splitindex;
  gint freelist;
  gint dv;
  gint dvsize;
  gint dvindex;

  object=freebuckets[i]; // object offset
  oldsize=dbfetch(db,object); // first gint at offset
  if (!isfreeobject(oldsize)) return -1; // not really a free object!
  oldsize=getfreeobjectsize(oldsize); // remove free bits, get real size
  // observe object is first obj in freelist, hence no free obj at prevptr
  oldnextptr=dbfetch(db,object+sizeof(gint)); // second gint at offset
  // store new size at offset (beginning of object) and mark as used with used prev
  // observe that a free object cannot follow another free object, hence we know prev is used
  dbstore(db,object,makeusedobjectsizeprevused(nr));
  freebuckets[i]=oldnextptr; // store ptr to next elem into bucket ptr
  splitsize=oldsize-nr; // remaining size
  splitobject=object+nr;  // offset of the part left
  // we may store the splitobject as a designated victim instead of a suitable freelist
  // but currently this is disallowed and the underlying code is not really finished:
  // marking of next used object prev-free/prev-used is missing
  // instead of this code we rely on using a newly freed object as dv is larger than dv
  dvsize=freebuckets[DVSIZEBUCKET];
  if (0) { // (splitsize>dvsize) {
    // store splitobj as a new designated victim, but first store current victim to freelist, if possible
    dv=freebuckets[DVBUCKET];
    if (dv!=0) {
      if (dvsize<MIN_VARLENOBJ_SIZE) {
        show_dballoc_error(db,"split_free notices corruption: too small designated victim");
        return -1; // error case
      }
      dbstore(db,dv,makefreeobjectsize(dvsize)); // store new size with freebits to dv
      dbstore(db,dv+dvsize-sizeof(gint),makefreeobjectsize(dvsize));
      dvindex=wg_freebuckets_index(db,dvsize);
      freelist=freebuckets[dvindex];
      if (freelist!=0) dbstore(db,freelist+2*sizeof(gint),dv); // update prev ptr
      dbstore(db,dv+sizeof(gint),freelist); // store previous freelist
      dbstore(db,dv+2*sizeof(gint),dbaddr(db,&freebuckets[dvindex])); // store ptr to previous
      freebuckets[dvindex]=dv; // store offset to correct bucket
      //printf("PUSHED DV WITH SIZE %d TO FREELIST TO BUCKET %d:\n",dvsize,dvindex);
      //show_bucket_freeobjects(db,freebuckets[dvindex]);
    }
    // store splitobj as a new victim
    //printf("REPLACING DV WITH OBJ AT %d AND SIZE %d\n",splitobject,splitsize);
    dbstore(db,splitobject,makespecialusedobjectsize(splitsize)); // length with special used object mark
    dbstore(db,splitobject+sizeof(gint),SPECIALGINT1DV); // marks that it is a dv kind of special object
    freebuckets[DVBUCKET]=splitobject;
    freebuckets[DVSIZEBUCKET]=splitsize;
    return 0;
  } else {
    // store splitobj in a freelist, no changes to designated victim
    dbstore(db,splitobject,makefreeobjectsize(splitsize)); // store new size with freebit to the second half of object
    dbstore(db,splitobject+splitsize-sizeof(gint),makefreeobjectsize(splitsize));
    splitindex=wg_freebuckets_index(db,splitsize); // bucket to store the split remainder
    if (splitindex<0) return splitindex; // error case
    freelist=freebuckets[splitindex];
    if (freelist!=0) dbstore(db,freelist+2*sizeof(gint),splitobject); // update prev ptr
    dbstore(db,splitobject+sizeof(gint),freelist); // store previous freelist
    dbstore(db,splitobject+2*sizeof(gint),dbaddr(db,&freebuckets[splitindex])); // store ptr to previous
    freebuckets[splitindex]=splitobject; // store remainder offset to correct bucket
    return 0;
  }
}

/** returns a correct freebuckets index for a given size of object
*
* returns -1 in case of error, 0,...,EXACBUCKETS_NR+VARBUCKETS_NR-1 otherwise
*
* sizes 0,1,2,...,255 in exactbuckets (say, EXACBUCKETS_NR=256)
* longer sizes in varbuckets:
* sizes 256-511 in bucket 256,
*       512-1023 in bucket 257 etc
* 256*2=512, 512*2=1024, etc
*/

gint wg_freebuckets_index(void* db, gint size) {
  gint i;
  gint cursize;

  if (size<EXACTBUCKETS_NR) return size;
  cursize=EXACTBUCKETS_NR*2;
  for(i=0; i<VARBUCKETS_NR; i++) {
    if (size<cursize) return EXACTBUCKETS_NR+i;
    cursize=cursize*2;
  }
  return -1; // too large size, not enough buckets
}

/** frees previously alloc_bytes obtained var-length object at offset
*
* returns 0 if ok, negative value if error (likely reason: wrong object ptr)
* merges the freed object with free neighbours, if available, to get larger free objects
*
*/

gint wg_free_object(void* db, void* area_header, gint object) {
  gint size;
  gint i;
  gint* freebuckets;

  gint objecthead;
  gint prevobject;
  gint prevobjectsize;
  gint prevobjecthead;
  gint previndex;
  gint nextobject;
  gint nextobjecthead;
  gint nextindex;
  gint freelist;
  gint prevnextptr;
  gint prevprevptr;
  gint nextnextptr;
  gint nextprevptr;
  gint bucketfreelist;
  db_area_header* areah;

  gint dv;
  gint dvsize;
  gint tmp;

  areah=(db_area_header*)area_header;
  if (!dbcheck(db)) {
    show_dballoc_error(db,"wg_free_object first arg is not a db address");
    return -1;
  }
  //printf("db %u object %u \n",db,object);
  //printf("freeing object %d with size %d and end %d\n",
  //        object,getusedobjectsize(dbfetch(db,object)),object+getusedobjectsize(dbfetch(db,object)));
  objecthead=dbfetch(db,object);
  if (isfreeobject(objecthead)) {
    show_dballoc_error(db,"wg_free_object second arg is already a free object");
    return -2; // attempting to free an already free object
  }
  size=getusedobjectsize(objecthead); // size stored at first gint of object
  if (size<MIN_VARLENOBJ_SIZE) {
    show_dballoc_error(db,"wg_free_object second arg has a too small size");
    return -3; // error: wrong size info (too small)
  }
  freebuckets=areah->freebuckets;

  // first try to merge with the previous free object, if so marked
  if (isnormalusedobjectprevfree(objecthead)) {
    //printf("**** about to merge object %d on free with prev %d !\n",object,prevobject);
    // use the size of the previous (free) object stored at the end of the previous object
    prevobjectsize=getfreeobjectsize(dbfetch(db,(object-sizeof(gint))));
    prevobject=object-prevobjectsize;
    prevobjecthead=dbfetch(db,prevobject);
    if (!isfreeobject(prevobjecthead) || !getfreeobjectsize(prevobject)==prevobjectsize) {
      show_dballoc_error(db,"wg_free_object notices corruption: previous object is not ok free object");
      return -4; // corruption noticed
    }
    // remove prev object from its freelist
    // first, get necessary information
    prevnextptr=dbfetch(db,prevobject+sizeof(gint));
    prevprevptr=dbfetch(db,prevobject+2*sizeof(gint));
    previndex=wg_freebuckets_index(db,prevobjectsize);
    freelist=freebuckets[previndex];
    // second, really remove prev object from freelist
    if (freelist==prevobject) {
      // prev object pointed to directly from bucket
      freebuckets[previndex]=prevnextptr;  // modify prev prev
      if (prevnextptr!=0) dbstore(db,prevnextptr+2*sizeof(gint),prevprevptr); // modify prev next
    } else {
      // prev object pointed to from another object, not directly bucket
      // next of prev of prev will point to next of next
      dbstore(db,prevprevptr+sizeof(gint),prevnextptr);
      // prev of next of prev will prev-point to prev of prev
      if (prevnextptr!=0) dbstore(db,prevnextptr+2*sizeof(gint),prevprevptr);
    }
    // now treat the prev object as the current object to be freed!
    object=prevobject;
    size=size+prevobjectsize;
  } else if ((freebuckets[DVBUCKET]+freebuckets[DVSIZEBUCKET])==object) {
    // should merge with a previous dv
    object=freebuckets[DVBUCKET];
    size=size+freebuckets[DVSIZEBUCKET]; // increase size to cover dv as well
    // modify dv size information in area header: dv will extend to freed object
    freebuckets[DVSIZEBUCKET]=size;
    // store dv size and marker to dv head
    dbstore(db,object,makespecialusedobjectsize(size));
    dbstore(db,object+sizeof(gint),SPECIALGINT1DV);
    return 0;    // do not store anything to freebuckets!!
  }

  // next, try to merge with the next object: either free object or dv
  // also, if next object is normally used instead, mark it as following the free object
  nextobject=object+size;
  nextobjecthead=dbfetch(db,nextobject);
  if (isfreeobject(nextobjecthead)) {
    // should merge with a following free object
    //printf("**** about to merge object %d on free with next %d !\n",object,nextobject);
    size=size+getfreeobjectsize(nextobjecthead); // increase size to cover next object as well
    // remove next object from its freelist
    // first, get necessary information
    nextnextptr=dbfetch(db,nextobject+sizeof(gint));
    nextprevptr=dbfetch(db,nextobject+2*sizeof(gint));
    nextindex=wg_freebuckets_index(db,getfreeobjectsize(nextobjecthead));
    freelist=freebuckets[nextindex];
    // second, really remove next object from freelist
    if (freelist==nextobject) {
      // next object pointed to directly from bucket
      freebuckets[nextindex]=nextnextptr;  // modify next prev
      if (nextnextptr!=0) dbstore(db,nextnextptr+2*sizeof(gint),nextprevptr); // modify next next
    } else {
      // next object pointed to from another object, not directly bucket
      // prev of next will point to next of next
      dbstore(db,nextprevptr+sizeof(gint),nextnextptr);
      // next of next will prev-point to prev of next
      if (nextnextptr!=0) dbstore(db,nextnextptr+2*sizeof(gint),nextprevptr);
    }
  } else if (isspecialusedobject(nextobjecthead) && nextobject==freebuckets[DVBUCKET]) {
    // should merge with a following dv
    size=size+freebuckets[DVSIZEBUCKET]; // increase size to cover next object as well
    // modify dv information in area header
    freebuckets[DVBUCKET]=object;
    freebuckets[DVSIZEBUCKET]=size;
    // store dv size and marker to dv head
    dbstore(db,object,makespecialusedobjectsize(size));
    dbstore(db,object+sizeof(gint),SPECIALGINT1DV);
    return 0;    // do not store anything to freebuckets!!
  }  else if (isnormalusedobject(nextobjecthead)) {
    // mark the next used object as following a free object
    dbstore(db,nextobject,makeusedobjectsizeprevfree(dbfetch(db,nextobject)));
  }  // we do no special actions in case next object is end marker

  // maybe the newly freed object is larger than the designated victim?
  // if yes, use the newly freed object as a new designated victim
  // and afterwards put the old dv to freelist
  if (size>freebuckets[DVSIZEBUCKET]) {
    dv=freebuckets[DVBUCKET];
    dvsize=freebuckets[DVSIZEBUCKET];
    freebuckets[DVBUCKET]=object;
    freebuckets[DVSIZEBUCKET]=size;
    dbstore(db,object,makespecialusedobjectsize(size));
    dbstore(db,object+sizeof(gint),SPECIALGINT1DV);
    // set the next used object mark to prev-used!
    nextobject=object+size;
    tmp=dbfetch(db,nextobject);
    if (isnormalusedobject(tmp)) dbstore(db,nextobject,makeusedobjectsizeprevused(tmp));
    // dv handling
    if (dv==0) return 0; // if no dv actually, then nothing to put to freelist
    // set the object point to dv to make it put into freelist after
    // but first mark the next object after dv as following free
    nextobject=dv+dvsize;
    tmp=dbfetch(db,nextobject);
    if (isnormalusedobject(tmp)) dbstore(db,nextobject,makeusedobjectsizeprevfree(tmp));
    // let the old dv be handled as object to be put to freelist after
    object=dv;
    size=dvsize;
  }
  // store freed (or freed and merged) object to the correct bucket,
  // except for dv-merge cases above (returns earlier)
  i=wg_freebuckets_index(db,size);
  bucketfreelist=freebuckets[i];
  if (bucketfreelist!=0) dbstore(db,bucketfreelist+2*sizeof(gint),object); // update prev ptr
  dbstore(db,object,makefreeobjectsize(size)); // store size and freebit
  dbstore(db,object+size-sizeof(gint),makefreeobjectsize(size)); // store size and freebit
  dbstore(db,object+sizeof(gint),bucketfreelist); // store previous freelist
  dbstore(db,object+2*sizeof(gint),dbaddr(db,&freebuckets[i])); // store prev ptr
  freebuckets[i]=object;
  return 0;
}


/*
Tanel Tammet
http://www.epl.ee/?i=112121212
Kuiv tn 9, Tallinn, Estonia
+3725524876

len |  refcount |   xsd:type |  namespace |  contents .... |

header: 4*4=16 bytes

128 bytes

*/

/***************** Child database functions ******************/


/* Register external database offset
 *
 * Stores offset and size of an external database. This allows
 * recognizing external pointers/offsets and computing their
 * base offset.
 *
 * Once external data is stored to the database, the memory
 * image can no longer be saved/restored.
 */
gint wg_register_external_db(void *db, void *extdb) {
#ifdef USE_CHILD_DB
  db_memsegment_header* dbh = dbmemsegh(db);

#ifdef CHECK
  if(dbh->key != 0) {
    show_dballoc_error(db,
      "external references not allowed in a shared memory db");
    return -1;
  }
#endif

  if(dbh->index_control_area_header.number_of_indexes > 0) {
    return show_dballoc_error(db,
      "Database has indexes, external references not allowed");
  }
  if(dbh->extdbs.count >= MAX_EXTDB) {
    show_dballoc_error(db, "cannot register external database");
  } else {
    dbh->extdbs.offset[dbh->extdbs.count] = ptrtooffset(db, dbmemsegh(extdb));
    dbh->extdbs.size[dbh->extdbs.count++] = \
      dbmemsegh(extdb)->size;
  }
  return 0;
#else
  show_dballoc_error(db, "child database support is not enabled");
  return -1;
#endif
}

/******************** Hash index support *********************/

/*
 * Initialize a new hash table for an index.
 */
gint wg_create_hash(void *db, db_hash_area_header* areah, gint size) {
  if(size <= 0)
    size = DEFAULT_IDXHASH_LENGTH;
  if(init_hash_subarea(db, areah, size)) {
    return show_dballoc_error(db," cannot create strhash array area");
  }
  return 0;
}

/********** Helper functions for accessing the header ********/

/*
 * Return free space in segment (in bytes)
 * Also tries to predict whether it is possible to allocate more
 * space in the segment.
 */
gint wg_database_freesize(void *db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint freesize = dbh->size - dbh->free;
  return (freesize < MINIMAL_SUBAREA_SIZE ? 0 : freesize);
}

/*
 * Return total segment size (in bytes)
 */
gint wg_database_size(void *db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  return dbh->size;
}


/* --------------- error handling ------------------------------*/

/** called with err msg when an allocation error occurs
*
*  may print or log an error
*  does not do any jumps etc
*/

static gint show_dballoc_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"db memory allocation error: %s\n",errmsg);
#endif
  return -1;
}

/** called with err msg and err nr when an allocation error occurs
*
*  may print or log an error
*  does not do any jumps etc
*/

static gint show_dballoc_error_nr(void* db, char* errmsg, gint nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"db memory allocation error: %s %d\n", errmsg, (int) nr);
#endif
  return -1;

}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Tanel Tammet 2004,2005,2006,2007,2008,2009
* Copyright (c) Priit JÃ¤rv 2009,2010,2011,2013,2014
*
* Contact: tanel.tammet@gmail.com
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbdata.c
 *  Procedures for handling actual data: strings, integers, records,  etc
 *
 */

/* ====== Includes =============== */


#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
/* For Sleep() */
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/timeb.h>
//#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//data.h"
//hash.h"
//log.h"
//index.h"
//compare.h"
//lock.h"

/* ====== Private headers and defs ======== */

#ifdef _WIN32
//Thread-safe localtime_r appears not to be present on windows: emulate using win localtime, which is thread-safe.
static struct tm * localtime_r (const time_t *timer, struct tm *result);
#define sscanf sscanf_s  // warning: needs extra buflen args for string etc params
#define snprintf sprintf_s
#endif


/* ======= Private protos ================ */

#ifdef USE_BACKLINKING
static gint remove_backlink_index_entries(void *db, gint *record,
  gint value, gint depth);
static gint restore_backlink_index_entries(void *db, gint *record,
  gint value, gint depth);
#endif

static int isleap(unsigned yr);
static unsigned months_to_days (unsigned month);
static long years_to_days (unsigned yr);
static long ymd_to_scalar (unsigned yr, unsigned mo, unsigned day);
static void scalar_to_ymd (long scalar, unsigned *yr, unsigned *mo, unsigned *day);

static gint free_field_encoffset(void* db,gint encoffset);
static gint find_create_longstr(void* db, char* data, char* extrastr, gint type, gint length);

#ifdef USE_CHILD_DB
static void *get_ptr_owner(void *db, gint encoded);
static int is_local_offset(void *db, gint offset);
#endif

#ifdef USE_RECPTR_BITMAP
static void recptr_setbit(void *db,void *ptr);
static void recptr_clearbit(void *db,void *ptr);
#endif

static gint show_data_error(void* db, char* errmsg);
static gint show_data_error_nr(void* db, char* errmsg, gint nr);
static gint show_data_error_double(void* db, char* errmsg, double nr);
static gint show_data_error_str(void* db, char* errmsg, char* str);


/* ====== Functions ============== */



/* ------------ full record handling ---------------- */


void* wg_create_record(void* db, wg_int length) {
  void *rec = wg_create_raw_record(db, length);
  /* Index all the created NULL fields to ensure index consistency */
  if(rec) {
    if(wg_index_add_rec(db, rec) < -1)
      return NULL; /* index error */
  }
  return rec;
}

/*
 * Creates the record and initializes the fields
 * to NULL, but does not update indexes. This is useful in two
 * scenarios: 1. fields are immediately initialized to something
 * else, making indexing NULLs useless 2. record will have
 * a RECORD_META_NOTDATA bit set, so the fields should not
 * be indexed at all.
 *
 * In the first case, it is required that wg_set_new_field()
 * is called on all the fields in the record. In the second case,
 * the caller is responsible for setting the meta bits, however
 * it is not mandatory to re-initialize all the fields.
 */
void* wg_create_raw_record(void* db, wg_int length) {
  gint offset;
  gint i;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error_nr(db,"wrong database pointer given to wg_create_record with length ",length);
    return 0;
  }
  if(length < 0) {
    show_data_error_nr(db, "invalid record length:",length);
    return 0;
  }
#endif

#ifdef USE_DBLOG
  /* Log first, modify shared memory next */
  if(dbmemsegh(db)->logging.active) {
    if(wg_log_create_record(db, length))
      return 0;
  }
#endif

  offset=wg_alloc_gints(db,
                     &(dbmemsegh(db)->datarec_area_header),
                    length+RECORD_HEADER_GINTS);
  if (!offset) {
    show_data_error_nr(db,"cannot create a record of size ",length);
#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      wg_log_encval(db, 0);
    }
#endif
    return 0;
  }

  /* Init header */
  dbstore(db, offset+RECORD_META_POS*sizeof(gint), 0);
  dbstore(db, offset+RECORD_BACKLINKS_POS*sizeof(gint), 0);
  for(i=RECORD_HEADER_GINTS;i<length+RECORD_HEADER_GINTS;i++) {
    dbstore(db,offset+(i*(sizeof(gint))),0);
  }

#ifdef USE_DBLOG
  /* Append the created offset to log */
  if(dbmemsegh(db)->logging.active) {
    if(wg_log_encval(db, offset))
      return 0; /* journal error */
  }
#endif

  return offsettoptr(db,offset);
}

/** Delete record from database
 * returns 0 on success
 * returns -1 if the record is referenced by others and cannot be deleted.
 * returns -2 on general error
 * returns -3 on fatal error
 *
 * XXX: when USE_BACKLINKING is off, this function should be used
 * with extreme care.
 */
gint wg_delete_record(void* db, void *rec) {
  gint offset;
  gint* dptr;
  gint* dendptr;
  gint data;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db, "wrong database pointer given to wg_delete_record");
    return -2;
  }
#endif

#ifdef USE_BACKLINKING
  if(*((gint *) rec + RECORD_BACKLINKS_POS))
    return -1;
#endif

#ifdef USE_DBLOG
  /* Log first, modify shared memory next */
  if(dbmemsegh(db)->logging.active) {
    if(wg_log_delete_record(db, ptrtooffset(db, rec)))
      return -3;
  }
#endif

  /* Remove data from index */
  if(!is_special_record(rec)) {
    if(wg_index_del_rec(db, rec) < -1)
      return -3; /* index error */
  }

  offset = ptrtooffset(db, rec);
#if defined(CHECK) && defined(USE_CHILD_DB)
  /* Check if it's a local record */
  if(!is_local_offset(db, offset)) {
    show_data_error(db, "not deleting an external record");
    return -2;
  }
#endif

  /* Loop over fields, freeing them */
  dendptr = (gint *) (((char *) rec) + datarec_size_bytes(*((gint *)rec)));
  for(dptr=(gint *)rec+RECORD_HEADER_GINTS; dptr<dendptr; dptr++) {
    data = *dptr;

#ifdef USE_BACKLINKING
    /* Is the field value a record pointer? If so, remove the backlink. */
#ifdef USE_CHILD_DB
    if(wg_get_encoded_type(db, data) == WG_RECORDTYPE &&
      is_local_offset(db, decode_datarec_offset(data))) {
#else
    if(wg_get_encoded_type(db, data) == WG_RECORDTYPE) {
#endif
      gint *child = (gint *) wg_decode_record(db, data);
      gint *next_offset = child + RECORD_BACKLINKS_POS;
      gcell *old = NULL;

      while(*next_offset) {
        old = (gcell *) offsettoptr(db, *next_offset);
        if(old->car == offset) {
          gint old_offset = *next_offset;
          *next_offset = old->cdr; /* remove from list chain */
          wg_free_listcell(db, old_offset); /* free storage */
          goto recdel_backlink_removed;
        }
        next_offset = &(old->cdr);
      }
      show_data_error(db, "Corrupt backlink chain");
      return -3; /* backlink error */
    }
recdel_backlink_removed:
#endif

    if(isptr(data)) free_field_encoffset(db,data);
  }

  /* Free the record storage */
  wg_free_object(db,
    &(dbmemsegh(db)->datarec_area_header),
    offset);

  return 0;
}


/** Get the first data record from the database
 *  Uses header meta bits to filter out special records
 *  (rules, system records etc)
 */
void* wg_get_first_record(void* db) {
  void *res = wg_get_first_raw_record(db);
  if(res && is_special_record(res))
    return wg_get_next_record(db, res); /* find first data record */
  return res;
}

/** Get the next data record from the database
 *  Uses header meta bits to filter out special records
 */
void* wg_get_next_record(void* db, void* record) {
  void *res = record;
  do {
    res = wg_get_next_raw_record(db, res);
  } while(res && is_special_record(res));
  return res;
}

/** Get the first record from the database
 *
 */
void* wg_get_first_raw_record(void* db) {
  db_subarea_header* arrayadr;
  gint firstoffset;
  void* res;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_get_first_record");
    return NULL;
  }
#endif
  arrayadr=&((dbmemsegh(db)->datarec_area_header).subarea_array[0]);
  firstoffset=((arrayadr[0]).alignedoffset); // do NOT skip initial "used" marker
  //printf("arrayadr %x firstoffset %d \n",(uint)arrayadr,firstoffset);
  res=wg_get_next_raw_record(db,offsettoptr(db,firstoffset));
  return res;
}

/** Get the next record from the database
 *
 */
void* wg_get_next_raw_record(void* db, void* record) {
  gint curoffset;
  gint head;
  db_subarea_header* arrayadr;
  gint last_subarea_index;
  gint i;
  gint found;
  gint subareastart;
  gint subareaend;
  gint freemarker;

  curoffset=ptrtooffset(db,record);
  //printf("curroffset %d record %x\n",curoffset,(uint)record);
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_get_first_record");
    return NULL;
  }
  head=dbfetch(db,curoffset);
  if (isfreeobject(head)) {
    show_data_error(db,"wrong record pointer (free) given to wg_get_next_record");
    return NULL;
  }
#endif
  freemarker=0; //assume input pointer to used object
  head=dbfetch(db,curoffset);
  while(1) {
    // increase offset to next memory block
    curoffset=curoffset+(freemarker ? getfreeobjectsize(head) : getusedobjectsize(head));
    head=dbfetch(db,curoffset);
    //printf("new curoffset %d head %d isnormaluseobject %d isfreeobject %d \n",
    //       curoffset,head,isnormalusedobject(head),isfreeobject(head));
    // check if found a normal used object
    if (isnormalusedobject(head)) return offsettoptr(db,curoffset); //return ptr to normal used object
    if (isfreeobject(head)) {
      freemarker=1;
      // loop start leads us to next object
    } else {
      // found a special object (dv or end marker)
      freemarker=0;
      if (dbfetch(db,curoffset+sizeof(gint))==SPECIALGINT1DV) {
        // we have reached a dv object
        continue; // loop start leads us to next object
      } else {
        // we have reached an end marker, have to find the next subarea
        // first locate subarea for this offset
        arrayadr=&((dbmemsegh(db)->datarec_area_header).subarea_array[0]);
        last_subarea_index=(dbmemsegh(db)->datarec_area_header).last_subarea_index;
        found=0;
        for(i=0;(i<=last_subarea_index)&&(i<SUBAREA_ARRAY_SIZE);i++) {
          subareastart=((arrayadr[i]).alignedoffset);
          subareaend=((arrayadr[i]).offset)+((arrayadr[i]).size);
          if (curoffset>=subareastart && curoffset<subareaend) {
            found=1;
            break;
          }
        }
        if (!found) {
          show_data_error(db,"wrong record pointer (out of area) given to wg_get_next_record");
          return NULL;
        }
        // take next subarea, while possible
        i++;
        if (i>last_subarea_index || i>=SUBAREA_ARRAY_SIZE) {
          //printf("next used object not found: i %d curoffset %d \n",i,curoffset);
          return NULL;
        }
        //printf("taking next subarea i %d\n",i);
        curoffset=((arrayadr[i]).alignedoffset);  // curoffset is now the special start marker
        head=dbfetch(db,curoffset);
        // loop start will lead us to next object from special marker
      }
    }
  }
}

/** Get the first data parent pointer from the backlink chain.
 *
 */
void *wg_get_first_parent(void* db, void *record) {
#ifdef USE_BACKLINKING
  gint backlink_list;
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"invalid database pointer given to wg_get_first_parent");
    return NULL;
  }
#endif
  backlink_list = *((gint *) record + RECORD_BACKLINKS_POS);
  if(backlink_list) {
    gcell *cell = (gcell *) offsettoptr(db, backlink_list);
    return (void *) offsettoptr(db, cell->car);
  }
#endif /* USE_BACKLINKING */
  return NULL; /* no parents or backlinking not enabled */
}

/** Get the next parent pointer from the backlink chain.
 *
 */
void *wg_get_next_parent(void* db, void* record, void *parent) {
#ifdef USE_BACKLINKING
  gint backlink_list;
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"invalid database pointer given to wg_get_next_parent");
    return NULL;
  }
#endif
  backlink_list = *((gint *) record + RECORD_BACKLINKS_POS);
  if(backlink_list) {
    gcell *next = (gcell *) offsettoptr(db, backlink_list);
    while(next->cdr) {
      void *pp = (void *) offsettoptr(db, next->car);
      next = (gcell *) offsettoptr(db, next->cdr);
      if(pp == parent && next->car) {
        return (void *) offsettoptr(db, next->car);
      }
    }
  }
#endif /* USE_BACKLINKING */
  return NULL; /* no more parents or backlinking not enabled */
}


/* ------------ backlink chain recursive functions ------------------- */

#ifdef USE_BACKLINKING

/** Remove index entries in backlink chain recursively.
 *  Needed for index maintenance when records are compared by their
 *  contens, as change in contents also changes the value of the entire
 *  record and thus affects it's placement in the index.
 *  Returns 0 for success
 *  Returns -1 in case of errors.
 */
static gint remove_backlink_index_entries(void *db, gint *record,
  gint value, gint depth) {
  gint col, length, err = 0;
  db_memsegment_header *dbh = dbmemsegh(db);

  if(!is_special_record(record)) {
    /* Find all fields in the record that match value (which is actually
     * a reference to a child record in encoded form) and remove it from
     * indexes. It will be recreated in the indexes by wg_set_field() later.
     */
    length = getusedobjectwantedgintsnr(*record) - RECORD_HEADER_GINTS;
    if(length > MAX_INDEXED_FIELDNR)
      length = MAX_INDEXED_FIELDNR + 1;

    for(col=0; col<length; col++) {
      if(*(record + RECORD_HEADER_GINTS + col) == value) {
        /* Changed value is always a WG_RECORDDTYPE field, therefore
         * we don't need to deal with index templates here
         * (record links are not allowed in templates).
         */
        if(dbh->index_control_area_header.index_table[col]) {
          if(wg_index_del_field(db, record, col) < -1)
            return -1;
        }
      }
    }
  }

  /* If recursive depth is not exchausted, continue with the parents
   * of this record.
   */
  if(depth > 0) {
    gint backlink_list = *(record + RECORD_BACKLINKS_POS);
    if(backlink_list) {
      gcell *next = (gcell *) offsettoptr(db, backlink_list);
      for(;;) {
        err = remove_backlink_index_entries(db,
          (gint *) offsettoptr(db, next->car),
          wg_encode_record(db, record), depth-1);
        if(err)
          return err;
        if(!next->cdr)
          break;
        next = (gcell *) offsettoptr(db, next->cdr);
      }
    }
  }

  return 0;
}

/** Add index entries in backlink chain recursively.
 *  Called after doing remove_backling_index_entries() and updating
 *  data in the record that originated the call. This recreates the
 *  entries in the indexes for all the records that were affected.
 *  Returns 0 for success
 *  Returns -1 in case of errors.
 */
static gint restore_backlink_index_entries(void *db, gint *record,
  gint value, gint depth) {
  gint col, length, err = 0;
  db_memsegment_header *dbh = dbmemsegh(db);

  if(!is_special_record(record)) {
    /* Find all fields in the record that match value (which is actually
     * a reference to a child record in encoded form) and add it back to
     * indexes.
     */
    length = getusedobjectwantedgintsnr(*record) - RECORD_HEADER_GINTS;
    if(length > MAX_INDEXED_FIELDNR)
      length = MAX_INDEXED_FIELDNR + 1;

    for(col=0; col<length; col++) {
      if(*(record + RECORD_HEADER_GINTS + col) == value) {
        if(dbh->index_control_area_header.index_table[col]) {
          if(wg_index_add_field(db, record, col) < -1)
            return -1;
        }
      }
    }
  }

  /* Continue to the parents until depth==0 */
  if(depth > 0) {
    gint backlink_list = *(record + RECORD_BACKLINKS_POS);
    if(backlink_list) {
      gcell *next = (gcell *) offsettoptr(db, backlink_list);
      for(;;) {
        err = restore_backlink_index_entries(db,
          (gint *) offsettoptr(db, next->car),
          wg_encode_record(db, record), depth-1);
        if(err)
          return err;
        if(!next->cdr)
          break;
        next = (gcell *) offsettoptr(db, next->cdr);
      }
    }
  }

  return 0;
}

#endif

/* ------------ field handling: data storage and fetching ---------------- */


wg_int wg_get_record_len(void* db, void* record) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_get_record_len");
    return -1;
  }
#endif
  return ((gint)(getusedobjectwantedgintsnr(*((gint*)record))))-RECORD_HEADER_GINTS;
}

wg_int* wg_get_record_dataarray(void* db, void* record) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_get_record_dataarray");
    return NULL;
  }
#endif
  return (((gint*)record)+RECORD_HEADER_GINTS);
}

/** Update contents of one field
 *  returns 0 if successful
 *  returns -1 if invalid db pointer passed (by recordcheck macro)
 *  returns -2 if invalid record passed (by recordcheck macro)
 *  returns -3 for fatal index error
 *  returns -4 for backlink-related error
 *  returns -5 for invalid external data
 *  returns -6 for journal error
 */
wg_int wg_set_field(void* db, void* record, wg_int fieldnr, wg_int data) {
  gint* fieldadr;
  gint fielddata;
  gint* strptr;
#ifdef USE_BACKLINKING
  gint backlink_list;           /** start of backlinks for this record */
  gint rec_enc = WG_ILLEGAL;    /** this record as encoded value. */
#endif
  db_memsegment_header *dbh = dbmemsegh(db);
#ifdef USE_CHILD_DB
  void *offset_owner = dbmemseg(db);
#endif

#ifdef CHECK
  recordcheck(db,record,fieldnr,"wg_set_field");
#endif

#ifdef USE_DBLOG
  /* Do not proceed before we've logged the operation */
  if(dbh->logging.active) {
    if(wg_log_set_field(db,record,fieldnr,data))
      return -6; /* journal error, cannot write */
  }
#endif

  /* Read the old encoded value */
  fieldadr=((gint*)record)+RECORD_HEADER_GINTS+fieldnr;
  fielddata=*fieldadr;

  /* Update index(es) while the old value is still in the db */
#ifdef USE_INDEX_TEMPLATE
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    (dbh->index_control_area_header.index_table[fieldnr] ||\
     dbh->index_control_area_header.index_template_table[fieldnr])) {
#else
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    dbh->index_control_area_header.index_table[fieldnr]) {
#endif
    if(wg_index_del_field(db, record, fieldnr) < -1)
      return -3; /* index error */
  }

  /* If there are backlinks, go up the chain and remove the reference
   * to this record from all indexes (updating a field in the record
   * causes the value of the record to change). Note that we only go
   * as far as the recursive comparison depth - records higher in the
   * hierarchy are not affected.
   */
#if defined(USE_BACKLINKING) && (WG_COMPARE_REC_DEPTH > 0)
  backlink_list = *((gint *) record + RECORD_BACKLINKS_POS);
  if(backlink_list) {
    gint err;
    gcell *next = (gcell *) offsettoptr(db, backlink_list);
    rec_enc = wg_encode_record(db, record);
    for(;;) {
      err = remove_backlink_index_entries(db,
        (gint *) offsettoptr(db, next->car),
        rec_enc, WG_COMPARE_REC_DEPTH-1);
      if(err) {
        return -4; /* override the error code, for now. */
      }
      if(!next->cdr)
        break;
      next = (gcell *) offsettoptr(db, next->cdr);
    }
  }
#endif

#ifdef USE_CHILD_DB
  /* Get the offset owner */
  if(isptr(data)) {
    offset_owner = get_ptr_owner(db, data);
    if(!offset_owner) {
      show_data_error(db, "External reference not recognized");
      return -5;
    }
  }
#endif

#ifdef USE_BACKLINKING
  /* Is the old field value a record pointer? If so, remove the backlink.
   * XXX: this can be optimized to use a custom macro instead of
   * wg_get_encoded_type().
   */
#ifdef USE_CHILD_DB
  /* Only touch local records */
  if(wg_get_encoded_type(db, fielddata) == WG_RECORDTYPE &&
    offset_owner == dbmemseg(db)) {
#else
  if(wg_get_encoded_type(db, fielddata) == WG_RECORDTYPE) {
#endif
    gint *rec = (gint *) wg_decode_record(db, fielddata);
    gint *next_offset = rec + RECORD_BACKLINKS_POS;
    gint parent_offset = ptrtooffset(db, record);
    gcell *old = NULL;

    while(*next_offset) {
      old = (gcell *) offsettoptr(db, *next_offset);
      if(old->car == parent_offset) {
        gint old_offset = *next_offset;
        *next_offset = old->cdr; /* remove from list chain */
        wg_free_listcell(db, old_offset); /* free storage */
        goto setfld_backlink_removed;
      }
      next_offset = &(old->cdr);
    }
    show_data_error(db, "Corrupt backlink chain");
    return -4; /* backlink error */
  }
setfld_backlink_removed:
#endif

  //printf("wg_set_field adr %d offset %d\n",fieldadr,ptrtooffset(db,fieldadr));
  if (isptr(fielddata)) {
    //printf("wg_set_field freeing old data\n");
    free_field_encoffset(db,fielddata);
  }
  (*fieldadr)=data; // store data to field
#ifdef USE_CHILD_DB
  if (islongstr(data) && offset_owner == dbmemseg(db)) {
#else
  if (islongstr(data)) {
#endif
    // increase data refcount for longstr-s
    strptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
    ++(*(strptr+LONGSTR_REFCOUNT_POS));
  }

  /* Update index after new value is written */
#ifdef USE_INDEX_TEMPLATE
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    (dbh->index_control_area_header.index_table[fieldnr] ||\
     dbh->index_control_area_header.index_template_table[fieldnr])) {
#else
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    dbh->index_control_area_header.index_table[fieldnr]) {
#endif
    if(wg_index_add_field(db, record, fieldnr) < -1)
      return -3;
  }

#ifdef USE_BACKLINKING
  /* Is the new field value a record pointer? If so, add a backlink */
#ifdef USE_CHILD_DB
  if(wg_get_encoded_type(db, data) == WG_RECORDTYPE &&
    offset_owner == dbmemseg(db)) {
#else
  if(wg_get_encoded_type(db, data) == WG_RECORDTYPE) {
#endif
    gint *rec = (gint *) wg_decode_record(db, data);
    gint *next_offset = rec + RECORD_BACKLINKS_POS;
    gint new_offset = wg_alloc_fixlen_object(db,
      &(dbmemsegh(db)->listcell_area_header));
    gcell *new_cell = (gcell *) offsettoptr(db, new_offset);

    while(*next_offset)
      next_offset = &(((gcell *) offsettoptr(db, *next_offset))->cdr);
    new_cell->car = ptrtooffset(db, record);
    new_cell->cdr = 0;
    *next_offset = new_offset;
  }
#endif

#if defined(USE_BACKLINKING) && (WG_COMPARE_REC_DEPTH > 0)
  /* Create new entries in indexes in all referring records */
  if(backlink_list) {
    gint err;
    gcell *next = (gcell *) offsettoptr(db, backlink_list);
    for(;;) {
      err = restore_backlink_index_entries(db,
        (gint *) offsettoptr(db, next->car),
        rec_enc, WG_COMPARE_REC_DEPTH-1);
      if(err) {
        return -4;
      }
      if(!next->cdr)
        break;
      next = (gcell *) offsettoptr(db, next->cdr);
    }
  }
#endif

  return 0;
}

/** Write contents of one field.
 *
 *  Used to initialize fields in records that have been created with
 *  wg_create_raw_record().
 *
 *  This function ignores the previous contents of the field. The
 *  rationale is that newly created fields do not have any meaningful
 *  content and this allows faster writing. It is up to the programmer
 *  to ensure that this function is not called on fields that already
 *  contain data.
 *
 *  returns 0 if successful
 *  returns -1 if invalid db pointer passed
 *  returns -2 if invalid record or field passed
 *  returns -3 for fatal index error
 *  returns -4 for backlink-related error
 *  returns -5 for invalid external data
 *  returns -6 for journal error
 */
wg_int wg_set_new_field(void* db, void* record, wg_int fieldnr, wg_int data) {
  gint* fieldadr;
  gint* strptr;
#ifdef USE_BACKLINKING
  gint backlink_list;           /** start of backlinks for this record */
#endif
  db_memsegment_header *dbh = dbmemsegh(db);
#ifdef USE_CHILD_DB
  void *offset_owner = dbmemseg(db);
#endif

#ifdef CHECK
  recordcheck(db,record,fieldnr,"wg_set_field");
#endif

#ifdef USE_DBLOG
  /* Do not proceed before we've logged the operation */
  if(dbh->logging.active) {
    if(wg_log_set_field(db,record,fieldnr,data))
      return -6; /* journal error, cannot write */
  }
#endif

#ifdef USE_CHILD_DB
  /* Get the offset owner */
  if(isptr(data)) {
    offset_owner = get_ptr_owner(db, data);
    if(!offset_owner) {
      show_data_error(db, "External reference not recognized");
      return -5;
    }
  }
#endif

  /* Write new value */
  fieldadr=((gint*)record)+RECORD_HEADER_GINTS+fieldnr;
#ifdef CHECK
  if(*fieldadr) {
    show_data_error(db,"wg_set_new_field called on field that contains data");
    return -2;
  }
#endif
  (*fieldadr)=data;

#ifdef USE_CHILD_DB
  if (islongstr(data) && offset_owner == dbmemseg(db)) {
#else
  if (islongstr(data)) {
#endif
    // increase data refcount for longstr-s
    strptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
    ++(*(strptr+LONGSTR_REFCOUNT_POS));
  }

  /* Update index after new value is written */
#ifdef USE_INDEX_TEMPLATE
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    (dbh->index_control_area_header.index_table[fieldnr] ||\
     dbh->index_control_area_header.index_template_table[fieldnr])) {
#else
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    dbh->index_control_area_header.index_table[fieldnr]) {
#endif
    if(wg_index_add_field(db, record, fieldnr) < -1)
      return -3;
  }

#ifdef USE_BACKLINKING
  /* Is the new field value a record pointer? If so, add a backlink */
#ifdef USE_CHILD_DB
  if(wg_get_encoded_type(db, data) == WG_RECORDTYPE &&
    offset_owner == dbmemseg(db)) {
#else
  if(wg_get_encoded_type(db, data) == WG_RECORDTYPE) {
#endif
    gint *rec = (gint *) wg_decode_record(db, data);
    gint *next_offset = rec + RECORD_BACKLINKS_POS;
    gint new_offset = wg_alloc_fixlen_object(db,
      &(dbmemsegh(db)->listcell_area_header));
    gcell *new_cell = (gcell *) offsettoptr(db, new_offset);

    while(*next_offset)
      next_offset = &(((gcell *) offsettoptr(db, *next_offset))->cdr);
    new_cell->car = ptrtooffset(db, record);
    new_cell->cdr = 0;
    *next_offset = new_offset;
  }
#endif

#if defined(USE_BACKLINKING) && (WG_COMPARE_REC_DEPTH > 0)
  /* Create new entries in indexes in all referring records. Normal
   * usage scenario would be that the record is also new, so that
   * there are no backlinks, however this is not guaranteed.
   */
  backlink_list = *((gint *) record + RECORD_BACKLINKS_POS);
  if(backlink_list) {
    gint err;
    gcell *next = (gcell *) offsettoptr(db, backlink_list);
    gint rec_enc = wg_encode_record(db, record);
    for(;;) {
      err = restore_backlink_index_entries(db,
        (gint *) offsettoptr(db, next->car),
        rec_enc, WG_COMPARE_REC_DEPTH-1);
      if(err) {
        return -4;
      }
      if(!next->cdr)
        break;
      next = (gcell *) offsettoptr(db, next->cdr);
    }
  }
#endif

  return 0;
}

wg_int wg_set_int_field(void* db, void* record, wg_int fieldnr, gint data) {
  gint fielddata;
  fielddata=wg_encode_int(db,data);
  //printf("wg_set_int_field data %d encoded %d\n",data,fielddata);
  if (fielddata==WG_ILLEGAL) return -1;
  return wg_set_field(db,record,fieldnr,fielddata);
}

wg_int wg_set_double_field(void* db, void* record, wg_int fieldnr, double data) {
  gint fielddata;

  fielddata=wg_encode_double(db,data);
  if (fielddata==WG_ILLEGAL) return -1;
  return wg_set_field(db,record,fieldnr,fielddata);
}

wg_int wg_set_str_field(void* db, void* record, wg_int fieldnr, char* data) {
  gint fielddata;

  fielddata=wg_encode_str(db,data,NULL);
  if (fielddata==WG_ILLEGAL) return -1;
  return wg_set_field(db,record,fieldnr,fielddata);
}

wg_int wg_set_rec_field(void* db, void* record, wg_int fieldnr, void* data) {
  gint fielddata;

  fielddata=wg_encode_record(db,data);
  if (fielddata==WG_ILLEGAL) return -1;
  return wg_set_field(db,record,fieldnr,fielddata);
}

/** Special case of updating a field value without a write-lock.
 *
 *  Operates like wg_set_field but takes a previous value in a field
 *  as an additional argument for atomicity check.
 *
 *  This special case does not require a write lock: however,
 *  you MUST still get a read-lock before the operation while
 *  doing parallel processing, otherwise the operation
 *  may corrupt the database: no complex write operations should
 *  happen in parallel to this operation.
 *
 *  NB! the operation may still confuse other parallel readers, changing
 *  the value in a record they have just read. Use only if this is
 *  known to not create problems for other processes.
 *
 *  It can be only used to write an immediate value (NULL, short int,
 *  char, date, time) to a non-indexed field containing also an
 *  immediate field: checks whether these conditions hold.
 *
 *  The operation will fail if the original value passed has been
 *  overwritten before we manage to store a new value: this is
 *  a guaranteed atomic check and enables correct operation of
 *  several parallel wg_set_atomic_field operations
 *  changing the same field.
 *
 *  returns 0 if successful
 *  returns -1 if wrong db pointer
 *  returns -2 if wrong fieldnr
 *  returns -10 if new value non-immediate
 *  returns -11 if old value non-immediate
 *  returns -12 if cannot fetch old data
 *  returns -13 if the field has an index
 *  returns -14 if logging is active
 *  returns -15 if the field value has been changed from old_data
 *  may return other field-setting error codes from wg_set_new_field
 *
 */

wg_int wg_update_atomic_field(void* db, void* record, wg_int fieldnr, wg_int data, wg_int old_data) {
  gint* fieldadr;
  db_memsegment_header *dbh = dbmemsegh(db);
  gint tmp;

  // basic sanity check
#ifdef CHECK
  recordcheck(db,record,fieldnr,"wg_update_atomic_field");
#endif
  // check whether new value and old value are direct values in a record
  if (!isimmediatedata(data)) return -10;
  if (!isimmediatedata(old_data)) return -11;
  // check whether there is index on the field
#ifdef USE_INDEX_TEMPLATE
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    (dbh->index_control_area_header.index_table[fieldnr] ||\
     dbh->index_control_area_header.index_template_table[fieldnr])) {
#else
  if(!is_special_record(record) && fieldnr<=MAX_INDEXED_FIELDNR &&\
    dbh->index_control_area_header.index_table[fieldnr]) {
#endif
    return -13;
  }
  // check that no logging is used
#ifdef USE_DBLOG
  if(dbh->logging.active) {
    return -14;
  }
#endif
  // checks passed, do atomic field setting
  fieldadr=((gint*)record)+RECORD_HEADER_GINTS+fieldnr;
  tmp=wg_compare_and_swap(fieldadr, old_data, data);
  if (tmp) return 0;
  else return -15;
}


/** Special case of setting a field value without a write-lock.
 *
 * Calls wg_update_atomic_field iteratively until compare-and-swap succeeds.
 *
 * The restrictions and error codes from wg_update_atomic_field apply.
 * returns 0 if successful
 * returns -1...-15 with an error defined before in wg_update_atomic_field.
 * returns -17 if atomic assignment failed after a large number (1000) of tries
*/

wg_int wg_set_atomic_field(void* db, void* record, wg_int fieldnr, wg_int data) {
  gint* fieldadr;
  gint old,r;
  int i;
#ifdef _WIN32
  int ts=1;
#else
  struct timespec ts;
#endif

  // basic sanity check
#ifdef CHECK
  recordcheck(db,record,fieldnr,"wg_set_atomic_field");
#endif
  fieldadr=((gint*)record)+RECORD_HEADER_GINTS+fieldnr;
  for(i=0;;i++) {
    // loop until preconditions fail or addition succeeds and
    // the old value is not changed during compare-and-swap
    old=*fieldadr;
    r=wg_update_atomic_field(db,record,fieldnr,data,old);
    if (!r) return 0;
    if (r!=-15) return r; // -15 is field changed error
    // here compare-and-swap failed, try again
    if (i>1000) return -17; // possibly a deadlock
    if (i%10!=0) continue; // sleep only every tenth loop
    // several loops passed, sleep a bit
#ifdef _WIN32
    Sleep(ts); // 1000 for loops take ca 0.1 sec
#else
    ts.tv_sec=0;
    ts.tv_nsec=100+i;
    nanosleep(&ts,NULL); // 1000 for loops take ca 60 microsec
#endif
  }
  return -17; // should not reach here
}


/** Special case of adding to an int field without a write-lock.
 *
 * fieldnr must contain a smallint and the result of addition
 * must also be a smallint.
 *
 * The restrictions and error codes from wg_update_atomic_field apply.
 *
 * returns 0 if successful
 * returns -1...-15 with an error defined before in wg_set_atomic_field.
 * returns -16 if the result of the addition does not fit into a smallint
 * returns -17 if atomic assignment failed after a large number (1000) of tries
 *
*/

wg_int wg_add_int_atomic_field(void* db, void* record, wg_int fieldnr, int data) {
  gint* fieldadr;
  gint old,nxt,r;
  int i,sum;
#ifdef _WIN32
  int ts=1;
#else
  struct timespec ts;
#endif

  // basic sanity check
#ifdef CHECK
  recordcheck(db,record,fieldnr,"wg_add_int_atomic_field");
#endif
  fieldadr=((gint*)record)+RECORD_HEADER_GINTS+fieldnr;
  for(i=0;;i++) {
    // loop until preconditions fail or addition succeeds and
    // the old value is not changed during compare-and-swap
    old=*fieldadr;
    if (!issmallint(old)) return -11;
    sum=wg_decode_int(db,(gint)old)+data;
    if (!fits_smallint(sum)) return -16;
    nxt=encode_smallint(sum);
    r=wg_update_atomic_field(db,record,fieldnr,nxt,old);
    if (!r) return 0;
    if (r!=-15) return r; // -15 is field changed error
    // here compare-and-swap failed, try again
    if (i>1000) return -17; // possibly a deadlock
    if (i%10!=0) continue; // sleep only every tenth loop
    // several loops passed, sleep a bit
#ifdef _WIN32
    Sleep(ts); // 1000 for loops take ca 0.1 sec
#else
    ts.tv_sec=0;
    ts.tv_nsec=100+i;
    nanosleep(&ts,NULL); // 1000 for loops take ca 60 microsec
#endif
  }
  return -17; // should not reach here
}


wg_int wg_get_field(void* db, void* record, wg_int fieldnr) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error_nr(db,"wrong database pointer given to wg_get_field",fieldnr);
    return WG_ILLEGAL;
  }
  if (fieldnr<0 || (getusedobjectwantedgintsnr(*((gint*)record))<=fieldnr+RECORD_HEADER_GINTS)) {
    show_data_error_nr(db,"wrong field number given to wg_get_field",fieldnr);\
    return WG_ILLEGAL;
  }
#endif
  //printf("wg_get_field adr %d offset %d\n",
  //       (((gint*)record)+RECORD_HEADER_GINTS+fieldnr),
  //       ptrtooffset(db,(((gint*)record)+RECORD_HEADER_GINTS+fieldnr)));
  return *(((gint*)record)+RECORD_HEADER_GINTS+fieldnr);
}

wg_int wg_get_field_type(void* db, void* record, wg_int fieldnr) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error_nr(db,"wrong database pointer given to wg_get_field_type",fieldnr);\
    return 0;
  }
  if (fieldnr<0 || (getusedobjectwantedgintsnr(*((gint*)record))<=fieldnr+RECORD_HEADER_GINTS)) {
    show_data_error_nr(db,"wrong field number given to wg_get_field_type",fieldnr);\
    return 0;
  }
#endif
  return wg_get_encoded_type(db,*(((gint*)record)+RECORD_HEADER_GINTS+fieldnr));
}

/* ------------- general operations -------------- */



wg_int wg_free_encoded(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_free_encoded");
    return 0;
  }
#endif
  if (isptr(data)) {
    gint *strptr;

    /* XXX: Major hack: since free_field_encoffset() decrements
     * the refcount, but wg_encode_str() does not (which is correct),
     * before, increment the refcount once before we free the
     * object. If the string is in use already, this will be a
     * no-op, otherwise it'll be successfully freed anyway.
     */
#ifdef USE_CHILD_DB
    if (islongstr(data) &&
      is_local_offset(db, decode_longstr_offset(data))) {
#else
    if (islongstr(data)) {
#endif
      // increase data refcount for longstr-s
      strptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
      ++(*(strptr+LONGSTR_REFCOUNT_POS));
    }
    return free_field_encoffset(db,data);
  }
  return 0;
}

/** properly removes ptr (offset) to data
*
* assumes fielddata is offset to allocated data
* depending on type of fielddata either deallocates pointed data or
* removes data back ptr or decreases refcount
*
* in case fielddata points to record or longstring, these
* are freed only if they have no more pointers
*
* returns non-zero in case of error
*/

static gint free_field_encoffset(void* db,gint encoffset) {
  gint offset;
#if 0
  gint* dptr;
  gint* dendptr;
  gint data;
  gint i;
#endif
  gint tmp;
  gint* objptr;
  gint* extrastr;

  // takes last three bits to decide the type
  // fullint is represented by two options: 001 and 101
  switch(encoffset&NORMALPTRMASK) {
    case DATARECBITS:
#if 0
/* This section of code in quarantine */
      // remove from list
      // refcount check
      offset=decode_datarec_offset(encoffset);
      tmp=dbfetch(db,offset+sizeof(gint)*LONGSTR_REFCOUNT_POS);
      tmp--;
      if (tmp>0) {
        dbstore(db,offset+LONGSTR_REFCOUNT_POS,tmp);
      } else {
        // free frompointers structure
        // loop over fields, freeing them
        dptr=offsettoptr(db,offset);
        dendptr=(gint*)(((char*)dptr)+datarec_size_bytes(*dptr));
        for(i=0,dptr=dptr+RECORD_HEADER_GINTS;dptr<dendptr;dptr++,i++) {
          data=*dptr;
          if (isptr(data)) free_field_encoffset(db,data);
        }
        // really free object from area
        wg_free_object(db,&(dbmemsegh(db)->datarec_area_header),offset);
      }
#endif
      break;
    case LONGSTRBITS:
      offset=decode_longstr_offset(encoffset);
#ifdef USE_CHILD_DB
      if(!is_local_offset(db, offset))
        break; /* Non-local reference, ignore it */
#endif
      // refcount check
      tmp=dbfetch(db,offset+sizeof(gint)*LONGSTR_REFCOUNT_POS);
      tmp--;
      if (tmp>0) {
        dbstore(db,offset+sizeof(gint)*LONGSTR_REFCOUNT_POS,tmp);
      } else {
        objptr = (gint *) offsettoptr(db,offset);
        extrastr=(gint*)(((char*)(objptr))+(sizeof(gint)*LONGSTR_EXTRASTR_POS));
        tmp=*extrastr;
        // remove from hash
        wg_remove_from_strhash(db,encoffset);
        // remove extrastr
        if (tmp!=0) free_field_encoffset(db,tmp);
        *extrastr=0;
        // really free object from area
        wg_free_object(db,&(dbmemsegh(db)->longstr_area_header),offset);
      }
      break;
    case SHORTSTRBITS:
#ifdef USE_CHILD_DB
      offset = decode_shortstr_offset(encoffset);
      if(!is_local_offset(db, offset))
        break; /* Non-local reference, ignore it */
      wg_free_shortstr(db, offset);
#else
      wg_free_shortstr(db,decode_shortstr_offset(encoffset));
#endif
      break;
    case FULLDOUBLEBITS:
#ifdef USE_CHILD_DB
      offset = decode_fulldouble_offset(encoffset);
      if(!is_local_offset(db, offset))
        break; /* Non-local reference, ignore it */
      wg_free_doubleword(db, offset);
#else
      wg_free_doubleword(db,decode_fulldouble_offset(encoffset));
#endif
      break;
    case FULLINTBITSV0:
#ifdef USE_CHILD_DB
      offset = decode_fullint_offset(encoffset);
      if(!is_local_offset(db, offset))
        break; /* Non-local reference, ignore it */
      wg_free_word(db, offset);
#else
      wg_free_word(db,decode_fullint_offset(encoffset));
#endif
      break;
    case FULLINTBITSV1:
#ifdef USE_CHILD_DB
      offset = decode_fullint_offset(encoffset);
      if(!is_local_offset(db, offset))
        break; /* Non-local reference, ignore it */
      wg_free_word(db, offset);
#else
      wg_free_word(db,decode_fullint_offset(encoffset));
#endif
      break;

  }
  return 0;
}



/* ------------- data encoding and decoding ------------ */


/** determines the type of encoded data
*
* returns a zero-or-bigger macro integer value from wg_db_api.h beginning:
*
* #define WG_NULLTYPE 1
* #define WG_RECORDTYPE 2
* #define WG_INTTYPE 3
* #define WG_DOUBLETYPE 4
* #define WG_STRTYPE 5
* ... etc ...
*
* returns a negative number -1 in case of error
*
*/


wg_int wg_get_encoded_type(void* db, wg_int data) {
  gint fieldoffset;
  gint tmp;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_get_encoded_type");
    return 0;
  }
#endif
  if (!data) return WG_NULLTYPE;
  if (((data)&NONPTRBITS)==NONPTRBITS) {
    // data is one of the non-pointer types
    if (isvar(data)) return (gint)WG_VARTYPE;
    if (issmallint(data)) return (gint)WG_INTTYPE;
    switch(data&LASTBYTEMASK) {
      case CHARBITS: return WG_CHARTYPE;
      case FIXPOINTBITS: return WG_FIXPOINTTYPE;
      case DATEBITS: return WG_DATETYPE;
      case TIMEBITS: return WG_TIMETYPE;
      case TINYSTRBITS: return WG_STRTYPE;
      case VARBITS: return WG_VARTYPE;
      case ANONCONSTBITS: return WG_ANONCONSTTYPE;
      default: return -1;
    }
  }
  // here we know data must be of ptr type
  // takes last three bits to decide the type
  // fullint is represented by two options: 001 and 101
  //printf("cp0\n");
  switch(data&NORMALPTRMASK) {
    case DATARECBITS: return (gint)WG_RECORDTYPE;
    case LONGSTRBITS:
      //printf("cp1\n");
      fieldoffset=decode_longstr_offset(data)+LONGSTR_META_POS*sizeof(gint);
      //printf("fieldoffset %d\n",fieldoffset);
      tmp=dbfetch(db,fieldoffset);
      //printf("str meta %d lendiff %d subtype %d\n",
      //  tmp,(tmp&LONGSTR_META_LENDIFMASK)>>LONGSTR_META_LENDIFSHFT,tmp&LONGSTR_META_TYPEMASK);
      return tmp&LONGSTR_META_TYPEMASK; // WG_STRTYPE, WG_URITYPE, WG_XMLLITERALTYPE
    case SHORTSTRBITS:   return (gint)WG_STRTYPE;
    case FULLDOUBLEBITS: return (gint)WG_DOUBLETYPE;
    case FULLINTBITSV0:  return (gint)WG_INTTYPE;
    case FULLINTBITSV1:  return (gint)WG_INTTYPE;
    default: return -1;
  }
  return 0;
}


char* wg_get_type_name(void* db, wg_int type) {
  switch (type) {
    case WG_NULLTYPE: return "null";
    case WG_RECORDTYPE: return "record";
    case WG_INTTYPE: return "int";
    case WG_DOUBLETYPE: return "double";
    case WG_STRTYPE: return "string";
    case WG_XMLLITERALTYPE: return "xmlliteral";
    case WG_URITYPE: return "uri";
    case WG_BLOBTYPE: return "blob";
    case WG_CHARTYPE: return "char";
    case WG_FIXPOINTTYPE: return "fixpoint";
    case WG_DATETYPE: return "date";
    case WG_TIMETYPE: return "time";
    case WG_ANONCONSTTYPE: return "anonconstant";
    case WG_VARTYPE: return "var";
    default: return "unknown";
  }
}


wg_int wg_encode_null(void* db, char* data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_null");
    return WG_ILLEGAL;
  }
  if (data!=NULL) {
    show_data_error(db,"data given to wg_encode_null is not NULL");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_NULLTYPE, NULL, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return (gint)0;
}

char* wg_decode_null(void* db,wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_null");
    return NULL;
  }
  if (data!=(gint)0) {
    show_data_error(db,"data given to wg_decode_null is not an encoded NULL");
    return NULL;
  }
#endif
  return NULL;
}

wg_int wg_encode_int(void* db, wg_int data) {
  gint offset;
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_int");
    return WG_ILLEGAL;
  }
#endif
  if (fits_smallint(data)) {
    return encode_smallint(data);
  } else {
#ifdef USE_DBLOG
    /* Log before allocating. Note this call is skipped when
     * we have a small int.
     */
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_encode(db, WG_INTTYPE, &data, 0, NULL, 0))
        return WG_ILLEGAL;
    }
#endif
    offset=alloc_word(db);
    if (!offset) {
      show_data_error_nr(db,"cannot store an integer in wg_set_int_field: ",data);
#ifdef USE_DBLOG
      if(dbmemsegh(db)->logging.active) {
        wg_log_encval(db, WG_ILLEGAL);
      }
#endif
      return WG_ILLEGAL;
    }
    dbstore(db,offset,data);
#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_encval(db, encode_fullint_offset(offset)))
        return WG_ILLEGAL; /* journal error */
    }
#endif
    return encode_fullint_offset(offset);
  }
}

wg_int wg_decode_int(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_int");
    return 0;
  }
#endif
  if (issmallint(data)) return decode_smallint(data);
  if (isfullint(data)) return dbfetch(db,decode_fullint_offset(data));
  show_data_error_nr(db,"data given to wg_decode_int is not an encoded int: ",data);
  return 0;
}



wg_int wg_encode_char(void* db, char data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_char");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_CHARTYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return (wg_int)(encode_char((wg_int)data));
}


char wg_decode_char(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_char");
    return 0;
  }
#endif
  return (char)(decode_char(data));
}


wg_int wg_encode_double(void* db, double data) {
  gint offset;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_double");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
  /* Log before allocating. */
  if(dbmemsegh(db)->logging.active) {
    if(wg_log_encode(db, WG_DOUBLETYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
#endif
  if (0) {
    // possible future case for tiny floats
  } else {
    offset=alloc_doubleword(db);
    if (!offset) {
      show_data_error_double(db,"cannot store a double in wg_set_double_field: ",data);
#ifdef USE_DBLOG
      if(dbmemsegh(db)->logging.active) {
        wg_log_encval(db, WG_ILLEGAL);
      }
#endif
      return WG_ILLEGAL;
    }
    *((double*)(offsettoptr(db,offset)))=data;
#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_encval(db, encode_fulldouble_offset(offset)))
        return WG_ILLEGAL; /* journal error */
    }
#endif
    return encode_fulldouble_offset(offset);
  }
}

double wg_decode_double(void* db, wg_int data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_double");
    return 0;
  }
#endif
  if (isfulldouble(data)) return *((double*)(offsettoptr(db,decode_fulldouble_offset(data))));
  show_data_error_nr(db,"data given to wg_decode_double is not an encoded double: ",data);
  return 0;
}


wg_int wg_encode_fixpoint(void* db, double data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_fixpoint");
    return WG_ILLEGAL;
  }
  if (!fits_fixpoint(data)) {
    show_data_error(db,"argument given to wg_encode_fixpoint too big or too small");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_FIXPOINTTYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return encode_fixpoint(data);
}

double wg_decode_fixpoint(void* db, wg_int data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_double");
    return 0;
  }
#endif
  if (isfixpoint(data)) return decode_fixpoint(data);
  show_data_error_nr(db,"data given to wg_decode_fixpoint is not an encoded fixpoint: ",data);
  return 0;
}


wg_int wg_encode_date(void* db, int data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_date");
    return WG_ILLEGAL;
  }
  if (!fits_date(data)) {
    show_data_error(db,"argument given to wg_encode_date too big or too small");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_DATETYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return encode_date(data);
}

int wg_decode_date(void* db, wg_int data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_date");
    return 0;
  }
#endif
  if (isdate(data)) return decode_date(data);
  show_data_error_nr(db,"data given to wg_decode_date is not an encoded date: ",data);
  return 0;
}

wg_int wg_encode_time(void* db, int data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_time");
    return WG_ILLEGAL;
  }
  if (!fits_time(data)) {
    show_data_error(db,"argument given to wg_encode_time too big or too small");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_TIMETYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return encode_time(data);
}

int wg_decode_time(void* db, wg_int data) {

#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_time");
    return 0;
  }
#endif
  if (istime(data)) return decode_time(data);
  show_data_error_nr(db,"data given to wg_decode_time is not an encoded time: ",data);
  return 0;
}

int wg_current_utcdate(void* db) {
  time_t ts;
  int epochadd=719163; // y 1970 m 1 d 1

  ts=time(NULL); // secs since Epoch 1970
  return (int)(ts/(24*60*60))+epochadd;
}

int wg_current_localdate(void* db) {
  time_t esecs;
  int res;
  struct tm ctime;

  esecs=time(NULL); // secs since Epoch 1970tstruct.time;
  localtime_r(&esecs,&ctime);
  res=ymd_to_scalar(ctime.tm_year+1900,ctime.tm_mon+1,ctime.tm_mday);
  return res;
}


int wg_current_utctime(void* db) {
  struct timeb tstruct;
  int esecs;
  int days;
  int secs;
  int milli;
  int secsday=24*60*60;

  ftime(&tstruct);
  esecs=(int)(tstruct.time);
  milli=tstruct.millitm;
  days=esecs/secsday;
  secs=esecs-(days*secsday);
  return (secs*100)+(milli/10);
}

int wg_current_localtime(void* db) {
  struct timeb tstruct;
  time_t esecs;
  int secs;
  int milli;
  struct tm ctime;

  ftime(&tstruct);
  esecs=tstruct.time;
  milli=tstruct.millitm;
  localtime_r(&esecs,&ctime);
  secs=ctime.tm_hour*60*60+ctime.tm_min*60+ctime.tm_sec;
  return (secs*100)+(milli/10);
}

int wg_strf_iso_datetime(void* db, int date, int time, char* buf) {
  unsigned yr, mo, day, hr, min, sec, spart;
  int t=time;
  int c;

  hr=t/(60*60*100);
  t=t-(hr*(60*60*100));
  min=t/(60*100);
  t=t-(min*(60*100));
  sec=t/100;
  t=t-(sec*(100));
  spart=t;

  scalar_to_ymd(date,&yr,&mo,&day);
  c=snprintf(buf,24,"%04d-%02d-%02dT%02d:%02d:%02d.%02d",yr,mo,day,hr,min,sec,spart);
  return(c);
}

int wg_strp_iso_date(void* db, char* inbuf) {
  int sres;
  int yr=0;
  int mo=0;
  int day=0;
  int res;

  sres=sscanf(inbuf,"%4d-%2d-%2d",&yr,&mo,&day);
  if (sres<3 || yr<0 || mo<1 || mo>12 || day<1 || day>31) return -1;
  res=ymd_to_scalar(yr,mo,day);
  return res;
}


int wg_strp_iso_time(void* db, char* inbuf) {
  int sres;
  int hr=0;
  int min=0;
  int sec=0;
  int prt=0;

  sres=sscanf(inbuf,"%2d:%2d:%2d.%2d",&hr,&min,&sec,&prt);
  if (sres<3 || hr<0 || hr>24 || min<0 || min>60 || sec<0 || sec>60 || prt<0 || prt>99) return -1;
  return hr*(60*60*100)+min*(60*100)+sec*100+prt;
}


int wg_ymd_to_date(void* db, int yr, int mo, int day) {
  if (yr<0 || mo<1 || mo>12 || day<1 || day>31) return -1;
  return ymd_to_scalar(yr,mo,day);
}


int wg_hms_to_time(void* db, int hr, int min, int sec, int prt) {
  if (hr<0 || hr>24 || min<0 || min>60 || sec<0 || sec>60 || prt<0 || prt>99)
    return -1;
  return hr*(60*60*100)+min*(60*100)+sec*100+prt;
}


void wg_date_to_ymd(void* db, int date, int *yr, int *mo, int *day) {
  unsigned int y, m, d;

  scalar_to_ymd(date, &y, &m, &d);
  *yr=y;
  *mo=m;
  *day=d;
}


void wg_time_to_hms(void* db, int time, int *hr, int *min, int *sec, int *prt) {
  int t=time;

  *hr=t/(60*60*100);
  t=t-(*hr * (60*60*100));
  *min=t/(60*100);
  t=t-(*min * (60*100));
  *sec=t/100;
  t=t-(*sec * (100));
  *prt=t;
}


// record

wg_int wg_encode_record(void* db, void* data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_char");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_RECORDTYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return (wg_int)(encode_datarec_offset(ptrtooffset(db,data)));
}


void* wg_decode_record(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_char");
    return 0;
  }
#endif
  return (void*)(offsettoptr(db,decode_datarec_offset(data)));
}





/* ============================================

Separate string, xmlliteral, uri, blob funs
call universal funs defined later

============================================== */

/* string */

wg_int wg_encode_str(void* db, char* str, char* lang) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_str");
    return WG_ILLEGAL;
  }
  if (str==NULL) {
    show_data_error(db,"NULL string ptr given to wg_encode_str");
    return WG_ILLEGAL;
  }
#endif
  /* Logging handled inside wg_encode_unistr() */
  return wg_encode_unistr(db,str,lang,WG_STRTYPE);
}


char* wg_decode_str(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_str");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_str is 0, not an encoded string");
    return NULL;
  }
#endif
  return wg_decode_unistr(db,data,WG_STRTYPE);
}


wg_int wg_decode_str_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_str_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_str_len is 0, not an encoded string");
    return -1;
  }
#endif
  return wg_decode_unistr_len(db,data,WG_STRTYPE);
}



wg_int wg_decode_str_copy(void* db, wg_int data, char* strbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_str_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_str_copy is 0, not an encoded string");
    return -1;
  }
  if (strbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_str_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_str_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_copy(db,data,strbuf,buflen,WG_STRTYPE);
}


char* wg_decode_str_lang(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_str");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_str_lang is 0, not an encoded string");
    return NULL;
  }
#endif
  return wg_decode_unistr_lang(db,data,WG_STRTYPE);
}


wg_int wg_decode_str_lang_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_str_lang_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_str_lang_len is 0, not an encoded string");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_len(db,data,WG_STRTYPE);
}



wg_int wg_decode_str_lang_copy(void* db, wg_int data, char* langbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_str_lang_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_str_lang_copy is 0, not an encoded string");
    return -1;
  }
  if (langbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_str_lang_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_str_lang_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_copy(db,data,langbuf,buflen,WG_STRTYPE);
}


/* xmlliteral */


wg_int wg_encode_xmlliteral(void* db, char* str, char* xsdtype) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_xmlliteral");
    return WG_ILLEGAL;
  }
  if (str==NULL) {
    show_data_error(db,"NULL string ptr given to wg_encode_xmlliteral");
    return WG_ILLEGAL;
  }
  if (xsdtype==NULL) {
    show_data_error(db,"NULL xsdtype ptr given to wg_encode_xmlliteral");
    return WG_ILLEGAL;
  }
#endif
  /* Logging handled inside wg_encode_unistr() */
  return wg_encode_unistr(db,str,xsdtype,WG_XMLLITERALTYPE);
}


char* wg_decode_xmlliteral(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_xmlliteral");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_xmlliteral is 0, not an encoded xmlliteral");
    return NULL;
  }
#endif
  return wg_decode_unistr(db,data,WG_XMLLITERALTYPE);
}


wg_int wg_decode_xmlliteral_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_xmlliteral_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_xmlliteral_len is 0, not an encoded xmlliteral");
    return -1;
  }
#endif
  return wg_decode_unistr_len(db,data,WG_XMLLITERALTYPE);
}



wg_int wg_decode_xmlliteral_copy(void* db, wg_int data, char* strbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_xmlliteral_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_xmlliteral_copy is 0, not an encoded xmlliteral");
    return -1;
  }
  if (strbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_xmlliteral_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_xmlliteral_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_copy(db,data,strbuf,buflen,WG_XMLLITERALTYPE);
}


char* wg_decode_xmlliteral_xsdtype(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_xmlliteral");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_xmlliteral_xsdtype is 0, not an encoded xmlliteral");
    return NULL;
  }
#endif
  return wg_decode_unistr_lang(db,data,WG_XMLLITERALTYPE);
}


wg_int wg_decode_xmlliteral_xsdtype_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_xmlliteral_xsdtype_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_xmlliteral_lang_xsdtype is 0, not an encoded xmlliteral");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_len(db,data,WG_XMLLITERALTYPE);
}



wg_int wg_decode_xmlliteral_xsdtype_copy(void* db, wg_int data, char* langbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_xmlliteral_xsdtype_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_xmlliteral_xsdtype_copy is 0, not an encoded xmlliteral");
    return -1;
  }
  if (langbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_xmlliteral_xsdtype_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_xmlliteral_xsdtype_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_copy(db,data,langbuf,buflen,WG_XMLLITERALTYPE);
}


/* uri */


wg_int wg_encode_uri(void* db, char* str, char* prefix) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_uri");
    return WG_ILLEGAL;
  }
  if (str==NULL) {
    show_data_error(db,"NULL string ptr given to wg_encode_uri");
    return WG_ILLEGAL;
  }
#endif
  /* Logging handled inside wg_encode_unistr() */
  return wg_encode_unistr(db,str,prefix,WG_URITYPE);
}


char* wg_decode_uri(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_uri");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_uri is 0, not an encoded string");
    return NULL;
  }
#endif
  return wg_decode_unistr(db,data,WG_URITYPE);
}


wg_int wg_decode_uri_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_uri_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_uri_len is 0, not an encoded string");
    return -1;
  }
#endif
  return wg_decode_unistr_len(db,data,WG_URITYPE);
}



wg_int wg_decode_uri_copy(void* db, wg_int data, char* strbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_uri_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_uri_copy is 0, not an encoded string");
    return -1;
  }
  if (strbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_uri_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_uri_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_copy(db,data,strbuf,buflen,WG_URITYPE);
}


char* wg_decode_uri_prefix(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_uri_prefix");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_uri_prefix is 0, not an encoded uri");
    return NULL;
  }
#endif
  return wg_decode_unistr_lang(db,data,WG_URITYPE);
}


wg_int wg_decode_uri_prefix_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_uri_prefix_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_uri_prefix_len is 0, not an encoded string");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_len(db,data,WG_URITYPE);
}



wg_int wg_decode_uri_prefix_copy(void* db, wg_int data, char* langbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_uri_prefix_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_uri_prefix_copy is 0, not an encoded string");
    return -1;
  }
  if (langbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_uri_prefix_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_uri_prefix_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_copy(db,data,langbuf,buflen,WG_URITYPE);
}


/* blob */


wg_int wg_encode_blob(void* db, char* str, char* type, wg_int len) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_blob");
    return WG_ILLEGAL;
  }
  if (str==NULL) {
    show_data_error(db,"NULL string ptr given to wg_encode_blob");
    return WG_ILLEGAL;
  }
#endif
  return wg_encode_uniblob(db,str,type,WG_BLOBTYPE,len);
}


char* wg_decode_blob(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_blob");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_blob is 0, not an encoded string");
    return NULL;
  }
#endif
  return wg_decode_unistr(db,data,WG_BLOBTYPE);
}


wg_int wg_decode_blob_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_blob_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_blob_len is 0, not an encoded string");
    return -1;
  }
#endif
  return wg_decode_unistr_len(db,data,WG_BLOBTYPE)+1;
}



wg_int wg_decode_blob_copy(void* db, wg_int data, char* strbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_blob_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_blob_copy is 0, not an encoded string");
    return -1;
  }
  if (strbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_blob_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_blob_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_copy(db,data,strbuf,buflen,WG_BLOBTYPE);
}


char* wg_decode_blob_type(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_blob_type");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_blob_type is 0, not an encoded blob");
    return NULL;
  }
#endif
  return wg_decode_unistr_lang(db,data,WG_BLOBTYPE);
}


wg_int wg_decode_blob_type_len(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_blob_type_len");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_blob_type_len is 0, not an encoded string");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_len(db,data,WG_BLOBTYPE);
}



wg_int wg_decode_blob_type_copy(void* db, wg_int data, char* langbuf, wg_int buflen) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_blob_type_copy");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_blob_type_copy is 0, not an encoded string");
    return -1;
  }
  if (langbuf==NULL) {
     show_data_error(db,"buffer given to wg_decode_blob_type_copy is 0, not a valid buffer pointer");
    return -1;
  }
  if (buflen<1) {
     show_data_error(db,"buffer len given to wg_decode_blob_type_copy is 0 or less");
    return -1;
  }
#endif
  return wg_decode_unistr_lang_copy(db,data,langbuf,buflen,WG_BLOBTYPE);
}


/* anonconst */


wg_int wg_encode_anonconst(void* db, char* str) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_anonconst");
    return WG_ILLEGAL;
  }
  if (str==NULL) {
    show_data_error(db,"NULL string ptr given to wg_encode_anonconst");
    return WG_ILLEGAL;
  }
#endif
  //return wg_encode_unistr(db,str,NULL,WG_ANONCONSTTYPE);
  /* Logging handled inside wg_encode_unistr() */
  return wg_encode_unistr(db,str,NULL,WG_URITYPE);
}


char* wg_decode_anonconst(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_anonconst");
    return NULL;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_anonconst is 0, not an encoded anonconst");
    return NULL;
  }
#endif
  //return wg_decode_unistr(db,data,WG_ANONCONSTTYPE);
  return wg_decode_unistr(db,data,WG_URITYPE);
}


/* var */


wg_int wg_encode_var(void* db, wg_int varnr) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_encode_var");
    return WG_ILLEGAL;
  }
  if (!fits_var(varnr)) {
    show_data_error(db,"int given to wg_encode_var too big/small");
    return WG_ILLEGAL;
  }
#endif
#ifdef USE_DBLOG
/* Skip logging values that do not cause storage allocation.
  if(dbh->logging.active) {
    if(wg_log_encode(db, WG_VARTYPE, &data, 0, NULL, 0))
      return WG_ILLEGAL;
  }
*/
#endif
  return encode_var(varnr);
}


wg_int wg_decode_var(void* db, wg_int data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_data_error(db,"wrong database pointer given to wg_decode_var");
    return -1;
  }
  if (!data) {
    show_data_error(db,"data given to wg_decode_var is 0, not an encoded var");
    return -1;
  }
#endif
  return decode_var(data);
}




/* ============================================

Universal funs for string, xmlliteral, uri, blob

============================================== */


gint wg_encode_unistr(void* db, char* str, char* lang, gint type) {
  gint offset;
  gint len;
#ifdef USETINYSTR
  gint res;
#endif
  char* dptr;
  char* sptr;
  char* dendptr;

  len=(gint)(strlen(str));
#ifdef USE_DBLOG
  /* Log before allocating. */
  if(dbmemsegh(db)->logging.active) {
    gint extlen = 0;
    if(lang) extlen = strlen(lang);
    if(wg_log_encode(db, type, str, len, lang, extlen))
      return WG_ILLEGAL;
  }
#endif
#ifdef USETINYSTR
/* XXX: add tinystr support to logging */
#ifdef USE_DBLOG
#error USE_DBLOG and USETINYSTR are incompatible
#endif
  if (lang==NULL && type==WG_STRTYPE && len<(sizeof(gint)-1)) {
    res=TINYSTRBITS; // first zero the field and set last byte to mask
    if (LITTLEENDIAN) {
      dptr=((char*)(&res))+1; // type bits stored in lowest addressed byte
    } else {
      dptr=((char*)(&res));  // type bits stored in highest addressed byte
    }
    memcpy(dptr,str,len+1);
    return res;
  }
#endif
  if (lang==NULL && type==WG_STRTYPE && len<SHORTSTR_SIZE) {
    // short string, store in a fixlen area
    offset=alloc_shortstr(db);
    if (!offset) {
      show_data_error_str(db,"cannot store a string in wg_encode_unistr",str);
#ifdef USE_DBLOG
      if(dbmemsegh(db)->logging.active) {
        wg_log_encval(db, WG_ILLEGAL);
      }
#endif
      return WG_ILLEGAL;
    }
    // loop over bytes, storing them starting from offset
    dptr = (char *) offsettoptr(db,offset);
    dendptr=dptr+SHORTSTR_SIZE;
    //
    //strcpy(dptr,sptr);
    //memset(dptr+len,0,SHORTSTR_SIZE-len);
    //
    for(sptr=str; (*dptr=*sptr)!=0; sptr++, dptr++) {}; // copy string
    for(dptr++; dptr<dendptr; dptr++) { *dptr=0; }; // zero the rest
    // store offset to field
#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_encval(db, encode_shortstr_offset(offset)))
        return WG_ILLEGAL; /* journal error */
    }
#endif
    return encode_shortstr_offset(offset);
    //dbstore(db,ptrtoffset(record)+RECORD_HEADER_GINTS+fieldnr,encode_shortstr_offset(offset));
  } else {
    offset=find_create_longstr(db,str,lang,type,len+1);
    if (!offset) {
      show_data_error_nr(db,"cannot create a string of size ",len);
#ifdef USE_DBLOG
      if(dbmemsegh(db)->logging.active) {
        wg_log_encval(db, WG_ILLEGAL);
      }
#endif
      return WG_ILLEGAL;
    }
#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_encval(db, encode_longstr_offset(offset)))
        return WG_ILLEGAL; /* journal error */
    }
#endif
    return encode_longstr_offset(offset);
  }
}


gint wg_encode_uniblob(void* db, char* str, char* lang, gint type, gint len) {
  gint offset;

  if (0) {
  } else {
    offset=find_create_longstr(db,str,lang,type,len);
    if (!offset) {
      show_data_error_nr(db,"cannot create a blob of size ",len);
      return WG_ILLEGAL;
    }
    return encode_longstr_offset(offset);
  }
}


static gint find_create_longstr(void* db, char* data, char* extrastr, gint type, gint length) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint offset;
  size_t i;
  gint tmp;
  gint lengints;
  gint lenrest;
  char* lstrptr;
  gint old=0;
  int hash;
  gint hasharrel;
  gint res;

  if (0) {
  } else {

    // find hash, check if exists and use if found
    hash=wg_hash_typedstr(db,data,extrastr,type,length);
    //hasharrel=((gint*)(offsettoptr(db,((db->strhash_area_header).arraystart))))[hash];
    hasharrel=dbfetch(db,((dbh->strhash_area_header).arraystart)+(sizeof(gint)*hash));
    //printf("hash %d((dbh->strhash_area_header).arraystart)+(sizeof(gint)*hash) %d hasharrel %d\n",
    //        hash,((dbh->strhash_area_header).arraystart)+(sizeof(gint)*hash), hasharrel);
    if (hasharrel) old=wg_find_strhash_bucket(db,data,extrastr,type,length,hasharrel);
    //printf("old %d \n",old);
    if (old) {
      //printf("str found in hash\n");
      return old;
    }
    //printf("str not found in hash\n");
    //printf("hasharrel 1 %d \n",hasharrel);
    // equal string not found in hash
    // allocate a new string
    lengints=length/sizeof(gint);  // 7/4=1, 8/4=2, 9/4=2,
    lenrest=length%sizeof(gint);  // 7%4=3, 8%4=0, 9%4=1,
    if (lenrest) lengints++;
    offset=wg_alloc_gints(db,
                     &(dbmemsegh(db)->longstr_area_header),
                    lengints+LONGSTR_HEADER_GINTS);
    if (!offset) {
      //show_data_error_nr(db,"cannot create a data string/blob of size ",length);
      return 0;
    }
    lstrptr=(char*)(offsettoptr(db,offset));
    // store string contents
    memcpy(lstrptr+(LONGSTR_HEADER_GINTS*sizeof(gint)),data,length);
    //zero the rest
    for(i=0;lenrest && i<sizeof(gint)-lenrest;i++) {
/*    for(i=0;i<lenrest;i++) {*/
      *(lstrptr+length+(LONGSTR_HEADER_GINTS*sizeof(gint))+i)=0;
    }
    // if extrastr exists, encode extrastr and store ptr to longstr record field
    if (extrastr!=NULL) {
      tmp=wg_encode_str(db,extrastr,NULL);
      if (tmp==WG_ILLEGAL) {
        //show_data_error_nr(db,"cannot create an (extra)string of size ",strlen(extrastr));
        return 0;
      }
      dbstore(db,offset+LONGSTR_EXTRASTR_POS*sizeof(gint),tmp);
      // increase extrastr refcount
      if(islongstr(tmp)) {
        gint *strptr = (gint *) offsettoptr(db,decode_longstr_offset(tmp));
        ++(*(strptr+LONGSTR_REFCOUNT_POS));
      }
    } else {
      dbstore(db,offset+LONGSTR_EXTRASTR_POS*sizeof(gint),0); // no extrastr ptr
    }
    // store metainfo: full obj len and str len difference, plus type
    tmp=(getusedobjectsize(*((gint*)lstrptr))-length)<<LONGSTR_META_LENDIFSHFT;
    tmp=tmp|type; // subtype of str stored in lowest byte of meta
    //printf("storing obj size %d, str len %d lengints %d lengints*4 %d lenrest %d lendiff %d metaptr %d meta %d \n",
    //  getusedobjectsize(*((gint*)lstrptr)),strlen(data),lengints,lengints*4,lenrest,
    //  (getusedobjectsize(*((gint*)lstrptr))-length),
    //  ((gint*)(offsettoptr(db,offset)))+LONGSTR_META_POS,
    //  tmp);
    dbstore(db,offset+LONGSTR_META_POS*sizeof(gint),tmp); // type and str length diff
    dbstore(db,offset+LONGSTR_REFCOUNT_POS*sizeof(gint),0); // not pointed from anywhere yet
    dbstore(db,offset+LONGSTR_BACKLINKS_POS*sizeof(gint),0); // no backlinks yet
    // encode
    res=encode_longstr_offset(offset);
    // store to hash and update hashchain
    dbstore(db,((dbh->strhash_area_header).arraystart)+(sizeof(gint)*hash),res);
    //printf("hasharrel 2 %d \n",hasharrel);
    dbstore(db,offset+LONGSTR_HASHCHAIN_POS*sizeof(gint),hasharrel); // store old hash array el
    // return result
    return res;
  }

}



char* wg_decode_unistr(void* db, gint data, gint type) {
  gint* objptr;
  char* dataptr;
#ifdef USETINYSTR
  if (type==WG_STRTYPE && istinystr(data)) {
    if (LITTLEENDIAN) {
      dataptr=((char*)(&data))+1; // type bits stored in lowest addressed byte
    } else {
      dataptr=((char*)(&data));  // type bits stored in highest addressed byte
    }
    return dataptr;
  }
#endif
  if (isshortstr(data)) {
    dataptr=(char*)(offsettoptr(db,decode_shortstr_offset(data)));
    return dataptr;
  }
  if (islongstr(data)) {
    objptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
    dataptr=((char*)(objptr))+(LONGSTR_HEADER_GINTS*sizeof(gint));
    return dataptr;
  }
  show_data_error(db,"data given to wg_decode_unistr is not an encoded string");
  return NULL;
}


char* wg_decode_unistr_lang(void* db, gint data, gint type) {
  gint* objptr;
  gint* fldptr;
  gint fldval;
  char* res;

#ifdef USETINYSTR
  if (type==WG_STRTYPE && istinystr(data)) {
    return NULL;
  }
#endif
  if (type==WG_STRTYPE && isshortstr(data)) {
    return NULL;
  }
  if (islongstr(data)) {
    objptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
    fldptr=((gint*)objptr)+LONGSTR_EXTRASTR_POS;
    fldval=*fldptr;
    if (fldval==0) return NULL;
    res=wg_decode_unistr(db,fldval,type);
    return res;
  }
  show_data_error(db,"data given to wg_decode_unistr_lang is not an encoded string");
  return NULL;
}

/**
* return length of the main string, not including terminating 0
*
*
*/

gint wg_decode_unistr_len(void* db, gint data, gint type) {
  char* dataptr;
  gint* objptr;
  gint objsize;
  gint strsize;

#ifdef USETINYSTR
  if (type==WG_STRTYPE && istinystr(data)) {
    if (LITTLEENDIAN) {
      dataptr=((char*)(&data))+1; // type bits stored in lowest addressed byte
    } else {
      dataptr=((char*)(&data));  // type bits stored in highest addressed byte
    }
    strsize=strlen(dataptr);
    return strsize;
  }
#endif
  if (isshortstr(data)) {
    dataptr=(char*)(offsettoptr(db,decode_shortstr_offset(data)));
    strsize=strlen(dataptr);
    return strsize;
  }
  if (islongstr(data)) {
    objptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
    objsize=getusedobjectsize(*objptr);
    dataptr=((char*)(objptr))+(LONGSTR_HEADER_GINTS*sizeof(gint));
    //printf("dataptr to read from %d str '%s' of len %d\n",dataptr,dataptr,strlen(dataptr));
    strsize=objsize-(((*(objptr+LONGSTR_META_POS))&LONGSTR_META_LENDIFMASK)>>LONGSTR_META_LENDIFSHFT);
    return strsize-1;
  }
  show_data_error(db,"data given to wg_decode_unistr_len is not an encoded string");
  return 0;
}

/**
* copy string, return length of a copied string, not including terminating 0
*
* return -1 in case of error
*
*/

gint wg_decode_unistr_copy(void* db, gint data, char* strbuf, gint buflen, gint type) {
  gint i;
  gint* objptr;
  char* dataptr;
  gint objsize;
  gint strsize;

#ifdef USETINYSTR
  if (type==WG_STRTYPE && istinystr(data)) {
    if (LITTLEENDIAN) {
      dataptr=((char*)(&data))+1; // type bits stored in lowest addressed byte
    } else {
      dataptr=((char*)(&data));  // type bits stored in highest addressed byte
    }
    strsize=strlen(dataptr)+1;
    if (strsize>=sizeof(gint)) {
      show_data_error_nr(db,"wrong data stored as tinystr, impossible length:",strsize);
      return 0;
    }
    if (buflen<strsize) {
      show_data_error_nr(db,"insufficient buffer length given to wg_decode_unistr_copy:",buflen);
      return 0;
    }
    memcpy(strbuf,dataptr,strsize);
    //printf("tinystr was read to strbuf '%s'\n",strbuf);
    return strsize-1;
  }
#endif
  if (type==WG_STRTYPE && isshortstr(data)) {
    dataptr=(char*)(offsettoptr(db,decode_shortstr_offset(data)));
    for (i=1;i<SHORTSTR_SIZE && (*dataptr)!=0; i++,dataptr++,strbuf++) {
      if (i>=buflen) {
        show_data_error_nr(db,"insufficient buffer length given to wg_decode_unistr_copy:",buflen);
        return -1;
      }
      *strbuf=*dataptr;
    }
    *strbuf=0;
    return i-1;
  }
  if (islongstr(data)) {
    objptr = (gint *) offsettoptr(db,decode_longstr_offset(data));
    objsize=getusedobjectsize(*objptr);
    dataptr=((char*)(objptr))+(LONGSTR_HEADER_GINTS*sizeof(gint));
    //printf("dataptr to read from %d str '%s' of len %d\n",dataptr,dataptr,strlen(dataptr));
    strsize=objsize-(((*(objptr+LONGSTR_META_POS))&LONGSTR_META_LENDIFMASK)>>LONGSTR_META_LENDIFSHFT);
    //printf("objsize %d metaptr %d meta %d lendiff %d strsize %d \n",
    //  objsize,((gint*)objptr+LONGSTR_META_POS),*((gint*)objptr+LONGSTR_META_POS),
    //  (((*(objptr+LONGSTR_META_POS))&LONGSTR_META_LENDIFMASK)>>LONGSTR_META_LENDIFSHFT),strsize);
    if(buflen<strsize) {
      show_data_error_nr(db,"insufficient buffer length given to wg_decode_unistr_copy:",buflen);
      return -1;
    }
    memcpy(strbuf,dataptr,strsize);
    //*(dataptr+strsize)=0;
    //printf("copied str %s with strsize %d\n",strbuf,strlen(strbuf));
    if (type==WG_BLOBTYPE) return strsize;
    else return strsize-1;
  }
  show_data_error(db,"data given to wg_decode_unistr_copy is not an encoded string");
  return -1;
}

/**
* return length of the lang string, not including terminating 0
*
*
*/

gint wg_decode_unistr_lang_len(void* db, gint data, gint type) {
  char* langptr;
  gint len;

  langptr=wg_decode_unistr_lang(db,data,type);
  if (langptr==NULL) {
    return 0;
  }
  len=strlen(langptr);
  return len;
}


/**
* copy lang string, return length of a copied string, not including terminating 0
* in case of NULL lang write a single 0 to beginning of buffer and return 0
*
* return -1 in case of error
*
*/

gint wg_decode_unistr_lang_copy(void* db, gint data, char* strbuf, gint buflen, gint type) {
  char* langptr;
  gint len;

  langptr=wg_decode_unistr_lang(db,data,type);
  if (langptr==NULL) {
    *strbuf=0;
    return 0;
  }
  len=strlen(langptr);
  if (len>=buflen) {
    show_data_error_nr(db,"insufficient buffer length given to wg_decode_unistr_lang_copy:",buflen);
    return -1;
  }
  memcpy(strbuf,langptr,len+1);
  return len;
}





/* ----------- calendar and time functions ------------------- */

/*

Scalar date routines used are written and given to public domain by Ray Gardner.

*/

static int isleap(unsigned yr) {
  return yr % 400 == 0 || (yr % 4 == 0 && yr % 100 != 0);
}

static unsigned months_to_days (unsigned month) {
  return (month * 3057 - 3007) / 100;
}

static long years_to_days (unsigned yr) {
  return yr * 365L + yr / 4 - yr / 100 + yr / 400;
}

static long ymd_to_scalar (unsigned yr, unsigned mo, unsigned day) {
  long scalar;
  scalar = day + months_to_days(mo);
  if ( mo > 2 )                         /* adjust if past February */
      scalar -= isleap(yr) ? 1 : 2;
  yr--;
  scalar += years_to_days(yr);
  return scalar;
}

static void scalar_to_ymd (long scalar, unsigned *yr, unsigned *mo, unsigned *day) {
  unsigned n;                /* compute inverse of years_to_days() */

  for ( n = (unsigned)((scalar * 400L) / 146097L); years_to_days(n) < scalar;) n++; /* 146097 == years_to_days(400) */
  *yr = n;
  n = (unsigned)(scalar - years_to_days(n-1));
  if ( n > 59 ) {                       /* adjust if past February */
    n += 2;
    if (isleap(*yr))  n -= n > 62 ? 1 : 2;
  }
  *mo = (n * 100 + 3007) / 3057;    /* inverse of months_to_days() */
  *day = n - months_to_days(*mo);
}

/*

Thread-safe localtime_r appears not to be present on windows: emulate using win localtime_s, which is thread-safe

*/

#ifdef _WIN32
static struct tm * localtime_r (const time_t *timer, struct tm *result) {
   struct tm local_result;
   int res;

   res = localtime_s (&local_result,timer);
   if (!res) return NULL;
   //if (local_result == NULL || result == NULL) return NULL;
   memcpy (result, &local_result, sizeof (result));
   return result;
}
#endif


/* ------ value offset translation ---- */

/* Translate externally encoded value in relation to current base address
 *
 * Data argument is a value encoded in the database extdb. Returned value is
 * translated so that it can be used in WhiteDB API functions with the
 * database db.
 */
gint wg_encode_external_data(void *db, void *extdb, gint encoded) {
#ifdef USE_CHILD_DB
  return wg_translate_hdroffset(db, dbmemseg(extdb), encoded);
#else
  show_data_error(db, "child databases support is not enabled.");
  return WG_ILLEGAL;
#endif
}

#ifdef USE_CHILD_DB

gint wg_translate_hdroffset(void *db, void *exthdr, gint encoded) {
  gint extoff = ptrtooffset(db, exthdr); /* relative offset of external db */

  /* Only pointer-type values need translating */
  if(isptr(encoded)) {
    switch(encoded&NORMALPTRMASK) {
      case DATARECBITS:
        return encode_datarec_offset(
          decode_datarec_offset(encoded) + extoff);
      case LONGSTRBITS:
        return encode_longstr_offset(
          decode_longstr_offset(encoded) + extoff);
      case SHORTSTRBITS:
        return encode_shortstr_offset(
          decode_shortstr_offset(encoded) + extoff);
      case FULLDOUBLEBITS:
        return encode_fulldouble_offset(
          decode_fulldouble_offset(encoded) + extoff);
      case FULLINTBITSV0:
      case FULLINTBITSV1:
        return encode_fullint_offset(
          decode_fullint_offset(encoded) + extoff);
      default:
        /* XXX: it's not entirely correct to fail silently here, but
         * we can only end up here if new pointer types are added without
         * updating this function.
         */
        break;
    }
  }
  return encoded;
}

/** Return base address that an encoded value is "native" to.
 *
 * The external database must be registered first for the offset
 * to be recognized. Returns NULL if none of the registered
 * databases match.
 */
static void *get_ptr_owner(void *db, gint encoded) {
  gint offset = 0;

  if(isptr(encoded)) {
    switch(encoded&NORMALPTRMASK) {
      case DATARECBITS:
        offset = decode_datarec_offset(encoded);
      case LONGSTRBITS:
        offset = decode_longstr_offset(encoded);
      case SHORTSTRBITS:
        offset = decode_shortstr_offset(encoded);
      case FULLDOUBLEBITS:
        offset = decode_fulldouble_offset(encoded);
      case FULLINTBITSV0:
      case FULLINTBITSV1:
        offset = decode_fullint_offset(encoded);
      default:
        break;
    }
  } else {
    return dbmemseg(db); /* immediate values default to "Local" */
  }

  if(!offset)
    return NULL; /* data values do not point at memsegment header
                  * start anyway. */

  if(offset > 0 && offset < dbmemsegh(db)->size) {
    return dbmemseg(db);  /* "Local" record */
  } else {
    int i;
    db_memsegment_header* dbh = dbmemsegh(db);

    for(i=0; i<dbh->extdbs.count; i++) {
      if(offset > dbh->extdbs.offset[i] && \
        offset < dbh->extdbs.offset[i] + dbh->extdbs.size[i]) {
        return (void *) (dbmemsegbytes(db) + dbh->extdbs.offset[i]);
      }
    }
    return NULL;
  }
}

/** Check if an offset is "native" to the current database.
 *
 * Returns 1 if the offset is local, 0 otherwise.
 */
static int is_local_offset(void *db, gint offset) {
  if(offset > 0 && offset < dbmemsegh(db)->size) {
      return 1;  /* "Local" data */
  }
  return 0;
}
#endif

/** Return base address that the record belongs to.
 *
 *  Takes pointer values as arguments.
 *  The external database must be registered first for the offset
 *  to be recognized. Returns NULL if none of the registered
 *  databases match.
 *  XXX: needed to compile the lib under windows even
 *  if child databases are disabled.
 */
void *wg_get_rec_owner(void *db, void *rec) {
  int i;
  db_memsegment_header* dbh = dbmemsegh(db);

  if((gint) rec > (gint) dbmemseg(db)) {
    void *eodb = (void *) (dbmemsegbytes(db) + dbh->size);
    if((gint) rec < (gint) eodb)
      return dbmemseg(db);  /* "Local" record */
  }

  for(i=0; i<dbh->extdbs.count; i++) {
    void *base = (void *) (dbmemsegbytes(db) + dbh->extdbs.offset[i]);
    void *eodb = (void *) (((char *) base) + dbh->extdbs.size[i]);
    if((gint) rec > (gint) base && (gint) rec < (gint) eodb) {
      return base;
    }
  }
  show_data_error(db, "invalid pointer in wg_get_rec_base_offset");
  return NULL;
}

/* ----------- record pointer bitmap operations -------- */

/*
 We assume records are aligned at minimum each 8 bytes.
 Each possible record offset is assigned one bit in a bitmap.
 Consider
 offsets:   0,8,16,24,32,40,48,56 | 64,72,80,88,...
 addr:            byte 0          |     byte 1 ...
 shft:      0 1  2  3  4  5  6  7 | 0  1   2  3  ...
*/

/** Check both that db and record pointer ptr are correct.

 Uses the record pointer bitmap.
  
*/

#ifdef USE_RECPTR_BITMAP /* currently disabled, as nothing is updating
                          * the bitmap. Re-enable as needed.
                          */
gint wg_recptr_check(void *db,void *ptr) {
  gint addr;
  int shft;
  unsigned char byte;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint offset=ptrtooffset(db,ptr);
  
  if (!dbcheckh(dbh)) return -1; // not a correct db
  if (offset<=0 || offset>=dbh->size) return -2; // ptr out of area
  if (offset%8) return -3; // ptr not correctly aligned
  addr=offset/64; // divide by alignment
  shft=(offset%64)/8; // bit position in byte
  if (!(dbh->recptr_bitmap.offset)) return -4; // bitmap not allocated
  byte=*((char*)(offsettoptr(db,dbh->recptr_bitmap.offset+addr)));
  if (byte & (1<<shft)) return 0;
  else return -5; // no record at this position
}

static void recptr_setbit(void *db,void *ptr) {
  char* byteptr;
  gint addr;
  int shft;
  unsigned char byte;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint offset=ptrtooffset(db,ptr);
  
  //if (offset<=0 || offset>=dbh->size) return -1; // out of area
  //if (offset%8) return -2; // not correctly aligned
  addr=offset/64; // divide by alignment
  shft=(offset%64)/8; // bit position in byte
  byteptr=(char*)(offsettoptr(db,dbh->recptr_bitmap.offset+addr));
  byte=*byteptr;
  *byteptr=byte | (1<<shft);
}

static void recptr_clearbit(void *db,void *ptr) {
  char* byteptr;
  gint addr;
  int shft;
  unsigned char byte;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint offset=ptrtooffset(db,ptr);
  
  //if (offset<=0 || offset>=dbh->size) return -1; // out of area
  //if (offset%8) return -2; // not correctly aligned
  addr=offset/64; // divide by alignment
  shft=(offset%64)/8; // bit position in byte
  byteptr=(char*)(offsettoptr(db,dbh->recptr_bitmap.offset+addr));
  byte=*byteptr;
  *byteptr=byte ^ (1<<shft);
}
#endif

/* ------------ errors ---------------- */


static gint show_data_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg data handling error: %s\n",errmsg);
#endif
  return -1;

}

static gint show_data_error_nr(void* db, char* errmsg, gint nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg data handling error: %s %d\n", errmsg, (int) nr);
#endif
  return -1;

}

static gint show_data_error_double(void* db, char* errmsg, double nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg data handling error: %s %f\n",errmsg,nr);
#endif
  return -1;

}

static gint show_data_error_str(void* db, char* errmsg, char* str) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg data handling error: %s %s\n",errmsg,str);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Andri Rebane 2009
* Copyright (c) Priit Järv 2013,2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dblog.c
 *  DB logging support for WhiteDB memory database
 *
 */

/* ====== Includes =============== */

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#include <errno.h>
#include <malloc.h>
#include <io.h>
#include <share.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//data.h"
//hash.h"

/* ====== Private headers and defs ======== */

//log.h"

#if defined(USE_DBLOG) && !defined(USE_DATABASE_HANDLE)
#error Logging requires USE_DATABASE_HANDLE
#endif

#ifdef _WIN32
#define snprintf(s, sz, f, ...) _snprintf_s(s, sz+1, sz, f, ## __VA_ARGS__)
#endif

#ifndef _WIN32
#define JOURNAL_FAIL(f, e) \
  close(f); \
  return e;
#else
#define JOURNAL_FAIL(f, e) \
  _close(f); \
  return e;
#endif

#define GET_LOG_BYTE(d, f, v) \
  if((v = fgetc(f)) == EOF) { \
    return show_log_error(d, "Failed to read log entry"); \
  }

#define GET_LOG_CMD(d, f, v) \
  if((v = fgetc(f)) == EOF) { \
    if(feof(f)) break; \
    else return show_log_error(d, "Failed to read log entry"); \
  }

/* Does not emit a message as fget_varint() does that already. */
#define GET_LOG_VARINT(d, f, v, e) \
  if(fget_varint(d, f, (wg_uint *) &v))  { \
    return e; \
  }

#ifdef HAVE_64BIT_GINT
#define VARINT_SIZE 9
#else
#define VARINT_SIZE 5
#endif

/* ====== data structures ======== */

/* ======= Private protos ================ */

#ifdef USE_DBLOG
static int backup_journal(void *db, char *journal_fn);
static gint check_journal(void *db, int fd);
static int open_journal(void *db, int create);

static gint add_tran_offset(void *db, void *table, gint old, gint new);
static gint add_tran_enc(void *db, void *table, gint old, gint new);
static gint translate_offset(void *db, void *table, gint offset);
static gint translate_encoded(void *db, void *table, gint enc);
static gint recover_encode(void *db, FILE *f, gint type);
static gint recover_journal(void *db, FILE *f, void *table);

static gint write_log_buffer(void *db, void *buf, int buflen);
#endif /* USE_DBLOG */

static gint show_log_error(void *db, char *errmsg);

/* ====== Functions ============== */

#ifdef USE_DBLOG

/** Check the file magic of the journal file.
 *
 * Since the files are opened in append mode, we don't need to
 * seek before or after reading the header (on Linux).
 */
static gint check_journal(void *db, int fd) {
  char buf[WG_JOURNAL_MAGIC_BYTES + 1];
#ifndef _WIN32
  if(read(fd, buf, WG_JOURNAL_MAGIC_BYTES) != WG_JOURNAL_MAGIC_BYTES) {
#else
  if(_read(fd, buf, WG_JOURNAL_MAGIC_BYTES) != WG_JOURNAL_MAGIC_BYTES) {
#endif
    return show_log_error(db, "Error checking log file");
  }
  buf[WG_JOURNAL_MAGIC_BYTES] = '\0';
  if(strncmp(buf, WG_JOURNAL_MAGIC, WG_JOURNAL_MAGIC_BYTES)) {
    return show_log_error(db, "Bad log file magic");
  }
  return 0;
}


/** Rename the existing journal.
 *
 * Uses a naming scheme of xxx.yy where xxx is the journal filename
 * and yy is a sequence number that is incremented.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int backup_journal(void *db, char *journal_fn) {
  int i, logidx, err;
  time_t oldest = 0;
  /* keep this buffer large enough to fit the backup counter length */
  char journal_backup[WG_JOURNAL_FN_BUFSIZE + 10];

  for(i=0, logidx=0; i<WG_JOURNAL_MAX_BACKUPS; i++) {
#ifndef _WIN32
    struct stat tmp;
#else
    struct _stat tmp;
#endif
    snprintf(journal_backup, WG_JOURNAL_FN_BUFSIZE + 10, "%s.%d",
      journal_fn, i);
#ifndef _WIN32
    if(stat(journal_backup, &tmp) == -1) {
#else
    if(_stat(journal_backup, &tmp) == -1) {
#endif
      if(errno == ENOENT) {
        logidx = i;
        break;
      }
    } else if(!oldest || oldest > tmp.st_mtime) {
      oldest = tmp.st_mtime;
      logidx = i;
    }
  }

  /* at this point, logidx points to either an available backup
   * filename or the oldest existing backup (which will be overwritten).
   * If all else fails, filename xxx.0 is used.
   */
  snprintf(journal_backup, WG_JOURNAL_FN_BUFSIZE + 10, "%s.%d",
    journal_fn, logidx);
#ifdef _WIN32
  _unlink(journal_backup);
#endif
  err = rename(journal_fn, journal_backup);
  if(!err) {
    db_memsegment_header* dbh = dbmemsegh(db);
    dbh->logging.serial++; /* new journal file */
  }
  return err;
}

/** Open the journal file.
 *
 * In create mode, we also take care of the backup copy.
 */
static int open_journal(void *db, int create) {
  char journal_fn[WG_JOURNAL_FN_BUFSIZE];
  db_memsegment_header* dbh = dbmemsegh(db);
  int addflags = 0;
  int fd = -1;
#ifndef _WIN32
  mode_t savemask = 0;
#endif

  wg_journal_filename(db, journal_fn, WG_JOURNAL_FN_BUFSIZE);
  if(create) {
#ifndef _WIN32
    struct stat tmp;
    db_handle_logdata *ld = \
      (db_handle_logdata *) (((db_handle *) db)->logdata);
    savemask = umask(ld->umask);
    addflags |= O_CREAT;
#else
    struct _stat tmp;
    addflags |= _O_CREAT;
#endif
#ifndef _WIN32
    if(!dbh->logging.dirty && !stat(journal_fn, &tmp)) {
#else
    if(!dbh->logging.dirty && !_stat(journal_fn, &tmp)) {
#endif
      if(backup_journal(db, journal_fn)) {
        show_log_error(db, "Failed to back up the existing journal.");
        goto abort;
      }
    }
  }

#ifndef _WIN32
  if((fd = open(journal_fn, addflags|O_APPEND|O_RDWR,
    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) == -1) {
#else
  if(_sopen_s(&fd, journal_fn, addflags|_O_APPEND|_O_BINARY|_O_RDWR,
    _SH_DENYNO, _S_IREAD|_S_IWRITE)) {
#endif
    show_log_error(db, "Error opening log file");
  }

abort:
  if(create) {
#ifndef _WIN32
    umask(savemask);
#endif
  }
  return fd;
}

/** Varint encoder
 *  this needs to be fast, so we don't check array size. It must
 *  be at least 9 bytes.
 *  based on http://stackoverflow.com/a/2982965
 */
static size_t enc_varint(unsigned char *buf, wg_uint val) {
  buf[0] = (unsigned char)(val | 0x80);
  if(val >= (1 << 7)) {
    buf[1] = (unsigned char)((val >>  7) | 0x80);
    if(val >= (1 << 14)) {
      buf[2] = (unsigned char)((val >> 14) | 0x80);
      if(val >= (1 << 21)) {
        buf[3] = (unsigned char)((val >> 21) | 0x80);
        if(val >= (1 << 28)) {
#ifndef HAVE_64BIT_GINT
          buf[4] = (unsigned char)(val >> 28);
          return 5;
#else
          buf[4] = (unsigned char)((val >> 28) | 0x80);
          if(val >= ((wg_uint) 1 << 35)) {
            buf[5] = (unsigned char)((val >> 35) | 0x80);
            if(val >= ((wg_uint) 1 << 42)) {
              buf[6] = (unsigned char)((val >> 42) | 0x80);
              if(val >= ((wg_uint) 1 << 49)) {
                buf[7] = (unsigned char)((val >> 49) | 0x80);
                if(val >= ((wg_uint) 1 << 56)) {
                  buf[8] = (unsigned char)(val >> 56);
                  return 9;
                } else {
                  buf[7] &= 0x7f;
                  return 8;
                }
              } else {
                buf[6] &= 0x7f;
                return 7;
              }
            } else {
              buf[5] &= 0x7f;
              return 6;
            }
          } else {
            buf[4] &= 0x7f;
            return 5;
          }
#endif
        } else {
          buf[3] &= 0x7f;
          return 4;
        }
      } else {
        buf[2] &= 0x7f;
        return 3;
      }
    } else {
      buf[1] &= 0x7f;
      return 2;
    }
  } else {
    buf[0] &= 0x7f;
    return 1;
  }
}

#if 0
/** Varint decoder
 *  returns the number of bytes consumed (so that the caller
 *  knows where the next value starts). Note that this approach
 *  assumes we're using a read buffer - this is acceptable and
 *  probably preferable when doing the journal replay.
 */
static size_t dec_varint(unsigned char *buf, wg_uint *val) {
  wg_uint tmp = buf[0] & 0x7f;
  if(buf[0] & 0x80) {
    tmp |= ((buf[1] & 0x7f) << 7);
    if(buf[1] & 0x80) {
      tmp |= ((buf[2] & 0x7f) << 14);
      if(buf[2] & 0x80) {
        tmp |= ((buf[3] & 0x7f) << 21);
        if(buf[3] & 0x80) {
#ifndef HAVE_64BIT_GINT
          tmp |= (buf[4] << 28);
          *val = tmp;
          return 5;
#else
          tmp |= ((wg_uint) (buf[4] & 0x7f) << 28);
          if(buf[4] & 0x80) {
            tmp |= ((wg_uint) (buf[5] & 0x7f) << 35);
            if(buf[5] & 0x80) {
              tmp |= ((wg_uint) (buf[6] & 0x7f) << 42);
              if(buf[6] & 0x80) {
                tmp |= ((wg_uint) (buf[7] & 0x7f) << 49);
                if(buf[7] & 0x80) {
                  tmp |= ((wg_uint) buf[8] << 56);
                  *val = tmp;
                  return 9;
                } else {
                  *val = tmp;
                  return 8;
                }
              } else {
                *val = tmp;
                return 7;
              }
            } else {
              *val = tmp;
              return 6;
            }
          } else {
            *val = tmp;
            return 5;
          }
#endif
        } else {
          *val = tmp;
          return 4;
        }
      } else {
        *val = tmp;
        return 3;
      }
    } else {
      *val = tmp;
      return 2;
    }
  } else {
    *val = tmp;
    return 1;
  }
}
#endif

/** Read varint from a buffered stream
 *  returns 0 on success
 *  returns -1 on error
 */
static int fget_varint(void *db, FILE *f, wg_uint *val) {
  register int c;
  wg_uint tmp;

  GET_LOG_BYTE(db, f, c)
  tmp = c & 0x7f;
  if(c & 0x80) {
    GET_LOG_BYTE(db, f, c)
    tmp |= ((c & 0x7f) << 7);
    if(c & 0x80) {
      GET_LOG_BYTE(db, f, c)
      tmp |= ((c & 0x7f) << 14);
      if(c & 0x80) {
        GET_LOG_BYTE(db, f, c)
        tmp |= ((c & 0x7f) << 21);
        if(c & 0x80) {
          GET_LOG_BYTE(db, f, c)
#ifndef HAVE_64BIT_GINT
          tmp |= (c << 28);
#else
          tmp |= ((wg_uint) (c & 0x7f) << 28);
          if(c & 0x80) {
            GET_LOG_BYTE(db, f, c)
            tmp |= ((wg_uint) (c & 0x7f) << 35);
            if(c & 0x80) {
              GET_LOG_BYTE(db, f, c)
              tmp |= ((wg_uint) (c & 0x7f) << 42);
              if(c & 0x80) {
                GET_LOG_BYTE(db, f, c)
                tmp |= ((wg_uint) (c & 0x7f) << 49);
                if(c & 0x80) {
                  GET_LOG_BYTE(db, f, c)
                  tmp |= ((wg_uint) c << 56);
                }
              }
            }
          }
#endif
        }
      }
    }
  }
  *val = tmp;
  return 0;
}

/** Add a log recovery translation entry
 *  Uses extendible gint hashtable internally.
 */
static gint add_tran_offset(void *db, void *table, gint old, gint new)
{
  return wg_ginthash_addkey(db, table, old, new);
}

/** Wrapper around add_tran_offset() to handle encoded data
 *
 */
static gint add_tran_enc(void *db, void *table, gint old, gint new)
{
  if(isptr(old)) {
    gint offset, newoffset;
    switch(old & NORMALPTRMASK) {
      case LONGSTRBITS:
        offset = decode_longstr_offset(old);
        newoffset = decode_longstr_offset(new);
        return add_tran_offset(db, table, offset, newoffset);
      case SHORTSTRBITS:
        offset = decode_shortstr_offset(old);
        newoffset = decode_shortstr_offset(new);
        return add_tran_offset(db, table, offset, newoffset);
      case FULLDOUBLEBITS:
        offset = decode_fulldouble_offset(old);
        newoffset = decode_fulldouble_offset(new);
        return add_tran_offset(db, table, offset, newoffset);
      case FULLINTBITSV0:
      case FULLINTBITSV1:
        offset = decode_fullint_offset(old);
        newoffset = decode_fullint_offset(new);
        return add_tran_offset(db, table, offset, newoffset);
      default:
        return 0;
    }
  }
  return 0;
}

/** Translate a log offset
 *
 */
static gint translate_offset(void *db, void *table, gint offset)
{
  gint newoffset;
  if(wg_ginthash_getkey(db, table, offset, &newoffset))
    return offset;
  else
    return newoffset;
}

/** Wrapper around translate_offset() to handle encoded data
 *
 */
static gint translate_encoded(void *db, void *table, gint enc)
{
  if(isptr(enc)) {
    gint offset;
    switch(enc & NORMALPTRMASK) {
      case DATARECBITS:
        return translate_offset(db, table, enc);
      case LONGSTRBITS:
        offset = decode_longstr_offset(enc);
        return encode_longstr_offset(translate_offset(db, table, offset));
      case SHORTSTRBITS:
        offset = decode_shortstr_offset(enc);
        return encode_shortstr_offset(translate_offset(db, table, offset));
      case FULLDOUBLEBITS:
        offset = decode_fulldouble_offset(enc);
        return encode_fulldouble_offset(translate_offset(db, table, offset));
      case FULLINTBITSV0:
      case FULLINTBITSV1:
        offset = decode_fullint_offset(enc);
        return encode_fullint_offset(translate_offset(db, table, offset));
      default:
        return enc;
    }
  }
  return enc;
}

/** Parse an encode entry from the log.
 *
 */
gint recover_encode(void *db, FILE *f, gint type)
{
  char *strbuf, *extbuf;
  gint length = 0, extlength = 0, enc;
  int intval;
  double doubleval;

  switch(type) {
    case WG_INTTYPE:
      if(fread((char *) &intval, sizeof(int), 1, f) != 1) {
        show_log_error(db, "Failed to read log entry");
        return WG_ILLEGAL;
      }
      return wg_encode_int(db, intval);
    case WG_DOUBLETYPE:
      if(fread((char *) &doubleval, sizeof(double), 1, f) != 1) {
        show_log_error(db, "Failed to read log entry");
        return WG_ILLEGAL;
      }
      return wg_encode_double(db, doubleval);
    case WG_STRTYPE:
    case WG_URITYPE:
    case WG_XMLLITERALTYPE:
    case WG_ANONCONSTTYPE:
    case WG_BLOBTYPE: /* XXX: no encode func for this yet */
      /* strings with extdata */
      GET_LOG_VARINT(db, f, length, WG_ILLEGAL)
      GET_LOG_VARINT(db, f, extlength, WG_ILLEGAL)

      strbuf = (char *) malloc(length + 1);
      if(!strbuf) {
        show_log_error(db, "Failed to allocate buffers");
        return WG_ILLEGAL;
      }
      if(fread(strbuf, 1, length, f) != length) {
        show_log_error(db, "Failed to read log entry");
        free(strbuf);
        return WG_ILLEGAL;
      }
      strbuf[length] = '\0';

      if(extlength) {
        extbuf = (char *) malloc(extlength + 1);
        if(!extbuf) {
          free(strbuf);
          show_log_error(db, "Failed to allocate buffers");
          return WG_ILLEGAL;
        }
        if(fread(extbuf, 1, extlength, f) != extlength) {
          show_log_error(db, "Failed to read log entry");
          free(strbuf);
          free(extbuf);
          return WG_ILLEGAL;
        }
        extbuf[extlength] = '\0';
      } else {
        extbuf = NULL;
      }

      enc = wg_encode_unistr(db, strbuf, extbuf, type);
      free(strbuf);
      if(extbuf)
        free(extbuf);
      return enc;
    default:
      break;
  }

  return show_log_error(db, "Unsupported data type");
}

/** Parse the journal file. Used internally only.
 *
 */
static gint recover_journal(void *db, FILE *f, void *table)
{
  int c;
  gint length = 0, offset = 0, newoffset;
  gint col = 0, enc = 0, newenc, meta = 0;
  void *rec;

  for(;;) {
    GET_LOG_CMD(db, f, c)
    switch((unsigned char) c & WG_JOURNAL_ENTRY_CMDMASK) {
      case WG_JOURNAL_ENTRY_CRE:
        GET_LOG_VARINT(db, f, length, -1)
        GET_LOG_VARINT(db, f, offset, -1)
        rec = wg_create_record(db, length);
        if(offset != 0) {
          /* XXX: should we have even tried if this failed earlier? */
          if(!rec) {
            return show_log_error(db, "Failed to create a new record");
          }
          newoffset = ptrtooffset(db, rec);
          if(newoffset != offset) {
            if(add_tran_offset(db, table, offset, newoffset)) {
              return show_log_error(db, "Failed to parse log "\
                "(out of translation memory)");
            }
          }
        }
        break;
      case WG_JOURNAL_ENTRY_DEL:
        GET_LOG_VARINT(db, f, offset, -1)
        newoffset = translate_offset(db, table, offset);
        rec = offsettoptr(db, newoffset);
        if(wg_delete_record(db, rec) < -1) {
          return show_log_error(db, "Failed to delete a record");
        }
        break;
      case WG_JOURNAL_ENTRY_ENC:
        newenc = recover_encode(db, f,
          (unsigned char) c & WG_JOURNAL_ENTRY_TYPEMASK);
        GET_LOG_VARINT(db, f, enc, -1)
        if(enc != WG_ILLEGAL) {
          /* Encode was supposed to succeed */
          if(newenc == WG_ILLEGAL) {
            return -1;
          }
          if(newenc != enc) {
            if(add_tran_enc(db, table, enc, newenc)) {
              return show_log_error(db, "Failed to parse log "\
                "(out of translation memory)");
            }
          }
        }
        break;
      case WG_JOURNAL_ENTRY_SET:
        GET_LOG_VARINT(db, f, offset, -1)
        GET_LOG_VARINT(db, f, col, -1)
        GET_LOG_VARINT(db, f, enc, -1)
        newoffset = translate_offset(db, table, offset);
        rec = offsettoptr(db, newoffset);
        newenc = translate_encoded(db, table, enc);
        if(wg_set_field(db, rec, col, newenc)) {
          return show_log_error(db, "Failed to set field data");
        }
        break;
      case WG_JOURNAL_ENTRY_META:
        GET_LOG_VARINT(db, f, offset, -1)
        GET_LOG_VARINT(db, f, meta, -1)
        newoffset = translate_offset(db, table, offset);
        rec = offsettoptr(db, newoffset);
        *((gint *) rec + RECORD_META_POS) = meta;
        break;
      default:
        return show_log_error(db, "Invalid log entry");
    }
  }
  return 0;
}
#endif /* USE_DBLOG */

/** Return the name of the current journal
 *
 */
void wg_journal_filename(void *db, char *buf, size_t buflen) {
#ifdef USE_DBLOG
  db_memsegment_header* dbh = dbmemsegh(db);

#ifndef _WIN32
  snprintf(buf, buflen, "%s.%td", WG_JOURNAL_FILENAME, dbh->key);
#else
  snprintf(buf, buflen, "%s.%Id", WG_JOURNAL_FILENAME, dbh->key);
#endif
  buf[buflen-1] = '\0';
#else
  buf[0] = '\0';
#endif
}

/** Set up the logging area in the database handle
 *  Normally called when opening the database connection.
 */
gint wg_init_handle_logdata(void *db) {
#ifdef USE_DBLOG
  db_handle_logdata **ld = \
    (db_handle_logdata **) &(((db_handle *) db)->logdata);
  *ld = malloc(sizeof(db_handle_logdata));
  if(!(*ld)) {
    return show_log_error(db, "Error initializing local log data");
  }
  memset(*ld, 0, sizeof(db_handle_logdata));
  (*ld)->fd = -1;
#endif
  return 0;
}

/** Clean up the state of logging in the database handle.
 *  Normally called when closing the database connection.
 */
void wg_cleanup_handle_logdata(void *db) {
#ifdef USE_DBLOG
  db_handle_logdata *ld = \
    (db_handle_logdata *) (((db_handle *) db)->logdata);
  if(ld) {
    if(ld->fd >= 0) {
#ifndef _WIN32
      close(ld->fd);
#else
      _close(ld->fd);
#endif
      ld->fd = -1;
    }
    free(ld);
    ((db_handle *) db)->logdata = NULL;
  }
#endif
}

/** Set journal file umask.
 *  This needs to be done separately from initializing the logging
 *  data in the handle, as the mask may be derived from the
 *  permissions of the shared memory segment and this is not
 *  guaranteed to exist during the handle initialization.
 *  Returns the old mask.
 */
int wg_log_umask(void *db, int cmask) {
  int prev = 0;
#ifdef USE_DBLOG
  db_handle_logdata *ld = \
    (db_handle_logdata *) (((db_handle *) db)->logdata);
  if(ld) {
    prev = ld->umask;
    ld->umask = cmask & 0777;
  }
#endif
  return prev;
}

/** Activate logging
 *
 * When successful, does the following:
 *   opens the logfile and initializes it;
 *   sets the logging active flag.
 *
 * Security concerns:
 *   - the log file name is compiled in (so we can't trick other
 *   processes into writing over files they're not supposed to)
 *   - the log file has a magic header (see above, avoid accidentally
 *   destroying files)
 *   - the process that initialized logging needs to have write
 *   access to the log file.
 *
 * Returns 0 on success
 * Returns -1 when logging is already active
 * Returns -2 when the function failed and logging is not active
 * Returns -3 when additionally, the log file was possibly destroyed
 */
gint wg_start_logging(void *db)
{
#ifdef USE_DBLOG
  db_memsegment_header* dbh = dbmemsegh(db);
/*  db_handle_logdata *ld = ((db_handle *) db)->logdata;*/
  int fd;

  if(dbh->logging.active) {
    show_log_error(db, "Logging is already active");
    return -1;
  }

  if((fd = open_journal(db, 1)) == -1) {
    show_log_error(db, "Error opening log file");
    return -2;
  }

  if(!dbh->logging.dirty) {
    /* logfile is clean, re-initialize */
    /* fseek(f, 0, SEEK_SET); */
#ifndef _WIN32
    ftruncate(fd, 0); /* XXX: this is a no-op with backups */
    if(write(fd, WG_JOURNAL_MAGIC, WG_JOURNAL_MAGIC_BYTES) != \
                                            WG_JOURNAL_MAGIC_BYTES) {
#else
    _chsize_s(fd, 0);
    if(_write(fd, WG_JOURNAL_MAGIC, WG_JOURNAL_MAGIC_BYTES) != \
                                            WG_JOURNAL_MAGIC_BYTES) {
#endif
      show_log_error(db, "Error initializing log file");
      JOURNAL_FAIL(fd, -3)
    }
  } else {
    /* check the magic header */
    if(check_journal(db, fd)) {
      JOURNAL_FAIL(fd, -2)
    }
  }

#if 0
  /* Keep using this handle */
  ld->fd = fd;
  ld->serial = dbh->logging.serial;
#else
#ifndef _WIN32
  close(fd);
#else
  _close(fd);
#endif
#endif

  dbh->logging.active = 1;
  return 0;
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

/** Turn journal logging off.
 *
 * Returns 0 on success
 * Returns non-zero on failure
 */
gint wg_stop_logging(void *db)
{
#ifdef USE_DBLOG
  db_memsegment_header* dbh = dbmemsegh(db);

  if(!dbh->logging.active) {
    show_log_error(db, "Logging is not active");
    return -1;
  }

  dbh->logging.active = 0;
  return 0;
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}


/** Replay journal file.
 *
 * Requires exclusive access to the database.
 * Marks the log as clean, but does not re-initialize the file.
 *
 * Returns 0 on success
 * Returns -1 on non-fatal error (database unmodified)
 * Returns -2 on fatal error (database inconsistent)
 */
gint wg_replay_log(void *db, char *filename)
{
#ifdef USE_DBLOG
  db_memsegment_header* dbh = dbmemsegh(db);
  gint active, err = 0;
  void *tran_tbl;
  int fd;
  FILE *f;

#ifndef _WIN32
  if((fd = open(filename, O_RDONLY)) == -1) {
#else
  if(_sopen_s(&fd, filename, _O_RDONLY|_O_BINARY, _SH_DENYNO, 0)) {
#endif
    show_log_error(db, "Error opening log file");
    return -1;
  }

  if(check_journal(db, fd)) {
    err = -1;
    goto abort2;
  }

  active = dbh->logging.active;
  dbh->logging.active = 0; /* turn logging off before restoring */

  /* Reading can be done with buffered IO */
#ifndef _WIN32
  f = fdopen(fd, "r");
#else
  f = _fdopen(fd, "rb");
#endif
  /* XXX: may consider fcntl-locking here */
  /* restore the log contents */
  tran_tbl = wg_ginthash_init(db);
  if(!tran_tbl) {
    show_log_error(db, "Failed to create log translation table");
    err = -1;
    goto abort1;
  }
  if(recover_journal(db, f, tran_tbl)) {
    err = -2;
    goto abort0;
  }

  dbh->logging.dirty = 0; /* on success, set the log as clean. */

abort0:
  wg_ginthash_free(db, tran_tbl);

abort1:
  fclose(f);

abort2:
  if(!err && active) {
    if(wg_start_logging(db)) {
      show_log_error(db, "Log restored but failed to reactivate logging");
      err = -2;
    }
  }

  return err;
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

#ifdef USE_DBLOG
/** Write a byte buffer to the log file.
 *
 */
static gint write_log_buffer(void *db, void *buf, int buflen)
{
  db_memsegment_header* dbh = dbmemsegh(db);
  db_handle_logdata *ld = \
    (db_handle_logdata *) (((db_handle *) db)->logdata);

  if(ld->fd >= 0 && ld->serial != dbh->logging.serial) {
    /* Stale file descriptor, get a new one */
#ifndef _WIN32
    close(ld->fd);
#else
    _close(ld->fd);
#endif
    ld->fd = -1;
  }
  if(ld->fd < 0) {
    int fd;
    if((fd = open_journal(db, 0)) == -1) {
      show_log_error(db, "Error opening log file");
    } else {
      if(check_journal(db, fd)) {
#ifndef _WIN32
        close(fd);
#else
        _close(fd);
#endif
      } else {
        /* fseek(f, 0, SEEK_END); */
        ld->fd = fd;
        ld->serial = dbh->logging.serial;
      }
    }
  }
  if(ld->fd < 0)
    return -1;

  /* Always mark log as dirty when writing something */
  dbh->logging.dirty = 1;

#ifndef _WIN32
  if(write(ld->fd, (char *) buf, buflen) != buflen) {
#else
  if(_write(ld->fd, (char *) buf, buflen) != buflen) {
#endif
    show_log_error(db, "Error writing to log file");
    JOURNAL_FAIL(ld->fd, -5)
  }

  return 0;
}
#endif /* USE_DBLOG */

/*
 * Operations (and data) logged:
 *
 * WG_JOURNAL_ENTRY_CRE - create a record (length)
 *   followed by a single varint field that contains the newly allocated offset
 * WG_JOURNAL_ENTRY_DEL - delete a record (offset)
 * WG_JOURNAL_ENTRY_ENC - encode a value (data bytes, extdata if applicable)
 *   followed by a single varint field that contains the encoded value
 * WG_JOURNAL_ENTRY_SET - set a field value (record offset, column, encoded value)
 * WG_JOURNAL_ENTRY_META - set the metadata of a record
 *
 * lengths, offsets and encoded values are stored as varints
 */

/** Log the creation of a record.
 *  This call should always be followed by wg_log_encval()
 *
 *  We assume that dbh->logging.active flag is checked before calling this.
 */
gint wg_log_create_record(void *db, gint length)
{
#ifdef USE_DBLOG
  unsigned char buf[1 + VARINT_SIZE], *optr;
  buf[0] = WG_JOURNAL_ENTRY_CRE;
  optr = &buf[1];
  optr += enc_varint(optr, (wg_uint) length);
  return write_log_buffer(db, (void *) buf, optr - buf);
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

/** Log the deletion of a record.
 *
 */
gint wg_log_delete_record(void *db, gint enc)
{
#ifdef USE_DBLOG
  unsigned char buf[1 + VARINT_SIZE], *optr;
  buf[0] = WG_JOURNAL_ENTRY_DEL;
  optr = &buf[1];
  optr += enc_varint(optr, (wg_uint) enc);
  return write_log_buffer(db, (void *) buf, optr - buf);
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

/** Log the result of an encode operation. Also handles records.
 *
 *  If the encode function or record creation failed, call this
 *  with WG_ILLEGAL to indicate the failure of the operation.
 */
gint wg_log_encval(void *db, gint enc)
{
#ifdef USE_DBLOG
  unsigned char buf[VARINT_SIZE];
  size_t buflen = enc_varint(buf, (wg_uint) enc);
  return write_log_buffer(db, (void *) buf, buflen);
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

/** Log an encode operation.
 *
 * This is the most expensive log operation as we need to write the
 * chunk of data to be encoded.
 */
gint wg_log_encode(void *db, gint type, void *data, gint length,
  void *extdata, gint extlength)
{
#ifdef USE_DBLOG
  unsigned char *buf, *optr, *oend, *iptr;
  size_t buflen = 0;
  int err;

  switch(type) {
    case WG_NULLTYPE:
    case WG_RECORDTYPE:
    case WG_CHARTYPE:
    case WG_DATETYPE:
    case WG_TIMETYPE:
    case WG_VARTYPE:
    case WG_FIXPOINTTYPE:
      /* Shared memory not altered, don't log */
      return 0;
      break;
    case WG_INTTYPE:
      /* int argument */
      if(fits_smallint(*((int *) data))) {
        return 0; /* self-contained, don't log */
      } else {
        buflen = 1 + sizeof(int);
        buf = (unsigned char *) malloc(buflen);
        optr = buf + 1;
        *((int *) optr) = *((int *) data);
      }
      break;
    case WG_DOUBLETYPE:
      /* double precision argument */
      buflen = 1 + sizeof(double);
      buf = (unsigned char *) malloc(buflen);
      optr = buf + 1;
      *((double *) optr) = *((double *) data);
      break;
    case WG_STRTYPE:
    case WG_URITYPE:
    case WG_XMLLITERALTYPE:
    case WG_ANONCONSTTYPE:
    case WG_BLOBTYPE: /* XXX: no encode func for this yet */
      /* strings with extdata */
      buflen = 1 + 2*VARINT_SIZE + length + extlength;
      buf = (unsigned char *) malloc(buflen);

      /* data and extdata length */
      optr = buf + 1;
      optr += enc_varint(optr, (wg_uint) length);
      optr += enc_varint(optr, (wg_uint) extlength);
      buflen -= 1 + 2*VARINT_SIZE - (optr - buf); /* actual size known */

      /* data */
      oend = optr + length;
      iptr = (unsigned char *) data;
      while(optr < oend) *(optr++) = *(iptr++);

      /* extdata */
      oend = optr + extlength;
      iptr = (unsigned char *) extdata;
      while(optr < oend) *(optr++) = *(iptr++);
      break;
    default:
      return show_log_error(db, "Unsupported data type");
  }

  /* Add a fixed prefix */
  buf[0] = WG_JOURNAL_ENTRY_ENC | type;

  err = write_log_buffer(db, (void *) buf, buflen);
  free(buf);
  return err;
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

/** Log setting a data field.
 *
 *  We assume that dbh->logging.active flag is checked before calling this.
 */
gint wg_log_set_field(void *db, void *rec, gint col, gint data)
{
#ifdef USE_DBLOG
  unsigned char buf[1 + 3*VARINT_SIZE], *optr;
  buf[0] = WG_JOURNAL_ENTRY_SET;
  optr = &buf[1];
  optr += enc_varint(optr, (wg_uint) ptrtooffset(db, rec));
  optr += enc_varint(optr, (wg_uint) col);
  optr += enc_varint(optr, (wg_uint) data);
  return write_log_buffer(db, (void *) buf, optr - buf);
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}

/** Log setting metadata
 *
 *  We assume that dbh->logging.active flag is checked before calling this.
 */
gint wg_log_set_meta(void *db, void *rec, gint meta)
{
#ifdef USE_DBLOG
  unsigned char buf[1 + 2*VARINT_SIZE], *optr;
  buf[0] = WG_JOURNAL_ENTRY_META;
  optr = &buf[1];
  optr += enc_varint(optr, (wg_uint) ptrtooffset(db, rec));
  optr += enc_varint(optr, (wg_uint) meta);
  return write_log_buffer(db, (void *) buf, optr - buf);
#else
  return show_log_error(db, "Logging is disabled");
#endif /* USE_DBLOG */
}


/* ------------ error handling ---------------- */

static gint show_log_error(void *db, char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg log error: %s.\n", errmsg);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Andri Rebane 2009, Priit Järv 2009,2010,2013,2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbdump.c
 *  DB dumping support for WhiteDB memory database
 *
 */

/* ====== Includes =============== */

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//mem.h"
//lock.h"
//log.h"

/* ====== Private headers and defs ======== */

//dump.h"
//c1.h"

/* ======= Private protos ================ */


static gint show_dump_error(void *db, char *errmsg);
static gint show_dump_error_str(void *db, char *errmsg, char *str);


/* ====== Functions ============== */


/** dump shared memory to the disk.
 *  Returns 0 when successful (no error).
 *  -1 non-fatal error (db may continue)
 *  -2 fatal error (should abort db)
 *  This function is parallel-safe (may run during normal db usage)
 */

gint wg_dump(void * db,char fileName[]) {
  return wg_dump_internal(db, fileName, 1);
}

/** Handle the actual dumping (called by the API wrapper)
 *  if locking is non-zero, properly acquire locks on the database.
 *  Otherwise do a rescue dump by copying the memory image without locking.
 */
gint wg_dump_internal(void * db, char fileName[], int locking) {
  FILE *f;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint dbsize = dbh->free; /* first unused offset - 0 = db size */
#ifdef USE_DBLOG
  gint active;
#endif
  gint err = -1;
  gint lock_id = 0;
  gint32 crc;

#ifdef CHECK
  if(dbh->extdbs.count != 0) {
    show_dump_error(db, "Database contains external references");
  }
#endif

  /* Open the dump file */
#ifdef _WIN32
  if(fopen_s(&f, fileName, "wb")) {
#else
  if(!(f = fopen(fileName, "wb"))) {
#endif
    show_dump_error(db, "Error opening file");
    return -1;
  }

#ifndef USE_DBLOG
  /* Get shared lock on the db */
  if(locking) {
    lock_id = db_rlock(db, DEFAULT_LOCK_TIMEOUT);
    if(!lock_id) {
      show_dump_error(db, "Failed to lock the database for dump");
      return -1;
    }
  }
#else
  /* Get exclusive lock on the db, we need to modify the logging area */
  if(locking) {
    lock_id = db_wlock(db, DEFAULT_LOCK_TIMEOUT);
    if(!lock_id) {
      show_dump_error(db, "Failed to lock the database for dump");
      return -1;
    }
  }

  active = dbh->logging.active;
  if(active) {
    wg_stop_logging(db);
  }
#endif

  /* Compute the CRC32 of the used area */
  crc = update_crc32(dbmemsegbytes(db), dbsize, 0x0);

  /* Now, write the memory area to file */
  if(fwrite(dbmemseg(db), dbsize, 1, f) == 1) {
    /* Overwrite checksum field */
    fseek(f, ptrtooffset(db, &(dbh->checksum)), SEEK_SET);
    if(fwrite(&crc, sizeof(gint32), 1, f) == 1) {
      err = 0;
    }
  }

  if(err)
    show_dump_error(db, "Error writing file");

#ifndef USE_DBLOG
  /* We're done writing */
  if(locking) {
    if(!db_rulock(db, lock_id)) {
      show_dump_error(db, "Failed to unlock the database");
      err = -2; /* This error should be handled as fatal */
    }
  }
#else
  /* restart logging */
  if(active) {
    dbh->logging.dirty = 0;
    if(wg_start_logging(db)) {
      err = -2; /* Failed to re-initialize log */
    }
  }

  if(locking) {
    if(!db_wulock(db, lock_id)) {
      show_dump_error(db, "Failed to unlock the database");
      err = -2; /* Write lock failure --> fatal */
    }
  }
#endif

  fflush(f);
  fclose(f);

  return err;
}


/* This has to be large enough to hold all the relevant
 * fields in the header during the first pass of the read.
 * (Currently this is the first 24 bytes of the dump file)
 */
#define BUFSIZE 8192

/** Check dump file for compatibility and errors.
 *  Returns 0 when successful (no error).
 *  -1 on system error (cannot open file, no memory)
 *  -2 header is incompatible
 *  -3 on file integrity error (size mismatch, CRC32 error).
 *
 *  Sets minsize to minimum required segment size and maxsize
 *  to original memory image size if check was successful. Otherwise
 *  the contents of these variables may be undefined.
 */
gint wg_check_dump(void *db, char fileName[], gint *minsize, gint *maxsize) {
  char *buf;
  FILE *f;
  gint len, filesize;
  gint32 crc, dump_crc;
  gint err = -1;

  /* Attempt to open the dump file */
#ifdef _WIN32
  if(fopen_s(&f, fileName, "rb")) {
#else
  if(!(f = fopen(fileName, "rb"))) {
#endif
    show_dump_error(db, "Error opening file");
    return -1;
  }

  buf = (char *) malloc(BUFSIZE);
  if(!buf) {
    show_dump_error(db, "malloc error in wg_import_dump");
    goto abort1;
  }

  /* First pass of reading. Examine the header. */
  if(fread(buf, BUFSIZE, 1, f) != 1) {
    show_dump_error(db, "Error reading dump header");
    goto abort2;
  }

  if(wg_check_header_compat((db_memsegment_header *) buf)) {
    show_dump_error_str(db, "Incompatible dump file", fileName);
    wg_print_code_version();
    wg_print_header_version((db_memsegment_header *) buf, 1);
    err = -2;
    goto abort2;
  }

  *minsize = ((db_memsegment_header *) buf)->free;
  *maxsize = ((db_memsegment_header *) buf)->size;

  /* Now check file integrity. */
  dump_crc = ((db_memsegment_header *) buf)->checksum;
  ((db_memsegment_header *) buf)->checksum = 0;
  len = BUFSIZE;
  filesize = 0;
  crc = 0;
  do {
    filesize += len;
    crc = update_crc32(buf, len, crc);
  } while((len=fread(buf,1,BUFSIZE,f)) > 0);

  if(filesize != *minsize) {
    show_dump_error_str(db, "File size incorrect", fileName);
    err = -3;
  }
  else if(crc != dump_crc) {
    show_dump_error_str(db, "File CRC32 incorrect", fileName);
    err = -3;
  }
  else
    err = 0;

abort2:
  free(buf);
abort1:
  fclose(f);

  return err;
}


/** Import database dump from disk.
 *  Returns 0 when successful (no error).
 *  -1 non-fatal error (db may continue)
 *  -2 fatal error (should abort db)
 *
 *  this function is NOT parallel-safe. Other processes accessing
 *  db concurrently may cause undefined behaviour (including data loss)
 */
gint wg_import_dump(void * db,char fileName[]) {
  db_memsegment_header* dumph;
  FILE *f;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint dbsize = -1, newsize;
  gint err = -1;
#ifdef USE_DBLOG
  gint active = dbh->logging.active;
#endif


  /* Attempt to open the dump file */
#ifdef _WIN32
  if(fopen_s(&f, fileName, "rb")) {
#else
  if(!(f = fopen(fileName, "rb"))) {
#endif
    show_dump_error(db, "Error opening file");
    return -1;
  }

  /* Examine the dump header. We only read the size, it is
   * implied that the integrity and compatibility were verified
   * earlier.
   */
  dumph = (db_memsegment_header *) malloc(sizeof(db_memsegment_header));
  if(!dumph) {
    show_dump_error(db, "malloc error in wg_import_dump");
  }
  else if(fread(dumph, sizeof(db_memsegment_header), 1, f) != 1) {
    show_dump_error(db, "Error reading dump header");
  }
  else {
    dbsize = dumph->free;
    if(dumph->extdbs.count != 0) {
      show_dump_error(db, "Dump contains external references");
      goto abort;
    }
  }
  if(dumph) free(dumph);

  /* 0 > dbsize >= dbh->size indicates that we were able to read the dump
   * and it contained a memory image that fits in our current shared memory.
   */
  if(dbh->size < dbsize) {
    show_dump_error(db, "Data does not fit in shared memory area");
  } else if(dbsize > 0) {
    /* We have a compatible dump file. */
    newsize = dbh->size;
    fseek(f, 0, SEEK_SET);
    if(fread(dbmemseg(db), dbsize, 1, f) != 1) {
      show_dump_error(db, "Error reading dump file");
      err = -2; /* database is in undetermined state now */
    } else {
      err = 0;
      dbh->size = newsize;
      dbh->checksum = 0;
    }
  }

abort:
  fclose(f);

  /* any errors up to now? */
  if(err) return err;

  /* Initialize db state */
#ifdef USE_DBLOG
  /* restart logging */
  dbh->logging.dirty = 0;
  dbh->logging.active = 0;
  if(active) { /* state inherited from memory */
    if(wg_start_logging(db)) {
      return -2; /* Failed to re-initialize log */
    }
  }
#endif
  return wg_init_locks(db);
}

/* ------------ error handling ---------------- */

static gint show_dump_error(void *db, char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg dump error: %s.\n", errmsg);
#endif
  return -1;

}

static gint show_dump_error_str(void *db, char *errmsg, char *str) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg dump error: %s: %s.\n", errmsg, str);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Tanel Tammet 2004,2005,2006,2007,2008,2009
* Copyright (c) Priit Järv 2013,2014
*
* Contact: tanel.tammet@gmail.com
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbhash.c
 *  Hash operations for strings and other datatypes.
 *
 *
 */

/* ====== Includes =============== */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//hash.h"
//data.h"
//mpool.h"


/* ====== Private headers and defs ======== */

/* Bucket capacity > 1 reduces the impact of collisions */
#define GINTHASH_BUCKETCAP 7

/* Level 24 hash consumes approx 640MB with bucket capacity 3 on 32-bit
 * architecture and about twice as much on 64-bit systems. With bucket
 * size increased to 7 (which is more space efficient due to imperfect
 * hash distribution) we can reduce the level by 1 for the same space
 * requirements.
 */
#define GINTHASH_MAXLEVEL 23

/* rehash keys (useful for lowering the impact of bad distribution) */
#define GINTHASH_SCRAMBLE(v) (rehash_gint(v))
/*#define GINTHASH_SCRAMBLE(v) (v)*/

typedef struct {
  gint level;                         /* local level */
  gint fill;                          /* slots filled / next slot index */
  gint key[GINTHASH_BUCKETCAP + 1];   /* includes one overflow slot */
  gint value[GINTHASH_BUCKETCAP + 1];
} ginthash_bucket;

/* Dynamic local memory hashtable for gint key/value pairs. Resize
 * is handled using the extendible hashing algorithm.
 * Note: we don't use 0-level hash, so buckets[0] is unused.
 */
typedef struct {
  gint level;                  /* global level */
  ginthash_bucket **directory; /* bucket pointers, contiguous memory */
  void *mpool;                 /* dbmpool storage */
} ext_ginthash;

/* Static local memory hash table for existence tests (double hashing) */
typedef struct {
  size_t dhash_size;
  gint *keys;
} dhash_table;

#ifdef HAVE_64BIT_GINT
#define FNV_offset_basis ((wg_uint) 14695981039346656037ULL)
#define FNV_prime ((wg_uint) 1099511628211ULL)
#else
#define FNV_offset_basis ((wg_uint) 2166136261UL)
#define FNV_prime ((wg_uint) 16777619UL)
#endif

/* ======= Private protos ================ */



// static gint show_consistency_error(void* db, char* errmsg);
static gint show_consistency_error_nr(void* db, char* errmsg, gint nr) ;
// static gint show_consistency_error_double(void* db, char* errmsg, double nr);
// static gint show_consistency_error_str(void* db, char* errmsg, char* str);
static gint show_hash_error(void* db, char* errmsg);
static gint show_ginthash_error(void *db, char* errmsg);

static wg_uint hash_bytes(void *db, char *data, gint length, gint hashsz);
static gint find_idxhash_bucket(void *db, char *data, gint length,
  gint *chainoffset);

static gint rehash_gint(gint val);
static gint grow_ginthash(void *db, ext_ginthash *tbl);
static ginthash_bucket *ginthash_newbucket(void *db, ext_ginthash *tbl);
static ginthash_bucket *ginthash_splitbucket(void *db, ext_ginthash *tbl,
  ginthash_bucket *bucket);
static gint add_to_bucket(ginthash_bucket *bucket, gint key, gint value);
static gint remove_from_bucket(ginthash_bucket *bucket, int idx);

/* ====== Functions ============== */


/* ------------- strhash operations ------------------- */




/* Hash function for two-part strings and blobs.
*
* Based on sdbm.
*
*/

int wg_hash_typedstr(void* db, char* data, char* extrastr, gint type, gint length) {
  char* endp;
  unsigned long hash = 0;
  int c;

  //printf("in wg_hash_typedstr %s %s %d %d \n",data,extrastr,type,length);
  if (data!=NULL) {
    for(endp=data+length; data<endp; data++) {
      c = (int)(*data);
      hash = c + (hash << 6) + (hash << 16) - hash;
    }
  }
  if (extrastr!=NULL) {
    while ((c = *extrastr++))
      hash = c + (hash << 6) + (hash << 16) - hash;
  }

  return (int)(hash % (dbmemsegh(db)->strhash_area_header).arraylength);
}



/* Find longstr from strhash bucket chain
*
*
*/

gint wg_find_strhash_bucket(void* db, char* data, char* extrastr, gint type, gint size, gint hashchain) {
  //printf("wg_find_strhash_bucket called %s %s type %d size %d hashchain %d\n",data,extrastr,type,size,hashchain);
  for(;hashchain!=0;
      hashchain=dbfetch(db,decode_longstr_offset(hashchain)+LONGSTR_HASHCHAIN_POS*sizeof(gint))) {
    if (wg_right_strhash_bucket(db,hashchain,data,extrastr,type,size)) {
      // found equal longstr, return it
      //printf("wg_find_strhash_bucket found hashchain %d\n",hashchain);
      return hashchain;
    }
  }
  return 0;
}

/* Check whether longstr hash bucket matches given new str
*
*
*/

int wg_right_strhash_bucket
            (void* db, gint longstr, char* cstr, char* cextrastr, gint ctype, gint cstrsize) {
  char* str;
  char* extrastr;
  int strsize;
  gint type;
  //printf("wg_right_strhash_bucket called with %s %s type %d size %d\n",
  //              cstr,cextrastr,ctype,cstrsize);
  type=wg_get_encoded_type(db,longstr);
  if (type!=ctype) return 0;
  strsize=wg_decode_str_len(db,longstr)+1;
  if (strsize!=cstrsize) return 0;
  str=wg_decode_str(db,longstr);
  if ((cstr==NULL && str!=NULL) || (cstr!=NULL && str==NULL)) return 0;
  if ((cstr!=NULL) && (memcmp(str,cstr,cstrsize))) return 0;
  extrastr=wg_decode_str_lang(db,longstr);
  if ((cextrastr==NULL && extrastr!=NULL) || (cextrastr!=NULL && extrastr==NULL)) return 0;
  if ((cextrastr!=NULL) && (strcmp(extrastr,cextrastr))) return 0;
  return 1;
}

/* Remove longstr from strhash
*
*  Internal langstr etc are not removed by this op.
*
*/

gint wg_remove_from_strhash(void* db, gint longstr) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint type;
  gint* extrastrptr;
  char* extrastr;
  char* data;
  gint length;
  gint hash;
  gint chainoffset;
  gint hashchain;
  gint nextchain;
  gint offset;
  gint* objptr;
  gint fldval;
  gint objsize;
  gint strsize;
  gint* typeptr;

  //printf("wg_remove_from_strhash called on %d\n",longstr);
  //wg_debug_print_value(db,longstr);
  //printf("\n\n");
  offset=decode_longstr_offset(longstr);
  objptr=(gint*) offsettoptr(db,offset);
  // get string data elements
  //type=objptr=offsettoptr(db,decode_longstr_offset(data));
  extrastrptr=(gint *) (((char*)(objptr))+(LONGSTR_EXTRASTR_POS*sizeof(gint)));
  fldval=*extrastrptr;
  if (fldval==0) extrastr=NULL;
  else extrastr=wg_decode_str(db,fldval);
  data=((char*)(objptr))+(LONGSTR_HEADER_GINTS*sizeof(gint));
  objsize=getusedobjectsize(*objptr);
  strsize=objsize-(((*(objptr+LONGSTR_META_POS))&LONGSTR_META_LENDIFMASK)>>LONGSTR_META_LENDIFSHFT);
  length=strsize;
  typeptr=(gint*)(((char*)(objptr))+(+LONGSTR_META_POS*sizeof(gint)));
  type=(*typeptr)&LONGSTR_META_TYPEMASK;
  //type=wg_get_encoded_type(db,longstr);
  // get hash of data elements and find the location in hashtable/chains
  hash=wg_hash_typedstr(db,data,extrastr,type,length);
  chainoffset=((dbh->strhash_area_header).arraystart)+(sizeof(gint)*hash);
  hashchain=dbfetch(db,chainoffset);
  while(hashchain!=0) {
    if (hashchain==longstr) {
      nextchain=dbfetch(db,decode_longstr_offset(hashchain)+(LONGSTR_HASHCHAIN_POS*sizeof(gint)));
      dbstore(db,chainoffset,nextchain);
      return 0;
    }
    chainoffset=decode_longstr_offset(hashchain)+(LONGSTR_HASHCHAIN_POS*sizeof(gint));
    hashchain=dbfetch(db,chainoffset);
  }
  show_consistency_error_nr(db,"string not found in hash during deletion, offset",offset);
  return -1;
}


/* -------------- hash index support ------------------ */

#define CONCAT_FOR_HASHING(d, b, e, l, bb, en) \
  if(e) { \
    gint xl = wg_decode_xmlliteral_xsdtype_len(d, en); \
    bb = malloc(xl + l + 1); \
    if(!bb) \
      return 0; \
    memcpy(bb, e, xl); \
    bb[xl] = '\0'; \
    memcpy(bb + xl + 1, b, l); \
    b = bb; \
    l += xl + 1; \
  }

/*
 * Return an encoded value as a decoded byte array.
 * It should be freed afterwards.
 * returns the number of bytes in the array.
 * returns 0 if the decode failed.
 *
 * NOTE: to differentiate between identical byte strings
 * the value is prefixed with a type identifier.
 * TODO: For values with varying length that can contain
 * '\0' bytes, add length to the prefix.
 */
gint wg_decode_for_hashing(void *db, gint enc, char **decbytes) {
  gint len;
  gint type;
  gint ptrdata;
  int intdata;
  double doubledata;
  char *bytedata;
  char *exdata, *buf = NULL, *outbuf;

  type = wg_get_encoded_type(db, enc);
  switch(type) {
    case WG_NULLTYPE:
      len = sizeof(gint);
      ptrdata = 0;
      bytedata = (char *) &ptrdata;
      break;
    case WG_RECORDTYPE:
      len = sizeof(gint);
      ptrdata = enc;
      bytedata = (char *) &ptrdata;
      break;
    case WG_INTTYPE:
      len = sizeof(int);
      intdata = wg_decode_int(db, enc);
      bytedata = (char *) &intdata;
      break;
    case WG_DOUBLETYPE:
      len = sizeof(double);
      doubledata = wg_decode_double(db, enc);
      bytedata = (char *) &doubledata;
      break;
    case WG_FIXPOINTTYPE:
      len = sizeof(double);
      doubledata = wg_decode_fixpoint(db, enc);
      bytedata = (char *) &doubledata;
      break;
    case WG_STRTYPE:
      len = wg_decode_str_len(db, enc);
      bytedata = wg_decode_str(db, enc);
      break;
    case WG_URITYPE:
      len = wg_decode_uri_len(db, enc);
      bytedata = wg_decode_uri(db, enc);
      exdata = wg_decode_uri_prefix(db, enc);
      CONCAT_FOR_HASHING(db, bytedata, exdata, len, buf, enc)
      break;
    case WG_XMLLITERALTYPE:
      len = wg_decode_xmlliteral_len(db, enc);
      bytedata = wg_decode_xmlliteral(db, enc);
      exdata = wg_decode_xmlliteral_xsdtype(db, enc);
      CONCAT_FOR_HASHING(db, bytedata, exdata, len, buf, enc)
      break;
    case WG_CHARTYPE:
      len = sizeof(int);
      intdata = wg_decode_char(db, enc);
      bytedata = (char *) &intdata;
      break;
    case WG_DATETYPE:
      len = sizeof(int);
      intdata = wg_decode_date(db, enc);
      bytedata = (char *) &intdata;
      break;
    case WG_TIMETYPE:
      len = sizeof(int);
      intdata = wg_decode_time(db, enc);
      bytedata = (char *) &intdata;
      break;
    case WG_VARTYPE:
      len = sizeof(int);
      intdata = wg_decode_var(db, enc);
      bytedata = (char *) &intdata;
      break;
    case WG_ANONCONSTTYPE:
      /* Ignore anonconst */
    default:
      return 0;
  }

  /* Form the hashable buffer. It is not 0-terminated */
  outbuf = malloc(len + 1);
  if(outbuf) {
    outbuf[0] = (char) type;
    memcpy(outbuf + 1, bytedata, len++);
    *decbytes = outbuf;
  } else {
    /* Indicate failure */
    len = 0;
  }

  if(buf)
    free(buf);
  return len;
}

/*
 * Calculate a hash for a byte buffer. Truncates the hash to given size.
 */
static wg_uint hash_bytes(void *db, char *data, gint length, gint hashsz) {
  char* endp;
  wg_uint hash = 0;

  if (data!=NULL) {
    for(endp=data+length; data<endp; data++) {
      hash = *data + (hash << 6) + (hash << 16) - hash;
    }
  }
  return hash % hashsz;
}

/*
 * Finds a matching bucket in hash chain.
 * chainoffset should point to the offset storing the chain head.
 * If the call is successful, it will point to the offset storing
 * the matching bucket.
 */
static gint find_idxhash_bucket(void *db, char *data, gint length,
  gint *chainoffset)
{
  gint bucket = dbfetch(db, *chainoffset);
  while(bucket) {
    gint meta = dbfetch(db, bucket + HASHIDX_META_POS*sizeof(gint));
    if(meta == length) {
      /* Currently, meta stores just size */
      char *bucket_data = offsettoptr(db, bucket + \
        HASHIDX_HEADER_SIZE*sizeof(gint));
      if(!memcmp(bucket_data, data, length))
        return bucket;
    }
    *chainoffset = bucket + HASHIDX_HASHCHAIN_POS*sizeof(gint);
    bucket = dbfetch(db, *chainoffset);
  }
  return 0;
}

/*
 * Store a hash string and an offset to the index hash.
 * Based on longstr hash, with some simplifications.
 *
 * Returns 0 on success
 * Returns -1 on error.
 */
gint wg_idxhash_store(void* db, db_hash_area_header *ha,
  char* data, gint length, gint offset)
{
  db_memsegment_header* dbh = dbmemsegh(db);
  wg_uint hash;
  gint head_offset, head, bucket;
  gint rec_head, rec_offset;
  gcell *rec_cell;

  hash = hash_bytes(db, data, length, ha->arraylength);
  head_offset = (ha->arraystart)+(sizeof(gint) * hash);
  head = dbfetch(db, head_offset);

  /* Traverse the hash chain to check if there is a matching
   * hash string already
   */
  bucket = find_idxhash_bucket(db, data, length, &head_offset);
  if(!bucket) {
    size_t i;
    gint lengints, lenrest;
    char* dptr;

    /* Make a new bucket */
    lengints = length / sizeof(gint);
    lenrest = length % sizeof(gint);
    if(lenrest) lengints++;
    bucket = wg_alloc_gints(db,
         &(dbh->indexhash_area_header),
        lengints + HASHIDX_HEADER_SIZE);
    if(!bucket) {
      return -1;
    }

    /* Copy the byte data */
    dptr = (char *) (offsettoptr(db,
      bucket + HASHIDX_HEADER_SIZE*sizeof(gint)));
    memcpy(dptr, data, length);
    for(i=0;lenrest && i<sizeof(gint)-lenrest;i++) {
      *(dptr + length + i)=0; /* XXX: since we have the length, in meta,
                               * this is possibly unnecessary. */
    }

    /* Metadata */
    dbstore(db, bucket + HASHIDX_META_POS*sizeof(gint), length);
    dbstore(db, bucket + HASHIDX_RECLIST_POS*sizeof(gint), 0);

    /* Prepend to hash chain */
    dbstore(db, ((ha->arraystart)+(sizeof(gint) * hash)), bucket);
    dbstore(db, bucket + HASHIDX_HASHCHAIN_POS*sizeof(gint), head);
  }

  /* Add the record offset to the list. */
  rec_head = dbfetch(db, bucket + HASHIDX_RECLIST_POS*sizeof(gint));
  rec_offset = wg_alloc_fixlen_object(db, &(dbh->listcell_area_header));
  rec_cell = (gcell *) offsettoptr(db, rec_offset);
  rec_cell->car = offset;
  rec_cell->cdr = rec_head;
  dbstore(db, bucket + HASHIDX_RECLIST_POS*sizeof(gint), rec_offset);

  return 0;
}

/*
 * Remove an offset from the index hash.
 *
 * Returns 0 on success
 * Returns -1 on error.
 */
gint wg_idxhash_remove(void* db, db_hash_area_header *ha,
  char* data, gint length, gint offset)
{
  wg_uint hash;
  gint bucket_offset, bucket;
  gint *next_offset, *reclist_offset;

  hash = hash_bytes(db, data, length, ha->arraylength);
  bucket_offset = (ha->arraystart)+(sizeof(gint) * hash); /* points to head */

  /* Find the correct bucket. */
  bucket = find_idxhash_bucket(db, data, length, &bucket_offset);
  if(!bucket) {
    return show_hash_error(db, "wg_idxhash_remove: Hash value not found.");
  }

  /* Remove the record offset from the list. */
  reclist_offset = offsettoptr(db, bucket + HASHIDX_RECLIST_POS*sizeof(gint));
  next_offset = reclist_offset;
  while(*next_offset) {
    gcell *rec_cell = (gcell *) offsettoptr(db, *next_offset);
    if(rec_cell->car == offset) {
      gint rec_offset = *next_offset;
      *next_offset = rec_cell->cdr; /* remove from list chain */
      wg_free_listcell(db, rec_offset); /* free storage */
      goto is_bucket_empty;
    }
    next_offset = &(rec_cell->cdr);
  }
  return show_hash_error(db, "wg_idxhash_remove: Offset not found");

is_bucket_empty:
  if(!(*reclist_offset)) {
    gint nextchain = dbfetch(db, bucket + HASHIDX_HASHCHAIN_POS*sizeof(gint));
    dbstore(db, bucket_offset, nextchain);
    wg_free_object(db, &(dbmemsegh(db)->indexhash_area_header), bucket);
  }

  return 0;
}

/*
 * Retrieve the list of matching offsets from the hash.
 *
 * Returns the offset to head of the linked list.
 * Returns 0 if value was not found.
 */
gint wg_idxhash_find(void* db, db_hash_area_header *ha,
  char* data, gint length)
{
  wg_uint hash;
  gint head_offset, bucket;

  hash = hash_bytes(db, data, length, ha->arraylength);
  head_offset = (ha->arraystart)+(sizeof(gint) * hash); /* points to head */

  /* Find the correct bucket. */
  bucket = find_idxhash_bucket(db, data, length, &head_offset);
  if(!bucket)
    return 0;

  return dbfetch(db, bucket + HASHIDX_RECLIST_POS*sizeof(gint));
}

/* ------- local-memory extendible gint hash ---------- */

/*
 * Dynamically growing gint hash.
 *
 * Implemented in local memory for temporary usage (database memory is not well
 * suited as it is not resizable). Uses the extendible hashing algorithm
 * proposed by Fagin et al '79 as this allows the use of simple, easily
 * disposable data structures.
 */

/** Initialize the hash table.
 *  The initial hash level is 1.
 *  returns NULL on failure.
 */
void *wg_ginthash_init(void *db) {
  ext_ginthash *tbl = malloc(sizeof(ext_ginthash));
  if(!tbl) {
    show_ginthash_error(db, "Failed to allocate table.");
    return NULL;
  }

  memset(tbl, 0, sizeof(ext_ginthash));
  if(grow_ginthash(db, tbl)) { /* initial level is set to 1 */
    free(tbl);
    return NULL;
  }
  return tbl;
}

/** Add a key/value pair to the hash table.
 *  tbl should be created with wg_ginthash_init()
 *  Returns 0 on success
 *  Returns -1 on failure
 */
gint wg_ginthash_addkey(void *db, void *tbl, gint key, gint val) {
  size_t dirsize = 1<<((ext_ginthash *)tbl)->level;
  size_t hash = GINTHASH_SCRAMBLE(key) & (dirsize - 1);
  ginthash_bucket *bucket = ((ext_ginthash *)tbl)->directory[hash];
  /*static gint keys = 0;*/
  /* printf("add: %d hash %d items %d\n", key, hash, ++keys); */
  if(!bucket) {
    /* allocate a new bucket, store value, we're done */
    bucket = ginthash_newbucket(db, (ext_ginthash *) tbl);
    if(!bucket)
      return -1;
    bucket->level = ((ext_ginthash *) tbl)->level;
    add_to_bucket(bucket, key, val); /* Always fits, no check needed */
    ((ext_ginthash *)tbl)->directory[hash] = bucket;
  }
  else {
    add_to_bucket(bucket, key, val);
    while(bucket->fill > GINTHASH_BUCKETCAP) {
      ginthash_bucket *newb;
      /* Overflow, bucket split needed. */
      if(!(newb = ginthash_splitbucket(db, (ext_ginthash *)tbl, bucket)))
        return -1;
      /* Did everything flow to the new bucket, causing another overflow? */
      if(newb->fill > GINTHASH_BUCKETCAP) {
        bucket = newb; /* Keep splitting */
      }
    }
  }
  return 0;
}

/** Fetch a value from the hash table.
 *  If the value is not found, returns -1 (val is unmodified).
 *  Otherwise returns 0; contents of val is replaced with the
 *  value from the hash table.
 */
gint wg_ginthash_getkey(void *db, void *tbl, gint key, gint *val) {
  size_t dirsize = 1<<((ext_ginthash *)tbl)->level;
  size_t hash = GINTHASH_SCRAMBLE(key) & (dirsize - 1);
  ginthash_bucket *bucket = ((ext_ginthash *)tbl)->directory[hash];
  if(bucket) {
    int i;
    for(i=0; i<bucket->fill; i++) {
      if(bucket->key[i] == key) {
        *val = bucket->value[i];
        return 0;
      }
    }
  }
  return -1;
}

/** Release all memory allocated for the hash table.
 *
 */
void wg_ginthash_free(void *db, void *tbl) {
  if(tbl) {
    if(((ext_ginthash *) tbl)->directory)
      free(((ext_ginthash *) tbl)->directory);
    if(((ext_ginthash *) tbl)->mpool)
      wg_free_mpool(db, ((ext_ginthash *) tbl)->mpool);
    free(tbl);
  }
}

/** Scramble a gint value
 *  This is useful when dealing with aligned offsets, that are
 *  multiples of 4, 8 or larger values and thus waste the majority
 *  of the directory space when used directly.
 *  Uses FNV-1a.
 */
static gint rehash_gint(gint val) {
  int i;
  wg_uint hash = FNV_offset_basis;

  for(i=0; i<sizeof(gint); i++) {
    hash ^= ((unsigned char *) &val)[i];
    hash *= FNV_prime;
  }
  return (gint) hash;
}

/** Grow the hash directory and allocate a new bucket pool.
 *
 */
static gint grow_ginthash(void *db, ext_ginthash *tbl) {
  void *tmp;
  gint newlevel = tbl->level + 1;
  if(newlevel >= GINTHASH_MAXLEVEL)
    return show_ginthash_error(db, "Maximum level exceeded.");

  if((tmp = realloc((void *) tbl->directory,
    (1<<newlevel) * sizeof(ginthash_bucket *)))) {
    tbl->directory = (ginthash_bucket **) tmp;

    if(tbl->level) {
      size_t i;
      size_t dirsize = 1<<tbl->level;
      /* duplicate the existing pointers. */
      for(i=0; i<dirsize; i++)
        tbl->directory[dirsize + i] = tbl->directory[i];
    } else {
      /* Initialize the memory pool (2 buckets) */
      if((tmp = wg_create_mpool(db, 2*sizeof(ginthash_bucket)))) {
        tbl->mpool = tmp;
        /* initial directory is empty */
        memset(tbl->directory, 0, 2*sizeof(ginthash_bucket *));
      } else {
        return show_ginthash_error(db, "Failed to allocate bucket pool.");
      }
    }
  } else {
    return show_ginthash_error(db, "Failed to reallocate directory.");
  }
  tbl->level = newlevel;
  return 0;
}

/** Allocate a new bucket.
 *
 */
static ginthash_bucket *ginthash_newbucket(void *db, ext_ginthash *tbl) {
  ginthash_bucket *bucket = (ginthash_bucket *) \
    wg_alloc_mpool(db, tbl->mpool, sizeof(ginthash_bucket));
  if(bucket) {
    /* bucket->level = tbl->level; */
    bucket->fill = 0;
  }
  return bucket;
}

/** Split a bucket.
 *  Returns the newly created bucket on success
 *  Returns NULL on failure (likely cause being out of memory)
 */
static ginthash_bucket *ginthash_splitbucket(void *db, ext_ginthash *tbl,
  ginthash_bucket *bucket)
{
  gint msbmask, lowbits;
  int i;
  ginthash_bucket *newbucket;

  if(bucket->level == tbl->level) {
    /* can't split at this level anymore, extend directory */
    /*printf("grow: curr level %d\n", tbl->level);*/
    if(grow_ginthash(db, (ext_ginthash *) tbl))
      return NULL;
  }

  /* Hash values for the new level (0+lowbits, msb+lowbits) */
  msbmask = (1<<(bucket->level++));
  lowbits = GINTHASH_SCRAMBLE(bucket->key[0]) & (msbmask - 1);

  /* Create a bucket to split into */
  newbucket = ginthash_newbucket(db, tbl);
  if(!newbucket)
    return NULL;
  newbucket->level = bucket->level;

  /* Split the entries based on the most significant
   * bit for the local level hash (the ones with msb set are relocated)
   */
  for(i=bucket->fill-1; i>=0; i--) {
    gint k_i = bucket->key[i];
    if(GINTHASH_SCRAMBLE(k_i) & msbmask) {
      add_to_bucket(newbucket, k_i, remove_from_bucket(bucket, i));
      /* printf("reassign: %d hash %d --> %d\n",
        k_i, lowbits, msbmask | lowbits); */
    }
  }

  /* Update the directory */
  if(bucket->level == tbl->level) {
    /* There are just two pointers pointing to bucket,
     * we can compute the location of the one that has the index
     * with msb set. The other one's contents do not need to be
     * modified.
     */
    tbl->directory[msbmask | lowbits] = newbucket;
  } else {
    /* The pointers that need to be updated have indexes
     * of xxx1yyyy where 1 is the msb in the index of the new
     * bucket, yyyy is the hash value of the bucket masked
     * by the previous level and xxx are all combinations of
     * bits that still remain masked by the local level after
     * the split. The pointers xxx0yyyy will remain pointing
     * to the old bucket.
     */
    size_t msbbuckets = 1<<(tbl->level - bucket->level), j;
    for(j=0; j<msbbuckets; j++) {
      size_t k = (j<<bucket->level) | msbmask | lowbits;
      /* XXX: paranoia check, remove in production */
      if(tbl->directory[k] != bucket)
        return NULL;
      tbl->directory[k] = newbucket;
    }
  }
  return newbucket;
}

/** Add a key/value pair to bucket.
 *  Returns bucket fill.
 */
static gint add_to_bucket(ginthash_bucket *bucket, gint key, gint value) {
#ifdef CHECK
  if(bucket->fill > GINTHASH_BUCKETCAP) { /* Should never happen */
    return bucket->fill + 1;
  } else {
#endif
    bucket->key[bucket->fill] = key;
    bucket->value[bucket->fill] = value;
    return ++(bucket->fill);
#ifdef CHECK
  }
#endif
}

/** Remove an indexed value from bucket.
 *  Returns the value.
 */
static gint remove_from_bucket(ginthash_bucket *bucket, int idx) {
  int i;
  gint val = bucket->value[idx];
  for(i=idx; i<GINTHASH_BUCKETCAP; i++) {
    /* Note we ignore the last slot. Generally keys/values
     * in slots indexed >=bucket->fill are always undefined
     * and shouldn't be accessed directly.
     */
    bucket->key[i] = bucket->key[i+1];
    bucket->value[i] = bucket->value[i+1];
  }
  bucket->fill--;
  return val;
}

/* ------- set membership hash (double hashing)  --------- */

/*
 * Compute a suitable hash table size for the known number of
 * entries. Returns 0 if the size is not supported.
 * Max hash table size is 63GB (~2G entries on 64-bit), this can
 * be extended by adding more primes.
 * Size is chosen so that the table load would be < 0.5
 */
static size_t dhash_size(size_t entries) {
  /* List of primes lifted from stlport
   * (http://sourceforge.net/projects/stlport/) */
  size_t primes[] = {
    389UL, 769UL, 1543UL, 3079UL, 6151UL,
    12289UL, 24593UL, 49157UL, 98317UL, 196613UL,
    393241UL, 786433UL, 1572869UL, 3145739UL, 6291469UL,
    12582917UL, 25165843UL, 50331653UL, 100663319UL, 201326611UL,
    402653189UL, 805306457UL, 1610612741UL, 3221225473UL, 4294967291UL
  };
  size_t const p_count = 20;
  size_t wantsize = entries<<1, i;
  if(entries > 2147483645UL) {
    return 0; /* give up here for now */
  }
  for(i=0; i<p_count-1; i++) {
    if(primes[i] > wantsize) {
      break;
    }
  }
  return primes[i];
}

#define DHASH_H1(k, sz) ((k) % (sz))
#define DHASH_H2(k, sz) (1 + ((k) % ((sz)-1)))
#define DHASH_PROBE(h1, h2, i, sz) (((h1) + (i)*(h2)) % sz)

/*
 * Find a slot matching the key.
 * Always returns a slot. Interpreting the results:
 * *b == 0 --> key not present in table, slot may be used to store it
 * *b == key --> key found
 * otherwise --> hash table full
 */
static gint *dhash_lookup(dhash_table *tbl, gint key) {
  gint h = rehash_gint(key);
  size_t sz = tbl->dhash_size;
  size_t h1 = DHASH_H1(h, sz), h2;
  size_t i;
  gint *bb = tbl->keys, *b = bb + h1;

  if(*b == key || *b == 0)
    return b;

  h2 = DHASH_H2(h, sz);
  for(i=1; i<sz; i++) {
    b = bb + DHASH_PROBE(h1, h2, i, sz);
    if(*b == key || *b == 0)
      break;
  }
  return b;
}

/*
 * Creates the hash table for the given number of entries.
 * The returned hash table should be treated as an opaque pointer
 * of type (void *). Returns NULL if memory allocation fails.
 * wg_dhash_free() should be called to free the structure after use.
 */
void *wg_dhash_init(void *db, size_t entries) {
  dhash_table *tbl = malloc(sizeof(dhash_table));
  if(tbl) {
    tbl->dhash_size = dhash_size(entries);
    tbl->keys = calloc(tbl->dhash_size, sizeof(gint)); /* set to 0x0 */
    if(!tbl->keys || !tbl->dhash_size) {
      free(tbl);
      tbl = NULL;
    }
  }
  return (void *) tbl;
}

/*
 * Free the structure created by wg_dhash_init()
 */
void wg_dhash_free(void *db, void *tbl) {
  if(tbl) {
    if(((dhash_table *) tbl)->keys)
      free(((dhash_table *) tbl)->keys);
    free(tbl);
  }
}

/*
 * Add an entry to the hash table.
 * returns 0 on success (including when they key is already present).
 * returns -1 on failure.
 */
gint wg_dhash_addkey(void *db, void *tbl, gint key) {
  gint *b = dhash_lookup((dhash_table *) tbl, key);
  if(*b == 0) {
    *b = key; /* key not present, free slot found, add the key */
  } else if (*b != key) {
    return -1; /* key not present and no free slot */
  }
  return 0;
}

/*
 * Find a key in the hash table.
 * Returns 1 if key is present.
 * Returns 0 if key is not present.
 */
gint wg_dhash_haskey(void *db, void *tbl, gint key) {
  gint *b = dhash_lookup((dhash_table *) tbl, key);
  return (*b == key);
}

/* -------------    error handling  ------------------- */

/*

static gint show_consistency_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg consistency error: %s\n",errmsg);
#endif
  return -1;
}
*/

static gint show_consistency_error_nr(void* db, char* errmsg, gint nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg consistency error: %s %d\n", errmsg, (int) nr);
  return -1;
#endif
}

/*
static gint show_consistency_error_double(void* db, char* errmsg, double nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg consistency error: %s %f\n",errmsg,nr);
#endif
  return -1;
}

static gint show_consistency_error_str(void* db, char* errmsg, char* str) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg consistency error: %s %s\n",errmsg,str);
#endif
  return -1;
}
*/

static gint show_hash_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg hash error: %s\n",errmsg);
#endif
  return -1;
}

static gint show_ginthash_error(void *db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg gint hash error: %s\n", errmsg);
#endif
  return -1;
}

/*

//tdint.h" // Replace with <stdint.h> if appropriate
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

uint32_t SuperFastHash (const char * data, int len) {
uint32_t hash = len, tmp;
int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    // Main loop
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    // Handle end cases
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    // Force "avalanching" of final 127 bits
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

*/

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Enar Reilent 2009, Priit Järv 2010,2011,2013,2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbindex.c
 *  Implementation of T-tree index
 */

/* ====== Includes =============== */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

//data.h"
//index.h"
//compare.h"
//hash.h"


/* ====== Private defs =========== */

#define LL_CASE 0
#define LR_CASE 1
#define RL_CASE 2
#define RR_CASE 3

#ifndef max
#define max(a,b) (a>b ? a : b)
#endif

#define HASHIDX_OP_STORE 1
#define HASHIDX_OP_REMOVE 2
#define HASHIDX_OP_FIND 3

/* ======= Private protos ================ */

#ifndef TTREE_SINGLE_COMPARE
static gint db_find_bounding_tnode(void *db, gint rootoffset, gint key,
  gint *result, struct wg_tnode *rb_node);
#endif
static int db_which_branch_causes_overweight(void *db, struct wg_tnode *root);
static int db_rotate_ttree(void *db, gint index_id, struct wg_tnode *root,
  int overw);
static gint ttree_add_row(void *db, gint index_id, void *rec);
static gint ttree_remove_row(void *db, gint index_id, void * rec);

static gint create_ttree_index(void *db, gint index_id);
static gint drop_ttree_index(void *db, gint column);

static gint insert_into_list(void *db, gint *head, gint value);
static void delete_from_list(void *db, gint *head);
#ifdef USE_INDEX_TEMPLATE
static gint add_index_template(void *db, gint *matchrec, gint reclen);
static gint find_index_template(void *db, gint *matchrec, gint reclen);
static gint remove_index_template(void *db, gint template_offset);
#endif

static gint hash_add_row(void *db, gint index_id, void *rec);
static gint hash_remove_row(void *db, gint index_id, void *rec);
static gint hash_recurse(void *db, wg_index_header *hdr, char *prefix,
  gint prefixlen, gint *values, gint count, void *rec, gint op, gint expand);
static gint hash_extend_prefix(void *db, wg_index_header *hdr, char *prefix,
  gint prefixlen, gint nextval, gint *values, gint count, void *rec, gint op,
  gint expand);

static gint create_hash_index(void *db, gint index_id);
static gint drop_hash_index(void *db, gint index_id);

static gint sort_columns(gint *sorted_cols, gint *columns, gint col_count);

static gint show_index_error(void* db, char* errmsg);
static gint show_index_error_nr(void* db, char* errmsg, gint nr);


/* ====== Functions ============== */

/*
 * Index implementation:
 * - T-Tree, as described by Lehman & Carey '86
 *   This includes search with a single compare per node, enabled by
 *   defining TTREE_SINGLE_COMPARE
 *
 * - improvements loosely based on T* tree (Kim & Choi '96)
 *   Nodes have predecessor and successor pointers. This is turned
 *   on by defining TTREE_CHAINED_NODES. Other alterations described in
 *   the original T* tree paper were not implemented.
 *
 * - hash index (allows multi-column indexes) (not done yet)
 *
 * Index metainfo:
 * data about indexes in system is stored in dbh->index_control_area_header
 *
 *  index_table[]  - 0 - 0 - v - 0 - 0 - v - 0
 *                           |           |
 *      index hdr A <--- list elem    list elem ---> index hdr B
 *            ^             0            v
 *            |                          |
 *            ----------------------- list elem
 *                                       0
 *
 *  index_table is a fixed size array that contains offsets to index
 *  lists by database field (column) number. Index lists themselves contain
 *  offsets to index headers. This arrangement is used so that one
 *  index can be referred to from several fields (index headers are
 *  unique, index list elements are not).
 *
 *  In the above example, A is a (hash) index on columns 2 and 5, while B
 *  is an index on column 5.
 *
 * Note: offset to index header struct is also used as an index id.
 */


/* ------------------- T-tree private functions ------------- */

#ifndef TTREE_SINGLE_COMPARE
/**
*  returns bounding node offset or if no really bounding node exists, then the closest node
*/
static gint db_find_bounding_tnode(void *db, gint rootoffset, gint key,
  gint *result, struct wg_tnode *rb_node) {

  struct wg_tnode * node = (struct wg_tnode *)offsettoptr(db,rootoffset);

  /* Original tree search algorithm: compares both bounds of
   * the node to determine immediately if the value falls between them.
   */

  if(WG_COMPARE(db, key, node->current_min) == WG_LESSTHAN) {
    /* if(key < node->current_max) */
    if(node->left_child_offset != 0)
      return db_find_bounding_tnode(db, node->left_child_offset,
        key, result, NULL);
    else {
      *result = DEAD_END_LEFT_NOT_BOUNDING;
      return rootoffset;
    }
  } else if(WG_COMPARE(db, key, node->current_max) != WG_GREATER) {
    *result = REALLY_BOUNDING_NODE;
    return rootoffset;
  }
  else { /* if(key > node->current_max) */
    if(node->right_child_offset != 0)
      return db_find_bounding_tnode(db, node->right_child_offset,
        key, result, NULL);
    else{
      *result = DEAD_END_RIGHT_NOT_BOUNDING;
      return rootoffset;
    }
  }
}
#else
/* "rightmost" node search is the improved tree search described in
 * the original T-tree paper.
 */
#define db_find_bounding_tnode wg_search_ttree_rightmost
#endif

/**
*  returns the description of imbalance - 4 cases possible
*  LL - left child of the left child is overweight
*  LR - right child of the left child is overweight
*  etc
*/
static int db_which_branch_causes_overweight(void *db, struct wg_tnode *root){
  struct wg_tnode *child;
  if(root->left_subtree_height > root->right_subtree_height){
    child = (struct wg_tnode *)offsettoptr(db,root->left_child_offset);
    if(child->left_subtree_height >= child->right_subtree_height)return LL_CASE;
    else return LR_CASE;
  }else{
    child = (struct wg_tnode *)offsettoptr(db,root->right_child_offset);
    if(child->left_subtree_height > child->right_subtree_height)return RL_CASE;
    else return RR_CASE;
  }
}

static int db_rotate_ttree(void *db, gint index_id, struct wg_tnode *root, int overw){
  gint grandparent = root->parent_offset;
  gint initialrootoffset = ptrtooffset(db,root);
  struct wg_tnode *r = NULL;
  struct wg_tnode *g = (struct wg_tnode *)offsettoptr(db,grandparent);
  wg_index_header *hdr = (wg_index_header *)offsettoptr(db,index_id);
  gint column = hdr->rec_field_index[0]; /* always one column for T-tree */

  if(overw == LL_CASE){

/*                       A                          B
*                     B     C                    D     A
*                   D  E             ->        N     E  C
*                  N
*/
    //printf("LL_CASE\n");
    //save some stuff into variables for later use
    gint offset_left_child = root->left_child_offset;
    gint offset_right_grandchild = ((struct wg_tnode *)offsettoptr(db,offset_left_child))->right_child_offset;
    gint right_grandchild_height = ((struct wg_tnode *)offsettoptr(db,offset_left_child))->right_subtree_height;


    //first switch: E goes to A's left child
    root->left_child_offset = offset_right_grandchild;
    root->left_subtree_height = right_grandchild_height;
    if(offset_right_grandchild != 0){
      ((struct wg_tnode *)offsettoptr(db,offset_right_grandchild))->parent_offset = ptrtooffset(db,root);
    }
    //second switch: A goes to B's right child
    ((struct wg_tnode *)offsettoptr(db,offset_left_child)) -> right_child_offset = ptrtooffset(db,root);
    ((struct wg_tnode *)offsettoptr(db,offset_left_child)) -> right_subtree_height = max(root->left_subtree_height,root->right_subtree_height)+1;
    root->parent_offset = offset_left_child;
    //for later grandparent fix
    r = (struct wg_tnode *)offsettoptr(db,offset_left_child);

  }else if(overw == RR_CASE){

/*                       A                          C
*                     B     C                    A     E
*                         D   E         ->     B  D      N
*                              N
*/
    //printf("RR_CASE\n");
    //save some stuff into variables for later use
    gint offset_right_child = root->right_child_offset;
    gint offset_left_grandchild = ((struct wg_tnode *)offsettoptr(db,offset_right_child))->left_child_offset;
    gint left_grandchild_height = ((struct wg_tnode *)offsettoptr(db,offset_right_child))->left_subtree_height;
    //first switch: D goes to A's right child
    root->right_child_offset = offset_left_grandchild;
    root->right_subtree_height = left_grandchild_height;
    if(offset_left_grandchild != 0){
      ((struct wg_tnode *)offsettoptr(db,offset_left_grandchild))->parent_offset = ptrtooffset(db,root);
    }
    //second switch: A goes to C's left child
    ((struct wg_tnode *)offsettoptr(db,offset_right_child)) -> left_child_offset = ptrtooffset(db,root);
    ((struct wg_tnode *)offsettoptr(db,offset_right_child)) -> left_subtree_height = max(root->right_subtree_height,root->left_subtree_height)+1;
    root->parent_offset = offset_right_child;
    //for later grandparent fix
    r = (struct wg_tnode *)offsettoptr(db,offset_right_child);

  }else if(overw == LR_CASE){
/*               A                    E
*             B     C             B       A
*          D    E        ->     D  F    G    C
*             F  G                 N
*             N
*/
    struct wg_tnode *bb, *ee;
    //save some stuff into variables for later use
    gint offset_left_child = root->left_child_offset;
    gint offset_right_grandchild = ((struct wg_tnode *)offsettoptr(db,offset_left_child))->right_child_offset;

    //first swtich: G goes to A's left child
    ee = (struct wg_tnode *)offsettoptr(db,offset_right_grandchild);
    root -> left_child_offset = ee -> right_child_offset;
    root -> left_subtree_height = ee -> right_subtree_height;
    if(ee -> right_child_offset != 0){
      ((struct wg_tnode *)offsettoptr(db,ee->right_child_offset))->parent_offset = ptrtooffset(db, root);
    }
    //second switch: F goes to B's right child
    bb = (struct wg_tnode *)offsettoptr(db,offset_left_child);
    bb -> right_child_offset = ee -> left_child_offset;
    bb -> right_subtree_height = ee -> left_subtree_height;
    if(ee -> left_child_offset != 0){
      ((struct wg_tnode *)offsettoptr(db,ee->left_child_offset))->parent_offset = offset_left_child;
    }
    //third switch: B goes to E's left child
    /* The Lehman/Carey "special" LR rotation - instead of creating
     * an internal node with one element, the values of what will become the
     * left child will be moved over to the parent, thus ensuring the internal
     * node is adequately filled. This is only allowed if E is a leaf.
     */
    if(ee->number_of_elements == 1 && !ee->right_child_offset &&\
      !ee->left_child_offset && bb->number_of_elements == WG_TNODE_ARRAY_SIZE){
      int i;

      /* Create space for elements from B */
      ee->array_of_values[bb->number_of_elements - 1] = ee->array_of_values[0];

      /* All the values moved are smaller than in E */
      for(i=1; i<bb->number_of_elements; i++)
        ee->array_of_values[i-1] = bb->array_of_values[i];
      ee->number_of_elements = bb->number_of_elements;

      /* Examine the new leftmost element to find current_min */
      ee->current_min = wg_get_field(db, (void *)offsettoptr(db,
        ee->array_of_values[0]), column);

      bb -> number_of_elements = 1;
      bb -> current_max = bb -> current_min;
    }

    //then switch the nodes
    ee -> left_child_offset = offset_left_child;
    ee -> left_subtree_height = max(bb->right_subtree_height,bb->left_subtree_height)+1;
    bb -> parent_offset = offset_right_grandchild;
    //fourth switch: A goes to E's right child
    ee -> right_child_offset = ptrtooffset(db, root);
    ee -> right_subtree_height = max(root->right_subtree_height,root->left_subtree_height)+1;
    root -> parent_offset = offset_right_grandchild;
    //for later grandparent fix
    r = ee;

  }else if(overw == RL_CASE){

/*               A                    E
*             C     B             A       B
*                 E   D  ->     C  G    F   D
*               G  F                    N
*                  N
*/
    struct wg_tnode *bb, *ee;
    //save some stuff into variables for later use
    gint offset_right_child = root->right_child_offset;
    gint offset_left_grandchild = ((struct wg_tnode *)offsettoptr(db,offset_right_child))->left_child_offset;

    //first swtich: G goes to A's left child
    ee = (struct wg_tnode *)offsettoptr(db,offset_left_grandchild);
    root -> right_child_offset = ee -> left_child_offset;
    root -> right_subtree_height = ee -> left_subtree_height;
    if(ee -> left_child_offset != 0){
      ((struct wg_tnode *)offsettoptr(db,ee->left_child_offset))->parent_offset = ptrtooffset(db, root);
    }

    //second switch: F goes to B's right child
    bb = (struct wg_tnode *)offsettoptr(db,offset_right_child);
    bb -> left_child_offset = ee -> right_child_offset;
    bb -> left_subtree_height = ee -> right_subtree_height;
    if(ee -> right_child_offset != 0){
      ((struct wg_tnode *)offsettoptr(db,ee->right_child_offset))->parent_offset = offset_right_child;
    }

    //third switch: B goes to E's right child
    /* "special" RL rotation - see comments for LR_CASE */
    if(ee->number_of_elements == 1 && !ee->right_child_offset &&\
      !ee->left_child_offset &&  bb->number_of_elements == WG_TNODE_ARRAY_SIZE){
      int i;

      /* All the values moved are larger than in E */
      for(i=1; i<bb->number_of_elements; i++)
        ee->array_of_values[i] = bb->array_of_values[i-1];
      ee->number_of_elements = bb->number_of_elements;

      /* Examine the new rightmost element to find current_max */
      ee->current_max = wg_get_field(db, (void *)offsettoptr(db,
        ee->array_of_values[ee->number_of_elements - 1]), column);

      /* Remaining B node array element should sit in slot 0 */
      bb->array_of_values[0] = \
        bb->array_of_values[bb->number_of_elements - 1];
      bb -> number_of_elements = 1;
      bb -> current_min = bb -> current_max;
    }

    ee -> right_child_offset = offset_right_child;
    ee -> right_subtree_height = max(bb->right_subtree_height,bb->left_subtree_height)+1;
    bb -> parent_offset = offset_left_grandchild;
    //fourth switch: A goes to E's right child

    ee -> left_child_offset = ptrtooffset(db, root);
    ee -> left_subtree_height = max(root->right_subtree_height,root->left_subtree_height)+1;
    root -> parent_offset = offset_left_grandchild;
    //for later grandparent fix
    r = ee;

  } else {
    /* catch an error case (can't really happen) */
    show_index_error(db, "tree rotate called with invalid argument, "\
      "index may have become corrupt");
    return -1;
  }

  //fix grandparent - regardless of current 'overweight' case

  if(grandparent == 0){//'grandparent' is index header data
    r->parent_offset = 0;
    //TODO more error check here
    TTREE_ROOT_NODE(hdr) = ptrtooffset(db,r);
  }else{//grandparent is usual node
    //printf("change grandparent node\n");
    r -> parent_offset = grandparent;
    if(g->left_child_offset == initialrootoffset){//new subtree must replace the left child of grandparent
      g->left_child_offset = ptrtooffset(db,r);
      g->left_subtree_height = max(r->left_subtree_height,r->right_subtree_height)+1;
    }else{
      g->right_child_offset = ptrtooffset(db,r);
      g->right_subtree_height = max(r->left_subtree_height,r->right_subtree_height)+1;
    }
  }

  return 0;
}

/**  inserts pointer to data row into index tree structure
*
*  returns:
*  0 - on success
*  -1 - if error
*/
static gint ttree_add_row(void *db, gint index_id, void *rec) {
  gint rootoffset, column;
  gint newvalue, boundtype, bnodeoffset, newoffset;
  struct wg_tnode *node;
  wg_index_header *hdr = (wg_index_header *)offsettoptr(db,index_id);
  db_memsegment_header* dbh = dbmemsegh(db);

  rootoffset = TTREE_ROOT_NODE(hdr);
#ifdef CHECK
  if(rootoffset == 0){
#ifdef WG_NO_ERRPRINT
#else
    fprintf(stderr,"index at offset %d does not exist\n", (int) index_id);
#endif
    return -1;
  }
#endif
  column = hdr->rec_field_index[0]; /* always one column for T-tree */

  //extract real value from the row (rec)
  newvalue = wg_get_field(db, rec, column);

  //find bounding node for the value
  bnodeoffset = db_find_bounding_tnode(db, rootoffset, newvalue, &boundtype, NULL);
  node = (struct wg_tnode *)offsettoptr(db,bnodeoffset);
  newoffset = 0;//save here the offset of newly created tnode - 0 if no node added into the tree
  //if bounding node exists - follow one algorithm, else the other
  if(boundtype == REALLY_BOUNDING_NODE){

    //check if the node has room for a new entry
    if(node->number_of_elements < WG_TNODE_ARRAY_SIZE){
      int i, j;
      gint cr;

      /* add array entry and update control data. We keep the
       * array sorted, smallest values left. */
      for(i=0; i<node->number_of_elements; i++) {
        /* The node is small enough for naive scans to be
         * "good enough" inside the node. Note that we
         * branch into re-sort loop as early as possible
         * with >= operator (> would be algorithmically correct too)
         * since here the compare is more expensive than the slot
         * copying.
         */
        cr = WG_COMPARE(db, wg_get_field(db,
          (void *)offsettoptr(db,node->array_of_values[i]), column),
          newvalue);

        if(cr != WG_LESSTHAN) { /* value >= newvalue */
          /* Push remaining values to the right */
          for(j=node->number_of_elements; j>i; j--)
            node->array_of_values[j] = node->array_of_values[j-1];
          break;
        }
      }
      /* i is either number_of_elements or a vacated slot
       * in the array now. */
      node->array_of_values[i] = ptrtooffset(db,rec);
      node->number_of_elements++;

      /* Update min. Due to the >= comparison max is preserved
       * in this case. Note that we are overwriting values that
       * WG_COMPARE() may deem equal. This is intentional, because other
       * parts of T-tree algorithm rely on encoded values of min/max fields
       * to be in sync with the leftmost/rightmost slots.
       */
      if(i==0) {
        node->current_min = newvalue;
      }
    }
    else{
      //still, insert the value here, but move minimum out of this node
      //get the minimum element from this node
      int i, j;
      gint cr, minvalue, minvaluerowoffset;

      minvalue = node->current_min;
      minvaluerowoffset = node->array_of_values[0];

      /* Now scan for the matching slot. However, since
       * we already know the 0 slot will be re-filled, we
       * do this scan (and sort) in reverse order, compared to the case
       * where array had some space left. */
      for(i=WG_TNODE_ARRAY_SIZE-1; i>0; i--) {
        cr = WG_COMPARE(db, wg_get_field(db,
          (void *)offsettoptr(db,node->array_of_values[i]), column),
          newvalue);
        if(cr != WG_GREATER) { /* value <= newvalue */
          /* Push remaining values to the left */
          for(j=0; j<i; j++)
            node->array_of_values[j] = node->array_of_values[j+1];
          break;
        }
      }
      /* i is either 0 or a freshly vacated slot */
      node->array_of_values[i] = ptrtooffset(db,rec);

      /* Update minimum. Thanks to the sorted array, we know for a fact
       * that the minimum sits in slot 0. */
      if(i==0) {
        node->current_min = newvalue;
      } else {
        node->current_min = wg_get_field(db,
          (void *)offsettoptr(db,node->array_of_values[0]), column);
        /* The scan for the free slot starts from the right and
         * tries to exit as fast as possible. So it's possible that
         * the rightmost slot was changed.
         */
        if(i == WG_TNODE_ARRAY_SIZE-1) {
          node->current_max = newvalue;
        }
      }

      //proceed to the node that holds greatest lower bound - must be leaf (can be the initial bounding node)
      if(node->left_child_offset != 0){
#ifndef TTREE_CHAINED_NODES
        gint greatestlb = wg_ttree_find_glb_node(db,node->left_child_offset);
#else
        gint greatestlb = node->pred_offset;
#endif
        node = (struct wg_tnode *)offsettoptr(db, greatestlb);
      }
      //if the greatest lower bound node has room, insert value
      //otherwise make the new node as right child and put the value there
      if(node->number_of_elements < WG_TNODE_ARRAY_SIZE){
        //add array entry and update control data
        node->array_of_values[node->number_of_elements] = minvaluerowoffset;//save offset, use first free slot
        node->number_of_elements++;
        node->current_max = minvalue;

      }else{
        //create, initialize and save first value
        struct wg_tnode *leaf;
        gint newnode = wg_alloc_fixlen_object(db, &dbh->tnode_area_header);
        if(newnode == 0)return -1;
        leaf =(struct wg_tnode *)offsettoptr(db,newnode);
        leaf->parent_offset = ptrtooffset(db,node);
        leaf->left_subtree_height = 0;
        leaf->right_subtree_height = 0;
        leaf->current_max = minvalue;
        leaf->current_min = minvalue;
        leaf->number_of_elements = 1;
        leaf->left_child_offset = 0;
        leaf->right_child_offset = 0;
        leaf->array_of_values[0] = minvaluerowoffset;
        /* If the original, full node did not have a left child, then
         * there also wasn't a separate GLB node, so we are adding one now
         * as the left child. Otherwise, the new node is added as the right
         * child to the current GLB node.
         */
        if(bnodeoffset == ptrtooffset(db,node)) {
          node->left_child_offset = newnode;
#ifdef TTREE_CHAINED_NODES
          /* Create successor / predecessor relationship */
          leaf->succ_offset = ptrtooffset(db, node);
          leaf->pred_offset = node->pred_offset;

          if(node->pred_offset) {
            struct wg_tnode *pred = \
              (struct wg_tnode *) offsettoptr(db, node->pred_offset);
            pred->succ_offset = newnode;
          } else {
            TTREE_MIN_NODE(hdr) = newnode;
          }
          node->pred_offset = newnode;
#endif
        } else {
#ifdef TTREE_CHAINED_NODES
          struct wg_tnode *succ;
#endif
          node->right_child_offset = newnode;
#ifdef TTREE_CHAINED_NODES
          /* Insert the new node in the sequential chain between
           * the original node and the GLB node found */
          leaf->succ_offset = node->succ_offset;
          leaf->pred_offset = ptrtooffset(db, node);

#ifdef CHECK
          if(!node->succ_offset) {
            show_index_error(db, "GLB with no successor, panic");
            return -1;
          } else {
#endif
            succ = (struct wg_tnode *) offsettoptr(db, leaf->succ_offset);
            succ->pred_offset = newnode;
#ifdef CHECK
          }
#endif
          node->succ_offset = newnode;
#endif /* TTREE_CHAINED_NODES */
        }
        newoffset = newnode;
      }
    }

  }//the bounding node existed - first algorithm
  else{// bounding node does not exist
    //try to insert the new value to that node - becoming new min or max
    //if the node has room for a new entry
    if(node->number_of_elements < WG_TNODE_ARRAY_SIZE){
      int i;

      /* add entry, keeping the array sorted (see also notes for the
       * bounding node case. The difference this time is that we already
       * know if this value is becoming the new min or max).
       */
      if(boundtype == DEAD_END_LEFT_NOT_BOUNDING) {
        /* our new value is the new min, push everything right */
        for(i=node->number_of_elements; i>0; i--)
          node->array_of_values[i] = node->array_of_values[i-1];
        node->array_of_values[0] = ptrtooffset(db,rec);
        node->current_min = newvalue;
      } else { /* DEAD_END_RIGHT_NOT_BOUNDING */
        /* even simpler case, new value is added to the right */
        node->array_of_values[node->number_of_elements] = ptrtooffset(db,rec);
        node->current_max = newvalue;
      }

      node->number_of_elements++;

      /* XXX: not clear if the empty node can occur here. Until this
       * is checked, we'll be paranoid and overwrite both min and max. */
      if(node->number_of_elements==1) {
        node->current_max = newvalue;
        node->current_min = newvalue;
      }
    }else{
      //make a new node and put data there
      struct wg_tnode *leaf;
      gint newnode = wg_alloc_fixlen_object(db, &dbh->tnode_area_header);
      if(newnode == 0)return -1;
      leaf =(struct wg_tnode *)offsettoptr(db,newnode);
      leaf->parent_offset = ptrtooffset(db,node);
      leaf->left_subtree_height = 0;
      leaf->right_subtree_height = 0;
      leaf->current_max = newvalue;
      leaf->current_min = newvalue;
      leaf->number_of_elements = 1;
      leaf->left_child_offset = 0;
      leaf->right_child_offset = 0;
      leaf->array_of_values[0] = ptrtooffset(db,rec);
      newoffset = newnode;
      //set new node as left or right leaf
      if(boundtype == DEAD_END_LEFT_NOT_BOUNDING){
        node->left_child_offset = newnode;
#ifdef TTREE_CHAINED_NODES
        /* Set the new node as predecessor of the parent */
        leaf->succ_offset = ptrtooffset(db, node);
        leaf->pred_offset = node->pred_offset;

        if(node->pred_offset) {
          /* Notify old predecessor that the node following
           * it changed */
          struct wg_tnode *pred = \
            (struct wg_tnode *) offsettoptr(db, node->pred_offset);
          pred->succ_offset = newnode;
        } else {
          TTREE_MIN_NODE(hdr) = newnode;
        }
        node->pred_offset = newnode;
#endif
      }else if(boundtype == DEAD_END_RIGHT_NOT_BOUNDING){
        node->right_child_offset = newnode;
#ifdef TTREE_CHAINED_NODES
        /* Set the new node as successor of the parent */
        leaf->succ_offset = node->succ_offset;
        leaf->pred_offset = ptrtooffset(db, node);

        if(node->succ_offset) {
          /* Notify old successor that the node preceding
           * it changed */
          struct wg_tnode *succ = \
            (struct wg_tnode *) offsettoptr(db, node->succ_offset);
          succ->pred_offset = newnode;
        } else {
          TTREE_MAX_NODE(hdr) = newnode;
        }
        node->succ_offset = newnode;
#endif
      }
    }
  }//no bounding node found - algorithm 2

  //if new node was added to tree - must update child height data in nodes from leaf to root
  //or until find a node with imbalance
  //then determine the bad balance case: LL, LR, RR or RL and execute proper rotation
  if(newoffset){
    struct wg_tnode *child = (struct wg_tnode *)offsettoptr(db,newoffset);
    struct wg_tnode *parent;
    int left = 0;
    while(child->parent_offset != 0){//this is not a root
      int balance;
      parent = (struct wg_tnode *)offsettoptr(db,child->parent_offset);
      //determine which child the child is, left or right one
      if(parent->left_child_offset == ptrtooffset(db,child)) left = 1;
      else left = 0;
      //increment parent left or right subtree height
      if(left)parent->left_subtree_height++;
      else parent->right_subtree_height++;

      //check balance
      balance = parent->left_subtree_height - parent->right_subtree_height;
      if(balance == 0) {
        /* As a result of adding a new node somewhere below, left
         * and right subtrees of the node we're checking became
         * of EQUAL height. This means that changes in subtree heights
         * do not propagate any further (the max depth in this node
         * dit NOT change).
         */
        break;
      }
      if(balance > 1 || balance < -1){//must rebalance
        //the current parent is root for balancing operation
        //determine the branch that causes overweight
        int overw = db_which_branch_causes_overweight(db,parent);
        //fix balance
        db_rotate_ttree(db,index_id,parent,overw);
        break;//while loop because balance does not change in the next levels
      }else{//just proceed to the parent node
        child = parent;
      }
    }
  }
  return 0;
}

/**  removes pointer to data row from index tree structure
*
*  returns:
*  0 - on success
*  -1 - if error, index doesnt exist
*  -2 - if error, no bounding node for key
*  -3 - if error, boundig node exists, value not
*  -4 - if error, tree not in balance
*/
static gint ttree_remove_row(void *db, gint index_id, void * rec) {
  int i, found;
  gint key, rootoffset, column, boundtype, bnodeoffset;
  gint rowoffset;
  struct wg_tnode *node, *parent;
  wg_index_header *hdr = (wg_index_header *)offsettoptr(db,index_id);

  rootoffset = TTREE_ROOT_NODE(hdr);
#ifdef CHECK
  if(rootoffset == 0){
#ifdef WG_NO_ERRPRINT
#else
    fprintf(stderr,"index at offset %d does not exist\n", (int) index_id);
#endif
    return -1;
  }
#endif
  column = hdr->rec_field_index[0]; /* always one column for T-tree */
  key = wg_get_field(db, rec, column);
  rowoffset = ptrtooffset(db, rec);

  /* find bounding node for the value. Since non-unique values
   * are allowed, we will find the leftmost node and scan
   * right from there (we *need* the exact row offset).
   */

  bnodeoffset = wg_search_ttree_leftmost(db,
          rootoffset, key, &boundtype, NULL);
  node = (struct wg_tnode *)offsettoptr(db,bnodeoffset);

  //if bounding node does not exist - error
  if(boundtype != REALLY_BOUNDING_NODE) return -2;

  /* find the record inside the node. This is an expensive loop if there
   * are many repeated values, so unnecessary deleting should be avoided
   * on higher level.
   */
  found = -1;
  for(;;) {
    for(i=0;i<node->number_of_elements;i++){
      if(node->array_of_values[i] == rowoffset) {
        found = i;
        goto found_row;
      }
    }
    bnodeoffset = TNODE_SUCCESSOR(db, node);
    if(!bnodeoffset)
      break; /* no more successors */
    node = (struct wg_tnode *)offsettoptr(db,bnodeoffset);
    if(WG_COMPARE(db, node->current_min, key) == WG_GREATER)
      break; /* successor is not a bounding node */
  }

found_row:
  if(found == -1) return -3;

  //delete the key and rearrange other elements
  node->number_of_elements--;
  if(found < node->number_of_elements) { /* not the last element */
    /* slide the elements to the right of the found value
     * one step to the left */
    for(i=found; i<node->number_of_elements; i++)
      node->array_of_values[i] = node->array_of_values[i+1];
  }

  /* Update min/max */
  if(found==node->number_of_elements && node->number_of_elements != 0) {
    /* Rightmost element was removed, so new max should be updated to
     * the new rightmost value */
    node->current_max = wg_get_field(db, (void *)offsettoptr(db,
      node->array_of_values[node->number_of_elements - 1]), column);
  } else if(found==0 && node->number_of_elements != 0) {
    /* current_min removed, update to new leftmost value */
    node->current_min = wg_get_field(db, (void *)offsettoptr(db,
      node->array_of_values[0]), column);
  }

  //check underflow and take some actions if needed
  if(node->number_of_elements < 5){//TODO use macro
    //if the node is internal node - borrow its gratest lower bound from the node where it is
    if(node->left_child_offset != 0 && node->right_child_offset != 0){//internal node
#ifndef TTREE_CHAINED_NODES
      gint greatestlb = wg_ttree_find_glb_node(db,node->left_child_offset);
#else
      gint greatestlb = node->pred_offset;
#endif
      struct wg_tnode *glbnode = (struct wg_tnode *)offsettoptr(db, greatestlb);

      /* Make space for a new min value */
      for(i=node->number_of_elements; i>0; i--)
        node->array_of_values[i] = node->array_of_values[i-1];

      /* take the glb value (always the rightmost in the array) and
       * insert it in our node */
      node -> array_of_values[0] = \
        glbnode->array_of_values[glbnode->number_of_elements-1];
      node -> number_of_elements++;
      node -> current_min = glbnode -> current_max;
      if(node->number_of_elements == 1) /* we just got our first element */
        node->current_max = glbnode -> current_max;
      glbnode -> number_of_elements--;

      //reset new max for glbnode
      if(glbnode->number_of_elements != 0) {
        glbnode->current_max = wg_get_field(db, (void *)offsettoptr(db,
          glbnode->array_of_values[glbnode->number_of_elements - 1]), column);
      }

      node = glbnode;
    }
  }

  //now variable node points to the node which really lost an element
  //this is definitely leaf or half-leaf
  //if the node is empty - free it and rebalanc the tree
  parent = NULL;
  //delete the empty leaf
  if(node->left_child_offset == 0 && node->right_child_offset == 0 && node->number_of_elements == 0){
    if(node->parent_offset != 0){
      parent = (struct wg_tnode *)offsettoptr(db, node->parent_offset);
      //was it left or right child
      if(parent->left_child_offset == ptrtooffset(db,node)){
        parent->left_child_offset=0;
        parent->left_subtree_height=0;
      }else{
        parent->right_child_offset=0;
        parent->right_subtree_height=0;
      }
    }
#ifdef TTREE_CHAINED_NODES
    /* Remove the node from sequential chain */
    if(node->succ_offset) {
      struct wg_tnode *succ = \
        (struct wg_tnode *) offsettoptr(db, node->succ_offset);
      succ->pred_offset = node->pred_offset;
    } else {
      TTREE_MAX_NODE(hdr) = node->pred_offset;
    }
    if(node->pred_offset) {
      struct wg_tnode *pred = \
        (struct wg_tnode *) offsettoptr(db, node->pred_offset);
      pred->succ_offset = node->succ_offset;
    } else {
      TTREE_MIN_NODE(hdr) = node->succ_offset;
    }
#endif
    /* Free the node, unless it's the root node */
    if(node != offsettoptr(db, TTREE_ROOT_NODE(hdr))) {
      wg_free_tnode(db, ptrtooffset(db,node));
    } else {
      /* Set empty state of root node */
      node->current_max = WG_ILLEGAL;
      node->current_min = WG_ILLEGAL;
#ifdef TTREE_CHAINED_NODES
      TTREE_MAX_NODE(hdr) = TTREE_ROOT_NODE(hdr);
      TTREE_MIN_NODE(hdr) = TTREE_ROOT_NODE(hdr);
#endif
    }
    //rebalance if needed
  }

  //or if the node was a half-leaf, see if it can be merged with its leaf
  if((node->left_child_offset == 0 && node->right_child_offset != 0) || (node->left_child_offset != 0 && node->right_child_offset == 0)){
    int elements = node->number_of_elements;
    int left;
    struct wg_tnode *child;
    if(node->left_child_offset != 0){
      child = (struct wg_tnode *)offsettoptr(db, node->left_child_offset);
      left = 1;//true
    }else{
      child = (struct wg_tnode *)offsettoptr(db, node->right_child_offset);
      left = 0;//false
    }
    elements += child->number_of_elements;
    if(!(child->left_subtree_height == 0 && child->right_subtree_height == 0)){
      show_index_error(db,
        "index tree is not balanced, deleting algorithm doesn't work");
      return -4;
    }
    //if possible move all elements from child to node and free child
    if(elements <= WG_TNODE_ARRAY_SIZE){
      int i = node->number_of_elements;
      int j;
      node->number_of_elements = elements;
      if(left){
        /* Left child elements are all smaller than in current node */
        for(j=i-1; j>=0; j--){
          node->array_of_values[j + child->number_of_elements] = \
            node->array_of_values[j];
        }
        for(j=0;j<child->number_of_elements;j++){
          node->array_of_values[j]=child->array_of_values[j];
        }
        node->left_subtree_height=0;
        node->left_child_offset=0;
        node->current_min=child->current_min;
        if(!i) node->current_max=child->current_max; /* parent was empty */
      }else{
        /* Right child elements are all larger than in current node */
        for(j=0;j<child->number_of_elements;j++){
          node->array_of_values[i+j]=child->array_of_values[j];
        }
        node->right_subtree_height=0;
        node->right_child_offset=0;
        node->current_max=child->current_max;
        if(!i) node->current_min=child->current_min; /* parent was empty */
      }
#ifdef TTREE_CHAINED_NODES
      /* Remove the child from sequential chain */
      if(child->succ_offset) {
        struct wg_tnode *succ = \
          (struct wg_tnode *) offsettoptr(db, child->succ_offset);
        succ->pred_offset = child->pred_offset;
      } else {
        TTREE_MAX_NODE(hdr) = child->pred_offset;
      }
      if(child->pred_offset) {
        struct wg_tnode *pred = \
          (struct wg_tnode *) offsettoptr(db, child->pred_offset);
        pred->succ_offset = child->succ_offset;
      } else {
        TTREE_MIN_NODE(hdr) = child->succ_offset;
      }
#endif
      wg_free_tnode(db, ptrtooffset(db, child));
      if(node->parent_offset) {
        parent = (struct wg_tnode *)offsettoptr(db, node->parent_offset);
        if(parent->left_child_offset==ptrtooffset(db,node)){
          parent->left_subtree_height=1;
        }else{
          parent->right_subtree_height=1;
        }
      }
    }
  }

  //check balance and update subtree height data
  //stop when find a node where subtree heights dont change
  if(parent != NULL){
    int balance, height;
    for(;;) {
      balance = parent->left_subtree_height - parent->right_subtree_height;
      if(balance > 1 || balance < -1){//must rebalance
        //the current parent is root for balancing operation
        //rotarion fixes subtree heights in grandparent
        //determine the branch that causes overweight
        int overw = db_which_branch_causes_overweight(db,parent);
        //fix balance
        db_rotate_ttree(db,index_id,parent,overw);
      }
      else if(parent->parent_offset) {
        struct wg_tnode *gp;
        //manually set grandparent subtree heights
        height = max(parent->left_subtree_height,parent->right_subtree_height);
        gp = (struct wg_tnode *)offsettoptr(db, parent->parent_offset);
        if(gp->left_child_offset==ptrtooffset(db,parent)){
          gp->left_subtree_height=1+height;
        }else{
          gp->right_subtree_height=1+height;
        }
      }
      if(!parent->parent_offset)
        break; /* root node reached */
      parent = (struct wg_tnode *)offsettoptr(db, parent->parent_offset);
    }
  }
  return 0;
}


/* ------------------- T-tree public functions ---------------- */

/**
*  returns offset to data row:
*  -1 - error, index does not exist
*  0 - if key NOT found
*  other integer - if key found (= offset to data row)
*  XXX: with duplicate values, which one is returned is somewhat
*  undetermined, so this function is mainly for early development/testing
*/
gint wg_search_ttree_index(void *db, gint index_id, gint key){
  int i;
  gint rootoffset, bnodetype, bnodeoffset;
  gint rowoffset, column;
  struct wg_tnode * node;
  wg_index_header *hdr = (wg_index_header *)offsettoptr(db,index_id);

  rootoffset = TTREE_ROOT_NODE(hdr);
#ifdef CHECK
  /* XXX: This is a rather weak check but might catch some errors */
  if(rootoffset == 0){
#ifdef WG_NO_ERRPRINT
#else
    fprintf(stderr,"index at offset %d does not exist\n", (int) index_id);
#endif
    return -1;
  }
#endif

  /* Find the leftmost bounding node */
  bnodeoffset = wg_search_ttree_leftmost(db,
          rootoffset, key, &bnodetype, NULL);
  node = (struct wg_tnode *)offsettoptr(db,bnodeoffset);

  if(bnodetype != REALLY_BOUNDING_NODE) return 0;

  column = hdr->rec_field_index[0]; /* always one column for T-tree */
  /* find the record inside the node. */
  for(;;) {
    for(i=0;i<node->number_of_elements;i++){
      rowoffset = node->array_of_values[i];
      if(WG_COMPARE(db,
        wg_get_field(db, (void *)offsettoptr(db,rowoffset), column),
        key) == WG_EQUAL) {
        return rowoffset;
      }
    }
    /* Normally we cannot end up here. We'll keep the code in case
     * implementation of wg_compare() changes in the future.
     */
    bnodeoffset = TNODE_SUCCESSOR(db, node);
    if(!bnodeoffset)
      break; /* no more successors */
    node = (struct wg_tnode *)offsettoptr(db,bnodeoffset);
    if(WG_COMPARE(db, node->current_min, key) == WG_GREATER)
      break; /* successor is not a bounding node */
  }

  return 0;
}

/*
 * The following pairs of functions implement tree traversal. Only
 * wg_ttree_find_glb_node() is used for the upkeep of T-tree (insert, delete,
 * re-balance), the rest are required for sequential scan and range queries
 * when the tree is implemented without predecessor and successor pointers.
 */

#ifndef TTREE_CHAINED_NODES

/** find greatest lower bound node
*  returns offset of the (half-) leaf node with greatest lower bound
*  goes only right - so: must call on the left child of the internal
*  which we are looking the GLB node for.
*/
gint wg_ttree_find_glb_node(void *db, gint nodeoffset) {
  struct wg_tnode * node = (struct wg_tnode *)offsettoptr(db,nodeoffset);
  if(node->right_child_offset != 0)
    return wg_ttree_find_glb_node(db, node->right_child_offset);
  else
    return nodeoffset;
}

/** find least upper bound node
*  returns offset of the (half-) leaf node with least upper bound
*  Call with the right child of an internal node as argument.
*/
gint wg_ttree_find_lub_node(void *db, gint nodeoffset) {
  struct wg_tnode * node = (struct wg_tnode *)offsettoptr(db,nodeoffset);
  if(node->left_child_offset != 0)
    return wg_ttree_find_lub_node(db, node->left_child_offset);
  else
    return nodeoffset;
}

/** find predecessor of a leaf.
*  Returns offset of the internal node which holds the value
*  immediately preceeding the current_min of the leaf.
*  If the search hit root (the leaf could be the leftmost one in
*  the tree) the function returns 0.
*  This is the reverse of finding the LUB node.
*/
gint wg_ttree_find_leaf_predecessor(void *db, gint nodeoffset) {
  struct wg_tnode *node, *parent;

  node = (struct wg_tnode *)offsettoptr(db,nodeoffset);
  if(node->parent_offset) {
    parent = (struct wg_tnode *) offsettoptr(db, node->parent_offset);
    /* If the current node was left child of the parent, the immediate
     * parent has larger values, so we need to climb to the next
     * level with our search. */
    if(parent->left_child_offset == nodeoffset)
      return wg_ttree_find_leaf_predecessor(db, node->parent_offset);
  }
  return node->parent_offset;
}

/** find successor of a leaf.
*  Returns offset of the internal node which holds the value
*  immediately succeeding the current_max of the leaf.
*  Returns 0 if there is no successor.
*  This is the reverse of finding the GLB node.
*/
gint wg_ttree_find_leaf_successor(void *db, gint nodeoffset) {
  struct wg_tnode *node, *parent;

  node = (struct wg_tnode *)offsettoptr(db,nodeoffset);
  if(node->parent_offset) {
    parent = (struct wg_tnode *) offsettoptr(db, node->parent_offset);
    if(parent->right_child_offset == nodeoffset)
      return wg_ttree_find_leaf_successor(db, node->parent_offset);
  }
  return node->parent_offset;
}

#endif /* TTREE_CHAINED_NODES */

/*
 * Functions to support range queries (and fetching multiple
 * duplicate values) using T-tree index. Since the nodes can be
 * traversed sequentially, the simplest way to implement queries that
 * have result sets is to find leftmost (or rightmost) value that
 * meets the query conditions and scan right (or left) from there.
 */

/** Find rightmost node containing given value
 *  returns NULL if node was not found
 */
gint wg_search_ttree_rightmost(void *db, gint rootoffset,
  gint key, gint *result, struct wg_tnode *rb_node) {

  struct wg_tnode * node;

#ifdef TTREE_SINGLE_COMPARE
  node = (struct wg_tnode *)offsettoptr(db,rootoffset);

  /* Improved(?) tree search algorithm with a single compare per node.
   * only lower bound is examined, if the value is larger the right subtree
   * is selected immediately. If the search ends in a dead end, the node where
   * the right branch was taken is examined again.
   */
  if(WG_COMPARE(db, key, node->current_min) == WG_LESSTHAN) {
    /* key < node->current_min */
    if(node->left_child_offset != 0) {
      return wg_search_ttree_rightmost(db, node->left_child_offset, key,
        result, rb_node);
    } else if (rb_node) {
      /* Dead end, but we still have an unexamined node left */
      if(WG_COMPARE(db, key, rb_node->current_max) != WG_GREATER) {
        /* key<=rb_node->current_max */
        *result = REALLY_BOUNDING_NODE;
        return ptrtooffset(db, rb_node);
      }
    }
    /* No left child, no rb_node or it's right bound was not interesting */
    *result = DEAD_END_LEFT_NOT_BOUNDING;
    return rootoffset;
  }
  else {
    if(node->right_child_offset != 0) {
      /* Here we jump the gun and branch to right, ignoring the
       * current_max of the node (therefore avoiding one expensive
       * compare operation).
       */
      return wg_search_ttree_rightmost(db, node->right_child_offset, key,
        result, node);
    } else if(WG_COMPARE(db, key, node->current_max) != WG_GREATER) {
      /* key<=node->current_max */
      *result = REALLY_BOUNDING_NODE;
      return rootoffset;
    }
    /* key is neither left of or inside this node and
     * there is no right child */
    *result = DEAD_END_RIGHT_NOT_BOUNDING;
    return rootoffset;
  }
#else
  gint bnodeoffset;

  bnodeoffset = db_find_bounding_tnode(db, rootoffset, key, result, NULL);
  if(*result != REALLY_BOUNDING_NODE)
    return bnodeoffset;

  /* There is at least one node with the key we're interested in,
   * now make sure we have the rightmost */
  node = offsettoptr(db, bnodeoffset);
  while(WG_COMPARE(db, node->current_max, key) == WG_EQUAL) {
    gint nextoffset = TNODE_SUCCESSOR(db, node);
    if(nextoffset) {
      struct wg_tnode *next = offsettoptr(db, nextoffset);
        if(WG_COMPARE(db, next->current_min, key) == WG_GREATER)
          /* next->current_min > key */
          break; /* overshot */
      node = next;
    }
    else
      break; /* last node in chain */
  }
  return ptrtooffset(db, node);
#endif
}

/** Find leftmost node containing given value
 *  returns NULL if node was not found
 */
gint wg_search_ttree_leftmost(void *db, gint rootoffset,
  gint key, gint *result, struct wg_tnode *lb_node) {

  struct wg_tnode * node;

#ifdef TTREE_SINGLE_COMPARE
  node = (struct wg_tnode *)offsettoptr(db,rootoffset);

  /* Rightmost bound search mirrored */
  if(WG_COMPARE(db, key, node->current_max) == WG_GREATER) {
    /* key > node->current_max */
    if(node->right_child_offset != 0) {
      return wg_search_ttree_leftmost(db, node->right_child_offset, key,
        result, lb_node);
    } else if (lb_node) {
      /* Dead end, but we still have an unexamined node left */
      if(WG_COMPARE(db, key, lb_node->current_min) != WG_LESSTHAN) {
        /* key>=lb_node->current_min */
        *result = REALLY_BOUNDING_NODE;
        return ptrtooffset(db, lb_node);
      }
    }
    *result = DEAD_END_RIGHT_NOT_BOUNDING;
    return rootoffset;
  }
  else {
    if(node->left_child_offset != 0) {
      return wg_search_ttree_leftmost(db, node->left_child_offset, key,
        result, node);
    } else if(WG_COMPARE(db, key, node->current_min) != WG_LESSTHAN) {
      /* key>=node->current_min */
      *result = REALLY_BOUNDING_NODE;
      return rootoffset;
    }
    *result = DEAD_END_LEFT_NOT_BOUNDING;
    return rootoffset;
  }
#else
  gint bnodeoffset;

  bnodeoffset = db_find_bounding_tnode(db, rootoffset, key, result, NULL);
  if(*result != REALLY_BOUNDING_NODE)
    return bnodeoffset;

  /* One (we don't know which) bounding node found, traverse the
   * tree to the leftmost. */
  node = offsettoptr(db, bnodeoffset);
  while(WG_COMPARE(db, node->current_min, key) == WG_EQUAL) {
    gint prevoffset = TNODE_PREDECESSOR(db, node);
    if(prevoffset) {
      struct wg_tnode *prev = offsettoptr(db, prevoffset);
      if(WG_COMPARE(db, prev->current_max, key) == WG_LESSTHAN)
        /* prev->current_max < key */
        break; /* overshot */
      node = prev;
    }
    else
      break; /* first node in chain */
  }
  return ptrtooffset(db, node);
#endif
}

/** Find first occurrence of a value in a T-tree node
 *  returns the number of the slot. If the value itself
 *  is missing, the location of the first value that
 *  exceeds it is returned.
 */
gint wg_search_tnode_first(void *db, gint nodeoffset, gint key,
  gint column) {

  gint i, encoded;
  struct wg_tnode *node = (struct wg_tnode *) offsettoptr(db, nodeoffset);

  for(i=0; i<node->number_of_elements; i++) {
    /* Naive scan is ok for small values of WG_TNODE_ARRAY_SIZE. */
    encoded = wg_get_field(db,
      (void *)offsettoptr(db,node->array_of_values[i]), column);
    if(WG_COMPARE(db, encoded, key) != WG_LESSTHAN)
      /* encoded >= key */
      return i;
  }

  return -1;
}

/** Find last occurrence of a value in a T-tree node
 *  returns the number of the slot. If the value itself
 *  is missing, the location of the first value that
 *  is smaller (when scanning from right to left) is returned.
 */
gint wg_search_tnode_last(void *db, gint nodeoffset, gint key,
  gint column) {

  gint i, encoded;
  struct wg_tnode *node = (struct wg_tnode *) offsettoptr(db, nodeoffset);

  for(i=node->number_of_elements -1; i>=0; i--) {
    encoded = wg_get_field(db,
      (void *)offsettoptr(db,node->array_of_values[i]), column);
    if(WG_COMPARE(db, encoded, key) != WG_GREATER)
      /* encoded <= key */
      return i;
  }

  return -1;
}

/** Create T-tree index on a column
*  returns:
*  0 - on success
*  -1 - error (failed to create the index)
*/
static gint create_ttree_index(void *db, gint index_id){
  gint node;
  unsigned int rowsprocessed;
  struct wg_tnode *nodest;
  void *rec;
  db_memsegment_header* dbh = dbmemsegh(db);
  wg_index_header *hdr = (wg_index_header *) offsettoptr(db, index_id);
  gint column = hdr->rec_field_index[0];

  /* allocate (+ init) root node for new index tree and save
   * the offset into index_array */
  node = wg_alloc_fixlen_object(db, &dbh->tnode_area_header);
  nodest =(struct wg_tnode *)offsettoptr(db,node);
  nodest->parent_offset = 0;
  nodest->left_subtree_height = 0;
  nodest->right_subtree_height = 0;
  nodest->current_max = WG_ILLEGAL;
  nodest->current_min = WG_ILLEGAL;
  nodest->number_of_elements = 0;
  nodest->left_child_offset = 0;
  nodest->right_child_offset = 0;
#ifdef TTREE_CHAINED_NODES
  nodest->succ_offset = 0;
  nodest->pred_offset = 0;
#endif

  TTREE_ROOT_NODE(hdr) = node;
#ifdef TTREE_CHAINED_NODES
  TTREE_MIN_NODE(hdr) = node;
  TTREE_MAX_NODE(hdr) = node;
#endif

  //scan all the data - make entry for every suitable row
  rec = wg_get_first_record(db);
  rowsprocessed = 0;

  while(rec != NULL) {
    if(column >= wg_get_record_len(db, rec)) {
      rec=wg_get_next_record(db,rec);
      continue;
    }
    if(MATCH_TEMPLATE(db, hdr, rec)) {
      ttree_add_row(db, index_id, rec);
      rowsprocessed++;
    }
    rec=wg_get_next_record(db,rec);
  }
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"new index created on rec field %d into slot %d and %d data rows inserted\n",
    (int) column, (int) index_id, rowsprocessed);
#endif

  return 0;
}

/** Drop T-tree index by id
*  Frees the memory in the T-node area
*  returns:
*  0 - on success
*  -1 - error
*/
static gint drop_ttree_index(void *db, gint index_id){
  struct wg_tnode *node;
  wg_index_header *hdr;

  hdr = (wg_index_header *) offsettoptr(db, index_id);

  /* Free the T-node memory. This is trivial for chained nodes, since
   * once we've found a successor for a node it can be deleted and
   * forgotten about. For plain T-tree this does not work since tree
   * traversal often runs down and up parent-child chains, which means
   * that some parents cannot be deleted before their children.
   */
  node = NULL;
#ifdef TTREE_CHAINED_NODES
  if(TTREE_MIN_NODE(hdr))
    node = (struct wg_tnode *) offsettoptr(db, TTREE_MIN_NODE(hdr));
  else if(TTREE_ROOT_NODE(hdr)) /* normally this does not happen */
    node = (struct wg_tnode *) offsettoptr(db, TTREE_ROOT_NODE(hdr));
  while(node) {
    gint deleteme = ptrtooffset(db, node);
    if(node->succ_offset)
      node = (struct wg_tnode *) offsettoptr(db, node->succ_offset);
    else
      node = NULL;
    wg_free_tnode(db, deleteme);
  }
#else
  /* XXX: not implemented */
  show_index_error(db, "Warning: T-node memory cannot be deallocated");
#endif

  return 0;
}

/* -------------- Hash index private functions ------------- */

/**  inserts pointer to data row into index tree structure
 *  returns:
 *  0 - on success
 *  -1 - if error
 */
static gint hash_add_row(void *db, gint index_id, void *rec) {
  wg_index_header *hdr = (wg_index_header *)offsettoptr(db,index_id);
  gint i;
  gint values[MAX_INDEX_FIELDS];

  for(i=0; i<hdr->fields; i++) {
    values[i] = wg_get_field(db, rec, hdr->rec_field_index[i]);
  }
  return hash_recurse(db, hdr, NULL, 0, values, hdr->fields, rec,
    HASHIDX_OP_STORE, (hdr->type == WG_INDEX_TYPE_HASH_JSON));
}

/** Remove all entries connected to a row from hash index
 *  returns:
 *  0 - on success
 *  -1 - if error
 */
static gint hash_remove_row(void *db, gint index_id, void *rec) {
  wg_index_header *hdr = (wg_index_header *)offsettoptr(db,index_id);
  gint i;
  gint values[MAX_INDEX_FIELDS];

  for(i=0; i<hdr->fields; i++) {
    values[i] = wg_get_field(db, rec, hdr->rec_field_index[i]);
  }
  return hash_recurse(db, hdr, NULL, 0, values, hdr->fields, rec,
    HASHIDX_OP_REMOVE, (hdr->type == WG_INDEX_TYPE_HASH_JSON));
}

/**
 * Construct a byte array for hashing recursively.
 * Hash it when it is complete.
 *
 * If we have a JSON index *and* we're acting on an indexable row,
 * all arrays are expanded. This does not happen if we're called
 * by updating a value *in* an array.
 *
 * returns:
 * 0 - on success
 * -1 - on error
 */
static gint hash_recurse(void *db, wg_index_header *hdr, char *prefix,
  gint prefixlen, gint *values, gint count, void *rec, gint op, gint expand) {

  if(count) {
    gint nextvalue = values[0];
    if(expand) {
      /* In case of a JSON/array index, check the value */
      if(wg_get_encoded_type(db, nextvalue) == WG_RECORDTYPE) {
        void *valrec = wg_decode_record(db, nextvalue);

        if(is_schema_array(valrec)) {
          /* expand the array */
          gint i, reclen, retv = 0;
          reclen = wg_get_record_len(db, valrec);
          for(i=0; i<reclen; i++) {
            retv = hash_extend_prefix(db, hdr, prefix, prefixlen,
              wg_get_field(db, valrec, i),
              &values[1], count - 1, rec, op, expand);
            if(retv)
              break;
          }
          return retv; /* This skips adding the array record itself. It's
                        * not useful as we can only hash the offset. */
        }
      }
    }
    /* Regular index. JSON/array index also falls back to this. */
    return hash_extend_prefix(db, hdr, prefix, prefixlen,
      nextvalue, &values[1], count - 1, rec, op, expand);
  }
  else {
    /* No more values, the hash string is complete. Add it to the index */
    if(op == HASHIDX_OP_STORE) {
      return wg_idxhash_store(db, HASHIDX_ARRAYP(hdr),
        prefix, prefixlen, ptrtooffset(db, rec));
    } else if(op == HASHIDX_OP_REMOVE) {
      return wg_idxhash_remove(db, HASHIDX_ARRAYP(hdr),
        prefix, prefixlen, ptrtooffset(db, rec));
    } else {
      /* assume HASHIDX_OP_FIND */
      return wg_idxhash_find(db, HASHIDX_ARRAYP(hdr), prefix, prefixlen);
    }
  }
  return 0; /* pacify the compiler */
}

/*
 * Helper function to convert the next value into an array of
 * bytes and append it to the existing prefix. Always calls
 * hash_recurse() to complete the recursion.
 */
static gint hash_extend_prefix(void *db, wg_index_header *hdr, char *prefix,
  gint prefixlen, gint nextval, gint *values, gint count, void *rec, gint op,
  gint expand) {

  char *fldbytes, *newprefix;
  gint newlen, fldlen, retv;

  fldlen = wg_decode_for_hashing(db, nextval, &fldbytes);
  if(fldlen < 1) {
    show_index_error(db,"Failed to decode a field value for hash");
    return -1;
  }

  if(prefix && prefixlen) {
    newlen = prefixlen + fldlen + 1;
  } else {
    newlen = fldlen;
  }

  newprefix = malloc(newlen);
  if(!newprefix) {
    free(fldbytes);
    show_index_error(db, "Failed to allocate memory");
    return -1;
  }
  if(prefix) {
    memcpy(newprefix, prefix, prefixlen);
    newprefix[prefixlen] = '\0'; /* XXX: why? double-check this */
  }

  memcpy(newprefix + (newlen - fldlen), fldbytes, fldlen);
  retv = hash_recurse(db, hdr, newprefix,
    newlen, values, count, rec, op, expand);
  free(fldbytes);
  free(newprefix);
  return retv;
}

/*
 * Create hash index.
 * Returns 0 on success
 * Returns -1 on failure.
 */
static gint create_hash_index(void *db, gint index_id){
  unsigned int rowsprocessed;
  void *rec;
  wg_index_header *hdr = (wg_index_header *) offsettoptr(db, index_id);
  gint type = hdr->type;
  gint firstcol = hdr->rec_field_index[0];
  gint i;

  /* Initialize the hash table (0 - use default size) */
  if(wg_create_hash(db, HASHIDX_ARRAYP(hdr), 0))
    return -1;

  /* Add existing records */
  rec = wg_get_first_record(db);
  rowsprocessed = 0;

  while(rec != NULL) {
    if(firstcol >= wg_get_record_len(db, rec)) {
      rec=wg_get_next_record(db,rec);
      continue;
    }
    if(MATCH_TEMPLATE(db, hdr, rec)) {
      if(type == WG_INDEX_TYPE_HASH_JSON) {
        /* Ignore array and object records. Their data is indexed
         * from the rows that point to them.
         */
        if(is_plain_record(rec)) {
          hash_add_row(db, index_id, rec);
          rowsprocessed++;
        }
      } else {
        /* Add all rows normally */
        hash_add_row(db, index_id, rec);
        rowsprocessed++;
      }
    }
    rec=wg_get_next_record(db,rec);
  }
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"new hash index created on (");
#endif
  for(i=0; i<hdr->fields; i++) {
#ifdef WG_NO_ERRPRINT
#else
#ifdef _WIN32
    fprintf(stderr,"%s%Id", (i ? "," : ""), hdr->rec_field_index[i]);
#else
    fprintf(stderr,"%s%td", (i ? "," : ""), hdr->rec_field_index[i]);
#endif
#endif
  }
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,") into slot %d and %d data rows inserted\n",
    (int) index_id, rowsprocessed);
#endif
  return 0;
}

/** Drop a hash index by id
 *  returns:
 *  0 - on success
 *  -1 - error
 *
 * XXX: implement this. Needs some method of de-allocating or reusing
 * the main hash table (list cells/varlen storage can be freed piece by
 * piece if necessary).
 */
static gint drop_hash_index(void *db, gint index_id){
  show_index_error(db, "Cannot drop hash index: not implemented");
  return -1;
}

/* -------------- Hash index public functions -------------- */

/**
 *  Search the hash index for given values.
 *
 *  returns offset to data row:
 *  -1 - error
 *  0 - if key NOT found
 *  >0 - offset to the linked list that contains the row offsets
 */
gint wg_search_hash(void *db, gint index_id, gint *values, gint count) {
  wg_index_header *hdr = (wg_index_header *) offsettoptr(db, index_id);
#ifdef CHECK
  gint type = wg_get_index_type(db, index_id); /* also validates the id */
  if(type < 0)
    return type;
  if(type != WG_INDEX_TYPE_HASH && type != WG_INDEX_TYPE_HASH_JSON)
    return show_index_error(db, "wg_search_hash: Not a hash index");
  if(hdr->fields != count) {
    show_index_error(db, "Number of indexed fields does not match");
    return -1;
  }
#endif
  return hash_recurse(db, hdr, NULL, 0, values, count, NULL,
    HASHIDX_OP_FIND, 0);
}


/* ----------------- Index template functions -------------- */

/** Insert into list
 *
 * helper function to insert list elements. Takes address of
 * a variable containing an offset to the first element (that
 * offset may be 0 for empty lists or when appending).
 */
static gint insert_into_list(void *db, gint *head, gint value) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint old = *head;

  *head = wg_alloc_fixlen_object(db, &dbh->listcell_area_header);
  if(*head) {
    gcell *listelem = (gcell *) offsettoptr(db, *head);
    listelem->car = value;
    listelem->cdr = old;
  }
  return *head;
}

/** Delete from list
 *
 * helper function to delete list elements. Deletes the current
 * element.
 */
static void delete_from_list(void *db, gint *head) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gcell *listelem = (gcell *) offsettoptr(db, *head);

  *head = listelem->cdr;
  /* Free the vacated list element */
  wg_free_fixlen_object(db, &dbh->listcell_area_header,
    ptrtooffset(db, listelem));
}

#ifdef USE_INDEX_TEMPLATE

/** Add index template
 *
 * Takes a gint array that represents an template for records
 * that are inserted into an index. Creates a database record
 * from that array and links the record into an ordered list.
 *
 * Returns offset to the created match record, if successful
 * Returns 0 on error.
 */
static gint add_index_template(void *db, gint *matchrec, gint reclen) {
  gint *ilist, *meta;
  void *rec;
  db_memsegment_header* dbh = dbmemsegh(db);
  wg_index_template *tmpl;
  gint fixed_columns = 0, template_offset = 0, last_fixed = 0;
  int i;

  /* Find the number of fixed columns in the template */
  for(i=0; i<reclen; i++) {
    gint type = wg_get_encoded_type(db, matchrec[i]);
    if(type == WG_RECORDTYPE) {
      /* Technically it would be possible to allow records
       * in templates but this kind of complexity is not
       * necessary. Therefore banned.
       */
      show_index_error(db, "record links not allowed in index templates");
      return 0;
    }
    if(type != WG_VARTYPE) {
      fixed_columns++;
      last_fixed = i;
    }
  }
  if(!fixed_columns) {
    /* useless template */
    return 0;
  }
  reclen = last_fixed + 1; /* trim trailing wildcards */

  /* Find if similar template exists. We are scanning the entire
   * template list so that no additional sorting is needed later:
   * once we've determined there is no matching template we can
   * break the loop at the exact position where the new template
   * is going to be inserted.
   */
  ilist = &dbh->index_control_area_header.index_template_list;
  while(*ilist) {
    gcell *ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(!ilistelem->car) {
      show_index_error(db, "Invalid header in index tempate list");
      return 0;
    }
    tmpl = (wg_index_template *) offsettoptr(db, ilistelem->car);
    if(tmpl->fixed_columns == fixed_columns) {
      rec = offsettoptr(db, tmpl->offset_matchrec);
      if(reclen != wg_get_record_len(db, rec))
        goto nextelem; /* match not possible */
      for(i=0; i<reclen; i++) {
        if(wg_get_encoded_type(db, matchrec[i]) != WG_VARTYPE) {
          if(WG_COMPARE(db,
            matchrec[i], wg_get_field(db, rec, i)) != WG_EQUAL)
            goto nextelem;
        }
      }
      /* The entire record matched, re-use it */
      return ilistelem->car;
    }
    else if(tmpl->fixed_columns < fixed_columns) {
      /* No matching record found. New template should be inserted
       * ahead of current element. */
      break;
    }
nextelem:
    ilist = &ilistelem->cdr;
  }

  /* Create the new match record */
  rec = wg_create_raw_record(db, reclen);
  if(!rec)
    return 0;
  for(i=0; i<reclen; i++) {
    if(wg_set_new_field(db, rec, i, matchrec[i]) < 0)
      return 0;
  }
  meta = ((gint *) rec + RECORD_META_POS);
  *meta |= (RECORD_META_NOTDATA | RECORD_META_MATCH);

  /* Add new template header */
  template_offset = wg_alloc_fixlen_object(db, &dbh->indextmpl_area_header);
  tmpl = (wg_index_template *) offsettoptr(db, template_offset);
  tmpl->offset_matchrec = ptrtooffset(db, rec);
  tmpl->fixed_columns = fixed_columns;

  /* Insert it into the template list */
  if(!insert_into_list(db, ilist, template_offset))
    return 0;

  return template_offset;
}

/** Find index template
 *
 * Takes a gint array that represents an template for records
 * that are inserted into an index. Checks if a matching template
 * exists in a database. This function is used for finding an
 * index.
 *
 * Returns the template offset on success.
 * Returns 0 on error.
 */
static gint find_index_template(void *db, gint *matchrec, gint reclen) {
  gint *ilist;
  void *rec;
  db_memsegment_header* dbh = dbmemsegh(db);
  wg_index_template *tmpl;
  gint fixed_columns = 0, last_fixed = 0;
  int i;

  /* Get some statistics about the match record and validate it */
  for(i=0; i<reclen; i++) {
    gint type = wg_get_encoded_type(db, matchrec[i]);
    if(type == WG_RECORDTYPE) {
      show_index_error(db, "record links not allowed in index templates");
      return 0;
    }
    if(type != WG_VARTYPE) {
      fixed_columns++;
      last_fixed = i;
    }
  }
  if(!fixed_columns) {
    show_index_error(db, "not a legal match record");
    return 0;
  }
  reclen = last_fixed + 1;

  /* Find a matching template. */
  ilist = &dbh->index_control_area_header.index_template_list;
  while(*ilist) {
    gcell *ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(!ilistelem->car) {
      show_index_error(db, "Invalid header in index tempate list");
      return 0;
    }
    tmpl = (wg_index_template *) offsettoptr(db, ilistelem->car);
    if(tmpl->fixed_columns == fixed_columns) {
      rec = offsettoptr(db, tmpl->offset_matchrec);
      if(reclen != wg_get_record_len(db, rec))
        goto nextelem; /* match not possible */
      for(i=0; i<reclen; i++) {
        if(wg_get_encoded_type(db, matchrec[i]) != WG_VARTYPE) {
          if(WG_COMPARE(db,
            matchrec[i], wg_get_field(db, rec, i)) != WG_EQUAL)
            goto nextelem;
        }
      }
      /* We have a match. */
      return ilistelem->car;
    }
    else if(tmpl->fixed_columns < fixed_columns) {
      /* No matching record found. New template should be inserted
       * ahead of current element. */
      break;
    }
nextelem:
    ilist = &ilistelem->cdr;
  }

  return 0;
}

/** Remove index template
 *
 * Caller should make sure that the template is no longer
 * referenced by any indexes before calling this.
 */
static gint remove_index_template(void *db, gint template_offset) {
  gint *ilist;
  void *rec;
  db_memsegment_header* dbh = dbmemsegh(db);
  wg_index_template *tmpl;

  tmpl = (wg_index_template *) offsettoptr(db, template_offset);

  /* Delete the database record */
  rec = offsettoptr(db, tmpl->offset_matchrec);
  wg_delete_record(db, rec);

  /* Remove from template list */
  ilist = &dbh->index_control_area_header.index_template_list;
  while(*ilist) {
    gcell *ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car == template_offset) {
      delete_from_list(db, ilist);
      break;
    }
    ilist = &ilistelem->cdr;
  }

  /* Free the template */
  wg_free_fixlen_object(db, &dbh->indextmpl_area_header, template_offset);

  return 0;
}

/** Check if a record matches a template
 *
 * Returns 1 if they match
 * Otherwise, returns 0
 */
gint wg_match_template(void *db, wg_index_template *tmpl, void *rec) {
  void *matchrec;
  gint reclen, mreclen;
  int i;

#ifdef CHECK
  /* Paranoia */
  if(!tmpl->offset_matchrec) {
    show_index_error(db, "Invalid match record template");
    return 0;
  }
#endif

  matchrec = offsettoptr(db, tmpl->offset_matchrec);
  mreclen = wg_get_record_len(db, matchrec);
  reclen = wg_get_record_len(db, rec);
  if(mreclen > reclen) {
    /* Match records always end in a fixed column, so
     * this is guaranteed to be a mismatch
     */
    return 0;
  }
  else if(mreclen < reclen) {
    /* Fields outside the template always match */
    reclen = mreclen;
  }
  for(i=0; i<reclen; i++) {
    gint enc = wg_get_field(db, matchrec, i);
    if(wg_get_encoded_type(db, enc) != WG_VARTYPE) {
      if(WG_COMPARE(db, enc, wg_get_field(db, rec, i)) != WG_EQUAL)
        return 0;
    }
  }
  return 1;
}

#endif

/* ----------------- General index functions --------------- */

/*
 * Sort the column list. Returns the number of unique values.
 */
static gint sort_columns(gint *sorted_cols, gint *columns,
  gint col_count) {
  gint i = 0;
  gint prev = -1;
  while(i < col_count) {
    gint lowest = MAX_INDEXED_FIELDNR + 1;
    gint j;
    for(j=0; j<col_count; j++) {
      if(columns[j] < lowest && columns[j] > prev)
        lowest = columns[j];
    }
    if(lowest == MAX_INDEXED_FIELDNR + 1)
      break;
    sorted_cols[i++] = lowest;
    prev = lowest;
  };
  return i;
}

/** Create an index.
 *
 * Single-column backward compatibility wrapper.
 */
gint wg_create_index(void *db, gint column, gint type,
  gint *matchrec, gint reclen)
{
  return wg_create_multi_index(db, &column, 1, type, matchrec, reclen);
}

/** Create an index.
 *
 * Arguments -
 * type - WG_INDEX_TYPE_TTREE - single-column T-tree index
 *        WG_INDEX_TYPE_TTREE_JSON - T-tree for JSON schema
 *        WG_INDEX_TYPE_HASH - multi-column hash index
 *        WG_INDEX_TYPE_HASH_JSON - hash index with JSON features
 *
 * columns - array of column numbers
 * col_count - size of the column number array
 *
 * matchrec - array of gints
 * reclen - size of matchrec
 * If matchrec is NULL, regular index will be created. Otherwise,
 * only database records that match the template defined by
 * matchrec are inserted in this index.
 */
gint wg_create_multi_index(void *db, gint *columns, gint col_count, gint type,
  gint *matchrec, gint reclen)
{
  gint index_id, template_offset = 0, i;
  wg_index_header *hdr;
#ifdef USE_INDEX_TEMPLATE
  wg_index_template *tmpl = NULL;
  gint fixed_columns = 0;
#endif
  gint *ilist[MAX_INDEX_FIELDS];
  gint sorted_cols[MAX_INDEX_FIELDS];
  db_memsegment_header* dbh = dbmemsegh(db);

  /* Check the arguments */
#ifdef CHECK
  if (!dbcheck(db)) {
    show_index_error(db, "Invalid database pointer in wg_create_multi_index");
    return -1;
  }
  if(!columns) {
    show_index_error(db, "columns list is a NULL pointer");
    return -1;
  }
#endif

#ifdef USE_CHILD_DB
  /* Workaround to handle external refs/ttree issue */
  if(dbh->extdbs.count > 0) {
    return show_index_error(db, "Database has external data, "\
      "indexes disabled.");
  }
#endif

  /* Column count validation */
  if(col_count < 1) {
    show_index_error(db, "need at least one indexed column");
    return -1;
  } else if(col_count > MAX_INDEX_FIELDS) {
    show_index_error_nr(db, "Max allowed indexed fields",
      MAX_INDEX_FIELDS);
    return -1;
  } else if(col_count > 1 &&\
    (type == WG_INDEX_TYPE_TTREE || type == WG_INDEX_TYPE_TTREE_JSON)) {
    show_index_error(db, "Cannot create a T-tree index on multiple columns");
    return -1;
  }

  if(sort_columns(sorted_cols, columns, col_count) < col_count) {
    show_index_error(db, "Duplicate columns not allowed");
    return -1;
  }

  for(i=0; i<col_count; i++) {
    if(sorted_cols[i] > MAX_INDEXED_FIELDNR) {
      show_index_error_nr(db, "Max allowed column number",
        MAX_INDEXED_FIELDNR);
      return -1;
    }
  }

#ifdef USE_INDEX_TEMPLATE
  /* Handle the template */
  if(matchrec) {
    if(!reclen) {
      show_index_error(db, "Zero-length match record not allowed");
      return -1;
    }

    if(reclen > MAX_INDEXED_FIELDNR+1) {
      show_index_error_nr(db, "Match record too long, max",
        MAX_INDEXED_FIELDNR+1);
      return -1;
    }

    /* Sanity check */
    for(i=0; i<col_count; i++) {
      if(sorted_cols[i] < reclen &&\
        wg_get_encoded_type(db, matchrec[sorted_cols[i]]) != WG_VARTYPE) {
        show_index_error(db, "Indexed column not allowed in template");
        return -1;
      }
    }

    template_offset = add_index_template(db, matchrec, reclen);
    if(!template_offset) {
      show_index_error(db, "Error adding index template");
      return -1;
    }
    tmpl = (wg_index_template *) offsettoptr(db, template_offset);
    fixed_columns = tmpl->fixed_columns;
  }
#endif

  /* Scan to the end of index chain for each column. If templates are used,
   * new indexes are inserted in between list elements to maintain
   * the chains sorted by number of fixed columns.
   */
  for(i=0; i<col_count; i++) {
    gint column = sorted_cols[i];
    ilist[i] = &dbh->index_control_area_header.index_table[column];
    while(*(ilist[i])) {
      gcell *ilistelem = (gcell *) offsettoptr(db, *(ilist[i]));

      if(!ilistelem->car) {
        show_index_error(db, "Invalid header in index list");
        return -1;
      }
      hdr = (wg_index_header *) offsettoptr(db, ilistelem->car);

      /* If this is the first column, check for a matching index.
       * Note that this is simplified by having the column lists sorted.
       */
      if(!i && hdr->type==type && template_offset==hdr->template_offset &&\
                                        hdr->fields==col_count) {
        gint j, match = 1;
        /* Compare the field lists */
        for(j=0; j<col_count; j++) {
          if(hdr->rec_field_index[j] != sorted_cols[j]) {
            match = 0;
            break;
          }
        }
        if(match) {
          show_index_error(db, "Identical index already exists on the column");
          return -1;
        }
      }

#ifdef USE_INDEX_TEMPLATE
      if(hdr->template_offset) {
        wg_index_template *t = \
          (wg_index_template *) offsettoptr(db, hdr->template_offset);
        if(t->fixed_columns < fixed_columns)
          break; /* new template is more promising, insert here */
      }
      else if(fixed_columns) {
        /* Current list element does not have a template, so
         * the new one should be inserted before it.
         */
        break;
      }
#endif
      ilist[i] = &ilistelem->cdr;
    }
  }

  /* Add new index header */
  index_id = wg_alloc_fixlen_object(db, &dbh->indexhdr_area_header);

  for(i=0; i<col_count; i++) {
    if(!insert_into_list(db, ilist[i], index_id)) {
      if(i) {
        /* XXX: need to clean up the earlier inserts :-( */
        return -1;
      } else {
        return -1;
      }
    }
  }

  /* Set up the header */
  hdr = (wg_index_header *) offsettoptr(db, index_id);
  hdr->type = type;
  hdr->fields = col_count;
  for(i=0; i < col_count; i++) {
    hdr->rec_field_index[i] = sorted_cols[i];
  }
  hdr->template_offset = template_offset;

  /* create the actual index */
  switch(hdr->type) {
    case WG_INDEX_TYPE_TTREE:
      create_ttree_index(db, index_id);
      break;
    case WG_INDEX_TYPE_HASH:
    case WG_INDEX_TYPE_HASH_JSON:
      if(create_hash_index(db, index_id))
        return -1;
      break;
    case WG_INDEX_TYPE_TTREE_JSON:
      /* Return an error, until proper implementation exists */
    default:
      show_index_error(db, "Invalid index type");
      return -1;
  }

  /* Add to master list */
  if(!insert_into_list(db,
     &dbh->index_control_area_header.index_list ,index_id))
    return -1;

#ifdef USE_INDEX_TEMPLATE
  if(hdr->template_offset) {
    int i;
    /* Update the template index */
    for(i=0; i<reclen; i++) {
      if(wg_get_encoded_type(db, matchrec[i]) != WG_VARTYPE) {
        /* No checking/sorting required here, so we can insert
         * the new element at the head of the list.
         */
        if(!insert_into_list(db,
          &(dbh->index_control_area_header.index_template_table[i]),
          index_id))
          return 0;
      }
    }
  }
#endif

  /* increase index counter */
  dbh->index_control_area_header.number_of_indexes++;
#ifdef USE_INDEX_TEMPLATE
  if(tmpl)
    tmpl->refcount++;
#endif

  return 0;
}


/** Drop index by index id
*
*  returns:
*  0 - on success
*  -1 - error
*/
gint wg_drop_index(void *db, gint index_id){
  int i;
  wg_index_header *hdr = NULL;
  gint *ilist;
  gcell *ilistelem;
  db_memsegment_header* dbh = dbmemsegh(db);

  /* Locate the header */
  ilist = &dbh->index_control_area_header.index_list;
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car == index_id) {
      hdr = (wg_index_header *) offsettoptr(db, index_id);
      /* Delete current element */
      delete_from_list(db, ilist);
      break;
    }
    ilist = &ilistelem->cdr;
  }

  if(!hdr) {
    show_index_error_nr(db, "Invalid index for delete", index_id);
    return -1;
  }

  /* Remove the index from index table */
  for(i=0; i<hdr->fields; i++) {
    int column = hdr->rec_field_index[i];

    ilist = &dbh->index_control_area_header.index_table[column];
    while(*ilist) {
      ilistelem = (gcell *) offsettoptr(db, *ilist);
      if(ilistelem->car == index_id) {
        delete_from_list(db, ilist);
        break;
      }
      ilist = &ilistelem->cdr;
    }
  }

#ifdef USE_INDEX_TEMPLATE
  if(hdr->template_offset) {
    wg_index_template *tmpl = \
      (wg_index_template *) offsettoptr(db, hdr->template_offset);
    void *matchrec = offsettoptr(db, tmpl->offset_matchrec);
    gint reclen = wg_get_record_len(db, matchrec);

    /* Remove from template index */
    for(i=0; i<reclen; i++) {
      if(wg_get_encoded_type(db,
        wg_get_field(db, matchrec, i)) != WG_VARTYPE) {
        ilist = &dbh->index_control_area_header.index_template_table[i];
        while(*ilist) {
          ilistelem = (gcell *) offsettoptr(db, *ilist);
          if(ilistelem->car == index_id) {
            delete_from_list(db, ilist);
            break;
          }
          ilist = &ilistelem->cdr;
        }
      }
    }
  }
#endif

  /* Drop the index */
  switch(hdr->type) {
    case WG_INDEX_TYPE_TTREE:
    case WG_INDEX_TYPE_TTREE_JSON:
      if(drop_ttree_index(db, index_id))
        return -1;
      break;
    case WG_INDEX_TYPE_HASH:
    case WG_INDEX_TYPE_HASH_JSON:
      if(drop_hash_index(db, index_id))
        return -1;
      break;
    default:
      show_index_error(db, "Invalid index type");
      return -1;
  }

#ifdef USE_INDEX_TEMPLATE
  if(hdr->template_offset) {
    wg_index_template *tmpl = \
      (wg_index_template *) offsettoptr(db, hdr->template_offset);
    if(!(--(tmpl->refcount)))
      remove_index_template(db, hdr->template_offset);
  }
#endif

  /* Now free the header */
  wg_free_fixlen_object(db, &dbh->indexhdr_area_header, index_id);

  /* decrement index counter */
  dbh->index_control_area_header.number_of_indexes--;

  return 0;
}

/** Find index id (index header) by column.
 *
 * Single-column backward compatibility wrapper.
 */
gint wg_column_to_index_id(void *db, gint column, gint type,
  gint *matchrec, gint reclen)
{
  return wg_multi_column_to_index_id(db, &column, 1, type, matchrec, reclen);
}

/** Find index id (index header) by column(s)
* Supports all types of indexes, calling program should examine the
* header of returned index to decide how to proceed. Alternatively,
* if type is not 0 then only indexes of the given type are
* returned.
*
* If matchrec is NULL, "full" index is returned. Otherwise
* the function attempts to locate a matching template.
*
*  returns:
*  -1 if no index found
*  offset > 0 if index found - index id
*/
gint wg_multi_column_to_index_id(void *db, gint *columns, gint col_count,
  gint type, gint *matchrec, gint reclen)
{
  int i;
  gint template_offset = 0;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint *ilist;
  gcell *ilistelem;
  gint sorted_cols[MAX_INDEX_FIELDS];

#ifdef USE_INDEX_TEMPLATE
  /* Validate the match record and find the template */
  if(matchrec) {
    if(!reclen) {
      show_index_error(db, "Zero-length match record not allowed");
      return -1;
    }

    if(reclen > MAX_INDEXED_FIELDNR+1) {
      show_index_error_nr(db, "Match record too long, max",
        MAX_INDEXED_FIELDNR+1);
      return -1;
    }

    template_offset = find_index_template(db, matchrec, reclen);
    if(!template_offset) {
      /* No matching template */
      return -1;
    }
  }
#endif

  /* Column count validation */
  if(col_count < 1) {
    show_index_error(db, "need at least one indexed column");
    return -1;
  } else if(col_count > MAX_INDEX_FIELDS) {
    show_index_error_nr(db, "Max allowed indexed fields",
      MAX_INDEX_FIELDS);
    return -1;
  }

  if(col_count > 1) {
    if(sort_columns(sorted_cols, columns, col_count) < col_count) {
      show_index_error(db, "Duplicate columns not allowed");
      return -1;
    }
  } else {
    sorted_cols[0] = columns[0];
  }

  for(i=0; i<col_count; i++) {
    if(sorted_cols[i] > MAX_INDEXED_FIELDNR) {
      show_index_error_nr(db, "Max allowed column number",
        MAX_INDEXED_FIELDNR);
      return -1;
    }
  }

  /* Find all indexes on the first column */
  ilist = &dbh->index_control_area_header.index_table[sorted_cols[0]];
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car) {
      wg_index_header *hdr = \
        (wg_index_header *) offsettoptr(db, ilistelem->car);
#ifndef USE_INDEX_TEMPLATE
      if(!type || type==hdr->type) {
#else
      if((!type || type==hdr->type) &&\
         hdr->template_offset == template_offset) {
#endif
        if(hdr->fields == col_count) {
          for(i=0; i<col_count; i++) {
            if(hdr->rec_field_index[i]!=sorted_cols[i])
              goto nextindex;
          }
          return ilistelem->car; /* index id */
        }
      }
    }
nextindex:
    ilist = &ilistelem->cdr;
  }

  return -1;
}

/** Return index type by index id
*
*  returns:
*  -1 if no index found
*  type >= 0 if index found
*/
gint wg_get_index_type(void *db, gint index_id) {
  wg_index_header *hdr = NULL;
  gint *ilist;
  gcell *ilistelem;
  db_memsegment_header* dbh = dbmemsegh(db);

  /* Locate the header */
  ilist = &dbh->index_control_area_header.index_list;
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car == index_id) {
      hdr = (wg_index_header *) offsettoptr(db, index_id);
      break;
    }
    ilist = &ilistelem->cdr;
  }

  if(!hdr) {
    show_index_error_nr(db, "Invalid index_id", index_id);
    return -1;
  }

  return hdr->type;
}

/** Return index template by index id
*
* Returns a pointer to the gint array used for the index template.
* reclen is set to the length of the array. The pointer may not
* be freed and it's contents should be accessed read-only.
*
* If the index is not found or has no template, NULL is returned.
* In that case contents of *reclen are unmodified.
*/
void * wg_get_index_template(void *db, gint index_id, gint *reclen) {
#ifdef USE_INDEX_TEMPLATE
  wg_index_header *hdr = NULL;
  gint *ilist;
  gcell *ilistelem;
  db_memsegment_header* dbh = dbmemsegh(db);
  wg_index_template *tmpl = NULL;
  void *matchrec;

  /* Locate the header */
  ilist = &dbh->index_control_area_header.index_list;
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car == index_id) {
      hdr = (wg_index_header *) offsettoptr(db, index_id);
      break;
    }
    ilist = &ilistelem->cdr;
  }

  if(!hdr) {
    show_index_error_nr(db, "Invalid index_id", index_id);
    return NULL;
  }

  if(!hdr->template_offset) {
    return NULL;
  }

  tmpl = (wg_index_template *) offsettoptr(db, hdr->template_offset);

#ifdef CHECK
  if(!tmpl->offset_matchrec) {
    show_index_error(db, "Invalid match record template");
    return NULL;
  }
#endif

  matchrec = offsettoptr(db, tmpl->offset_matchrec);
  *reclen = wg_get_record_len(db, matchrec);
  return wg_get_record_dataarray(db, matchrec);
#else
  return NULL;
#endif
}

/** Return all indexes in database.
*
* Returns a pointer to a NEW allocated array of index id-s.
* count is initialized to the number of indexes in the array.
*
* Returns NULL if there are no indexes.
*/
void * wg_get_all_indexes(void *db, gint *count) {
  int column;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint *ilist;
  gint *res;

  *count = 0;
  if(!dbh->index_control_area_header.number_of_indexes) {
    return NULL;
  }

  res = (gint *) malloc(dbh->index_control_area_header.number_of_indexes *\
    sizeof(gint));

  if(!res) {
    show_index_error(db, "Memory allocation failed");
    return NULL;
  }

  for(column=0; column<=MAX_INDEXED_FIELDNR; column++) {
    ilist = &dbh->index_control_area_header.index_table[column];
    while(*ilist) {
      gcell *ilistelem = (gcell *) offsettoptr(db, *ilist);
      if(ilistelem->car) {
        res[(*count)++] = ilistelem->car;
      }
      ilist = &ilistelem->cdr;
    }
  }

  if(*count != dbh->index_control_area_header.number_of_indexes) {
    show_index_error(db, "Index control area is corrupted");
    free(res);
    return NULL;
  }
  return res;
}

#define INDEX_ADD_ROW(d, h, i, r) \
  switch(h->type) { \
    case WG_INDEX_TYPE_TTREE: \
      if(ttree_add_row(d, i, r)) \
        return -2; \
      break; \
    case WG_INDEX_TYPE_TTREE_JSON: \
      if(is_plain_record(r)) { \
        if(ttree_add_row(d, i, r)) \
          return -2; \
      } \
      break; \
    case WG_INDEX_TYPE_HASH: \
      if(hash_add_row(d, i, r)) \
        return -2; \
      break; \
    case WG_INDEX_TYPE_HASH_JSON: \
      if(is_plain_record(r)) { \
        if(hash_add_row(d, i, r)) \
          return -2; \
      } \
      break; \
    default: \
      show_index_error(db, "unknown index type, ignoring"); \
      break; \
  }

#define INDEX_REMOVE_ROW(d, h, i, r) \
  switch(h->type) { \
    case WG_INDEX_TYPE_TTREE: \
      if(ttree_remove_row(d, i, r) < -2) \
        return -2; \
      break; \
    case WG_INDEX_TYPE_TTREE_JSON: \
      if(is_plain_record(r)) { \
        if(ttree_remove_row(d, i, r) < -2) \
          return -2; \
      } \
      break; \
    case WG_INDEX_TYPE_HASH: \
      if(hash_remove_row(d, i, r) < -2) \
        return -2; \
      break; \
    case WG_INDEX_TYPE_HASH_JSON: \
      if(is_plain_record(r)) { \
        if(hash_remove_row(d, i, r) < -2) \
          return -2; \
      } \
      break; \
    default: \
      show_index_error(db, "unknown index type, ignoring"); \
      break; \
  }

/** Add data of one field to all indexes
 * Loops over indexes in one field and inserts the data into
 * each one of them.
 * returns 0 for success
 * returns -1 for invalid arguments
 * returns -2 for error (insert failed, index is no longer consistent)
 */
gint wg_index_add_field(void *db, void *rec, gint column) {
  gint *ilist;
  gcell *ilistelem;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint reclen = wg_get_record_len(db, rec);

#ifdef CHECK
  /* XXX: if used from wg_set_field() only, this is redundant */
  if(column > MAX_INDEXED_FIELDNR || column >= reclen)
    return -1;
  if(is_special_record(rec))
    return -1;
#endif

#if 0
  /* XXX: if used from wg_set_field() only, this is redundant */
  if(!dbh->index_control_area_header.index_table[column])
    return -1;
#endif

  ilist = &dbh->index_control_area_header.index_table[column];
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car) {
      wg_index_header *hdr = \
        (wg_index_header *) offsettoptr(db, ilistelem->car);
      if(reclen > hdr->rec_field_index[hdr->fields - 1]) {
        if(MATCH_TEMPLATE(db, hdr, rec)) {
          INDEX_ADD_ROW(db, hdr, ilistelem->car, rec)
        }
      }
    }
    ilist = &ilistelem->cdr;
  }

#ifdef USE_INDEX_TEMPLATE
  /* Other candidates are indexes that have match
   * records. The current record may have become compatible
   * with their template.
   */
  ilist = &dbh->index_control_area_header.index_template_table[column];
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car) {
      wg_index_header *hdr = \
        (wg_index_header *) offsettoptr(db, ilistelem->car);
      if(reclen > hdr->rec_field_index[hdr->fields - 1]) {
        if(MATCH_TEMPLATE(db, hdr, rec)) {
          INDEX_ADD_ROW(db, hdr, ilistelem->car, rec)
        }
      }
    }
    ilist = &ilistelem->cdr;
  }
#endif

  return 0;
}

/** Add data of one record to all indexes
 * Convinience function to add an entire record into
 * all indexes in the database.
 * returns 0 on success, -2 on error
 * (-1 is skipped to have consistent error codes for add/del functions)
 */
gint wg_index_add_rec(void *db, void *rec) {
  gint i;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint reclen = wg_get_record_len(db, rec);

#ifdef CHECK
  if(is_special_record(rec))
    return -1;
#endif

  if(reclen > MAX_INDEXED_FIELDNR)
    reclen = MAX_INDEXED_FIELDNR + 1;

  for(i=0;i<reclen;i++){
    gint *ilist;
    gcell *ilistelem;

    /* Find all indexes on the column */
    ilist = &dbh->index_control_area_header.index_table[i];
    while(*ilist) {
      ilistelem = (gcell *) offsettoptr(db, *ilist);
      if(ilistelem->car) {
        wg_index_header *hdr = \
          (wg_index_header *) offsettoptr(db, ilistelem->car);
        if(hdr->rec_field_index[hdr->fields - 1] == i) {
          /* Only add the record if we're at the last column
           * of the index. This way we ensure that a.) a record
           * is entered once into a multi-column index and b.) the
           * record is long enough so that it qualifies for the
           * multi-column index.
           * For a single-column index, the indexed column is
           * also the last column, therefore the above is valid,
           * altough the check is unnecessary.
           */
          if(MATCH_TEMPLATE(db, hdr, rec)) {
            INDEX_ADD_ROW(db, hdr, ilistelem->car, rec)
          }
        }
      }
      ilist = &ilistelem->cdr;
    }

#ifdef USE_INDEX_TEMPLATE
    ilist = &dbh->index_control_area_header.index_template_table[i];
    while(*ilist) {
      ilistelem = (gcell *) offsettoptr(db, *ilist);
      if(ilistelem->car) {
        wg_index_header *hdr = \
          (wg_index_header *) offsettoptr(db, ilistelem->car);
        wg_index_template *tmpl = \
          (wg_index_template *) offsettoptr(db, hdr->template_offset);
        void *matchrec;
        gint mreclen;
        int j, firstmatch = -1;

        /* Here the check for a match is slightly more complicated.
         * If there is a match *but* the current column is not the
         * first fixed one in the template, the match has
         * already occurred earlier.
         */
        matchrec = offsettoptr(db, tmpl->offset_matchrec);
        mreclen = wg_get_record_len(db, matchrec);
        if(mreclen > reclen) {
          goto nexttmpl1;
        }
        for(j=0; j<mreclen; j++) {
          gint enc = wg_get_field(db, matchrec, j);
          if(wg_get_encoded_type(db, enc) != WG_VARTYPE) {
            if(WG_COMPARE(db, enc, wg_get_field(db, rec, j)) != WG_EQUAL)
              goto nexttmpl1;
            if(firstmatch < 0)
              firstmatch = j;
          }
        }
        if(firstmatch==i &&\
          reclen > hdr->rec_field_index[hdr->fields - 1]) {
          /* The record matches AND this is the first time we
           * see this index. Update it.
           */
          INDEX_ADD_ROW(db, hdr, ilistelem->car, rec)
        }
      }
nexttmpl1:
      ilist = &ilistelem->cdr;
    }
#endif

  }
  return 0;
}

/** Delete data of one field from all indexes
 * Loops over indexes in one column and removes the references
 * to the record from all of them.
 * returns 0 for success
 * returns -1 for invalid arguments
 * returns -2 for error (delete failed, possible index corruption)
 */
gint wg_index_del_field(void *db, void *rec, gint column) {
  gint *ilist;
  gcell *ilistelem;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint reclen = wg_get_record_len(db, rec);

#ifdef CHECK
  /* XXX: if used from wg_set_field() only, this is redundant */
  if(column > MAX_INDEXED_FIELDNR || column >= reclen)
    return -1;
  if(is_special_record(rec))
    return -1;
#endif

#if 0
  /* XXX: if used from wg_set_field() only, this is redundant */
  if(!dbh->index_control_area_header.index_table[column])
    return -1;
#endif

  /* Find all indexes on the column */
  ilist = &dbh->index_control_area_header.index_table[column];
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car) {
      wg_index_header *hdr = \
        (wg_index_header *) offsettoptr(db, ilistelem->car);

      if(reclen > hdr->rec_field_index[hdr->fields - 1]) {
        if(MATCH_TEMPLATE(db, hdr, rec)) {
          INDEX_REMOVE_ROW(db, hdr, ilistelem->car, rec)
        }
      }
    }
    ilist = &ilistelem->cdr;
  }

#ifdef USE_INDEX_TEMPLATE
  /* Find all indexes on the column */
  ilist = &dbh->index_control_area_header.index_template_table[column];
  while(*ilist) {
    ilistelem = (gcell *) offsettoptr(db, *ilist);
    if(ilistelem->car) {
      wg_index_header *hdr = \
        (wg_index_header *) offsettoptr(db, ilistelem->car);

      if(reclen > hdr->rec_field_index[hdr->fields - 1]) {
        if(MATCH_TEMPLATE(db, hdr, rec)) {
          INDEX_REMOVE_ROW(db, hdr, ilistelem->car, rec)
        }
      }
    }
    ilist = &ilistelem->cdr;
  }
#endif

  return 0;
}

/* Delete data of one record from all indexes
 * Should be called from wg_delete_record()
 * returns 0 for success
 * returns -2 for error (delete failed, index presumably corrupt)
 */
gint wg_index_del_rec(void *db, void *rec) {
  gint i;
  db_memsegment_header* dbh = dbmemsegh(db);
  gint reclen = wg_get_record_len(db, rec);

#ifdef CHECK
  if(is_special_record(rec))
    return -1;
#endif

  if(reclen > MAX_INDEXED_FIELDNR)
    reclen = MAX_INDEXED_FIELDNR + 1;

  for(i=0;i<reclen;i++){
    gint *ilist;
    gcell *ilistelem;

    /* Find all indexes on the column */
    ilist = &dbh->index_control_area_header.index_table[i];
    while(*ilist) {
      ilistelem = (gcell *) offsettoptr(db, *ilist);
      if(ilistelem->car) {
        wg_index_header *hdr = \
          (wg_index_header *) offsettoptr(db, ilistelem->car);
        if(hdr->rec_field_index[hdr->fields - 1] == i) {
          /* Only update once per index. See also comment for
           * wg_index_add_rec function.
           */
          if(MATCH_TEMPLATE(db, hdr, rec)) {
            INDEX_REMOVE_ROW(db, hdr, ilistelem->car, rec)
          }
        }
      }
      ilist = &ilistelem->cdr;
    }

#ifdef USE_INDEX_TEMPLATE
    ilist = &dbh->index_control_area_header.index_template_table[i];
    while(*ilist) {
      ilistelem = (gcell *) offsettoptr(db, *ilist);
      if(ilistelem->car) {
        wg_index_header *hdr = \
          (wg_index_header *) offsettoptr(db, ilistelem->car);
        wg_index_template *tmpl = \
          (wg_index_template *) offsettoptr(db, hdr->template_offset);
        void *matchrec;
        gint mreclen;
        int j, firstmatch = -1;

        /* Similar check as in wg_index_add_rec() */
        matchrec = offsettoptr(db, tmpl->offset_matchrec);
        mreclen = wg_get_record_len(db, matchrec);
        if(mreclen > reclen) {
          goto nexttmpl2; /* no match */
        }
        for(j=0; j<mreclen; j++) {
          gint enc = wg_get_field(db, matchrec, j);
          if(wg_get_encoded_type(db, enc) != WG_VARTYPE) {
            if(WG_COMPARE(db, enc, wg_get_field(db, rec, j)) != WG_EQUAL)
              goto nexttmpl2;
            if(firstmatch < 0)
              firstmatch = j;
          }
        }
        if(firstmatch==i &&\
          reclen > hdr->rec_field_index[hdr->fields - 1]) {
          /* The record matches AND this is the first time we
           * see this index. Update it.
           */
          INDEX_REMOVE_ROW(db, hdr, ilistelem->car, rec)
        }
      }
nexttmpl2:
      ilist = &ilistelem->cdr;
    }
#endif

  }
  return 0;
}

/* --------------- error handling ------------------------------*/

/** called with err msg
*
*  may print or log an error
*  does not do any jumps etc
*/

static gint show_index_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"index error: %s\n",errmsg);
#endif
  return -1;
}

/** called with err msg and additional int data
*
*  may print or log an error
*  does not do any jumps etc
*/

static gint show_index_error_nr(void* db, char* errmsg, gint nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"index error: %s %d\n", errmsg, (int) nr);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010,2011,2012,2013
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbcompare.c
 * Data comparison functions.
 */

/* ====== Includes =============== */

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

//data.h"

/* ====== Private headers and defs ======== */

//compare.h"

/* ====== Functions ============== */

/** Compare two encoded values
 * a, b - encoded values
 * returns WG_GREATER, WG_EQUAL or WG_LESSTHAN
 * assumes that a and b themselves are not equal and so
 * their decoded values need to be examined (which could still
 * be equal for some data types).
 * depth - recursion depth for records
 */
gint wg_compare(void *db, gint a, gint b, int depth) {
/* a very simplistic version of the function:
 * - we get the types of the variables
 * - if the types match, compare the decoded values
 * - otherwise compare the type codes (not really scientific,
 *   but will provide a means of ordering values).
 *
 * One important point that should be observed here is
 * that the returned values should be consistent when
 * comparing A to B and then B to A. This applies to cases
 * where we have no reason to think one is greater than
 * the other from the *user's* point of view, but for use
 * in T-tree index and similar, values need to be consistently
 * ordered. Examples include unknown types and record pointers
 * (once recursion depth runs out).
 */

  /* XXX: might be able to save time here to mask and compare
   * the type bits instead */
  gint typea = wg_get_encoded_type(db, a);
  gint typeb = wg_get_encoded_type(db, b);

  /* assume types are >2 (NULLs are always equal) and
   * <13 (not implemented as of now)
   * XXX: all of this will fall apart if type codes
   * are somehow rearranged :-) */
  if(typeb==typea) {
    if(typea>WG_CHARTYPE) { /* > 9, not a string */
      if(typea>WG_FIXPOINTTYPE) {
        /* date or time. Compare decoded gints */
        gint deca, decb;
        if(typea==WG_DATETYPE) {
          deca = wg_decode_date(db, a);
          decb = wg_decode_date(db, b);
        } else if(typea==WG_TIMETYPE) {
          deca = wg_decode_time(db, a);
          decb = wg_decode_time(db, b);
        } else if(typea==WG_VARTYPE) {
          deca = wg_decode_var(db, a);
          decb = wg_decode_var(db, b);
        } else {
          /* anon const or other new type, no idea how to compare */
          return (a>b ? WG_GREATER : WG_LESSTHAN);
        }
        return (deca>decb ? WG_GREATER : WG_LESSTHAN);
      } else {
        /* fixpoint, need to compare doubles */
        double deca, decb;
        deca = wg_decode_fixpoint(db, a);
        decb = wg_decode_fixpoint(db, b);
        return (deca>decb ? WG_GREATER : WG_LESSTHAN);
      }
    }
    else if(typea<WG_STRTYPE) { /* < 5, still not a string */
      if(typea==WG_RECORDTYPE) {
        void *deca, *decb;
        deca = wg_decode_record(db, a);
        decb = wg_decode_record(db, b);

        if(!depth) {
          /* No more recursion allowed and pointers aren't equal.
           * So while we're technically comparing the addresses here,
           * the main point is that the returned value != WG_EQUAL
           */
          return ((gint) deca> (gint) decb ? WG_GREATER : WG_LESSTHAN);
        }
        else {
          int i;
#ifdef USE_CHILD_DB
          void *parenta, *parentb;
#endif
          int lena = wg_get_record_len(db, deca);
          int lenb = wg_get_record_len(db, decb);

#ifdef USE_CHILD_DB
          /* Determine, if the records are inside the memory area beloning
           * to our current base address. If it is outside, the encoded
           * values inside the record contain offsets in relation to
           * a different base address and need to be translated.
           */
          parenta = wg_get_rec_owner(db, deca);
          parentb = wg_get_rec_owner(db, decb);
#endif

          /* XXX: Currently we're considering records of differing lengths
           * non-equal without comparing the elements
           */
          if(lena!=lenb)
            return (lena>lenb ? WG_GREATER : WG_LESSTHAN);

          /* Recursively check each element in the record. If they
           * are not equal, break and return with the obtained value
           */
          for(i=0; i<lena; i++) {
            gint elema = wg_get_field(db, deca, i);
            gint elemb = wg_get_field(db, decb, i);

#ifdef USE_CHILD_DB
            if(parenta != dbmemseg(db)) {
              elema = wg_translate_hdroffset(db, parenta, elema);
            }
            if(parentb != dbmemseg(db)) {
              elemb = wg_translate_hdroffset(db, parentb, elemb);
            }
#endif

            if(elema != elemb) {
              gint cr = wg_compare(db, elema, elemb, depth - 1);
              if(cr != WG_EQUAL)
                return cr;
            }
          }
          return WG_EQUAL; /* all elements matched */
        }
      }
      else if(typea==WG_INTTYPE) {
        gint deca, decb;
        deca = wg_decode_int(db, a);
        decb = wg_decode_int(db, b);
        if(deca==decb) return WG_EQUAL; /* large ints can be equal */
        return (deca>decb ? WG_GREATER : WG_LESSTHAN);
      } else {
        /* WG_DOUBLETYPE */
        double deca, decb;
        deca = wg_decode_double(db, a);
        decb = wg_decode_double(db, b);
        if(deca==decb) return WG_EQUAL; /* decoded doubles can be equal */
        return (deca>decb ? WG_GREATER : WG_LESSTHAN);
      }
    }
    else { /* string */
      /* Need to compare the characters. In case of 0-terminated
       * strings we use strcmp() directly, which in glibc is heavily
       * optimised. In case of blob type we need to query the length
       * and use memcmp().
       */
      char *deca, *decb, *exa=NULL, *exb=NULL;
      char buf[4];
      gint res;
      if(typea==WG_STRTYPE) {
        /* lang is ignored */
        deca = wg_decode_str(db, a);
        decb = wg_decode_str(db, b);
      }
      else if(typea==WG_URITYPE) {
        exa = wg_decode_uri_prefix(db, a);
        exb = wg_decode_uri_prefix(db, b);
        deca = wg_decode_uri(db, a);
        decb = wg_decode_uri(db, b);
      }
      else if(typea==WG_XMLLITERALTYPE) {
        exa = wg_decode_xmlliteral_xsdtype(db, a);
        exb = wg_decode_xmlliteral_xsdtype(db, b);
        deca = wg_decode_xmlliteral(db, a);
        decb = wg_decode_xmlliteral(db, b);
      }
      else if(typea==WG_CHARTYPE) {
        buf[0] = wg_decode_char(db, a);
        buf[1] = '\0';
        buf[2] = wg_decode_char(db, b);
        buf[3] = '\0';
        deca = buf;
        decb = &buf[2];
      }
      else { /* WG_BLOBTYPE */
        deca = wg_decode_blob(db, a);
        decb = wg_decode_blob(db, b);
      }

      if(exa || exb) {
        /* String type where extra information is significant
         * (we're ignoring this for plain strings and blobs).
         * If extra part is equal, normal comparison continues. If
         * one string is missing altogether, it is considered to be
         * smaller than the other string.
         */
        if(!exb) {
          if(exa[0])
            return WG_GREATER;
        } else if(!exa) {
          if(exb[0])
            return WG_LESSTHAN;
        } else {
          res = strcmp(exa, exb);
          if(res > 0) return WG_GREATER;
          else if(res < 0) return WG_LESSTHAN;
        }
      }

#if 0 /* paranoia check */
      if(!deca || !decb) {
        if(decb)
          if(decb[0])
            return WG_LESSTHAN;
        } else if(deca) {
          if(deca[0])
            return WG_GREATER;
        }
        return WG_EQUAL;
      }
#endif

      if(typea==WG_BLOBTYPE) {
        /* Blobs are not 0-terminated */
        int lena = wg_decode_blob_len(db, a);
        int lenb = wg_decode_blob_len(db, b);
        res = memcmp(deca, decb, (lena < lenb ? lena : lenb));
        if(!res) res = lena - lenb;
      } else {
        res = strcmp(deca, decb);
      }
      if(res > 0) return WG_GREATER;
      else if(res < 0) return WG_LESSTHAN;
      else return WG_EQUAL;
    }
  }
  else
    return (typea>typeb ? WG_GREATER : WG_LESSTHAN);
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010,2011,2013,2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbquery.c
 * WhiteDB query engine.
 */

/* ====== Includes =============== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ====== Private headers and defs ======== */

#ifdef __cplusplus
extern "C" {
#endif

//alloc.h"
//query.h"
//compare.h"
//mpool.h"
//schema.h"
//hash.h"

/* T-tree based scoring */
#define TTREE_SCORE_EQUAL 5
#define TTREE_SCORE_BOUND 2
#define TTREE_SCORE_NULL -1 /** penalty for null values, which
                             *  are likely to be abundant */
#define TTREE_SCORE_MASK 5  /** matching field in template */

/* Query flags for internal use */
#define QUERY_FLAGS_PREFETCH 0x1000

#define QUERY_RESULTSET_PAGESIZE 63  /* mpool is aligned, so we can align
                                      * the result pages too by selecting an
                                      * appropriate size */

/* Emulate array index when doing a scan of key-value pairs
 * in a JSON query.
 * If this is not desirable, commenting this out makes
 * scans somewhat faster.
 */
#define JSON_SCAN_UNWRAP_ARRAY

struct __query_result_page {
  gint rows[QUERY_RESULTSET_PAGESIZE];
  struct __query_result_page *next;
};

typedef struct __query_result_page query_result_page;

typedef struct {
  query_result_page *page;        /** current page of results */
  gint pidx;                      /** current index on page (reading) */
} query_result_cursor;

typedef struct {
  void *mpool;                    /** storage for row offsets */
  query_result_page *first_page;  /** first page of results, for rewinding */
  query_result_cursor wcursor;    /** read cursor */
  query_result_cursor rcursor;    /** write cursor */
  gint res_count;                 /** number of rows in results */
} query_result_set;

/* ======= Private protos ================ */

static gint most_restricting_column(void *db,
  wg_query_arg *arglist, gint argc, gint *index_id);
static gint check_arglist(void *db, void *rec, wg_query_arg *arglist,
  gint argc);
static gint prepare_params(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc,
  wg_query_arg **farglist, gint *fargc);
static gint find_ttree_bounds(void *db, gint index_id, gint col,
  gint start_bound, gint end_bound, gint start_inclusive, gint end_inclusive,
  gint *curr_offset, gint *curr_slot, gint *end_offset, gint *end_slot);
static wg_query *internal_build_query(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc, gint flags, wg_uint rowlimit);

static query_result_set *create_resultset(void *db);
static void free_resultset(void *db, query_result_set *set);
static void rewind_resultset(void *db, query_result_set *set);
static gint append_resultset(void *db, query_result_set *set, gint offset);
static gint fetch_resultset(void *db, query_result_set *set);
static query_result_set *intersect_resultset(void *db,
  query_result_set *seta, query_result_set *setb);
static gint check_and_merge_by_kv(void *db, void *rec,
  wg_json_query_arg *arg, query_result_set *next_set);
static gint check_and_merge_by_key(void *db, void *rec,
  wg_json_query_arg *arg, query_result_set *next_set);
static gint check_and_merge_recursively(void *db, void *rec,
  wg_json_query_arg *arg, query_result_set *next_set, int depth);
static gint prepare_json_arglist(void *db, wg_json_query_arg *arglist,
  wg_json_query_arg **sorted_arglist, gint argc,
  gint *index_id, gint *vindex_id, gint *kindex_id);

static gint encode_query_param_unistr(void *db, char *data, gint type,
  char *extdata, int length);

static gint show_query_error(void* db, char* errmsg);
/*static gint show_query_error_nr(void* db, char* errmsg, gint nr);*/

/* ====== Functions ============== */



/** Find most restricting column from query argument list
 *  This is probably a reasonable approach to optimize queries
 *  based on T-tree indexes, but might be difficult to combine
 *  with hash indexes.
 *  XXX: currently only considers the existence of T-tree
 *  index and nothing else.
 */
static gint most_restricting_column(void *db,
  wg_query_arg *arglist, gint argc, gint *index_id) {

  struct column_score {
    gint column;
    int score;
    int index_id;
  };
  struct column_score *sc;
  int i, j, mrc_score = -1;
  gint mrc = -1;
  db_memsegment_header* dbh = dbmemsegh(db);

  sc = (struct column_score *) malloc(argc * sizeof(struct column_score));
  if(!sc) {
    show_query_error(db, "Failed to allocate memory");
    return -1;
  }

  /* Scan through the arguments and calculate accumulated score
   * for each column. */
  for(i=0; i<argc; i++) {
    /* As a side effect, we're initializing the score array
     * in the same loop */
    sc[i].column = -1;
    sc[i].score = 0;
    sc[i].index_id = 0;

    /* Locate the slot for the column */
    for(j=0; j<argc; j++) {
      if(sc[j].column == -1) {
        sc[j].column = arglist[i].column;
        break;
      }
      if(sc[j].column == arglist[i].column) break;
    }

    /* Apply our primitive scoring */
    switch(arglist[i].cond) {
      case WG_COND_EQUAL:
        sc[j].score += TTREE_SCORE_EQUAL;
        if(arglist[i].value == 0) /* NULL values get a small penalty */
          sc[j].score += TTREE_SCORE_NULL;
        break;
      case WG_COND_LESSTHAN:
      case WG_COND_GREATER:
      case WG_COND_LTEQUAL:
      case WG_COND_GTEQUAL:
        /* these all qualify as a bound. So two bounds
         * appearing in the argument list on the same column
         * score higher than one bound. */
        sc[j].score += TTREE_SCORE_BOUND;
        break;
      default:
        /* Note that we consider WG_COND_NOT_EQUAL near useless */
        break;
    }
  }

  /* Now loop over the scores to find the best. */
  for(i=0; i<argc; i++) {
    if(sc[i].column == -1) break;
    /* Find the index on the column. The score is modified by the
     * estimated quality of the index (0 if no index found).
     */
    if(sc[i].column <= MAX_INDEXED_FIELDNR) {
      gint *ilist = &dbh->index_control_area_header.index_table[sc[i].column];
      while(*ilist) {
        gcell *ilistelem = (gcell *) offsettoptr(db, *ilist);
        if(ilistelem->car) {
          wg_index_header *hdr = \
            (wg_index_header *) offsettoptr(db, ilistelem->car);

          if(hdr->type == WG_INDEX_TYPE_TTREE) {
#ifdef USE_INDEX_TEMPLATE
            /* If index templates are available, we can increase the
             * score of the index if the template has any columns matching
             * the query parameters. On the other hand, in case of a
             * mismatch the index is unusable and has to be skipped.
             * The indexes are sorted in the order of fixed columns in
             * the template, so if there is a match, the search is
             * complete (remaining index are likely to be worse)
             */
            if(hdr->template_offset) {
              wg_index_template *tmpl = \
                (wg_index_template *) offsettoptr(db, hdr->template_offset);
              void *matchrec = offsettoptr(db, tmpl->offset_matchrec);
              gint reclen = wg_get_record_len(db, matchrec);
              for(j=0; j<reclen; j++) {
                gint enc = wg_get_field(db, matchrec, j);
                if(wg_get_encoded_type(db, enc) != WG_VARTYPE) {
                  /* defined column in matchrec. The score is increased
                   * if arglist has a WG_COND_EQUAL column with the same
                   * value. In any other case the index is not usable.
                   */
                  int match = 0, k;
                  for(k=0; k<argc; k++) {
                    if(arglist[k].column == j) {
                      if(arglist[k].cond == WG_COND_EQUAL &&\
                        WG_COMPARE(db, enc, arglist[k].value) == WG_EQUAL) {
                        match = 1;
                      }
                      else
                        goto nextindex;
                    }
                  }
                  if(match) {
                    sc[i].score += TTREE_SCORE_MASK;
                    if(!enc)
                      sc[i].score += TTREE_SCORE_NULL;
                  }
                  else
                    goto nextindex;
                }
              }
            }
#endif
            sc[i].index_id = ilistelem->car;
            break;
          }
        }
#ifdef USE_INDEX_TEMPLATE
nextindex:
#endif
        ilist = &ilistelem->cdr;
      }
    }
    if(!sc[i].index_id)
      sc[i].score = 0; /* no index, score reset */
    if(sc[i].score > mrc_score) {
      mrc_score = sc[i].score;
      mrc = sc[i].column;
      *index_id = sc[i].index_id;
    }
  }

  /* TODO: does the best score have no index? In that case,
   * try to locate an index that would restrict at least
   * some columns.
   */
  free(sc);
  return mrc;
}

/** Check a record against list of conditions
 *  returns 1 if the record matches
 *  returns 0 if the record fails at least one condition
 */
static gint check_arglist(void *db, void *rec, wg_query_arg *arglist,
  gint argc) {

  int i, reclen;

  reclen = wg_get_record_len(db, rec);
  for(i=0; i<argc; i++) {
    gint encoded;
    if(arglist[i].column < reclen)
      encoded = wg_get_field(db, rec, arglist[i].column);
    else
      return 0; /* XXX: should shorter records always fail?
                 * other possiblities here: compare to WG_ILLEGAL
                 * or WG_NULLTYPE. Current idea is based on SQL
                 * concept of comparisons to NULL always failing.
                 */

    switch(arglist[i].cond) {
      case WG_COND_EQUAL:
        if(WG_COMPARE(db, encoded, arglist[i].value) != WG_EQUAL)
          return 0;
        break;
      case WG_COND_LESSTHAN:
        if(WG_COMPARE(db, encoded, arglist[i].value) != WG_LESSTHAN)
          return 0;
        break;
      case WG_COND_GREATER:
        if(WG_COMPARE(db, encoded, arglist[i].value) != WG_GREATER)
          return 0;
        break;
      case WG_COND_LTEQUAL:
        if(WG_COMPARE(db, encoded, arglist[i].value) == WG_GREATER)
          return 0;
        break;
      case WG_COND_GTEQUAL:
        if(WG_COMPARE(db, encoded, arglist[i].value) == WG_LESSTHAN)
          return 0;
        break;
      case WG_COND_NOT_EQUAL:
        if(WG_COMPARE(db, encoded, arglist[i].value) == WG_EQUAL)
          return 0;
        break;
      default:
        break;
    }
  }

  return 1;
}

/** Prepare query parameters
 *
 * - Validates matchrec and arglist
 * - Converts external pointers to locally allocated data
 * - Builds an unified argument list
 *
 * Returns 0 on success, non-0 on error.
 *
 * If the function was successful, *farglist will be set to point
 * to a newly allocated unified argument list and *fargc will be set
 * to indicate the size of *farglist.
 *
 * If there was an error, *farglist and *fargc may be in
 * an undetermined state.
 */
static gint prepare_params(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc,
  wg_query_arg **farglist, gint *fargc) {
  int i;

  if(matchrec) {
    /* Get the correct length of matchrec data area and the pointer
     * to the beginning of the data. If matchrec is a plain array in
     * local memory (indicated by NON-zero reclen) we will skip this step.
     */
    if(!reclen) {
      reclen = wg_get_record_len(db, matchrec);
      matchrec = wg_get_record_dataarray(db, matchrec);
    }
#ifdef CHECK
    if(!reclen) {
      show_query_error(db, "Zero-length match record argument");
      return -1;
    }
#endif
  }

#ifdef CHECK
  if(arglist && !argc) {
    show_query_error(db, "Zero-length argument list");
    return -1;
  }
  if(!arglist && argc) {
    show_query_error(db, "Invalid argument list (NULL)");
    return -1;
  }
#endif

  /* Determine total number of query parameters (number of arguments
   * in arglist and non-wildcard fields of matchrec).
   */
  *fargc = argc;
  if(matchrec) {
    for(i=0; i<reclen; i++) {
      if(wg_get_encoded_type(db, ((gint *) matchrec)[i]) != WG_VARTYPE)
        (*fargc)++;
    }
  }

  if(*fargc) {
    wg_query_arg *tmp = NULL;

    /* The simplest way to treat matchrec is to convert it to
     * arglist. While doing this, we will create a local copy of the
     * argument list, which has the side effect of allowing the caller
     * to free the original arglist after wg_make_query() returns. The
     * local copy will be attached to the query object and needs to
     * survive beyond that.
     */
    tmp = (wg_query_arg *) malloc(*fargc * sizeof(wg_query_arg));
    if(!tmp) {
      show_query_error(db, "Failed to allocate memory");
      return -2;
    }

    /* Copy the arglist contents */
    for(i=0; i<argc; i++) {
      tmp[i].column = arglist[i].column;
      tmp[i].cond = arglist[i].cond;
      tmp[i].value = arglist[i].value;
    }

    /* Append the matchrec data */
    if(matchrec) {
      int j;
      for(i=0, j=argc; i<reclen; i++) {
        if(wg_get_encoded_type(db, ((gint *) matchrec)[i]) != WG_VARTYPE) {
          tmp[j].column = i;
          tmp[j].cond = WG_COND_EQUAL;
          tmp[j++].value = ((gint *) matchrec)[i];
        }
      }
    }

    *farglist = tmp;
  }
  else {
    *farglist = NULL;
  }

  return 0;
}

/*
 * Locate the node offset and slot for start and end bound
 * in a T-tree index.
 *
 * return -1 on error
 * return 0 on success
 */
static gint find_ttree_bounds(void *db, gint index_id, gint col,
  gint start_bound, gint end_bound, gint start_inclusive, gint end_inclusive,
  gint *curr_offset, gint *curr_slot, gint *end_offset, gint *end_slot)
{
  /* hold the offsets temporarily */
  gint co = *curr_offset;
  gint cs = *curr_slot;
  gint eo = *end_offset;
  gint es = *end_slot;
  wg_index_header *hdr = (wg_index_header *) offsettoptr(db, index_id);
  struct wg_tnode *node;

  if(start_bound==WG_ILLEGAL) {
    /* Find leftmost node in index */
#ifdef TTREE_CHAINED_NODES
    co = TTREE_MIN_NODE(hdr);
#else
    /* LUB node search function has the useful property
     * of returning the leftmost node when called directly
     * on index root node */
    co = wg_ttree_find_lub_node(db, TTREE_ROOT_NODE(hdr));
#endif
    cs = 0; /* leftmost slot */
  } else {
    gint boundtype;

    if(start_inclusive) {
      /* In case of inclusive range, we get the leftmost
       * node for the given value and the first slot that
       * is equal or greater than the given value.
       */
      co = wg_search_ttree_leftmost(db,
        TTREE_ROOT_NODE(hdr), start_bound, &boundtype, NULL);
      if(boundtype == REALLY_BOUNDING_NODE) {
        cs = wg_search_tnode_first(db, co, start_bound, col);
        if(cs == -1) {
          show_query_error(db, "Starting index node was bad");
          return -1;
        }
      } else if(boundtype == DEAD_END_RIGHT_NOT_BOUNDING) {
        /* No exact match, but the next node should be in
         * range. */
        node = (struct wg_tnode *) offsettoptr(db, co);
        co = TNODE_SUCCESSOR(db, node);
        cs = 0;
      } else if(boundtype == DEAD_END_LEFT_NOT_BOUNDING) {
        /* Simplest case, values that are in range start
         * with this node. */
        cs = 0;
      }
    } else {
      /* For non-inclusive, we need the rightmost node and
       * the last slot+1. The latter may overflow into next node.
       */
      co = wg_search_ttree_rightmost(db,
        TTREE_ROOT_NODE(hdr), start_bound, &boundtype, NULL);
      if(boundtype == REALLY_BOUNDING_NODE) {
        cs = wg_search_tnode_last(db, co, start_bound, col);
        if(cs == -1) {
          show_query_error(db, "Starting index node was bad");
          return -1;
        }
        cs++;
        node = (struct wg_tnode *) offsettoptr(db, co);
        if(node->number_of_elements <= cs) {
          /* Crossed node boundary */
          co = TNODE_SUCCESSOR(db, node);
          cs = 0;
        }
      } else if(boundtype == DEAD_END_RIGHT_NOT_BOUNDING) {
        /* Since exact value was not found, this case is exactly
         * the same as with the inclusive range. */
        node = (struct wg_tnode *) offsettoptr(db, co);
        co = TNODE_SUCCESSOR(db, node);
        cs = 0;
      } else if(boundtype == DEAD_END_LEFT_NOT_BOUNDING) {
        /* No exact value in tree, same as inclusive range */
        cs = 0;
      }
    }
  }

  /* Finding of the end of the range is more or less opposite
   * of finding the beginning. */
  if(end_bound==WG_ILLEGAL) {
    /* Rightmost node in index */
#ifdef TTREE_CHAINED_NODES
    eo = TTREE_MAX_NODE(hdr);
#else
    /* GLB search on root node returns the rightmost node in tree */
    eo = wg_ttree_find_glb_node(db, TTREE_ROOT_NODE(hdr));
#endif
    if(eo) {
      node = (struct wg_tnode *) offsettoptr(db, eo);
      es = node->number_of_elements - 1; /* rightmost slot */
    }
  } else {
    gint boundtype;

    if(end_inclusive) {
      /* Find the rightmost node with a given value and the
       * righmost slot that is equal or smaller than that value
       */
      eo = wg_search_ttree_rightmost(db,
        TTREE_ROOT_NODE(hdr), end_bound, &boundtype, NULL);
      if(boundtype == REALLY_BOUNDING_NODE) {
        es = wg_search_tnode_last(db, eo, end_bound, col);
        if(es == -1) {
          show_query_error(db, "Ending index node was bad");
          return -1;
        }
      } else if(boundtype == DEAD_END_RIGHT_NOT_BOUNDING) {
        /* Last node containing values in range. */
        node = (struct wg_tnode *) offsettoptr(db, eo);
        es = node->number_of_elements - 1;
      } else if(boundtype == DEAD_END_LEFT_NOT_BOUNDING) {
        /* Previous node should be in range. */
        node = (struct wg_tnode *) offsettoptr(db, eo);
        eo = TNODE_PREDECESSOR(db, node);
        if(eo) {
          node = (struct wg_tnode *) offsettoptr(db, eo);
          es = node->number_of_elements - 1; /* rightmost */
        }
      }
    } else {
      /* For non-inclusive, we need the leftmost node and
       * the first slot-1.
       */
      eo = wg_search_ttree_leftmost(db,
        TTREE_ROOT_NODE(hdr), end_bound, &boundtype, NULL);
      if(boundtype == REALLY_BOUNDING_NODE) {
        es = wg_search_tnode_first(db, eo,
          end_bound, col);
        if(es == -1) {
          show_query_error(db, "Ending index node was bad");
          return -1;
        }
        es--;
        if(es < 0) {
          /* Crossed node boundary */
          node = (struct wg_tnode *) offsettoptr(db, eo);
          eo = TNODE_PREDECESSOR(db, node);
          if(eo) {
            node = (struct wg_tnode *) offsettoptr(db, eo);
            es = node->number_of_elements - 1;
          }
        }
      } else if(boundtype == DEAD_END_RIGHT_NOT_BOUNDING) {
        /* No exact value in tree, same as inclusive range */
        node = (struct wg_tnode *) offsettoptr(db, eo);
        es = node->number_of_elements - 1;
      } else if(boundtype == DEAD_END_LEFT_NOT_BOUNDING) {
        /* No exact value in tree, same as inclusive range */
        node = (struct wg_tnode *) offsettoptr(db, eo);
        eo = TNODE_PREDECESSOR(db, node);
        if(eo) {
          node = (struct wg_tnode *) offsettoptr(db, eo);
          es = node->number_of_elements - 1; /* rightmost slot */
        }
      }
    }
  }

  /* Now detect the cases where the above bound search
   * has produced a result with an empty range.
   */
  if(co) {
    /* Value could be bounded inside a node, but actually
     * not present. Note that we require the end_slot to be
     * >= curr_slot, this implies that query->direction == 1.
     */
    if(eo == co && es < cs) {
      co = 0; /* query will return no rows */
      eo = 0;
    } else if(!eo) {
      /* If one offset is 0 the other should be forced to 0, so that
       * if we want to switch direction we won't run into any surprises.
       */
      co = 0;
    } else {
      /* Another case we have to watch out for is when we have a
       * range that fits in the space between two nodes. In that case
       * the end offset will end up directly left of the start offset.
       */
      node = (struct wg_tnode *) offsettoptr(db, co);
      if(eo == TNODE_PREDECESSOR(db, node)) {
        co = 0; /* no rows */
        eo = 0;
      }
    }
  } else {
    eo = 0; /* again, if one offset is 0,
             * the other should be, too */
  }

  *curr_offset = co;
  *curr_slot = cs;
  *end_offset = eo;
  *end_slot = es;
  return 0;
}

/** Create a query object.
 *
 * matchrec - array of encoded integers. Can be a pointer to a database record
 * or a user-allocated array. If reclen is 0, it is treated as a native
 * database record. If reclen is non-zero, reclen number of gint-sized
 * words is read, starting from the pointer.
 *
 * Fields of type WG_VARTYPE in matchrec are treated as wildcards. Other
 * types, including NULL, are used as "equals" conditions.
 *
 * arglist - array of wg_query_arg objects. The size is must be given
 * by argc.
 *
 * flags - type of query requested and other parameters
 *
 * rowlimit - maximum number of rows fetched. Only has an effect if
 * QUERY_FLAGS_PREFETCH is set.
 *
 * returns NULL if constructing the query fails. Otherwise returns a pointer
 * to a wg_query object.
 */
static wg_query *internal_build_query(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc, gint flags, wg_uint rowlimit) {

  wg_query *query;
  wg_query_arg *full_arglist;
  gint fargc = 0;
  gint col, index_id = -1;
  int i;

#ifdef CHECK
  if (!dbcheck(db)) {
    /* XXX: currently show_query_error would work too */
#ifdef WG_NO_ERRPRINT
#else
    fprintf(stderr, "Invalid database pointer in wg_make_query.\n");
#endif
    return NULL;
  }
#endif

  /* Check and prepare the parameters. If there was an error,
   * prepare_params() does it's own cleanup so we can (and should)
   * return immediately.
   */
  if(prepare_params(db, matchrec, reclen, arglist, argc,
    &full_arglist, &fargc)) {
    return NULL;
  }

  query = (wg_query *) malloc(sizeof(wg_query));
  if(!query) {
    show_query_error(db, "Failed to allocate memory");
    if(full_arglist) free(full_arglist);
    return NULL;
  }

  if(fargc) {
    /* Find the best (hopefully) index to base the query on.
     * Then initialise the query object to the first row in the
     * query result set.
     * XXX: only considering T-tree indexes now. */
    col = most_restricting_column(db, full_arglist, fargc, &index_id);
  }
  else {
    /* Create a "full scan" query with no arguments. */
    index_id = -1;
    full_arglist = NULL; /* redundant/paranoia */
  }

  if(index_id > 0) {
    int start_inclusive = 0, end_inclusive = 0;
    gint start_bound = WG_ILLEGAL; /* encoded values */
    gint end_bound = WG_ILLEGAL;

    query->qtype = WG_QTYPE_TTREE;
    query->column = col;
    query->curr_offset = 0;
    query->curr_slot = -1;
    query->end_offset = 0;
    query->end_slot = -1;
    query->direction = 1;

    /* Determine the bounds for the given column/index.
     *
     * Examples of using rightmost and leftmost bounds in T-tree queries:
     * val = 5  ==>
     *      find leftmost (A) and rightmost (B) nodes that contain value 5.
     *      Follow nodes sequentially from A until B is reached.
     * val > 1 & val < 7 ==>
     *      find rightmost node with value 1 (A). Find leftmost node with
     *      value 7 (B). Find the rightmost value in A that still equals 1.
     *      The value immediately to the right is the beginning of the result
     *      set and the value immediately to the left of the first occurrence
     *      of 7 in B is the end of the result set.
     * val > 1 & val <= 7 ==>
     *      A is the same as above. Find rightmost node with value 7 (B). The
     *      beginning of the result set is the same as above, the end is the
     *      last slot in B with value 7.
     * val <= 1 ==>
     *      find rightmost node with value 1. Find the last (rightmost) slot
     *      containing 1. The result set begins with that value, scan left
     *      until the end of chain is reached.
     */
    for(i=0; i<fargc; i++) {
      if(full_arglist[i].column != col) continue;
      switch(full_arglist[i].cond) {
        case WG_COND_EQUAL:
          /* Set bounds as if we had val >= 1 & val <= 1 */
          if(start_bound==WG_ILLEGAL ||\
            WG_COMPARE(db, start_bound, full_arglist[i].value)==WG_LESSTHAN) {
            start_bound = full_arglist[i].value;
            start_inclusive = 1;
          }
          if(end_bound==WG_ILLEGAL ||\
            WG_COMPARE(db, end_bound, full_arglist[i].value)==WG_GREATER) {
            end_bound = full_arglist[i].value;
            end_inclusive = 1;
          }
          break;
        case WG_COND_LESSTHAN:
          /* No earlier right bound or new end bound is a smaller
           * value (reducing the result set). The result set is also
           * possibly reduced if the value is equal, because this
           * condition is non-inclusive. */
          if(end_bound==WG_ILLEGAL ||\
            WG_COMPARE(db, end_bound, full_arglist[i].value)!=WG_LESSTHAN) {
            end_bound = full_arglist[i].value;
            end_inclusive = 0;
          }
          break;
        case WG_COND_GREATER:
          /* No earlier left bound or new left bound is >= of old value */
          if(start_bound==WG_ILLEGAL ||\
            WG_COMPARE(db, start_bound, full_arglist[i].value)!=WG_GREATER) {
            start_bound = full_arglist[i].value;
            start_inclusive = 0;
          }
          break;
        case WG_COND_LTEQUAL:
          /* Similar to "less than", but inclusive */
          if(end_bound==WG_ILLEGAL ||\
            WG_COMPARE(db, end_bound, full_arglist[i].value)==WG_GREATER) {
            end_bound = full_arglist[i].value;
            end_inclusive = 1;
          }
          break;
        case WG_COND_GTEQUAL:
          /* Similar to "greater", but inclusive */
          if(start_bound==WG_ILLEGAL ||\
            WG_COMPARE(db, start_bound, full_arglist[i].value)==WG_LESSTHAN) {
            start_bound = full_arglist[i].value;
            start_inclusive = 1;
          }
          break;
        case WG_COND_NOT_EQUAL:
          /* Force use of full argument list to check each row in the result
           * set since we have a condition we cannot satisfy using
           * a continuous range of T-tree values alone
           */
          query->column = -1;
          break;
        default:
          show_query_error(db, "Invalid condition (ignoring)");
          break;
      }
    }

    /* Simple sanity check. Is start_bound greater than end_bound? */
    if(start_bound!=WG_ILLEGAL && end_bound!=WG_ILLEGAL &&\
      WG_COMPARE(db, start_bound, end_bound) == WG_GREATER) {
      /* return empty query */
      query->argc = 0;
      query->arglist = NULL;
      free(full_arglist);
      return query;
    }

    /* Now find the bounding nodes for the query */
    if(find_ttree_bounds(db, index_id, col,
        start_bound, end_bound, start_inclusive, end_inclusive,
        &query->curr_offset, &query->curr_slot, &query->end_offset,
        &query->end_slot)) {
      free(query);
      free(full_arglist);
      return NULL;
    }

    /* XXX: here we can reverse the direction and switch the start and
     * end nodes/slots, if "descending" sort order is needed.
     */

  } else {
    /* Nothing better than full scan available */
    void *rec;

    query->qtype = WG_QTYPE_SCAN;
    query->column = -1; /* no special column, entire argument list
                         * should be checked for each row */

    rec = wg_get_first_record(db);
    if(rec)
      query->curr_record = ptrtooffset(db, rec);
    else
      query->curr_record = 0;
  }

  /* Now attach the argument list to the query. If the query is based
   * on a column index, we will create a slimmer copy that does not contain
   * the conditions already satisfied by the index bounds.
   */
  if(query->column == -1) {
    query->arglist = full_arglist;
    query->argc = fargc;
  }
  else {
    int cnt = 0;
    for(i=0; i<fargc; i++) {
      if(full_arglist[i].column != query->column)
        cnt++;
    }

    /* The argument list is reduced, but still contains columns */
    if(cnt) {
      int j;
      query->arglist = (wg_query_arg *) malloc(cnt * sizeof(wg_query_arg));
      if(!query->arglist) {
        show_query_error(db, "Failed to allocate memory");
        free(query);
        free(full_arglist);
        return NULL;
      }
      for(i=0, j=0; i<fargc; i++) {
        if(full_arglist[i].column != query->column) {
          query->arglist[j].column = full_arglist[i].column;
          query->arglist[j].cond = full_arglist[i].cond;
          query->arglist[j++].value = full_arglist[i].value;
        }
      }
    } else
      query->arglist = NULL;
    query->argc = cnt;
    free(full_arglist); /* Now we have a reduced argument list, free
                         * the original one */
  }

  /* Now handle any post-processing required.
   */
  if(flags & QUERY_FLAGS_PREFETCH) {
    query_result_page **prevnext;
    query_result_page *currpage;
    void *rec;

    query->curr_page = NULL; /* initialize as empty */
    query->curr_pidx = 0;
    query->res_count = 0;

    /* XXX: could move this inside the loop (speeds up empty
     * query, slows down other queries) */
    query->mpool = wg_create_mpool(db, sizeof(query_result_page));
    if(!query->mpool) {
      show_query_error(db, "Failed to allocate result memory pool");
      wg_free_query(db, query);
      return NULL;
    }

    i = QUERY_RESULTSET_PAGESIZE;
    prevnext = (query_result_page **) &(query->curr_page);

    while((rec = wg_fetch(db, query))) {
      if(i >= QUERY_RESULTSET_PAGESIZE) {
        currpage = (query_result_page *) \
          wg_alloc_mpool(db, query->mpool, sizeof(query_result_page));
        if(!currpage) {
          show_query_error(db, "Failed to allocate a resultset row");
          wg_free_query(db, query);
          return NULL;
        }
        memset(currpage->rows, 0, sizeof(gint) * QUERY_RESULTSET_PAGESIZE);
        *prevnext = currpage;
        prevnext = &(currpage->next);
        currpage->next = NULL;
        i = 0;
      }
      currpage->rows[i++] = ptrtooffset(db, rec);
      query->res_count++;
      if(rowlimit && query->res_count >= rowlimit)
        break;
    }

    /* Finally, convert the query type. */
    query->qtype = WG_QTYPE_PREFETCH;
  }

  return query;
}

/** Create a query object and pre-fetch all data rows.
 *
 * Allocates enough space to hold all row offsets, fetches them and stores
 * them in an array. Isolation is not guaranteed in any way, shape or form,
 * but can be implemented on top by the user.
 *
 * returns NULL if constructing the query fails. Otherwise returns a pointer
 * to a wg_query object.
 */
wg_query *wg_make_query(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc) {

  return internal_build_query(db,
    matchrec, reclen, arglist, argc, QUERY_FLAGS_PREFETCH, 0);
}

/** Create a query object and pre-fetch rowlimit number of rows.
 *
 * returns NULL if constructing the query fails. Otherwise returns a pointer
 * to a wg_query object.
 */
wg_query *wg_make_query_rc(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc, wg_uint rowlimit) {

  return internal_build_query(db,
    matchrec, reclen, arglist, argc, QUERY_FLAGS_PREFETCH, rowlimit);
}


/** Return next record from the query object
 *  returns NULL if no more records
 */
void *wg_fetch(void *db, wg_query *query) {
  void *rec;

#ifdef CHECK
  if (!dbcheck(db)) {
    /* XXX: currently show_query_error would work too */
#ifdef WG_NO_ERRPRINT
#else
    fprintf(stderr, "Invalid database pointer in wg_fetch.\n");
#endif
    return NULL;
  }
  if(!query) {
    show_query_error(db, "Invalid query object");
    return NULL;
  }
#endif
  if(query->qtype == WG_QTYPE_SCAN) {
    for(;;) {
      void *next;

      if(!query->curr_record) {
        /* Query exhausted */
        return NULL;
      }

      rec = offsettoptr(db, query->curr_record);

      /* Pre-fetch the next record */
      next = wg_get_next_record(db, rec);
      if(next)
        query->curr_record = ptrtooffset(db, next);
      else
        query->curr_record = 0;

      /* Check the record against all conditions; if it does
       * not match, go to next iteration.
       */
      if(!query->arglist || \
        check_arglist(db, rec, query->arglist, query->argc))
        return rec;
    }
  }
  else if(query->qtype == WG_QTYPE_TTREE) {
    struct wg_tnode *node;

    for(;;) {
      if(!query->curr_offset) {
        /* No more nodes to examine */
        return NULL;
      }
      node = (struct wg_tnode *) offsettoptr(db, query->curr_offset);
      rec = offsettoptr(db, node->array_of_values[query->curr_slot]);

      /* Increment the slot/and or node cursors before we
       * return. If the current node does not satisfy the
       * argument list we may need to do this multiple times.
       */
      if(query->curr_offset==query->end_offset && \
        query->curr_slot==query->end_slot) {
        /* Last slot reached, mark the query as exchausted */
        query->curr_offset = 0;
      } else {
        /* Some rows still left */
        query->curr_slot += query->direction;
        if(query->curr_slot < 0) {
#ifdef CHECK
          if(query->end_offset==query->curr_offset) {
            /* This should not happen */
            show_query_error(db, "Warning: end slot mismatch, possible bug");
            query->curr_offset = 0;
          } else {
#endif
            query->curr_offset = TNODE_PREDECESSOR(db, node);
            if(query->curr_offset) {
              node = (struct wg_tnode *) offsettoptr(db, query->curr_offset);
              query->curr_slot = node->number_of_elements - 1;
            }
#ifdef CHECK
          }
#endif
        } else if(query->curr_slot >= node->number_of_elements) {
#ifdef CHECK
          if(query->end_offset==query->curr_offset) {
            /* This should not happen */
            show_query_error(db, "Warning: end slot mismatch, possible bug");
            query->curr_offset = 0;
          } else {
#endif
            query->curr_offset = TNODE_SUCCESSOR(db, node);
            query->curr_slot = 0;
#ifdef CHECK
          }
#endif
        }
      }

      /* If there are no extra conditions or the row satisfies
       * all the conditions, we can return.
       */
      if(!query->arglist || \
        check_arglist(db, rec, query->arglist, query->argc))
        return rec;
    }
  }
  if(query->qtype == WG_QTYPE_PREFETCH) {
    if(query->curr_page) {
      query_result_page *currpage = (query_result_page *) query->curr_page;
      gint offset = currpage->rows[query->curr_pidx++];
      if(!offset) {
        /* page not filled completely */
        query->curr_page = NULL;
        return NULL;
      } else {
        if(query->curr_pidx >= QUERY_RESULTSET_PAGESIZE) {
          query->curr_page = (void *) (currpage->next);
          query->curr_pidx = 0;
        }
      }
      return offsettoptr(db, offset);
    }
    else
      return NULL;
  }
  else {
    show_query_error(db, "Unsupported query type");
    return NULL;
  }
}

/** Release the memory allocated for the query
 */
void wg_free_query(void *db, wg_query *query) {
  if(query->arglist)
    free(query->arglist);
  if(query->qtype==WG_QTYPE_PREFETCH && query->mpool)
    wg_free_mpool(db, query->mpool);
  free(query);
}

/* ----------- query parameter preparing functions -------------*/

/* Types that use no storage are encoded
 * using standard API functions.
 */

gint wg_encode_query_param_null(void *db, char *data) {
  return wg_encode_null(db, data);
}

gint wg_encode_query_param_record(void *db, void *data) {
  return wg_encode_record(db, data);
}

gint wg_encode_query_param_char(void *db, char data) {
  return wg_encode_char(db, data);
}

gint wg_encode_query_param_fixpoint(void *db, double data) {
  return wg_encode_fixpoint(db, data);
}

gint wg_encode_query_param_date(void *db, int data) {
  return wg_encode_date(db, data);
}

gint wg_encode_query_param_time(void *db, int data) {
  return wg_encode_time(db, data);
}

gint wg_encode_query_param_var(void *db, gint data) {
  return wg_encode_var(db, data);
}

/* Types using storage are encoded by emulating the behaviour
 * of dbdata.c functions. Some assumptions are made about storage
 * size of the data (but similar assumptions exist in dbdata.c)
 */

gint wg_encode_query_param_int(void *db, gint data) {
  void *dptr;

  if(fits_smallint(data)) {
    return encode_smallint(data);
  } else {
    dptr=malloc(sizeof(gint));
    if(!dptr) {
      show_query_error(db, "Failed to encode query parameter");
      return WG_ILLEGAL;
    }
    *((gint *) dptr) = data;
    return encode_fullint_offset(ptrtooffset(db, dptr));
  }
}

gint wg_encode_query_param_double(void *db, double data) {
  void *dptr;

  dptr=malloc(2*sizeof(gint));
  if(!dptr) {
    show_query_error(db, "Failed to encode query parameter");
    return WG_ILLEGAL;
  }
  *((double *) dptr) = data;
  return encode_fulldouble_offset(ptrtooffset(db, dptr));
}

gint wg_encode_query_param_str(void *db, char *data, char *lang) {
  if(data) {
    return encode_query_param_unistr(db, data, WG_STRTYPE, lang, strlen(data));
  } else {
    show_query_error(db, "NULL pointer given as parameter");
    return WG_ILLEGAL;
  }
}

gint wg_encode_query_param_xmlliteral(void *db, char *data, char *xsdtype) {
  if(data) {
    return encode_query_param_unistr(db, data, WG_XMLLITERALTYPE,
      xsdtype, strlen(data));
  } else {
    show_query_error(db, "NULL pointer given as parameter");
    return WG_ILLEGAL;
  }
}

gint wg_encode_query_param_uri(void *db, char *data, char *prefix) {
  if(data) {
    return encode_query_param_unistr(db, data, WG_URITYPE,
      prefix, strlen(data));
  } else {
    show_query_error(db, "NULL pointer given as parameter");
    return WG_ILLEGAL;
  }
}

/* Encode shortstr- or longstr-compatible data in local memory.
 * string type without lang is handled as "short", ignoring the
 * actual length. All other types require longstr storage to
 * handle the extdata field.
 */
static gint encode_query_param_unistr(void *db, char *data, gint type,
  char *extdata, int length) {

  void *dptr;
  if(type == WG_STRTYPE && extdata == NULL) {
    dptr=malloc(length+1);
    if(!dptr) {
      show_query_error(db, "Failed to encode query parameter");
      return WG_ILLEGAL;
    }
    memcpy((char *) dptr, data, length);
    ((char *) dptr)[length] = '\0';
    return encode_shortstr_offset(ptrtooffset(db, dptr));
  }
  else {
    size_t i;
    int extlen = 0;
    int dlen, lengints, lenrest;
    gint offset, meta;

    if(type != WG_BLOBTYPE)
      length++; /* include the terminating 0 */

    /* Determine storage size */
    lengints = length / sizeof(gint);
    lenrest = length % sizeof(gint);
    if(lenrest) lengints++;
    dlen = sizeof(gint) * (LONGSTR_HEADER_GINTS + lengints);

    /* Emulate the behaviour of wg_alloc_gints() */
    if(dlen < MIN_VARLENOBJ_SIZE) dlen = MIN_VARLENOBJ_SIZE;
    if(dlen % 8) dlen += 4;

    if(extdata) {
      extlen = strlen(extdata);
    }

    dptr=malloc(dlen + (extdata ? extlen + 1 : 0));
    if(!dptr) {
      show_query_error(db, "Failed to encode query parameter");
      return WG_ILLEGAL;
    }
    offset = ptrtooffset(db, dptr);

    /* Copy the data, fill the remainder with zeroes */
    memcpy((char *) dptr + (LONGSTR_HEADER_GINTS*sizeof(gint)), data, length);
    for(i=0; lenrest && i<sizeof(gint)-lenrest; i++) {
      *((char *)dptr + length + (LONGSTR_HEADER_GINTS*sizeof(gint)) + i) = '\0';
    }

    /* Use the rest of the allocated storage to encode extdata in
     * shortstr format.
     */
    if(extdata) {
      gint extenc;
      void *extptr = (char *) dptr + dlen;
      memcpy(extptr, extdata, extlen);
      ((char *) extptr)[extlen] = '\0';
      extenc = encode_shortstr_offset(ptrtooffset(db, extptr));
      dbstore(db, offset+LONGSTR_EXTRASTR_POS*sizeof(gint), extenc);
    } else {
      dbstore(db, offset+LONGSTR_EXTRASTR_POS*sizeof(gint), 0);
    }

    /* Metadata */
    dbstore(db, offset, dlen); /* Local memory, actual value OK here */
    meta = (dlen - length) << LONGSTR_META_LENDIFSHFT;
    meta = meta | type;
    dbstore(db, offset+LONGSTR_META_POS*sizeof(gint), meta);
    dbstore(db, offset+LONGSTR_REFCOUNT_POS*sizeof(gint), 0);
    dbstore(db, offset+LONGSTR_BACKLINKS_POS*sizeof(gint), 0);
    dbstore(db, offset+LONGSTR_HASHCHAIN_POS*sizeof(gint), 0);

    return encode_longstr_offset(offset);
  }
}

gint wg_free_query_param(void* db, gint data) {
#ifdef CHECK
  if (!dbcheck(db)) {
    show_query_error(db,"wrong database pointer given to wg_free_query_param");
    return 0;
  }
#endif
  if (isptr(data)) {
    gint offset;

    switch(data&NORMALPTRMASK) {
      case DATARECBITS:
        break;
      case SHORTSTRBITS:
        offset = decode_shortstr_offset(data);
        free(offsettoptr(db, offset));
        break;
      case LONGSTRBITS:
        offset = decode_longstr_offset(data);
        free(offsettoptr(db, offset));
        break;
      case FULLDOUBLEBITS:
        offset = decode_fulldouble_offset(data);
        free(offsettoptr(db, offset));
        break;
      case FULLINTBITSV0:
      case FULLINTBITSV1:
        offset = decode_fullint_offset(data);
        free(offsettoptr(db, offset));
        break;
      default:
        show_query_error(db,"Bad encoded value given to wg_free_query_param");
        break;
    }
  }
  return 0;
}

/* ------------------ Resultset manipulation -------------------*/

/* XXX: consider converting the main query function to use this as well.
 * Currently only used to support the JSON/document query.
 */

/*
 * Allocate and initialize a new result set.
 */
static query_result_set *create_resultset(void *db) {
  query_result_set *set;

  if(!(set = malloc(sizeof(query_result_set)))) {
    show_query_error(db, "Failed to allocate result set");
    return NULL;
  }

  set->rcursor.page = NULL;                 /* initialize as empty */
  set->rcursor.pidx = 0;
  set->wcursor.page = NULL;
  set->wcursor.pidx = QUERY_RESULTSET_PAGESIZE; /* new page needed */
  set->first_page = NULL;
  set->res_count = 0;

  set->mpool = wg_create_mpool(db, sizeof(query_result_page));
  if(!set->mpool) {
    show_query_error(db, "Failed to allocate result memory pool");
    free(set);
    return NULL;
  }
  return set;
}

/*
 * Free the resultset and it's memory pool
 */
static void free_resultset(void *db, query_result_set *set) {
  if(set->mpool)
    wg_free_mpool(db, set->mpool);
  free(set);
}

/*
 * Set the resultset pointers to the beginning of the
 * first results page.
 */
static void rewind_resultset(void *db, query_result_set *set) {
  set->rcursor.page = set->first_page;
  set->rcursor.pidx = 0;
}

/*
 * Append an offset to the result set.
 * returns 0 on success.
 * returns -1 on error.
 */
static gint append_resultset(void *db, query_result_set *set, gint offset) {
  if(set->wcursor.pidx >= QUERY_RESULTSET_PAGESIZE) {
    query_result_page *newpage = (query_result_page *) \
        wg_alloc_mpool(db, set->mpool, sizeof(query_result_page));
    if(!newpage) {
      return show_query_error(db, "Failed to allocate a resultset page");
    }

    memset(newpage->rows, 0, sizeof(gint) * QUERY_RESULTSET_PAGESIZE);
    newpage->next = NULL;

    if(set->wcursor.page) {
      set->wcursor.page->next = newpage;
    } else {
      /* first_page==NULL implied */
      set->first_page = newpage;
      set->rcursor.page = newpage;
    }
    set->wcursor.page = newpage;
    set->wcursor.pidx = 0;
  }

  set->wcursor.page->rows[set->wcursor.pidx++] = offset;
  set->res_count++;
  return 0;
}

/*
 * Fetch the next offset from the result set.
 * returns 0 if the set is exhausted.
 */
static gint fetch_resultset(void *db, query_result_set *set) {
  if(set->rcursor.page) {
    gint offset = set->rcursor.page->rows[set->rcursor.pidx++];
    if(!offset) {
      /* page not filled completely. Mark set as exhausted. */
      set->rcursor.page = NULL;
    } else {
      if(set->rcursor.pidx >= QUERY_RESULTSET_PAGESIZE) {
        set->rcursor.page = set->rcursor.page->next;
        set->rcursor.pidx = 0;
      }
    }
    return offset;
  }
  return 0;
}

#define NESTEDLOOP 0
#define HASHJOIN 1

/*
 * Create an intersection of two result sets.
 * Join strategy:
 *   if the number of inner loops expected is low (i.e. the sets
 *   are small), nested loop join is used. Otherwise, hash join
 *   is used.
 *
 * Returns a new result set (can be empty).
 * Returns NULL on error.
 */
static query_result_set *intersect_resultset(void *db,
  query_result_set *seta, query_result_set *setb)
{
  query_result_set *intersection;
  int strategy = HASHJOIN;

  if(!(intersection = create_resultset(db))) {
    return NULL;
  }
  if(seta->res_count * setb->res_count < 200) {
    strategy = NESTEDLOOP; /* don't bother with hash table */
  }

  if(strategy == HASHJOIN) {
    void *hasht = NULL;
    gint offset;

    if(seta->res_count > setb->res_count) {
      query_result_set *tmp = seta;
      seta = setb;
      setb = tmp;
    }

    if(!(hasht = wg_dhash_init(db, seta->res_count))) {
      free_resultset(db, intersection);
      return NULL;
    }

    rewind_resultset(db, seta);
    while((offset = fetch_resultset(db, seta))) {
      if(wg_dhash_addkey(db, hasht, offset)) {
        free_resultset(db, intersection);
        wg_dhash_free(db, hasht);
        return NULL;
      }
    }
    rewind_resultset(db, setb);
    while((offset = fetch_resultset(db, setb))) {
      if(wg_dhash_haskey(db, hasht, offset)) {
        gint err = append_resultset(db, intersection, offset);
        if(err) {
          free_resultset(db, intersection);
          wg_dhash_free(db, hasht);
          return NULL;
        }
      }
    }
    wg_dhash_free(db, hasht);
  }
  else { /* nested loop strategy */
    gint offseta;
    rewind_resultset(db, seta);
    while((offseta = fetch_resultset(db, seta))) {
      gint offsetb;
      rewind_resultset(db, setb);
      while((offsetb = fetch_resultset(db, setb))) {
        if(offseta == offsetb) {
          gint err = append_resultset(db, intersection, offseta);
          if(err) {
            free_resultset(db, intersection);
            return NULL;
          }
          break;
        }
      }
    }
  }
  return intersection;
}

/*
 * Create a result set that contains only unique rows.
 * Uniqueness test uses similar strategy to the intersect function
 * (hash table for membership test, but revert to nested loop if
 * low number of elements).
 *
 * Returns a new result set (can be empty).
 * Returns NULL on error.
 */
static query_result_set *unique_resultset(void *db, query_result_set *set)
{
  gint offset;
  query_result_set *unique;
  int strategy = HASHJOIN;

  if(!(unique = create_resultset(db))) {
    return NULL;
  }
  if(set->res_count < 20) {
    strategy = NESTEDLOOP; /* don't bother with hash table */
  }

  rewind_resultset(db, set);

  if(strategy == HASHJOIN) {
    void *hasht = NULL;
    if(!(hasht = wg_dhash_init(db, set->res_count))) {
      free_resultset(db, unique);
      return NULL;
    }

    while((offset = fetch_resultset(db, set))) {
      if(!wg_dhash_haskey(db, hasht, offset)) {
        gint err = append_resultset(db, unique, offset);
        if(!err) {
          err = wg_dhash_addkey(db, hasht, offset);
        }
        if(err) {
          free_resultset(db, unique);
          wg_dhash_free(db, hasht);
          return NULL;
        }
      }
    }
    wg_dhash_free(db, hasht);
  }
  else { /* nested loop */
    while((offset = fetch_resultset(db, set))) {
      gint offsetu, found = 0;
      rewind_resultset(db, unique);
      while((offsetu = fetch_resultset(db, unique))) {
        if(offset == offsetu) {
          found = 1;
          break;
        }
      }
      if(!found) {
        /* We're now at the end of the set and may append normally. */
        gint err = append_resultset(db, unique, offset);
        if(err) {
          free_resultset(db, unique);
          return NULL;
        }
      }
    }
  }
  return unique;
}

/* ------------------- (JSON) document query -------------------*/

/* Note the non-conventional return code values:
 * -1 adding the document failed
 * 1 adding the document succeeded
 * (0 is reserved for using this macro in a recursive function
 * to differentiate between matches and non-matches)
 */
#define ADD_DOC_TO_RESULTSET(db, rec, ns, rc) \
  void *doc = wg_find_document(db, rec); \
  if(doc) { \
    if(!append_resultset(db, ns, ptrtooffset(db, doc))) \
      rc = 1; \
    else \
      rc = -1; \
  } else { \
    rc = show_query_error(db, "Failed to retrieve the document"); \
  }

#define IF_ERR_CLEAN_UP(db, cr, ns, al, rc) \
  if(rc < 0) { \
    free_resultset(db, ns); \
    if(cr) \
      free_resultset(db, cr); \
    if(al) \
      free(al); \
    return NULL; \
  }

#define ARGLIST_CLEANUP(al) \
  if(al) \
    free(al);

#define ADD_DOC_ARRAY_UNWRAP(db, rec, ns, rc, k, v) \
  void *arec = wg_decode_record(db, k); \
  if(is_schema_array(arec)) { \
    gint areclen = wg_get_record_len(db, arec); \
    int j; \
    for(j=0; j<areclen; j++) { \
      if(WG_COMPARE(db, wg_get_field(db, arec, j), v) == WG_EQUAL) { \
        ADD_DOC_TO_RESULTSET(db, rec, ns, rc) \
        break; \
      } \
    } \
  }

/*
 * Check if a record matches a key-value pair given in a query
 * clause. If the value is an array in the record, each member
 * of the array is compared to the value in the clause.
 * (this behaviour emulates the JSON hash index, but can be disabled
 * by #undef-ing JSON_SCAN_UNWRAP_ARRAY).
 *
 * returns 1 if the record matches and is added to the resultset
 * returns 0 if the record does not match
 * returns -1 if the record matches, but adding fails
 */
static gint check_and_merge_by_kv(void *db, void *rec,
  wg_json_query_arg *arg, query_result_set *next_set)
{
  gint rc = 0;
  gint reclen = wg_get_record_len(db, rec);
  if(reclen > WG_SCHEMA_VALUE_OFFSET) { /* XXX: assume key
                                         * before value */
#ifndef JSON_SCAN_UNWRAP_ARRAY
    if(WG_COMPARE(db, wg_get_field(db, rec, WG_SCHEMA_KEY_OFFSET),
      arg->key) == WG_EQUAL &&\
      WG_COMPARE(db, wg_get_field(db, rec, WG_SCHEMA_VALUE_OFFSET),
      arg->value) == WG_EQUAL)
    {
      ADD_DOC_TO_RESULTSET(db, rec, next_set, rc)
    }
#else
    if(WG_COMPARE(db, wg_get_field(db, rec, WG_SCHEMA_KEY_OFFSET),
      arg->key) == WG_EQUAL) {
      gint k = wg_get_field(db, rec, WG_SCHEMA_VALUE_OFFSET);

      if(WG_COMPARE(db, k, arg->value) == WG_EQUAL) {
        /* Direct match. */
        ADD_DOC_TO_RESULTSET(db, rec, next_set, rc)
      } else if(wg_get_encoded_type(db, k) == WG_RECORDTYPE) {
        /* No direct match, but if it is a record AND an array,
         * scan the array contents.
         */
        ADD_DOC_ARRAY_UNWRAP(db, rec, next_set, rc, k, arg->value)
      }
    }
#endif
  }
  return rc;
}

/*
 * Like check_and_merge_by_kv() except key comparison is skipped
 * (i.e. the caller is iterating over key index)
 */
static gint check_and_merge_by_key(void *db, void *rec,
  wg_json_query_arg *arg, query_result_set *next_set)
{
  gint rc = 0;
  gint reclen = wg_get_record_len(db, rec);
  if(reclen > WG_SCHEMA_VALUE_OFFSET) {
#ifndef JSON_SCAN_UNWRAP_ARRAY
    if(WG_COMPARE(db, wg_get_field(db, rec, WG_SCHEMA_VALUE_OFFSET),
      arg->value) == WG_EQUAL)
    {
      ADD_DOC_TO_RESULTSET(db, rec, next_set, rc)
    }
#else
    gint k = wg_get_field(db, rec, WG_SCHEMA_VALUE_OFFSET);

    if(WG_COMPARE(db, k, arg->value) == WG_EQUAL) {
      ADD_DOC_TO_RESULTSET(db, rec, next_set, rc)
    } else if(wg_get_encoded_type(db, k) == WG_RECORDTYPE) {
      ADD_DOC_ARRAY_UNWRAP(db, rec, next_set, rc, k, arg->value)
    }
#endif
  }
  return rc;
}

/*
 * Check if the record or any of its children matches
 * the given key/value pair. The search is stopped upon
 * the first match.
 *
 * returns 1 if the record matches and is added to the resultset
 * returns 0 if the record does not match
 * returns -1 if the record matches, but adding fails
 */
static gint check_and_merge_recursively(void *db, void *rec,
  wg_json_query_arg *arg, query_result_set *next_set, int depth)
{
  gint i, reclen, rc;
  rc = check_and_merge_by_kv(db, rec, arg, next_set);
  if(rc) /* successful match or an error */
    return rc;

  if(depth <= 0) {
    return show_query_error(db, "scanning document: recursion too deep");
  }
  reclen = wg_get_record_len(db, rec);
  for(i=0; i<reclen; i++) {
    gint enc = wg_get_field(db, rec, i);
    gint type = wg_get_encoded_type(db, enc);
    if(type == WG_RECORDTYPE) {
      rc = check_and_merge_recursively(db, wg_decode_record(db, enc),
        arg, next_set, depth-1);
      if(rc) /* successful match or an error */
        return rc;
    }
  }
  return 0; /* no match */
}

/* Prepare argument list. This sorts clauses that are either less
 * costly to query or restrict the following processing the most
 * (not yet implemented, depends on statistics). Also determines
 * which indexes can and should be used.
 *
 * Returns 0 on success.
 * Returns -1 on error.
 * in case of error, the contents of return parameters are unmodified.
 * in case of success, **sorted_arglist may be set to NULL, if the
 * argument list does not require sorting. The caller should always
 * check that.
 */
static gint prepare_json_arglist(void *db, wg_json_query_arg *arglist,
  wg_json_query_arg **sorted_arglist, gint argc,
  gint *index_id, gint *vindex_id, gint *kindex_id)
{
  gint icols[2], need_ttree = 0;
  wg_json_query_arg *tmp = NULL;

  /* Get index */
  icols[0] = WG_SCHEMA_KEY_OFFSET;
  icols[1] = WG_SCHEMA_VALUE_OFFSET;
  *index_id = wg_multi_column_to_index_id(db, icols, 2,
    WG_INDEX_TYPE_HASH_JSON, NULL, 0);
  *vindex_id = *kindex_id = -1;

  if(argc > 1) {
    /* There is something to sort. In the future we can also sort by
     * cardinality here (provided that stats are available). */
    gint i, j;
    tmp = malloc(sizeof(wg_json_query_arg) * argc);
    if(!tmp) {
      return show_query_error(db, "Failed to prepare query arguments");
    }

    /* First pass: literal values only */
    for(i=0, j=0; i<argc; i++) {
      if(wg_get_encoded_type(db, arglist[i].value) != WG_RECORDTYPE) {
        tmp[j].key = arglist[i].key;
        tmp[j++].value = arglist[i].value;
      }
    }

    /* Was there something left? In that case, we might need T-tree
     * to speed up scanning for the remainder of clauses. We also use
     * T-tree if hash is not available at all.
     */
    if(j<i) {
      need_ttree = 1;
    }

    /* Second pass: complex structures only */
    for(i=0; i<argc; i++) {
      if(wg_get_encoded_type(db, arglist[i].value) == WG_RECORDTYPE) {
        tmp[j].key = arglist[i].key;
        tmp[j++].value = arglist[i].value;
      }
    }
  } else {
    /* Complex structures are not present in the hash index */
    if(wg_get_encoded_type(db, arglist[0].value) == WG_RECORDTYPE) {
      need_ttree = 1;
    }
  }

  /* Get T-tree index if needed. Value index is preferred, but
   * it must be of the type that supports array unwrap. Otherwise
   * we'll settle for a key index.
   */
  if(*index_id == -1 || need_ttree) {
    *vindex_id = wg_multi_column_to_index_id(db, &icols[1], 1,
      WG_INDEX_TYPE_TTREE_JSON, NULL, 0);
    if(*vindex_id == -1) {
      *kindex_id = wg_multi_column_to_index_id(db, &icols[0], 1,
        WG_INDEX_TYPE_TTREE, NULL, 0);
    }
  }

  *sorted_arglist = tmp;
  return 0;
}

/*
 * Find a list of documents that contain the key-value pairs.
 * Returns a prefetch query object.
 * Returns NULL on error.
 */
wg_query *wg_make_json_query(void *db, wg_json_query_arg *arglist, gint argc) {
  wg_query *query = NULL;
  query_result_set *curr_res = NULL;
  wg_json_query_arg *sorted_arglist = NULL;
  gint index_id = -1, vindex_id = -1, kindex_id = -1;
  gint i;

#ifdef CHECK
  if(!arglist || argc < 1) {
    show_query_error(db, "Not enough parameters");
    return NULL;
  }
  if (!dbcheck(db)) {
#ifdef WG_NO_ERRPRINT
#else
    fprintf(stderr, "Invalid database pointer in wg_make_json_query.\n");
#endif
    return NULL;
  }
#endif

  /* Sort the argument list. This also checks for usable indexes, so
   * we're calling it even if we have just one argument.
   */
  prepare_json_arglist(db, arglist, &sorted_arglist, argc,
    &index_id, &vindex_id, &kindex_id);
  /* HACK: this way, the following code does not need to care
   * whether we sorted the argument list or not.
   */
  if(sorted_arglist)
    arglist = sorted_arglist;

  /* Iterate over the argument pairs.
   * XXX: it is possible that getting the first set from index and
   * doing a scan to check the remaining arguments is faster than
   * doing the intersect operation of sets retrieved from index.
   */
  for(i=0; i<argc; i++) {
    query_result_set *next_set, *tmp_set;

    /* Initialize the set produced by this iteration */
    next_set = create_resultset(db);
    if(!next_set) {
      if(curr_res)
        free_resultset(db, curr_res);
      return NULL;
    }

    if(index_id > 0 &&\
      wg_get_encoded_type(db, arglist[i].value) != WG_RECORDTYPE) {
      /* Fetch the matching rows from the index, then retrieve the
       * documents they belong to.
       */
      gint values[2];
      gint reclist_offset;

      values[0] = arglist[i].key;
      values[1] = arglist[i].value;
      reclist_offset = wg_search_hash(db, index_id, values, 2);

      if(reclist_offset > 0) {
        gint *nextoffset = &reclist_offset;
        while(*nextoffset) {
          gcell *rec_cell = (gcell *) offsettoptr(db, *nextoffset);
          gint rc = -1;
          ADD_DOC_TO_RESULTSET(db, offsettoptr(db, rec_cell->car),
            next_set, rc)
          IF_ERR_CLEAN_UP(db, curr_res, next_set, sorted_arglist, rc)
          nextoffset = &(rec_cell->cdr);
        }
      }
    }
#if 0
    else if(vindex_id > 0) {
      /* XXX: unimplemented: scan T-tree for values */
    }
#endif
    else if(kindex_id > 0) {
      /* Hash index not usable, do a scan but leverage an index on the
       * key field to reduce the number of records visited.
       */
      gint curr_offset = 0, curr_slot = -1, end_offset = 0, end_slot = -1;

      if(find_ttree_bounds(db, kindex_id, WG_SCHEMA_KEY_OFFSET,
          arglist[i].key, arglist[i].key, 1, 1,
          &curr_offset, &curr_slot, &end_offset, &end_slot)) {
        curr_offset = 0;
      }

      while(curr_offset) {
        gint rc;
        struct wg_tnode *node = (struct wg_tnode *) offsettoptr(db, curr_offset);
        void *rec = offsettoptr(db, node->array_of_values[curr_slot]);

        rc = check_and_merge_by_key(db, rec, &arglist[i], next_set);
        IF_ERR_CLEAN_UP(db, curr_res, next_set, sorted_arglist, rc)

        if(curr_offset==end_offset && curr_slot==end_slot) {
          break;
        } else {
          curr_slot += 1; /* direction implied as 1 */
          if(curr_slot >= node->number_of_elements) {
#ifdef CHECK
            if(end_offset==curr_offset) {
              show_query_error(db, "Warning: end slot mismatch, possible bug");
              break;
            } else {
#endif
              curr_offset = TNODE_SUCCESSOR(db, node);
              curr_slot = 0;
#ifdef CHECK
            }
#endif
          }
        }
      }
    }
    else if(curr_res) {
      /* No index, do a scan over the current resultset. This also happens if
       * the value is a complex structure.
       */
      gint offset;
      rewind_resultset(db, curr_res);
      while((offset = fetch_resultset(db, curr_res))) {
        gint *rec = offsettoptr(db, offset);
#ifndef USE_BACKLINKING
        gint rc = check_and_merge_recursively(db,
          rec, &arglist[i], next_set, 99);
#else
        gint rc = check_and_merge_recursively(db,
          rec, &arglist[i], next_set, WG_COMPARE_REC_DEPTH);
#endif
        IF_ERR_CLEAN_UP(db, curr_res, next_set, sorted_arglist, rc)
      }
      /* Skip merge in this iteration, next_set is a subset of curr_res */
      free_resultset(db, curr_res);
      curr_res = NULL;
    }
    else {
      /* No index and no intermediate result to use, full
       * scan of database required.
       */
      gint *rec = wg_get_first_record(db);
      while(rec) {
        gint rc = check_and_merge_by_kv(db, rec, &arglist[i], next_set);
        IF_ERR_CLEAN_UP(db, curr_res, next_set, sorted_arglist, rc)
        rec = wg_get_next_record(db, rec);
      }
    }

    /* Delete duplicate documents */
    tmp_set = unique_resultset(db, next_set);
    free_resultset(db, next_set);
    if(!tmp_set) {
      if(curr_res)
        free_resultset(db, curr_res);
      ARGLIST_CLEANUP(sorted_arglist)
      return NULL;
    } else {
      next_set = tmp_set;
    }

    /* Update the query result */
    if(curr_res) {
      /* Working resultset exists, create an intersection */
      tmp_set = intersect_resultset(db, curr_res, next_set);
      free_resultset(db, curr_res);
      free_resultset(db, next_set);
      if(!tmp_set) {
        ARGLIST_CLEANUP(sorted_arglist)
        return NULL;
      } else {
        curr_res = tmp_set;
      }
    } else {
      /* This set becomes the working resultset */
      curr_res = next_set;
    }
  }
  ARGLIST_CLEANUP(sorted_arglist)

  /* Initialize query object */
  query = (wg_query *) malloc(sizeof(wg_query));
  if(!query) {
    free_resultset(db, curr_res);
    show_query_error(db, "Failed to allocate memory");
    return NULL;
  }
  query->qtype = WG_QTYPE_PREFETCH;
  query->arglist = NULL;
  query->argc = 0;
  query->column = -1;

  /* Copy the result. */
  query->curr_page = curr_res->first_page;
  query->curr_pidx = 0;
  query->res_count = curr_res->res_count;
  query->mpool = curr_res->mpool;
  free(curr_res); /* contents were inherited, dispose of the struct */

  return query;
}

/* ------------------ simple query functions -------------------*/

void *wg_find_record(void *db, gint fieldnr, gint cond, gint data,
    void* lastrecord) {
  gint index_id = -1;

  /* find index on colum */
  if(cond != WG_COND_NOT_EQUAL) {
    index_id = wg_multi_column_to_index_id(db, &fieldnr, 1,
      WG_INDEX_TYPE_TTREE, NULL, 0);
  }

  if(index_id > 0) {
    int start_inclusive = 1, end_inclusive = 1;
    /* WG_ILLEGAL is interpreted as "no bound" */
    gint start_bound = WG_ILLEGAL;
    gint end_bound = WG_ILLEGAL;
    gint curr_offset = 0, curr_slot = -1, end_offset = 0, end_slot = -1;
    void *prev = NULL;

    switch(cond) {
      case WG_COND_EQUAL:
        start_bound = end_bound = data;
        break;
      case WG_COND_LESSTHAN:
        end_bound = data;
        end_inclusive = 0;
        break;
      case WG_COND_GREATER:
        start_bound = data;
        start_inclusive = 0;
        break;
      case WG_COND_LTEQUAL:
        end_bound = data;
        break;
      case WG_COND_GTEQUAL:
        start_bound = data;
        break;
      default:
        show_query_error(db, "Invalid condition (ignoring)");
        return NULL;
    }

    if(find_ttree_bounds(db, index_id, fieldnr,
        start_bound, end_bound, start_inclusive, end_inclusive,
        &curr_offset, &curr_slot, &end_offset, &end_slot)) {
      return NULL;
    }

    /* We have the bounds, scan to lastrecord */
    while(curr_offset) {
      struct wg_tnode *node = (struct wg_tnode *) offsettoptr(db, curr_offset);
      void *rec = offsettoptr(db, node->array_of_values[curr_slot]);

      if(prev == lastrecord) {
        /* if lastrecord is NULL, first match returned */
        return rec;
      }

      prev = rec;
      if(curr_offset==end_offset && curr_slot==end_slot) {
        /* Last slot reached */
        break;
      } else {
        /* Some rows still left */
        curr_slot += 1; /* direction implied as 1 */
        if(curr_slot >= node->number_of_elements) {
#ifdef CHECK
          if(end_offset==curr_offset) {
            /* This should not happen */
            show_query_error(db, "Warning: end slot mismatch, possible bug");
            break;
          } else {
#endif
            curr_offset = TNODE_SUCCESSOR(db, node);
            curr_slot = 0;
#ifdef CHECK
          }
#endif
        }
      }
    }
  }
  else {
    /* no index (or cond == WG_COND_NOT_EQUAL), do a scan */
    wg_query_arg arg;
    void *rec;

    if(lastrecord) {
      rec = wg_get_next_record(db, lastrecord);
    } else {
      rec = wg_get_first_record(db);
    }

    arg.column = fieldnr;
    arg.cond = cond;
    arg.value = data;

    while(rec) {
      if(check_arglist(db, rec, &arg, 1)) {
        return rec;
      }
      rec = wg_get_next_record(db, rec);
    }
  }

  /* No records found (this can also happen if matching records were
   * found but lastrecord does not match any of them or matches the
   * very last one).
   */
  return NULL;
}

/*
 * Wrapper function for wg_find_record with unencoded data (null)
 */
void *wg_find_record_null(void *db, gint fieldnr, gint cond, char *data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_null(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (record)
 */
void *wg_find_record_record(void *db, gint fieldnr, gint cond, void *data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_record(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (char)
 */
void *wg_find_record_char(void *db, gint fieldnr, gint cond, char data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_char(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (fixpoint)
 */
void *wg_find_record_fixpoint(void *db, gint fieldnr, gint cond, double data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_fixpoint(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (date)
 */
void *wg_find_record_date(void *db, gint fieldnr, gint cond, int data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_date(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (time)
 */
void *wg_find_record_time(void *db, gint fieldnr, gint cond, int data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_time(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (var)
 */
void *wg_find_record_var(void *db, gint fieldnr, gint cond, gint data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_var(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (int)
 */
void *wg_find_record_int(void *db, gint fieldnr, gint cond, int data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_int(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  wg_free_query_param(db, enc);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (double)
 */
void *wg_find_record_double(void *db, gint fieldnr, gint cond, double data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_double(db, data);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  wg_free_query_param(db, enc);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (string)
 */
void *wg_find_record_str(void *db, gint fieldnr, gint cond, char *data,
    void* lastrecord) {
  gint enc = wg_encode_query_param_str(db, data, NULL);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  wg_free_query_param(db, enc);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (xmlliteral)
 */
void *wg_find_record_xmlliteral(void *db, gint fieldnr, gint cond, char *data,
    char *xsdtype, void* lastrecord) {
  gint enc = wg_encode_query_param_xmlliteral(db, data, xsdtype);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  wg_free_query_param(db, enc);
  return rec;
}

/*
 * Wrapper function for wg_find_record with unencoded data (uri)
 */
void *wg_find_record_uri(void *db, gint fieldnr, gint cond, char *data,
    char *prefix, void* lastrecord) {
  gint enc = wg_encode_query_param_uri(db, data, prefix);
  void *rec = wg_find_record(db, fieldnr, cond, enc, lastrecord);
  wg_free_query_param(db, enc);
  return rec;
}

/* --------------- error handling ------------------------------*/

/** called with err msg
*
*  may print or log an error
*  does not do any jumps etc
*/

static gint show_query_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"query error: %s\n",errmsg);
#endif
  return -1;
}

#if 0
/** called with err msg and additional int data
*
*  may print or log an error
*  does not do any jumps etc
*/

static gint show_query_error_nr(void* db, char* errmsg, gint nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"query error: %s %d\n",errmsg,nr);
#endif
  return -1;
}
#endif

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010,2011,2012,2013
*
* Minor mods by Tanel Tammet. Triple handler for raptor and raptor
* rdf parsing originally written by Tanel Tammet.
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbutil.c
 * Miscellaneous utility functions.
 */

/* ====== Includes =============== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_RAPTOR
#include <raptor.h>
#endif

/* ====== Private headers and defs ======== */

#ifdef __cplusplus
extern "C" {
#endif

//data.h"
//util.h"
//query.h"

#ifdef _WIN32
#define snprintf(s, sz, f, ...) _snprintf_s(s, sz+1, sz, f, ## __VA_ARGS__)
#define strncpy(d, s, sz) strncpy_s(d, sz+1, s, sz)
#else
/* Use error-detecting versions for other C libs */
#define atof(s) strtod(s, NULL)
#define atol(s) strtol(s, NULL, 10)
#endif

#define CSV_FIELD_BUF 4096      /** max size of csv I/O field */
#define CSV_FIELD_SEPARATOR ',' /** field separator, comma or semicolon */
#define CSV_DECIMAL_SEPARATOR '.'   /** comma or dot */
#define CSV_ENCDATA_BUF 10      /** initial storage for encoded (gint) data */

#define MAX_URI_SCHEME 10

/* ======== Data ========================= */

/** Recognized URI schemes (used when parsing input data)
 * when adding new schemes, check that MAX_URI_SCHEME is enough to
 * store the entire scheme + '\0'
 */
struct uri_scheme_info {
  char *prefix;
  int length;
} uri_scheme_table[] = {
  { "urn:", 4 },
  { "file:", 5 },
  { "http://", 7 },
  { "https://", 8 },
  { "mailto:", 7 },
  { NULL, 0 }
};


/* ======= Private protos ================ */

static gint show_io_error(void *db, char *errmsg);
static gint show_io_error_str(void *db, char *errmsg, char *str);
static void snprint_record(void *db, wg_int* rec, char *buf, int buflen);
static void csv_escaped_str(void *db, char *iptr, char *buf, int buflen);
static void snprint_value_csv(void *db, gint enc, char *buf, int buflen);
#if 0
static gint parse_and_encode_uri(void *db, char *buf);
#endif
static gint parse_input_type(void *db, char *buf, gint *intdata,
                                        double *doubledata, gint *datetime);
static gint fread_csv(void *db, FILE *f);

#ifdef HAVE_RAPTOR
static gint import_raptor(void *db, gint pref_fields, gint suff_fields,
  gint (*callback) (void *, void *), char *filename, raptor_parser *rdf_parser);
static void handle_triple(void* user_data, const raptor_statement* triple);
static raptor_uri *dburi_to_raptoruri(void *db, gint enc);
static gint export_raptor(void *db, gint pref_fields, char *filename,
  raptor_serializer *rdf_serializer);
#endif

/* ====== Functions ============== */

/** Print contents of database.
 *
 */

void wg_print_db(void *db) {
  void *rec;

  rec = wg_get_first_record(db);
  while(rec) {
    wg_print_record(db, (gint *) rec);
    printf("\n");
    rec = wg_get_next_record(db,rec);
  }
}

/** Print single record
 *
 */
void wg_print_record(void *db, wg_int* rec) {

  wg_int len, enc;
  int i;
  char strbuf[256];
#ifdef USE_CHILD_DB
  void *parent;
#endif

  if (rec==NULL) {
    printf("<null rec pointer>\n");
    return;
  }

#ifdef USE_CHILD_DB
  parent = wg_get_rec_owner(db, rec);
#endif

  len = wg_get_record_len(db, rec);
  printf("[");
  for(i=0; i<len; i++) {
    if(i) printf(",");
    enc = wg_get_field(db, rec, i);
#ifdef USE_CHILD_DB
    if(parent != db)
      enc = wg_translate_hdroffset(db, parent, enc);
#endif
    wg_snprint_value(db, enc, strbuf, 255);
    printf("%s", strbuf);
  }
  printf("]");
}

/** Print a record into a stream (to handle records recursively)
 *  expects buflen to be at least 2.
 */
static void snprint_record(void *db, wg_int* rec, char *buf, int buflen) {

  char *strbuf;
#ifdef USE_CHILD_DB
  void *parent;
#endif

  if(rec==NULL) {
    snprintf(buf, buflen, "<null rec pointer>\n");
    return;
  }
  if(buflen < 2)
    return;

  *buf++ = '[';
  buflen--;

#ifdef USE_CHILD_DB
  parent = wg_get_rec_owner(db, rec);
#endif

  strbuf = malloc(buflen);
  if(strbuf) {
    int i, strbuflen;
    gint enc;
    gint len = wg_get_record_len(db, rec);
    for(i=0; i<len; i++) {
      /* Use a fresh buffer for the value. This way we can
       * easily count how many bytes printing the value added.
       */
      enc = wg_get_field(db, rec, i);
  #ifdef USE_CHILD_DB
      if(parent != db)
        enc = wg_translate_hdroffset(db, parent, enc);
  #endif
      wg_snprint_value(db, enc, strbuf, buflen);
      strbuflen = strlen(strbuf);

      /* Check if the value fits comfortably, including
       * leading comma and trailing \0
       */
      if(buflen < strbuflen + 2)
        break;
      if(i) {
        *buf++ = ',';
        buflen--;
      }
      strncpy(buf, strbuf, buflen);
      buflen -= strbuflen;
      buf += strbuflen;
      if(buflen < 2)
        break;
    }
    free(strbuf);
  }
  if(buflen > 1)
    *buf++ = ']';
  *buf = '\0';
}

/** Print a single, encoded value
 *  The value is written into a character buffer.
 */
void wg_snprint_value(void *db, gint enc, char *buf, int buflen) {
  gint ptrdata;
  int intdata, len;
  char *strdata, *exdata;
  double doubledata;
  char strbuf[80];

  buflen--; /* snprintf adds '\0' */
  switch(wg_get_encoded_type(db, enc)) {
    case WG_NULLTYPE:
      snprintf(buf, buflen, "NULL");
      break;
    case WG_RECORDTYPE:
      ptrdata = (gint) wg_decode_record(db, enc);
      snprintf(buf, buflen, "<rec %x>", (int) ptrdata);
      len = strlen(buf);
      if(buflen - len > 1)
        snprint_record(db, (wg_int*)ptrdata, buf+len, buflen-len);
      break;
    case WG_INTTYPE:
      intdata = wg_decode_int(db, enc);
      snprintf(buf, buflen, "%d", intdata);
      break;
    case WG_DOUBLETYPE:
      doubledata = wg_decode_double(db, enc);
      snprintf(buf, buflen, "%f", doubledata);
      break;
    case WG_FIXPOINTTYPE:
      doubledata = wg_decode_fixpoint(db, enc);
      snprintf(buf, buflen, "%f", doubledata);
      break;
    case WG_STRTYPE:
      strdata = wg_decode_str(db, enc);
      snprintf(buf, buflen, "\"%s\"", strdata);
      break;
    case WG_URITYPE:
      strdata = wg_decode_uri(db, enc);
      exdata = wg_decode_uri_prefix(db, enc);
      if (exdata==NULL)
        snprintf(buf, buflen, "%s", strdata);
      else
        snprintf(buf, buflen, "%s:%s", exdata, strdata);
      break;
    case WG_XMLLITERALTYPE:
      strdata = wg_decode_xmlliteral(db, enc);
      exdata = wg_decode_xmlliteral_xsdtype(db, enc);
      snprintf(buf, buflen, "\"<xsdtype %s>%s\"", exdata, strdata);
      break;
    case WG_CHARTYPE:
      intdata = wg_decode_char(db, enc);
      snprintf(buf, buflen, "%c", (char) intdata);
      break;
    case WG_DATETYPE:
      intdata = wg_decode_date(db, enc);
      wg_strf_iso_datetime(db,intdata,0,strbuf);
      strbuf[10]=0;
      snprintf(buf, buflen, "<raw date %d>%s", intdata,strbuf);
      break;
    case WG_TIMETYPE:
      intdata = wg_decode_time(db, enc);
      wg_strf_iso_datetime(db,1,intdata,strbuf);
      snprintf(buf, buflen, "<raw time %d>%s",intdata,strbuf+11);
      break;
    case WG_VARTYPE:
      intdata = wg_decode_var(db, enc);
      snprintf(buf, buflen, "?%d", intdata);
      break;
    case WG_ANONCONSTTYPE:
      strdata = wg_decode_anonconst(db, enc);
      snprintf(buf, buflen, "!%s",strdata);
      break;
    default:
      snprintf(buf, buflen, "<unsupported type>");
      break;
  }
}


/** Create CSV-formatted quoted string
 *
 */
static void csv_escaped_str(void *db, char *iptr, char *buf, int buflen) {
  char *optr;

#ifdef CHECK
  if(buflen < 3) {
    show_io_error(db, "CSV field buffer too small");
    return;
  }
#endif
  optr = buf;
  *optr++ = '"';
  buflen--; /* space for terminating quote */
  while(*iptr) { /* \0 terminates */
    int nextsz = 1;
    if(*iptr == '"') nextsz++;

    /* Will our string fit? */
    if(((gint)optr + nextsz - (gint)buf) < buflen) {
      *optr++ = *iptr;
      if(*iptr++ == '"')
        *optr++ = '"'; /* quote -> double quote */
    } else
      break;
  }
  *optr++ = '"'; /* CSV string terminator */
  *optr = '\0'; /* C string terminator */
}


/** Print a single, encoded value, into a CSV-friendly format
 *  The value is written into a character buffer.
 */
static void snprint_value_csv(void *db, gint enc, char *buf, int buflen) {
  int intdata, ilen;
  double doubledata;
  char strbuf[80], *ibuf;

  buflen--; /* snprintf adds '\0' */
  switch(wg_get_encoded_type(db, enc)) {
    case WG_NULLTYPE:
      buf[0] = '\0'; /* output an empty field */
      break;
    case WG_RECORDTYPE:
      intdata = ptrtooffset(db, wg_decode_record(db, enc));
      snprintf(buf, buflen, "\"<record offset %d>\"", intdata);
      break;
    case WG_INTTYPE:
      intdata = wg_decode_int(db, enc);
      snprintf(buf, buflen, "%d", intdata);
      break;
    case WG_DOUBLETYPE:
      doubledata = wg_decode_double(db, enc);
      snprintf(buf, buflen, "%f", doubledata);
      break;
    case WG_FIXPOINTTYPE:
      doubledata = wg_decode_fixpoint(db, enc);
      snprintf(buf, buflen, "%f", doubledata);
      break;
    case WG_STRTYPE:
      csv_escaped_str(db, wg_decode_str(db, enc), buf, buflen);
      break;
    case WG_XMLLITERALTYPE:
      csv_escaped_str(db, wg_decode_xmlliteral(db, enc), buf, buflen);
      break;
    case WG_URITYPE:
      /* More efficient solutions are possible, but here we simply allocate
       * enough storage to concatenate the URI before encoding it for CSV.
       */
      ilen = wg_decode_uri_len(db, enc);
      ilen += wg_decode_uri_prefix_len(db, enc);
      ibuf = (char *) malloc(ilen + 1);
      if(!ibuf) {
        show_io_error(db, "Failed to allocate memory");
        return;
      }
      snprintf(ibuf, ilen+1, "%s%s",
        wg_decode_uri_prefix(db, enc), wg_decode_uri(db, enc));
      csv_escaped_str(db, ibuf, buf, buflen);
      free(ibuf);
      break;
    case WG_CHARTYPE:
      intdata = wg_decode_char(db, enc);
      snprintf(buf, buflen, "%c", (char) intdata);
      break;
    case WG_DATETYPE:
      intdata = wg_decode_date(db, enc);
      wg_strf_iso_datetime(db,intdata,0,strbuf);
      strbuf[10]=0;
      snprintf(buf, buflen, "%s", strbuf);
      break;
    case WG_TIMETYPE:
      intdata = wg_decode_time(db, enc);
      wg_strf_iso_datetime(db,1,intdata,strbuf);
      snprintf(buf, buflen, "%s", strbuf+11);
      break;
    default:
      snprintf(buf, buflen, "\"<unsupported type>\"");
      break;
  }
}


/** Try parsing an URI from a string.
 *  Returns encoded WG_URITYPE field when successful
 *  Returns WG_ILLEGAL on error
 *
 *  XXX: this is a very naive implementation. Something more robust
 *  is needed.
 *
 *  XXX: currently unused.
 */
#if 0
static gint parse_and_encode_uri(void *db, char *buf) {
  gint encoded = WG_ILLEGAL;
  struct uri_scheme_info *next = uri_scheme_table;

  /* Try matching to a known scheme */
  while(next->prefix) {
    if(!strncmp(buf, next->prefix, next->length)) {
      /* We have a matching URI scheme.
       * XXX: check this code for correct handling of prefix. */
      int urilen = strlen(buf);
      char *prefix = (char *) malloc(urilen + 1);
      char *dataptr;

      if(!prefix)
        break;
      strncpy(prefix, buf, urilen);

      dataptr = prefix + urilen;
      while(--dataptr >= prefix) {
        switch(*dataptr) {
          case ':':
          case '/':
          case '#':
            *(dataptr+1) = '\0';
            goto prefix_marked;
          default:
            break;
        }
      }
prefix_marked:
      encoded = wg_encode_uri(db, buf+((gint)dataptr-(gint)prefix+1), prefix);
      free(prefix);
      break;
    }
    next++;
  }
  return encoded;
}
#endif

/** Parse value from string, encode it for WhiteDB
 *  returns WG_ILLEGAL if value could not be parsed or
 *  encoded.
 *
 *  See the comment for parse_input_type() for the supported types.
 *  If other conversions fail, data will be encoded as string.
 */
gint wg_parse_and_encode(void *db, char *buf) {
  gint intdata = 0;
  double doubledata = 0;
  gint encoded = WG_ILLEGAL, res = 0;

  switch(parse_input_type(db, buf, &intdata, &doubledata, &res)) {
    case WG_NULLTYPE:
      encoded = 0;
      break;
    case WG_INTTYPE:
      encoded = wg_encode_int(db, intdata);
      break;
    case WG_DOUBLETYPE:
      encoded = wg_encode_double(db, doubledata);
      break;
    case WG_STRTYPE:
      encoded = wg_encode_str(db, buf, NULL);
      break;
    case WG_DATETYPE:
      encoded = wg_encode_date(db, res);
      break;
    case WG_TIMETYPE:
      encoded = wg_encode_time(db, res);
      break;
    default:
      break;
  }
  return encoded;
}

/** Parse value from string, encode it as a query parameter.
 *  returns WG_ILLEGAL if value could not be parsed or
 *  encoded.
 *
 *  Parameters encoded like this should be freed with
 *  wg_free_query_param() and cannot be used interchangeably
 *  with other encoded values.
 */
gint wg_parse_and_encode_param(void *db, char *buf) {
  gint intdata = 0;
  double doubledata = 0;
  gint encoded = WG_ILLEGAL, res = 0;

  switch(parse_input_type(db, buf, &intdata, &doubledata, &res)) {
    case WG_NULLTYPE:
      encoded = 0;
      break;
    case WG_INTTYPE:
      encoded = wg_encode_query_param_int(db, intdata);
      break;
    case WG_DOUBLETYPE:
      encoded = wg_encode_query_param_double(db, doubledata);
      break;
    case WG_STRTYPE:
      encoded = wg_encode_query_param_str(db, buf, NULL);
      break;
    case WG_DATETYPE:
      encoded = wg_encode_query_param_date(db, res);
      break;
    case WG_TIMETYPE:
      encoded = wg_encode_query_param_time(db, res);
      break;
    default:
      break;
  }
  return encoded;
}

/** Detect the type of input data in string format.
 *
 *  Supports following data types:
 *  NULL - empty string
 *  int - plain integer
 *  double - floating point number in fixed decimal notation
 *  date - ISO8601 date
 *  time - ISO8601 time+fractions of second.
 *  string - input data that does not match the above types
 *
 *  Does NOT support ambiguous types:
 *  fixpoint - floating point number in fixed decimal notation
 *  uri - string starting with an URI prefix
 *  char - single character
 *
 *  Does NOT support types which would require a special encoding
 *  scheme in string form:
 *  record, XML literal, blob, anon const, variables
 *
 *  Return values:
 *  0 - value type could not be parsed or detected
 *  WG_NULLTYPE - NULL
 *  WG_INTTYPE - int, *intdata contains value
 *  WG_DOUBLETYPE - double, *doubledata contains value
 *  WG_DATETYPE - date, *datetime contains internal representation
 *  WG_TIMETYPE - time, *datetime contains internal representation
 *  WG_STRTYPE - string, use entire buf
 *
 *  Since leading whitespace makes type guesses fail, it invariably
 *  causes WG_STRTYPE to be returned.
 */
static gint parse_input_type(void *db, char *buf, gint *intdata,
                                        double *doubledata, gint *datetime) {
  gint type = 0;
  char c = buf[0];

  if(c == 0) {
    /* empty fields become NULL-s */
    type = WG_NULLTYPE;
  }
  else if((c >= '0' && c <= '9') ||\
   (c == '-' && buf[1] >= '0' && buf[1] <= '9')) {
    /* This could be one of int, double, date or time */
    if(c != '-' && (*datetime = wg_strp_iso_date(db, buf)) >= 0) {
      type = WG_DATETYPE;
    } else if(c != '-' && (*datetime = wg_strp_iso_time(db, buf)) >= 0) {
      type = WG_TIMETYPE;
    } else {
      /* Examine the field contents to distinguish between float
       * and int, then convert using atol()/atof(). sscanf() tends to
       * be too optimistic about the conversion, especially under Win32.
       */
      char numbuf[80];
      char *ptr = buf, *wptr = numbuf, *decptr = NULL;
      int decsep = 0;
      while(*ptr) {
        if(*ptr == CSV_DECIMAL_SEPARATOR) {
          decsep++;
          decptr = wptr;
        }
        else if((*ptr < '0' || *ptr > '9') && ptr != buf) {
          /* Non-numeric. Mark this as an invalid number
           * by abusing the decimal separator count.
           */
          decsep = 2;
          break;
        }
        *(wptr++) = *(ptr++);
        if((int) (wptr - numbuf) >= 79)
          break;
      }
      *wptr = '\0';

      if(decsep==1) {
        char tmp = *decptr;
        *decptr = '.'; /* ignore locale, force conversion by plain atof() */
        *doubledata = atof(numbuf);
        if(errno!=ERANGE && errno!=EINVAL) {
          type = WG_DOUBLETYPE;
        } else {
          errno = 0; /* Under Win32, successful calls don't do this? */
        }
        *decptr = tmp; /* conversion might have failed, restore string */
      } else if(!decsep) {
        *intdata = atol(numbuf);
        if(errno!=ERANGE && errno!=EINVAL) {
          type = WG_INTTYPE;
        } else {
          errno = 0;
        }
      }
    }
  }

  if(type == 0) {
    /* Default type is string */
    type = WG_STRTYPE;
  }
  return type;
}

/** Write single record to stream in CSV format
 *
 */
void wg_fprint_record_csv(void *db, wg_int* rec, FILE *f) {

  wg_int len, enc;
  int i;
  char *strbuf;

  if(rec==NULL) {
    show_io_error(db, "null record pointer");
    return;
  }

  strbuf = (char *) malloc(CSV_FIELD_BUF);
  if(strbuf==NULL) {
    show_io_error(db, "Failed to allocate memory");
    return;
  }

  len = wg_get_record_len(db, rec);
  for(i=0; i<len; i++) {
    if(i) fprintf(f, "%c", CSV_FIELD_SEPARATOR);
    enc = wg_get_field(db, rec, i);
    snprint_value_csv(db, enc, strbuf, CSV_FIELD_BUF-1);
    fprintf(f, "%s", strbuf);
  }

  free(strbuf);
}

/** Export contents of database into a CSV file.
 *
 */

void wg_export_db_csv(void *db, char *filename) {
  void *rec;
  FILE *f;

#ifdef _WIN32
  if(fopen_s(&f, filename, "w")) {
#else
  if(!(f = fopen(filename, "w"))) {
#endif
    show_io_error_str(db, "failed to open file", filename);
    return;
  }

  rec = wg_get_first_record(db);
  while(rec) {
    wg_fprint_record_csv(db, (wg_int *) rec, f);
    fprintf(f, "\n");
    rec = wg_get_next_record(db, rec);
  };

  fclose(f);
}

/** Read CSV stream and convert it to database records.
 *  Returns 0 if there were no errors
 *  Returns -1 for non-fatal errors
 *  Returns -2 for database errors
 *  Returns -3 for other errors
 */
static gint fread_csv(void *db, FILE *f) {
  char *strbuf, *ptr;
  gint *encdata;
  gint err = 0;
  gint uq_field, quoted_field, esc_quote, eat_sep; /** State flags */
  gint commit_strbuf, commit_record;
  gint reclen;
  gint encdata_sz = CSV_ENCDATA_BUF;

  strbuf = (char *) malloc(CSV_FIELD_BUF);
  if(strbuf==NULL) {
    show_io_error(db, "Failed to allocate memory");
    return -1;
  }

  encdata = (gint *) malloc(sizeof(gint) * encdata_sz);
  if(strbuf==NULL) {
    free(strbuf);
    show_io_error(db, "Failed to allocate memory");
    return -1;
  }

  /* Init parser state */
  reclen = 0;
  uq_field = quoted_field = esc_quote = eat_sep = 0;
  commit_strbuf = commit_record = 0;
  ptr = strbuf;

  while(!feof(f)) {
    /* Parse cycle consists:
     * 1. read character from stream. This can either:
     *   - change the state of the parser
     *   - be appended to strbuf
     * 2. if the parser state changed, we need to do one
     *    of the following:
     *   - parse the field from strbuf
     *   - store the record in the database
     */

    char c = (char) fgetc(f);

    if(quoted_field) {
      /* We're parsing a quoted field. Anything we get is added to
       * strbuf unless it's a quote character.
       */
      if(!esc_quote && c == '"') {
        char nextc = (char) fgetc(f);
        ungetc((int) nextc, f);

        if(nextc!='"') {
          /* Field ends. Note that even EOF is acceptable here */
          quoted_field = 0;
          commit_strbuf = 1; /* set flag to commit buffer */
          eat_sep = 1; /* next separator can be ignored. */
        } else {
          esc_quote = 1; /* make a note that next quote is escaped */
        }
      } else {
        esc_quote = 0;
        /* read the character. It's simply ignored if the buffer is full */
        if(((gint) ptr - (gint) strbuf) < CSV_FIELD_BUF-1)
          *ptr++ = c;
      }
    } else if(uq_field) {
      /* In case of an unquoted field, terminator can be the field
       * separator or end of line. In the latter case we also need to
       * store the record.
       */
      if(c == CSV_FIELD_SEPARATOR) {
        uq_field = 0;
        commit_strbuf = 1;
      } else if(c == 13) { /* Ignore CR. */
        continue;
      } else if(c == 10) { /* LF is the last character for both DOS and UNIX */
        uq_field = 0;
        commit_strbuf = 1;
        commit_record = 1;
      } else {
        if(((gint) ptr - (gint) strbuf) < CSV_FIELD_BUF-1)
          *ptr++ = c;
      }
    } else {
      /* We are currently not parsing anything. Four things can happen:
       * - quoted field begins
       * - unquoted field begins
       * - we're on a field separator
       * - line ends
       */
      if(c == CSV_FIELD_SEPARATOR) {
        if(eat_sep) {
          /* A quoted field just ended, this separator can be skipped */
          eat_sep = 0;
          continue;
        } else {
          /* The other way to interpret this is that we have a NULL field.
           * Commit empty buffer. */
          commit_strbuf = 1;
        }
      } else if(c == 13) { /* CR is ignored, as we're expecting LF to follow */
        continue;
      } else if(c == 10) { /* LF is line terminator. */
        if(eat_sep) {
          eat_sep = 0; /* should reset this as well */
        } else if(reclen) {
          /* This state can occur when we've been preceded by a record
           * separator. The zero length field between ,\n counts as a NULL
           * field. XXX: this creates an inconsistent situation where
           * empty lines are discarded while a sincle comma (or semicolon)
           * generates a two-field record of NULL-s. The benefit is that
           * junk empty lines don't generate junk records. Check the
           * unofficial RFC to see if this should be changed.
           */
          commit_strbuf = 1;
        }
        commit_record = 1;
      } else {
        /* A new field begins */
        if(c == '"') {
          quoted_field = 1;
        }
        else {
          uq_field = 1;
          *ptr++ = c;
        }
      }
    }

    if(commit_strbuf) {
      gint enc;

      /* We were instructed to convert our string buffer to data. First
       * mark the end of string and reset strbuf state for next loop. */
      *ptr = (char) 0;
      commit_strbuf = 0;
      ptr = strbuf;

      /* Need more storage for encoded data? */
      if(reclen >= encdata_sz) {
        gint *tmp;
        encdata_sz += CSV_ENCDATA_BUF;
        tmp = (gint *) realloc(encdata, sizeof(gint) * encdata_sz);
        if(tmp==NULL) {
          err = -3;
          show_io_error(db, "Failed to allocate memory");
          break;
        } else
          encdata = tmp;
      }

      /* Do the actual parsing. This also allocates database-side
       * storage for the new data. */
      enc = wg_parse_and_encode(db, strbuf);
      if(enc == WG_ILLEGAL) {
        show_io_error_str(db, "Warning: failed to parse", strbuf);
        enc = 0; /* continue anyway */
      }
      encdata[reclen++] = enc;
    }

    if(commit_record) {
      /* Need to save the record to database. */
      int i;
      void *rec;

      commit_record = 0;
      if(!reclen)
        continue; /* Ignore empty rows */

      rec = wg_create_record(db, reclen);
      if(!rec) {
        err = -2;
        show_io_error(db, "Failed to create record");
        break;
      }
      for(i=0; i<reclen; i++) {
        if(wg_set_field(db, rec, i, encdata[i])) {
          err = -2;
          show_io_error(db, "Failed to save field data");
          break;
        }
      }

      /* Reset record data */
      reclen = 0;
    }
  }

  free(encdata);
  free(strbuf);
  return err;
}

/** Import data from a CSV file into database
 *  Data will be added to existing data.
 *  Returns 0 if there were no errors
 *  Returns -1 for file I/O errors
 *  Other error codes may be generated by fread_csv()
 */

gint wg_import_db_csv(void *db, char *filename) {
  FILE *f;
  gint err = 0;

#ifdef _WIN32
  if(fopen_s(&f, filename, "r")) {
#else
  if(!(f = fopen(filename, "r"))) {
#endif
    show_io_error_str(db, "failed to open file", filename);
    return -1;
  }

  err = fread_csv(db, f);
  fclose(f);
  return err;
}

#ifdef HAVE_RAPTOR

/** Import RDF data from file
 *  wrapper for import_raptor() that recognizes the content via filename
 */
gint wg_import_raptor_file(void *db, gint pref_fields, gint suff_fields,
  gint (*callback) (void *, void *), char *filename) {
  raptor_parser* rdf_parser=NULL;
  gint err = 0;

  raptor_init();
  rdf_parser = raptor_new_parser_for_content(NULL, NULL, NULL, 0,
    (unsigned char *) filename);
  if(!rdf_parser)
    return -1;

  err = import_raptor(db, pref_fields, suff_fields, (*callback),
    filename, rdf_parser);

  raptor_free_parser(rdf_parser);
  raptor_finish();
  return err;
}

/** Import RDF data from file, instructing raptor to use rdfxml parser
 *  Sample wrapper to demonstrate potential extensions to API
 */
gint wg_import_raptor_rdfxml_file(void *db, gint pref_fields, gint suff_fields,
  gint (*callback) (void *, void *), char *filename) {
  raptor_parser* rdf_parser=NULL;
  gint err = 0;

  raptor_init();
  rdf_parser=raptor_new_parser("rdfxml"); /* explicitly select the parser */
  if(!rdf_parser)
    return -1;

  err = import_raptor(db, pref_fields, suff_fields, (*callback),
    filename, rdf_parser);

  raptor_free_parser(rdf_parser);
  raptor_finish();
  return err;
}

/** File-based raptor import function
 *  Uses WhiteDB-specific API parameters of:
 *  pref_fields
 *  suff_fields
 *  callback
 *
 *  This function should be wrapped in a function that initializes
 *  raptor parser to the appropriate content type.
 */
static gint import_raptor(void *db, gint pref_fields, gint suff_fields,
  gint (*callback) (void *, void *), char *filename, raptor_parser *rdf_parser) {
  unsigned char *uri_string;
  raptor_uri *uri, *base_uri;
  struct wg_triple_handler_params user_data;
  int err;

  user_data.db = db;
  user_data.pref_fields = pref_fields;
  user_data.suff_fields = suff_fields;
  user_data.callback = (*callback);
  user_data.rdf_parser = rdf_parser;
  user_data.count = 0;
  user_data.error = 0;
  raptor_set_statement_handler(rdf_parser, &user_data, handle_triple);

  uri_string=raptor_uri_filename_to_uri_string(filename);
  uri=raptor_new_uri(uri_string);
  base_uri=raptor_uri_copy(uri);

  /* Parse the file. In some cases raptor returns an error but not
   * in all cases that interest us, we also consider feedback from
   * the triple handler.
   */
  err = raptor_parse_file(rdf_parser, uri, base_uri);
  if(err > 0)
    err = -1; /* XXX: not clear if fatal errors can occur here */
  if(!user_data.count && err > -1)
    err = -1; /* No rows read. File was total garbage? */
  if(err > user_data.error)
    err = user_data.error; /* More severe database error. */

  raptor_free_uri(base_uri);
  raptor_free_uri(uri);
  raptor_free_memory(uri_string);
  return (gint) err;
}

/** Triple handler for raptor
 *  Stores the triples parsed by raptor into database
 */
static void handle_triple(void* user_data, const raptor_statement* triple) {
  void* rec;
  struct wg_triple_handler_params *params = \
    (struct wg_triple_handler_params *) user_data;
  gint enc;

  rec=wg_create_record(params->db,
    params->pref_fields + 3 + params->suff_fields);
  if (!rec) {
    show_io_error(params->db, "cannot create a new record");
    params->error = -2;
    raptor_parse_abort(params->rdf_parser);
  }

  /* Field storage order: predicate, subject, object */
  enc = parse_and_encode_uri(params->db, (char*)(triple->predicate));
  if(enc==WG_ILLEGAL ||\
    wg_set_field(params->db, rec, params->pref_fields, enc)) {
    show_io_error(params->db, "failed to store field");
    params->error = -2;
    raptor_parse_abort(params->rdf_parser);
  }
  enc = parse_and_encode_uri(params->db, (char*)(triple->subject));
  if(enc==WG_ILLEGAL ||\
    wg_set_field(params->db, rec, params->pref_fields+1, enc)) {
    show_io_error(params->db, "failed to store field");
    params->error = -2;
    raptor_parse_abort(params->rdf_parser);
  }

  if ((triple->object_type)==RAPTOR_IDENTIFIER_TYPE_RESOURCE) {
    enc = parse_and_encode_uri(params->db, (char*)(triple->object));
  } else if ((triple->object_type)==RAPTOR_IDENTIFIER_TYPE_ANONYMOUS) {
    /* Fixed prefix urn:local: */
    enc=wg_encode_uri(params->db, (char*)(triple->object),
      "urn:local:");
  } else if ((triple->object_type)==RAPTOR_IDENTIFIER_TYPE_LITERAL) {
    if ((triple->object_literal_datatype)==NULL) {
      enc=wg_encode_str(params->db,(char*)(triple->object),
        (char*)(triple->object_literal_language));
    } else {
      enc=wg_encode_xmlliteral(params->db, (char*)(triple->object),
        (char*)(triple->object_literal_datatype));
    }
  } else {
    show_io_error(params->db, "Unknown triple object type");
    /* XXX: is this fatal? Maybe we should set error and continue here */
    params->error = -2;
    raptor_parse_abort(params->rdf_parser);
  }

  if(enc==WG_ILLEGAL ||\
    wg_set_field(params->db, rec, params->pref_fields+2, enc)) {
    show_io_error(params->db, "failed to store field");
    params->error = -2;
    raptor_parse_abort(params->rdf_parser);
  }

  /* After correctly storing the triple, call the designated callback */
  if(params->callback) {
    if((*(params->callback)) (params->db, rec)) {
      show_io_error(params->db, "record callback failed");
      params->error = -2;
      raptor_parse_abort(params->rdf_parser);
    }
  }

  params->count++;
}

/** WhiteDB RDF parsing callback
 *  This callback does nothing, but is always called when RDF files
 *  are imported using wgdb commandline tool. If import API is used from
 *  user application, alternative callback functions can be implemented
 *  in there.
 *
 *  Callback functions are expected to return 0 on success and
 *  <0 on errors that cause the database to go into an invalid state.
 */
gint wg_rdfparse_default_callback(void *db, void *rec) {
  return 0;
}

/** Export triple data to file
 *  wrapper for export_raptor(), allows user to specify serializer type.
 *
 *  raptor provides an API to enumerate serializers. This is not
 *  utilized here.
 */
gint wg_export_raptor_file(void *db, gint pref_fields, char *filename,
  char *serializer) {
  raptor_serializer *rdf_serializer=NULL;
  gint err = 0;

  raptor_init();
  rdf_serializer = raptor_new_serializer(serializer);
  if(!rdf_serializer)
    return -1;

  err = export_raptor(db, pref_fields, filename, rdf_serializer);

  raptor_free_serializer(rdf_serializer);
  raptor_finish();
  return err;
}

/** Export triple data to file, instructing raptor to use rdfxml serializer
 *
 */
gint wg_export_raptor_rdfxml_file(void *db, gint pref_fields, char *filename) {
  return wg_export_raptor_file(db, pref_fields, filename, "rdfxml");
}

/** Convert wgdb URI field to raptor URI
 *  Helper function. Caller is responsible for calling raptor_free_uri()
 *  when the returned value is no longer needed.
 */
static raptor_uri *dburi_to_raptoruri(void *db, gint enc) {
  raptor_uri *tmpuri = raptor_new_uri((unsigned char *)
    wg_decode_uri_prefix(db, enc));
  raptor_uri *uri = raptor_new_uri_from_uri_local_name(tmpuri,
    (unsigned char *) wg_decode_uri(db, enc));
  raptor_free_uri(tmpuri);
  return uri;
}

/** File-based raptor export function
 *  Uses WhiteDB-specific API parameters of:
 *  pref_fields
 *  suff_fields
 *
 *  Expects an initialized serializer as an argument.
 *  returns 0 on success.
 *  returns -1 on errors (no fatal errors that would corrupt
 *  the database are expected here).
 */
static gint export_raptor(void *db, gint pref_fields, char *filename,
  raptor_serializer *rdf_serializer) {
  int err, minsize;
  raptor_statement *triple;
  void *rec;

  err = raptor_serialize_start_to_filename(rdf_serializer, filename);
  if(err)
    return -1; /* initialization failed somehow */

  /* Start constructing triples and sending them to the serializer. */
  triple = (raptor_statement *) malloc(sizeof(raptor_statement));
  if(!triple) {
    show_io_error(db, "Failed to allocate memory");
    return -1;
  }
  memset(triple, 0, sizeof(raptor_statement));

  rec = wg_get_first_record(db);
  minsize = pref_fields + 3;
  while(rec) {
    if(wg_get_record_len(db, rec) >= minsize) {
      gint enc = wg_get_field(db, rec, pref_fields);

      if(wg_get_encoded_type(db, enc) == WG_URITYPE) {
        triple->predicate = dburi_to_raptoruri(db, enc);
      }
      else if(wg_get_encoded_type(db, enc) == WG_STRTYPE) {
        triple->predicate = (void *) raptor_new_uri(
          (unsigned char *) wg_decode_str(db, enc));
      }
      else {
        show_io_error(db, "Bad field type for predicate");
        err = -1;
        goto done;
      }
      triple->predicate_type = RAPTOR_IDENTIFIER_TYPE_RESOURCE;

      enc = wg_get_field(db, rec, pref_fields + 1);

      if(wg_get_encoded_type(db, enc) == WG_URITYPE) {
        triple->subject = dburi_to_raptoruri(db, enc);
      }
      else if(wg_get_encoded_type(db, enc) == WG_STRTYPE) {
        triple->subject = (void *) raptor_new_uri(
          (unsigned char *) wg_decode_str(db, enc));
      }
      else {
        show_io_error(db, "Bad field type for subject");
        err = -1;
        goto done;
      }
      triple->subject_type = RAPTOR_IDENTIFIER_TYPE_RESOURCE;

      enc = wg_get_field(db, rec, pref_fields + 2);

      triple->object_literal_language = NULL;
      triple->object_literal_datatype = NULL;
      if(wg_get_encoded_type(db, enc) == WG_URITYPE) {
        triple->object = dburi_to_raptoruri(db, enc);
        triple->object_type = RAPTOR_IDENTIFIER_TYPE_RESOURCE;
      }
      else if(wg_get_encoded_type(db, enc) == WG_XMLLITERALTYPE) {
        triple->object = (void *) raptor_new_uri(
          (unsigned char *) wg_decode_xmlliteral(db, enc));
        triple->object_literal_datatype = raptor_new_uri(
          (unsigned char *) wg_decode_xmlliteral_xsdtype(db, enc));
        triple->object_type = RAPTOR_IDENTIFIER_TYPE_LITERAL;
      }
      else if(wg_get_encoded_type(db, enc) == WG_STRTYPE) {
        triple->object = (void *) wg_decode_str(db, enc);
        triple->object_literal_language =\
          (unsigned char *) wg_decode_str_lang(db, enc);
        triple->object_type = RAPTOR_IDENTIFIER_TYPE_LITERAL;
      }
      else {
        show_io_error(db, "Bad field type for object");
        err = -1;
        goto done;
      }

      /* Write the triple */
      raptor_serialize_statement(rdf_serializer, triple);

      /* Cleanup current triple */
      raptor_free_uri((raptor_uri *) triple->subject);
      raptor_free_uri((raptor_uri *) triple->predicate);
      if(triple->object_type == RAPTOR_IDENTIFIER_TYPE_RESOURCE)
        raptor_free_uri((raptor_uri *) triple->object);
      else if(triple->object_literal_datatype)
        raptor_free_uri((raptor_uri *) triple->object_literal_datatype);
    }
    rec = wg_get_next_record(db, rec);
  }

done:
  raptor_serialize_end(rdf_serializer);
  free(triple);
  return (gint) err;
}


#endif /* HAVE_RAPTOR */

void wg_pretty_print_memsize(gint memsz, char *buf, size_t buflen) {
  if(memsz < 1000) {
    snprintf(buf, buflen-1, "%d bytes", (int) memsz);
  } else if(memsz < 1000000) {
    snprintf(buf, buflen-1, "%d kB", (int) (memsz/1000));
  } else if(memsz < 1000000000) {
    snprintf(buf, buflen-1, "%d MB", (int) (memsz/1000000));
  } else {
    snprintf(buf, buflen-1, "%d GB", (int) (memsz/1000000000));
  }
  buf[buflen-1] = '\0';
}

/* ------------ error handling ---------------- */

static gint show_io_error(void *db, char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"I/O error: %s.\n", errmsg);
#endif
  return -1;
}

static gint show_io_error_str(void *db, char *errmsg, char *str) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"I/O error: %s: %s.\n", errmsg, str);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Tanel Tammet 2004,2005,2006,2007,2008,2009
*
* Contact: tanel.tammet@gmail.com
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbmpool.c
 *  Allocating data using a temporary memory pool.
 *
 */

/* ====== Includes =============== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/shm.h>
#include <sys/errno.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//mem.h"
//api.h"

/* ====== Private headers and defs ======== */

#define NROF_SUBAREAS 100           // size of subarea array
#define MIN_FIRST_SUBAREA_SIZE 1024 // first free area minimum: if less asked, this given
#define ALIGNMENT_BYTES 4           // every val returned by wg_alloc_mpool is aligned to this

#define TYPEMASK 1    // memory pool convenience objects type mask for address
#define PAIRBITS 0    // memory pool convenience objects type bit for pairs (lists)
#define ATOMBITS 1    // memory pool convenience objects type bit for atoms (strings etc)


/** located inside mpool_header: one single memory subarea header
*
*
*/

typedef struct _wg_mpoolsubarea_header {
  int size;           /** size of subarea in bytes */
  void* area_start;   /** pointer to the first byte of the subarea */
  void* area_end;     /** pointer to the first byte after the subarea */
} mpool_subarea_header;


/** memory pool management data
*  stored in the beginning of the first segment of mempool
*
*/

typedef struct {
  void* freeptr;     /** pointer to the next free location in the pool */
  int cur_subarea;   /** index of the currently used subarea in the subarea_table (starts with 0) */
  int nrof_subareas; /** full nr of rows in the subarea table */
  mpool_subarea_header subarea_table[NROF_SUBAREAS];    /** subarea information (mpool_subarea_header) table */
} mpool_header;


/* ======= Private protos ================ */

static int extend_mpool(void* db, void* mpool, int minbytes);
static int show_mpool_error(void* db, char* errmsg);
static int show_mpool_error_nr(void* db, char* errmsg, int nr);
static void wg_mpool_print_aux(void* db, void* ptr, int depth, int pflag);

/* ====== Functions for mpool creating/extending/allocating/destroying ============== */


/** create and initialise a new memory pool
*
* initial pool has at least origbytes of free space
* mpool is extended automatically later when space used up
* returns void* pointer to mpool if OK, NULL if failure
*
* does a single malloc (latex extensions do further mallocs)
*/



void* wg_create_mpool(void* db, int origbytes) {
  int bytes;
  void* mpool;
  mpool_header* mpoolh;
  int puresize;
  void* nextptr;
  int i;

  if (origbytes<MIN_FIRST_SUBAREA_SIZE+ALIGNMENT_BYTES)
    bytes=sizeof(mpool_header)+MIN_FIRST_SUBAREA_SIZE+ALIGNMENT_BYTES;
  else
    bytes=sizeof(mpool_header)+origbytes+ALIGNMENT_BYTES;
  puresize=bytes-sizeof(mpool_header);
  mpool=malloc(bytes);
  if (mpool==NULL) {
    show_mpool_error_nr(db,
      " cannot create an mpool with size: ",origbytes);
    return NULL;
  }
  mpoolh=(mpool_header*)mpool;
  nextptr=(void*)(((char*)mpool)+sizeof(mpool_header));
  // set correct alignment for nextptr
  i=((size_t)nextptr)%ALIGNMENT_BYTES;
  if (i!=0) nextptr=((char*)nextptr)+(ALIGNMENT_BYTES-i);
  // aligment now ok
  (mpoolh->freeptr)=nextptr;
  (mpoolh->cur_subarea)=0;
  ((mpoolh->subarea_table)[0]).size=puresize;
  ((mpoolh->subarea_table)[0]).area_start=mpool;
  ((mpoolh->subarea_table)[0]).area_end=(void*)(((char*)mpool)+bytes);
  return mpool;
}


/** extend an existing memory pool
*
* called automatically when mpool space used up
* does one malloc for a new subarea
*
*/


static int extend_mpool(void* db, void* mpool, int minbytes) {
  int cursize;
  int bytes;
  void* subarea;
  mpool_header* mpoolh;
  int i;
  void* nextptr;

  mpoolh=(mpool_header*)mpool;
  cursize=((mpoolh->subarea_table)[(mpoolh->cur_subarea)]).size;
  bytes=cursize;
  for(i=0;i<100;i++) {
    bytes=bytes*2;
    if (bytes>=(minbytes+ALIGNMENT_BYTES)) break;
  }
  subarea=malloc(bytes);
  if (subarea==NULL) {
    show_mpool_error_nr(db,
      " cannot extend mpool to size: ",minbytes);
    return -1;
  }
  (mpoolh->freeptr)=subarea;
  (mpoolh->cur_subarea)++;
  ((mpoolh->subarea_table)[mpoolh->cur_subarea]).size=bytes;
  nextptr=subarea;
  // set correct alignment for nextptr
  i=((size_t)nextptr)%ALIGNMENT_BYTES;
  if (i!=0) nextptr=((char*)nextptr)+(ALIGNMENT_BYTES-i);
  // aligment now ok
  (mpoolh->freeptr)=nextptr;
  ((mpoolh->subarea_table)[mpoolh->cur_subarea]).area_start=subarea;
  ((mpoolh->subarea_table)[mpoolh->cur_subarea]).area_end=(void*)(((char*)subarea)+bytes);
  return 0;
}

/** free the whole memory pool
*
* frees all the malloced subareas and initial mpool
*
*/

void wg_free_mpool(void* db, void* mpool) {
  int i;
  mpool_header* mpoolh;

  mpoolh=(mpool_header*)mpool;
  i=mpoolh->cur_subarea;
  for(;i>0;i--) {
    free(((mpoolh->subarea_table)[i]).area_start);
  }
  free(mpool);
}

/** allocate bytes from a memory pool: analogous to malloc
*
* mpool is extended automatically if not enough free space present
* returns void* pointer to a memory block if OK, NULL if failure
*
*/

void* wg_alloc_mpool(void* db, void* mpool, int bytes) {
  void* curptr;
  void* nextptr;
  mpool_header* mpoolh;
  void* curend;
  int tmp;
  int i;

  if (bytes<=0) {
    show_mpool_error_nr(db,
      " trying to allocate too little from mpool: ",bytes);
    return NULL;
  }
  if (mpool==NULL) {
    show_mpool_error(db," mpool passed to wg_alloc_mpool is NULL ");
    return NULL;
  }
  mpoolh=(mpool_header*)mpool;
  nextptr=(void*)(((char*)(mpoolh->freeptr))+bytes);
  curend=((mpoolh->subarea_table)[(mpoolh->cur_subarea)]).area_end;
  if (nextptr>curend) {
    tmp=extend_mpool(db,mpool,bytes);
    if (tmp!=0) {
      show_mpool_error_nr(db," cannot extend mpool size by: ",bytes);
      return NULL;
    }
    nextptr=((char*)(mpoolh->freeptr))+bytes;
  }
  curptr=mpoolh->freeptr;
  // set correct alignment for nextptr
  i=((size_t)nextptr)%ALIGNMENT_BYTES;
  if (i!=0) nextptr=((char*)nextptr)+(ALIGNMENT_BYTES-i);
  // alignment now ok
  mpoolh->freeptr=nextptr;
  return curptr;
}



/* ====== Convenience functions for using data allocated from mpool ================= */

/*

Core object types are pairs and atoms plus 0 (NULL).

Lists are formed by pairs of gints. Each pair starts at address with two last bits 0.
The first element of the pair points to the contents of the cell, the second to rest.

Atoms may contain strings, ints etc etc. Each atom starts at address with last bit 1.

The first byte of the atom indicates its type. The following bytes are content, always
encoded as a 0-terminated string or TWO consequent 0-terminated strings.

The atom type byte contains dbapi.h values:

STRING, CONVERSION TO BE DETERMINED LATER: 0
#define WG_NULLTYPE 1
#define WG_RECORDTYPE 2
#define WG_INTTYPE 3
#define WG_DOUBLETYPE 4
#define WG_STRTYPE 5
#define WG_XMLLITERALTYPE 6
#define WG_URITYPE 7
#define WG_BLOBTYPE 8
#define WG_CHARTYPE 9
#define WG_FIXPOINTTYPE 10
#define WG_DATETYPE 11
#define WG_TIMETYPE 12
#define WG_ANONCONSTTYPE 13
#define WG_VARTYPE 14
#define WG_ILLEGAL 0xff

Atom types 5-8 (strings, xmlliterals, uris, blobs) contain TWO
consequent strings, first the main, terminating 0, then the
second (lang, namespace etc) and the terminating 0. Two terminating
0-s after the first indicates the missing second string (NULL).

Other types are simply terminated by two 0-s.

*/


// ------------- pairs ----------------


int wg_ispair(void* db, void* ptr) {
  return (ptr!=NULL && ((((gint)ptr)&TYPEMASK)==PAIRBITS));
}

void* wg_mkpair(void* db, void* mpool, void* x, void* y) {
  void* ptr;

  ptr=wg_alloc_mpool(db,mpool,sizeof(gint)*2);
  if (ptr==NULL) {
    show_mpool_error(db,"cannot create a pair in mpool");
    return NULL;
  }
  *((gint*)ptr)=(gint)x;
  *((gint*)ptr+1)=(gint)y;
  return ptr;
}

void* wg_first(void* db, void* ptr) {
  return (void*)(*((gint*)ptr));
}

void* wg_rest(void* db, void *ptr) {
  return (void*)(*((gint*)ptr+1));
}

int wg_listtreecount(void* db, void *ptr) {
  if (wg_ispair(db,ptr))
    return wg_listtreecount(db,wg_first(db,ptr)) + wg_listtreecount(db,wg_rest(db,ptr));
  else
    return 1;
}

// ------------ atoms ------------------


int wg_isatom(void* db, void* ptr) {
  return (ptr!=NULL && ((((gint)ptr)&TYPEMASK)==ATOMBITS));

}

void* wg_mkatom(void* db, void* mpool, int type, char* str1, char* str2) {
  char* ptr;
  char* curptr;
  int size=2;

  if (str1!=NULL) size=size+strlen(str1);
  size++;
  if (str2!=NULL) size=size+strlen(str2);
  size++;
  ptr=(char*)(wg_alloc_mpool(db,mpool,size));
  if (ptr==NULL) {
    show_mpool_error(db,"cannot create an atom in mpool");
    return NULL;
  }
  ptr++; // shift one pos right to set address last byte 1
  curptr=ptr;
  *curptr=(char)type;
  curptr++;
  if (str1!=NULL) {
    while((*curptr++ = *str1++));
  } else {
    *curptr=(char)0;
    curptr++;
  }
  if (str2!=NULL) {
    while((*curptr++ = *str2++));
  } else {
    *curptr=(char)0;
    curptr++;
  }
  return ptr;
}

int wg_atomtype(void* db, void* ptr) {
  if (ptr==NULL) return 0;
  else return (gint)*((char*)ptr);
}


char* wg_atomstr1(void* db, void* ptr) {
  if (ptr==NULL) return NULL;
  if (*(((char*)ptr)+1)==(char)0) return NULL;
  else return ((char*)ptr)+1;
}

char* wg_atomstr2(void* db, void* ptr) {
  if (ptr==NULL) return NULL;
  ptr=(char*)ptr+strlen((char*)ptr)+1;
  if (*(((char*)ptr)+1)==(char)0) return NULL;
  else return ((char*)ptr);
}


// ------------ printing ------------------

void wg_mpool_print(void* db, void* ptr) {
  wg_mpool_print_aux(db,ptr,0,1);
}

static void wg_mpool_print_aux(void* db, void* ptr, int depth, int pflag) {
  int type;
  char* p;
  int count;
  int ppflag=0;
  int i;
  void *curptr;

  if (ptr==NULL) {
    printf("()");
  } else if (wg_isatom(db,ptr)) {
    type=wg_atomtype(db,ptr);
    switch (type) {
      case 0: printf("_:"); break;
      case WG_NULLTYPE: printf("n:"); break;
      case WG_RECORDTYPE: printf("r:"); break;
      case WG_INTTYPE: printf("i:"); break;
      case WG_DOUBLETYPE: printf("d:"); break;
      case WG_STRTYPE: printf("s:"); break;
      case WG_XMLLITERALTYPE: printf("x:"); break;
      case WG_URITYPE: printf("u:"); break;
      case WG_BLOBTYPE: printf("b:"); break;
      case WG_CHARTYPE: printf("c:"); break;
      case WG_FIXPOINTTYPE: printf("f:"); break;
      case WG_DATETYPE: printf("date:"); break;
      case WG_TIMETYPE: printf("time:"); break;
      case WG_ANONCONSTTYPE: printf("a:"); break;
      case WG_VARTYPE: printf("?:"); break;
      default: printf("!:");
    }
    p=wg_atomstr1(db,ptr);
    if (p!=NULL) {
      if (strchr(p,' ')!=NULL || strchr(p,'\n')!=NULL || strchr(p,'\t')!=NULL) {
        printf("\"%s\"",p);
      } else {
        printf("%s",p);
      }
    } else {
      printf("\"\"");
    }
    p=wg_atomstr2(db,ptr);
    if (p!=NULL) {
      if (strchr(p,' ')!=NULL || strchr(p,'\n')!=NULL || strchr(p,'\t')!=NULL) {
        printf("^^\"%s\"",p);
      } else {
        printf("^^%s",p);
      }
    }
  } else {
    if (pflag && wg_listtreecount(db,ptr)>10) ppflag=1;
    printf ("(");
    for(curptr=ptr, count=0;curptr!=NULL && !wg_isatom(db,curptr);curptr=wg_rest(db,curptr), count++) {
      if (count>0) {
        if (ppflag) {
          printf("\n");
          for(i=0;i<depth;i++) printf(" ");
        }
        printf(" ");
      }
      wg_mpool_print_aux(db,wg_first(db,curptr),depth+1,0);
    }
    if (wg_isatom(db,curptr)) {
      printf(" . ");
      wg_mpool_print_aux(db,curptr,depth+1,ppflag);
    }
    printf (")");
    if (ppflag) printf("\n");
  }
}



// ------------- ints ---------------------



// ------------- floats --------------------





/* ============== error handling ==================== */

/** called with err msg when an mpool allocation error occurs
*
*  may print or log an error
*  does not do any jumps etc
*/

static int show_mpool_error(void* db, char* errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"db memory pool allocation error: %s\n",errmsg);
#endif
  return -1;
}

/** called with err msg and err nr when an mpool allocation error occurs
*
*  may print or log an error
*  does not do any jumps etc
*/

static int show_mpool_error_nr(void* db, char* errmsg, int nr) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"db memory pool allocation error: %s %d\n",errmsg,nr);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2013, 2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbjson.c
 * WhiteDB JSON input and output.
 */

/* ====== Includes =============== */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ====== Private headers and defs ======== */

#ifdef __cplusplus
extern "C" {
#endif

/*#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#endif*/

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

//data.h"
//compare.h"
//schema.h"
//json.h"
//util.h"
///json/yajl_api.h"

#ifdef _WIN32
#define strncpy(d, s, sz) strncpy_s(d, sz+1, s, sz)
#define strnlen strnlen_s
#endif

#ifdef USE_BACKLINKING
#if !defined(WG_COMPARE_REC_DEPTH) || (WG_COMPARE_REC_DEPTH < 2)
#error WG_COMPARE_REC_DEPTH not defined or too small
#else
#define MAX_DEPTH WG_COMPARE_REC_DEPTH
#endif
#else /* !USE_BACKLINKING */
#define MAX_DEPTH 99 /* no reason to limit */
#endif

/* Commenting this out allows parsing literal value in input, but
 * the current code lacks the capability of representing them
 * (what record should they be stored in?) so there would be
 * no obvious benefit.
 */
#define CHECK_TOPLEVEL_STRUCTURE

typedef enum { ARRAY, OBJECT } stack_entry_t;

struct __stack_entry_elem {
  gint enc;
  struct __stack_entry_elem *next;
};

typedef struct __stack_entry_elem stack_entry_elem;

typedef struct {
  stack_entry_t type;
  stack_entry_elem *head;
  stack_entry_elem *tail;
  char last_key[80];
  int size;
} stack_entry;

typedef struct {
  int state;
  stack_entry stack[MAX_DEPTH];
  int stack_ptr;
  void *db;
  int isparam;
  int isdocument;
  void **document;
} parser_context;

/* ======= Private protos ================ */

static int push(parser_context *ctx, stack_entry_t type);
static int pop(parser_context *ctx);
static int add_elem(parser_context *ctx, gint enc);
static int add_key(parser_context *ctx, char *key);
static int add_literal(parser_context *ctx, gint val);

static gint run_json_parser(void *db, char *buf,
  yajl_callbacks *cb, int isparam, int isdocument, void **document);
static int check_push_cb(void* cb_ctx);
static int check_pop_cb(void* cb_ctx);
static int array_begin_cb(void* cb_ctx);
static int array_end_cb(void* cb_ctx);
static int object_begin_cb(void* cb_ctx);
static int object_end_cb(void* cb_ctx);
static int elem_integer_cb(void* cb_ctx, long long intval);
static int elem_double_cb(void* cb_ctx, double doubleval);
static int object_key_cb(void* cb_ctx, const unsigned char * strval,
                           size_t strl);
static int elem_string_cb(void* cb_ctx, const unsigned char * strval,
                           size_t strl);
static void print_cb(void *cb_ctx, const char *str, size_t len);
static int pretty_print_json(void *db, yajl_gen *g, void *rec);
static int pretty_print_jsonval(void *db, yajl_gen *g, gint enc);

static gint show_json_error(void *db, char *errmsg);
static gint show_json_error_fn(void *db, char *errmsg, char *filename);
static gint show_json_error_byte(void *db, char *errmsg, int byte);

/* ======== Data ========================= */

yajl_callbacks validate_cb = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    check_push_cb,
    NULL,
    check_pop_cb,
    check_push_cb,
    check_pop_cb
};

yajl_callbacks input_cb = {
    NULL,
    NULL,
    elem_integer_cb,
    elem_double_cb,
    NULL,
    elem_string_cb,
    object_begin_cb,
    object_key_cb,
    object_end_cb,
    array_begin_cb,
    array_end_cb
};


/* ====== Functions ============== */

/**
 * Parse an input file. Does an initial pass to verify the syntax
 * of the input and passes it on to the document parser.
 * XXX: caches the data in memory, so this is very unsuitable
 * for large files. An alternative would be to feed bytes directly
 * to the document parser and roll the transaction back, if something fails;
 */
#define WG_JSON_INPUT_CHUNK 16384

gint wg_parse_json_file(void *db, char *filename) {
  char *buf = NULL;
  FILE *f = NULL;
  int count = 0, result = 0, bufsize = 0, depth = -1;
  yajl_handle hand = NULL;

  buf = malloc(WG_JSON_INPUT_CHUNK);
  if(!buf) {
    return show_json_error(db, "Failed to allocate memory");
  }
  bufsize = WG_JSON_INPUT_CHUNK;

  if(!filename) {
#ifdef _WIN32
    printf("reading JSON from stdin, press CTRL-Z and ENTER when done\n");
#else
    printf("reading JSON from stdin, press CTRL-D when done\n");
#endif
    fflush(stdout);
    f = stdin;
  } else {
#ifdef _WIN32
    if(fopen_s(&f, filename, "r")) {
#else
    if(!(f = fopen(filename, "r"))) {
#endif
      show_json_error_fn(db, "Failed to open input", filename);
      result = -1;
      goto done;
    }
  }

  /* setup parser */
  hand = yajl_alloc(&validate_cb, NULL, (void *) &depth);
  yajl_config(hand, yajl_allow_comments, 1);

  while(!feof(f)) {
    int rd = fread((void *) &buf[count], 1, WG_JSON_INPUT_CHUNK, f);
    if(rd == 0) {
      if(!feof(f)) {
        show_json_error_byte(db, "Read error", count);
        result = -1;
      }
      goto done;
    }
    if(yajl_parse(hand, (unsigned char *) &buf[count], rd) != yajl_status_ok) {
      unsigned char *errtxt = yajl_get_error(hand, 1,
        (unsigned char *) &buf[count], rd);
      show_json_error(db, (char *) errtxt);
      yajl_free_error(hand, errtxt);
      result = -1;
      goto done;
    }
    count += rd;
    if(count >= bufsize) {
      void *tmp = realloc(buf, bufsize + WG_JSON_INPUT_CHUNK);
      if(!tmp) {
        show_json_error(db, "Failed to allocate additional memory");
        result = -1;
        goto done;
      }
      buf = tmp;
      bufsize += WG_JSON_INPUT_CHUNK;
    }
  }
  if(yajl_complete_parse(hand) != yajl_status_ok) {
    show_json_error(db, "Syntax error (JSON not properly terminated?)");
    result = -1;
    goto done;
  }

#ifdef CHECK_TOPLEVEL_STRUCTURE
  if(depth == -1) {
    show_json_error(db, "Top-level array or object is required in JSON");
    result = -1;
    goto done;
  }
#endif


  buf[count] = '\0';
  result = wg_parse_json_document(db, buf, NULL);

done:
  if(buf) free(buf);
  if(filename && f) fclose(f);
  if(hand) yajl_free(hand);
  return result;
}

/* Validate JSON data in a string buffer.
 * Does not insert data into the database, so this may be used
 * as a first pass before calling the wg_parse_*() functions.
 *
 * returns 0 for success.
 * returns -1 in case of a syntax error.
 */
gint wg_check_json(void *db, char *buf) {
  int count = 0, result = 0, depth = -1;
  char *iptr = buf;
  yajl_handle hand = NULL;

#ifdef CHECK
  if(!buf)
    return show_json_error(db, "Invalid input buffer");
#endif

  /* setup parser */
  hand = yajl_alloc(&validate_cb, NULL, (void *) &depth);
  yajl_config(hand, yajl_allow_comments, 1);

  while((count = strnlen(iptr, WG_JSON_INPUT_CHUNK)) > 0) {
    if(yajl_parse(hand, (unsigned char *) iptr, count) != yajl_status_ok) {
      show_json_error(db, "JSON parsing failed");
      result = -1;
      goto done;
    }
    iptr += count;
  }

  if(yajl_complete_parse(hand) != yajl_status_ok) {
    show_json_error(db, "JSON parsing failed");
    result = -1;
  }
#ifdef CHECK_TOPLEVEL_STRUCTURE
  else if(depth == -1) {
    show_json_error(db, "Top-level array or object is required in JSON");
    result = -1;
  }
#endif

done:
  if(hand) yajl_free(hand);
  return result;
}

/* Parse a JSON buffer.
 * The data is inserted in database using the JSON schema.
 * If parsing is successful, the pointer referred to by
 * **document will point to the top-level record.
 * If **document is NULL, the pointer is discarded.
 *
 * returns 0 for success.
 * returns -1 on non-fatal error.
 * returns -2 if database is left non-consistent due to an error.
 */
gint wg_parse_json_document(void *db, char *buf, void **document) {
  void *rec = NULL;
  gint retv = run_json_parser(db, buf, &input_cb, 0, 1, &rec);
  if(document)
    *document = rec;
  return retv;
}

/* Parse a JSON buffer.
 * Like wg_parse_json_document, except the top-level object or
 * array is not marked as a document.
 *
 * returns 0 for success.
 * returns -1 on non-fatal error.
 * returns -2 if database is left non-consistent due to an error.
 */
gint wg_parse_json_fragment(void *db, char *buf, void **document) {
  void *rec = NULL;
  gint retv = run_json_parser(db, buf, &input_cb, 0, 0, &rec);
  if(document)
    *document = rec;
  return retv;
}

/* Parse a JSON parameter(s).
 * The data is inserted in database as "special" records.
 * It does not make sense to call this function with NULL as the
 * third parameter, as that would imply data input semantics but
 * the records generated here are speficially flagged *non-data*.
 *
 * returns 0 for success.
 * returns -1 on non-fatal error.
 * returns -2 if database is left non-consistent due to an error.
 */
gint wg_parse_json_param(void *db, char *buf, void **document) {
  if(!document) {
    return show_json_error(db, "wg_parse_json_param: arg 3 cannot be NULL");
  }
  return run_json_parser(db, buf, &input_cb, 1, 1, document);
}

/* Run JSON parser.
 * The data is inserted in the database. If there are any errors, the
 * database will currently remain in an inconsistent state, so beware.
 *
 * if isparam is specified, the data will not be indexed nor returned
 * by wg_get_*_record() calls.
 *
 * if isdocument is 0, the input will be treated as a fragment and
 * not as a full document.
 *
 * if the call is successful, *document contains a pointer to the
 * top-level record.
 *
 * returns 0 for success.
 * returns -1 on non-fatal error.
 * returns -2 if database is left non-consistent due to an error.
 */
static gint run_json_parser(void *db, char *buf,
  yajl_callbacks *cb, int isparam, int isdocument, void **document)
{
  int count = 0, result = 0;
  yajl_handle hand = NULL;
  char *iptr = buf;
  parser_context ctx;

  /* setup context */
  ctx.state = 0;
  ctx.stack_ptr = -1;
  ctx.db = db;
  ctx.isparam = isparam;
  ctx.isdocument = isdocument;
  ctx.document = document;

  /* setup parser */
  hand = yajl_alloc(cb, NULL, (void *) &ctx);
  yajl_config(hand, yajl_allow_comments, 1);

  while((count = strnlen(iptr, WG_JSON_INPUT_CHUNK)) > 0) {
    if(yajl_parse(hand, (unsigned char *) iptr, count) != yajl_status_ok) {
      show_json_error(db, "JSON parsing failed");
      result = -2; /* Fatal error */
      goto done;
    }
    iptr += count;
  }

  if(yajl_complete_parse(hand) != yajl_status_ok) {
    show_json_error(db, "JSON parsing failed");
    result = -2; /* Fatal error */
  }

done:
  if(hand) yajl_free(hand);
  return result;
}

static int check_push_cb(void* cb_ctx)
{
  int *depth = (int *) cb_ctx;
  if(*depth == -1) *depth = 0; /* hack: something was pushed */
  if(++(*depth) >= MAX_DEPTH) {
    return 0;
  }
  return 1;
}

static int check_pop_cb(void* cb_ctx)
{
  int *depth = (int *) cb_ctx;
  --(*depth);
  return 1;
}

/**
 * Push an object or an array on the stack.
 */
static int push(parser_context *ctx, stack_entry_t type)
{
  stack_entry *e;
  if(++ctx->stack_ptr >= MAX_DEPTH) /* paranoia, parser guards from this */
    return 0;
  e = &ctx->stack[ctx->stack_ptr];
  e->size = 0;
  e->type = type;
  e->head = NULL;
  e->tail = NULL;
  return 1;
}

/**
 * Pop an object or an array from the stack.
 * If this is not the top level in the document, the object is also added
 * as an element on the previous level.
 */
static int pop(parser_context *ctx)
{
  stack_entry *e;
  void *rec;
  int ret, istoplevel;

  if(ctx->stack_ptr < 0)
    return 0;
  e = &ctx->stack[ctx->stack_ptr--];

  /* is it a top level object? */
  if(ctx->stack_ptr < 0) {
    istoplevel = 1;
  } else {
    istoplevel = 0;
  }

  if(e->type == ARRAY) {
    rec = wg_create_array(ctx->db, e->size,
      (istoplevel && ctx->isdocument), ctx->isparam);
  } else {
    rec = wg_create_object(ctx->db, e->size,
      (istoplevel && ctx->isdocument), ctx->isparam);
  }

  /* add elements to the database */
  if(rec) {
    stack_entry_elem *curr = e->head;
    int i = 0;
    ret = 1;
    while(curr) {
      if(wg_set_field(ctx->db, rec, i++, curr->enc)) {
        ret = 0;
        break;
      }
      curr = curr->next;
    }
    if(istoplevel)
      *(ctx->document) = rec;
  } else {
    ret = 0;
  }

  /* free the elements */
  while(e->head) {
    stack_entry_elem *tmp = e->head;
    e->head = e->head->next;
    free(tmp);
  }
  e->tail = NULL;
  e->size = 0;

  /* is it an element of something? */
  if(!istoplevel && rec && ret) {
    gint enc = wg_encode_record(ctx->db, rec);
    ret = add_literal(ctx, enc);
  }
  return ret;
}

/**
 * Append an element to the current stack entry.
 */
static int add_elem(parser_context *ctx, gint enc)
{
  stack_entry *e;
  stack_entry_elem *tmp;

  if(ctx->stack_ptr < 0 || ctx->stack_ptr >= MAX_DEPTH)
    return 0; /* paranoia */

  e = &ctx->stack[ctx->stack_ptr];
  tmp = (stack_entry_elem *) malloc(sizeof(stack_entry_elem));
  if(!tmp)
    return 0;

  if(!e->tail) {
    e->head = tmp;
  } else {
    e->tail->next = tmp;
  }
  e->tail = tmp;
  e->size++;
  tmp->enc = enc;
  tmp->next = NULL;
  return 1;
}

/**
 * Store a key in the current stack entry.
 */
static int add_key(parser_context *ctx, char *key)
{
  stack_entry *e;

  if(ctx->stack_ptr < 0 || ctx->stack_ptr >= MAX_DEPTH)
    return 0; /* paranoia */

  e = &ctx->stack[ctx->stack_ptr];
  strncpy(e->last_key, key, 80);
  e->last_key[79] = '\0';
  return 1;
}

/**
 * Add a literal value. If it's inside an object, generate
 * a key-value pair using the last key. Otherwise insert
 * it directly.
 */
static int add_literal(parser_context *ctx, gint val)
{
  stack_entry *e;

  if(ctx->stack_ptr < 0 || ctx->stack_ptr >= MAX_DEPTH)
    return 0; /* paranoia */

  e = &ctx->stack[ctx->stack_ptr];
  if(e->type == ARRAY) {
    return add_elem(ctx, val);
  } else {
    void *rec;
    gint key = wg_encode_str(ctx->db, e->last_key, NULL);
    if(key == WG_ILLEGAL)
      return 0;
    rec = wg_create_kvpair(ctx->db, key, val, ctx->isparam);
    if(!rec)
      return 0;
    return add_elem(ctx, wg_encode_record(ctx->db, rec));
  }
}

#define OUT_INDENT(x,i,f) \
      for(i=0; i<x; i++) \
        fprintf(f, "  ");

static int array_begin_cb(void* cb_ctx)
{
/*  int i;*/
  parser_context *ctx = (parser_context *) cb_ctx;
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("BEGIN ARRAY\n");*/
  if(!push(ctx, ARRAY))
    return 0;
  return 1;
}

static int array_end_cb(void* cb_ctx)
{
/*  int i;*/
  parser_context *ctx = (parser_context *) cb_ctx;
  if(!pop(ctx))
    return 0;
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("END ARRAY\n");*/
  return 1;
}

static int object_begin_cb(void* cb_ctx)
{
/*  int i;*/
  parser_context *ctx = (parser_context *) cb_ctx;
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("BEGIN object\n");*/
  if(!push(ctx, OBJECT))
    return 0;
  return 1;
}

static int object_end_cb(void* cb_ctx)
{
/*  int i;*/
  parser_context *ctx = (parser_context *) cb_ctx;
  if(!pop(ctx))
    return 0;
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("END object\n");*/
  return 1;
}

static int elem_integer_cb(void* cb_ctx, long long intval)
{
/*  int i;*/
  gint val;
  parser_context *ctx = (parser_context *) cb_ctx;
  val = wg_encode_int(ctx->db, (gint) intval);
  if(val == WG_ILLEGAL)
    return 0;
  if(!add_literal(ctx, val))
    return 0;
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("INTEGER: %d\n", (int) intval);*/
  return 1;
}

static int elem_double_cb(void* cb_ctx, double doubleval)
{
/*  int i;*/
  gint val;
  parser_context *ctx = (parser_context *) cb_ctx;
  val = wg_encode_double(ctx->db, doubleval);
  if(val == WG_ILLEGAL)
    return 0;
  if(!add_literal(ctx, val))
    return 0;
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("FLOAT: %.6f\n", doubleval);*/
  return 1;
}

static int object_key_cb(void* cb_ctx, const unsigned char * strval,
                           size_t strl)
{
/*  int i;*/
  int res = 1;
  parser_context *ctx = (parser_context *) cb_ctx;
  char *buf = malloc(strl + 1);
  if(!buf)
    return 0;
  strncpy(buf, (char *) strval, strl);
  buf[strl] = '\0';

  if(!add_key(ctx, buf)) {
    res = 0;
  }
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("KEY: %s\n", buf);*/
  free(buf);
  return res;
}

static int elem_string_cb(void* cb_ctx, const unsigned char * strval,
                           size_t strl)
{
/*  int i;*/
  int res = 1;
  gint val;
  parser_context *ctx = (parser_context *) cb_ctx;
  char *buf = malloc(strl + 1);
  if(!buf)
    return 0;
  strncpy(buf, (char *) strval, strl);
  buf[strl] = '\0';

  val = wg_encode_str(ctx->db, buf, NULL);

  if(val == WG_ILLEGAL) {
    res = 0;
  } else if(!add_literal(ctx, val)) {
    res = 0;
  }
/*  OUT_INDENT(ctx->stack_ptr+1, i, stdout)
  printf("STRING: %s\n", buf);*/
  free(buf);
  return res;
}

static void print_cb(void *cb_ctx, const char *str, size_t len)
{
  FILE *f = (FILE *) cb_ctx;
  fwrite(str, len, 1, f);
}

/*
 * Print a JSON document. If a callback is given, it
 * should be of type (void) (void *, char *, size_t) where the first
 * pointer will be cast to FILE * stream. Otherwise the document will
 * be written to stdout.
 */
void wg_print_json_document(void *db, void *cb, void *cb_ctx, void *document) {
  yajl_gen g;
  if(!is_schema_document(document)) {
    /* Paranoia check. This increases the probability we're dealing
     * with records belonging to a proper schema. Omitting this check
     * would allow printing parts of documents as well.
     */
    show_json_error(db, "Given record is not a document");
    return;
  }
  g = yajl_gen_alloc(NULL);
  yajl_gen_config(g, yajl_gen_beautify, 1);
  if(cb) {
    yajl_gen_config(g, yajl_gen_print_callback, (yajl_print_t *) cb, cb_ctx);
  } else {
    yajl_gen_config(g, yajl_gen_print_callback, print_cb, (void *) stdout);
  }
  pretty_print_json(db, &g, document);
  yajl_gen_free(g);
}

/*
 * Recursively print JSON elements (using the JSON schema)
 * Returns 0 on success
 * Returns -1 on error.
 */
static int pretty_print_json(void *db, yajl_gen *g, void *rec)
{
  if(is_schema_object(rec)) {
    gint i, reclen;

    if(yajl_gen_map_open(*g) != yajl_gen_status_ok) {
      return show_json_error(db, "Formatter failure");
    }

    reclen = wg_get_record_len(db, rec);
    for(i=0; i<reclen; i++) {
      gint enc;
      enc = wg_get_field(db, rec, i);
      if(wg_get_encoded_type(db, enc) != WG_RECORDTYPE) {
        return show_json_error(db, "Object had an element of invalid type");
      }
      if(pretty_print_json(db, g, wg_decode_record(db, enc))) {
        return -1;
      }
    }

    if(yajl_gen_map_close(*g) != yajl_gen_status_ok) {
      return show_json_error(db, "Formatter failure");
    }
  }
  else if(is_schema_array(rec)) {
    gint i, reclen;

    if(yajl_gen_array_open(*g) != yajl_gen_status_ok) {
      return show_json_error(db, "Formatter failure");
    }

    reclen = wg_get_record_len(db, rec);
    for(i=0; i<reclen; i++) {
      gint enc;
      enc = wg_get_field(db, rec, i);
      if(pretty_print_jsonval(db, g, enc)) {
        return -1;
      }
    }

    if(yajl_gen_array_close(*g) != yajl_gen_status_ok) {
      return show_json_error(db, "Formatter failure");
    }
  }
  else {
    /* assume key-value pair */
    gint key, value;
    key = wg_get_field(db, rec, WG_SCHEMA_KEY_OFFSET);
    value = wg_get_field(db, rec, WG_SCHEMA_VALUE_OFFSET);

    if(wg_get_encoded_type(db, key) != WG_STRTYPE) {
      return show_json_error(db, "Key is of invalid type");
    } else {
      int len = wg_decode_str_len(db, key);
      char *buf = wg_decode_str(db, key);
      if(buf) {
        if(yajl_gen_string(*g, (unsigned char *) buf,
          (size_t) len) != yajl_gen_status_ok) {
          return show_json_error(db, "Formatter failure");
        }
      }
    }
    if(pretty_print_jsonval(db, g, value)) {
      return -1;
    }
  }
  return 0;
}

/*
 * Print a JSON array element or object value.
 * May be an array or object itself.
 */
static int pretty_print_jsonval(void *db, yajl_gen *g, gint enc)
{
  gint type = wg_get_encoded_type(db, enc);
  if(type == WG_RECORDTYPE) {
    if(pretty_print_json(db, g, wg_decode_record(db, enc))) {
      return -1;
    }
  } else if(type == WG_STRTYPE) {
    int len = wg_decode_str_len(db, enc);
    char *buf = wg_decode_str(db, enc);
    if(buf) {
      if(yajl_gen_string(*g, (unsigned char *) buf,
        (size_t) len) != yajl_gen_status_ok) {
        return show_json_error(db, "Formatter failure");
      }
    }
  } else {
    /* other literal value */
    size_t len;
    char buf[80];
    wg_snprint_value(db, enc, buf, 79);
    len = strlen(buf);
    if(type == WG_INTTYPE || type == WG_DOUBLETYPE ||\
      type == WG_FIXPOINTTYPE) {
      if(yajl_gen_number(*g, buf, len) != yajl_gen_status_ok) {
        return show_json_error(db, "Formatter failure");
      }
    } else {
      if(yajl_gen_string(*g, (unsigned char *) buf,
        len) != yajl_gen_status_ok) {
        return show_json_error(db, "Formatter failure");
      }
    }
  }
  return 0;
}

/* ------------ error handling ---------------- */

static gint show_json_error(void *db, char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg json I/O error: %s.\n", errmsg);
#endif
  return -1;
}

static gint show_json_error_fn(void *db, char *errmsg, char *filename) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg json I/O error: %s (file=`%s`)\n", errmsg, filename);
#endif
  return -1;
}

static gint show_json_error_byte(void *db, char *errmsg, int byte) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg json I/O error: %s (byte=%d)\n", errmsg, byte);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2013, 2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dbschema.c
 * WhiteDB (semi-)structured data representation
 */

/* ====== Includes =============== */

#include <stdio.h>

/* ====== Private headers and defs ======== */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

//data.h"
//compare.h"
//index.h"
//schema.h"
//log.h"

/* ======== Data ========================= */

/* ======= Private protos ================ */

#ifdef USE_BACKLINKING
static void *find_document_recursive(void *db, gint *rec, int depth);
#endif
static gint delete_record_recursive(void *db, void *rec, int depth);
static gint show_schema_error(void *db, char *errmsg);

/* ====== Functions ============== */

/*
 * Create a data triple (subj, prop, ob)
 * May also be called to create key-value pairs with (NULL, key, value)
 * if isparam is non-0, the data is not indexed.
 * returns the new record
 * returns NULL on error.
 */
void *wg_create_triple(void *db, gint subj, gint prop, gint ob, gint isparam) {
  void *rec = wg_create_raw_record(db, WG_SCHEMA_TRIPLE_SIZE);
  gint *meta;
  if(rec) {
    meta = ((gint *) rec + RECORD_META_POS);
    if(isparam) {
      *meta |= (RECORD_META_NOTDATA|RECORD_META_MATCH);
    } else if(wg_index_add_rec(db, rec) < -1) {
      return NULL; /* index error */
    }

    if(wg_set_field(db, rec, WG_SCHEMA_TRIPLE_OFFSET, subj))
      return NULL;
    if(wg_set_field(db, rec, WG_SCHEMA_TRIPLE_OFFSET + 1, prop))
      return NULL;
    if(wg_set_field(db, rec, WG_SCHEMA_TRIPLE_OFFSET + 2, ob))
      return NULL;
  }
  return rec;
}

/*
 * Create an empty (JSON) array of given size.
 * if isparam is non-0, the data is not indexed (incl. when updating later)
 * if isdocument is non-0, the record represents a top-level document
 * returns the new record
 * returns NULL on error.
 */
void *wg_create_array(void *db, gint size, gint isdocument, gint isparam) {
  void *rec = wg_create_raw_record(db, size);
  gint *metap, meta;
  if(rec) {
    metap = ((gint *) rec + RECORD_META_POS);
    meta = *metap; /* Temp variable used for write-ahead logging */
    meta |= RECORD_META_ARRAY;
    if(isdocument)
      meta |= RECORD_META_DOC;
    if(isparam)
      meta |= (RECORD_META_NOTDATA|RECORD_META_MATCH);

#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_set_meta(db, rec, meta))
        return NULL;
    }
#endif
    *metap = meta;
    if(!isparam) {
      if(wg_index_add_rec(db, rec) < -1) {
        return NULL; /* index error */
      }
    }
  }
  return rec;
}

/*
 * Create an empty (JSON) object of given size.
 * if isparam is non-0, the data is not indexed (incl. when updating later)
 * if isdocument is non-0, the record represents a top-level document
 * returns the new record
 * returns NULL on error.
 */
void *wg_create_object(void *db, gint size, gint isdocument, gint isparam) {
  void *rec = wg_create_raw_record(db, size);
  gint *metap, meta;
  if(rec) {
    metap = ((gint *) rec + RECORD_META_POS);
    meta = *metap;
    meta |= RECORD_META_OBJECT;
    if(isdocument)
      meta |= RECORD_META_DOC;
    if(isparam)
      meta |= (RECORD_META_NOTDATA|RECORD_META_MATCH);

#ifdef USE_DBLOG
    if(dbmemsegh(db)->logging.active) {
      if(wg_log_set_meta(db, rec, meta))
        return NULL;
    }
#endif
    *metap = meta;
    if(!isparam) {
      if(wg_index_add_rec(db, rec) < -1) {
        return NULL; /* index error */
      }
    }
  }
  return rec;
}

/*
 * Find a top-level document that the record belongs to.
 * returns the document pointer on success
 * returns NULL if the document was not found.
 */
void *wg_find_document(void *db, void *rec) {
#ifndef USE_BACKLINKING
  show_schema_error(db, "Backlinks are required to find complete documents");
  return NULL;
#else
  return find_document_recursive(db, (gint *) rec, WG_COMPARE_REC_DEPTH-1);
#endif
}


#ifdef USE_BACKLINKING
/*
 *  Find a document recursively.
 *  iterates through the backlink chain and checks each parent recursively.
 *  Returns the pointer to the (first) found document.
 *  Returns NULL if nothing found.
 *  XXX: if a document links to the contents of another document, it
 *  can "hijack" it in the search results this way. The priority
 *  depends on the position(s) in the backlink chain, as this is a depth-first
 *  search.
 */
static void *find_document_recursive(void *db, gint *rec, int depth) {
  if(is_schema_document(rec))
    return rec;

  if(depth > 0) {
    gint backlink_list = *(rec + RECORD_BACKLINKS_POS);
    if(backlink_list) {
      gcell *next = (gcell *) offsettoptr(db, backlink_list);
      for(;;) {
        void *res = find_document_recursive(db,
          (gint *) offsettoptr(db, next->car),
          depth-1);
        if(res)
          return res; /* Something was found recursively */
        if(!next->cdr)
          break;
        next = (gcell *) offsettoptr(db, next->cdr);
      }
    }
  }

  return NULL; /* Depth exhausted or nothing found. */
}
#endif

/*
 * Delete a top-level document
 * returns 0 on success
 * returns -1 on error
 */
gint wg_delete_document(void *db, void *document) {
#ifdef CHECK
  if(!is_schema_document(document)) {
    return show_schema_error(db, "wg_delete_document: not a document");
  }
#endif
#ifndef USE_BACKLINKING
  return delete_record_recursive(db, document, 99);
#else
  return delete_record_recursive(db, document, WG_COMPARE_REC_DEPTH);
#endif
}

/*
 * Delete a record and all the records it points to.
 * This is safe to call on JSON documents.
 */
static gint delete_record_recursive(void *db, void *rec, int depth) {
  gint i, reclen;
  if(depth <= 0) {
    return show_schema_error(db, "deleting record: recursion too deep");
  }

  reclen = wg_get_record_len(db, rec);
  for(i=0; i<reclen; i++) {
    gint enc = wg_get_field(db, rec, i);
    gint type = wg_get_encoded_type(db, enc);
    if(type == WG_RECORDTYPE) {
      if(wg_set_field(db, rec, i, 0))
        return -1;
      if(delete_record_recursive(db, wg_decode_record(db, enc), depth-1))
        return -1;
    }
  }

  if(wg_delete_record(db, rec))
    return -1;

  return 0;
}

/* ------------ error handling ---------------- */

static gint show_schema_error(void *db, char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg schema error: %s.\n", errmsg);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2009, 2010, 2011, 2013, 2014
*
* This file is part of WhiteDB
*
* WhiteDB is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* WhiteDB is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with WhiteDB.  If not, see <http://www.gnu.org/licenses/>.
*
*/

 /** @file dblock.c
 *  Concurrent access support for WhiteDB memory database
 *
 *  Note: this file contains compiler and target-specific code.
 *  For compiling on plaforms that do not have support for
 *  specific opcodes needed for atomic operations and spinlocks,
 *  locking may be disabled by ./configure --disable-locking
 *  or by editing the appropriate config-xxx.h file. This will
 *  allow the code to compile, but concurrent access will NOT
 *  work.
 */

/* ====== Includes =============== */

#include <stdio.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#include <limits.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"
//lock.h"

#if (LOCK_PROTO==TFQUEUE)
#ifdef __linux__
#include <linux/futex.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/errno.h>
#endif
#endif

/* ====== Private headers and defs ======== */

#define compare_and_swap wg_compare_and_swap // wg_ prefix used in dblock.h, non-wg below

#ifndef LOCK_PROTO
#define DUMMY_ATOMIC_OPS /* allow compilation on unsupported platforms */
#endif

#if (LOCK_PROTO==RPSPIN) || (LOCK_PROTO==WPSPIN)
#define WAFLAG 0x1  /* writer active flag */
#define RC_INCR 0x2  /* increment step for reader count */
#else
/* classes of locks. */
#define LOCKQ_READ 0x02
#define LOCKQ_WRITE 0x04
#endif

/* Macro to emit Pentium 4 "pause" instruction. */
#if !defined(LOCK_PROTO)
#define MM_PAUSE
#elif defined(__GNUC__)
#if defined(__SSE2__)
#define MM_PAUSE {\
  __asm__ __volatile__("pause;\n");\
}
#else
#define MM_PAUSE
#endif
#elif defined(_WIN32)
#include <emmintrin.h>
#define MM_PAUSE { _mm_pause(); }
#endif

/* Helper function for implementing atomic operations
 * with gcc 4.3 / ARM EABI by Julian Brown.
 * This works on Linux ONLY.
 */
#if defined(__ARM_EABI__) && defined(__linux__)
typedef int (kernel_cmpxchg_t) (int oldval, int newval, int *ptr);
#define kernel_cmpxchg (*(kernel_cmpxchg_t *) 0xffff0fc0)
#endif

/* For easier testing of GCC version */
#ifdef __GNUC__
#define GCC_VERSION (__GNUC__ * 10000 \
                   + __GNUC_MINOR__ * 100 \
                   + __GNUC_PATCHLEVEL__)
#endif

/* Spinlock timings
 * SPIN_COUNT: how many cycles until CPU is yielded
 * SLEEP_MSEC and SLEEP_NSEC: increment of wait time after each cycle
 */
#ifdef _WIN32
#define SPIN_COUNT 100000 /* Windows scheduling seems to force this */
#define SLEEP_MSEC 1 /* minimum resolution is 1 millisecond */
#else
#define SPIN_COUNT 500 /* shorter spins perform better with Linux */
#define SLEEP_NSEC 500000 /* 500 microseconds */
#endif

#ifdef _WIN32
#define INIT_SPIN_TIMEOUT(t)
#else /* timings are in nsec */
#define INIT_SPIN_TIMEOUT(t) \
  if(t > INT_MAX/1000000) /* hack: primitive overflow protection */ \
    t = INT_MAX; \
  else \
    t *= 1000000;
#endif

#ifdef _WIN32
#define UPDATE_SPIN_TIMEOUT(t, ts) t -= ts;
#else
#define UPDATE_SPIN_TIMEOUT(t, ts) t -= ts.tv_nsec;
#endif

#define INIT_QLOCK_TIMEOUT(t, ts) \
  ts.tv_sec = t / 1000; \
  ts.tv_nsec = t % 1000;

#define ALLOC_LOCK(d, l) \
  l = alloc_lock(d); \
  if(!l) { \
    unlock_queue(d); \
    show_lock_error(d, "Failed to allocate lock"); \
    return 0; \
  }

#define DEQUEUE_LOCK(d, dbh, l, lp) \
  if(lp->prev) { \
    lock_queue_node *pp = offsettoptr(d, lp->prev); \
    pp->next = lp->next; \
  } \
  if(lp->next) { \
    lock_queue_node *np = offsettoptr(d, lp->next); \
    np->prev = lp->prev; \
  } else if(dbh->locks.tail == l) { \
    dbh->locks.tail = lp->prev; \
  }

/* ======= Private protos ================ */


#if (LOCK_PROTO==WPSPIN)
static void atomic_increment(volatile gint *ptr, gint incr);
#endif
#if (LOCK_PROTO==WPSPIN) || (LOCK_PROTO==RPSPIN)
static void atomic_and(volatile gint *ptr, gint val);
#endif
#if (LOCK_PROTO==RPSPIN)
static gint fetch_and_add(volatile gint *ptr, gint incr);
#endif
#if 0 /* unused */
static gint fetch_and_store(volatile gint *ptr, gint val);
#endif
// static gint compare_and_swap(volatile gint *ptr, gint oldv, gint newv);

#if (LOCK_PROTO==TFQUEUE)
static gint alloc_lock(void * db);
static void free_lock(void * db, gint node);
/*static gint deref_link(void *db, volatile gint *link);*/
#ifdef __linux__
#ifndef USE_LOCK_TIMEOUT
static void futex_wait(volatile gint *addr1, int val1);
#endif
static int futex_trywait(volatile gint *addr1, int val1,
  struct timespec *timeout);
static void futex_wake(volatile gint *addr1, int val1);
#endif
#endif

static gint show_lock_error(void *db, char *errmsg);


/* ====== Functions ============== */


/* -------------- helper functions -------------- */

/*
 * System- and platform-dependent atomic operations
 */

/** Atomic increment. On x86 platform, this is internally
 *  the same as fetch_and_add().
 */

#if (LOCK_PROTO==WPSPIN)
static void atomic_increment(volatile gint *ptr, gint incr) {
#if defined(DUMMY_ATOMIC_OPS)
  *ptr += incr;
#elif defined(__GNUC__)
#if defined(_MIPS_ARCH)
  gint tmp1, tmp2;  /* XXX: any way to get rid of these? */
  __asm__ __volatile__(
    ".set	noreorder\n\t"
    "1: ll	%0,%4\n\t"    /* load old */
    "add	%1,%0,%3\n\t" /* compute tmp2=tmp1+incr */
    "sc		%1,%2\n\t"    /* store new */
    "beqz	%1,1b\n\t"    /* SC failed, retry */
    "sync\n\t"
    ".set	reorder\n\t"
    : "=&r" (tmp1), "=&r" (tmp2), "=m" (*ptr)
    : "r" (incr), "m" (*ptr)
    : "memory");
#elif (GCC_VERSION < 40400) && defined(__ARM_EABI__) && defined(__linux__)
  gint failure, tmp;
  do {
    tmp = *ptr;
    failure = kernel_cmpxchg(tmp, tmp + incr, (int *) ptr);
  } while (failure != 0);
#else /* try gcc intrinsic */
  __sync_fetch_and_add(ptr, incr);
#endif
#elif defined(_WIN32)
  _InterlockedExchangeAdd(ptr, incr);
#else
#error Atomic operations not implemented for this compiler
#endif
}
#endif

/** Atomic AND operation.
 */

#if (LOCK_PROTO==WPSPIN) || (LOCK_PROTO==RPSPIN)
static void atomic_and(volatile gint *ptr, gint val) {
#if defined(DUMMY_ATOMIC_OPS)
  *ptr &= val;
#elif defined(__GNUC__)
#if defined(_MIPS_ARCH)
  gint tmp1, tmp2;
  __asm__ __volatile__(
    ".set	noreorder\n\t"
    "1: ll	%0,%4\n\t"      /* load old */
    "and	%1,%0,%3\n\t"   /* compute tmp2=tmp1 & val; */
    "sc		%1,%2\n\t"      /* store new */
    "beqz	%1,1b\n\t"      /* SC failed, retry */
    "sync\n\t"
    ".set	reorder\n\t"
    : "=&r" (tmp1), "=&r" (tmp2), "=m" (*ptr)
    : "r" (val), "m" (*ptr)
    : "memory");
#elif (GCC_VERSION < 40400) && defined(__ARM_EABI__) && defined(__linux__)
  gint failure, tmp;
  do {
    tmp = *ptr;
    failure = kernel_cmpxchg(tmp, tmp & val, (int *) ptr);
  } while (failure != 0);
#else /* try gcc intrinsic */
  __sync_fetch_and_and(ptr, val);
#endif
#elif defined(_WIN32)
  _InterlockedAnd(ptr, val);
#else
#error Atomic operations not implemented for this compiler
#endif
}
#endif

/** Atomic OR operation.
 */

#if 0 /* unused */
static void atomic_or(volatile gint *ptr, gint val) {
#if defined(DUMMY_ATOMIC_OPS)
  *ptr |= val;
#elif defined(__GNUC__)
#if defined(_MIPS_ARCH)
  gint tmp1, tmp2;
  __asm__ __volatile__(
    ".set	noreorder\n\t"
    "1: ll	%0,%4\n\t"      /* load old */
    "or		%1,%0,%3\n\t"   /* compute tmp2=tmp1 | val; */
    "sc		%1,%2\n\t"      /* store new */
    "beqz	%1,1b\n\t"      /* SC failed, retry */
    "sync\n\t"
    ".set	reorder\n\t"
    : "=&r" (tmp1), "=&r" (tmp2), "=m" (*ptr)
    : "r" (val), "m" (*ptr)
    : "memory");
#elif (GCC_VERSION < 40400) && defined(__ARM_EABI__) && defined(__linux__)
  gint failure, tmp;
  do {
    tmp = *ptr;
    failure = kernel_cmpxchg(tmp, tmp | val, (int *) ptr);
  } while (failure != 0);
#else /* try gcc intrinsic */
  __sync_fetch_and_or(ptr, val);
#endif
#elif defined(_WIN32)
  _InterlockedOr(ptr, val);
#else
#error Atomic operations not implemented for this compiler
#endif
}
#endif

/** Fetch and (dec|inc)rement. Returns value before modification.
 */

#if (LOCK_PROTO==RPSPIN)
static gint fetch_and_add(volatile gint *ptr, gint incr) {
#if defined(DUMMY_ATOMIC_OPS)
  gint tmp = *ptr;
  *ptr += incr;
  return tmp;
#elif defined(__GNUC__)
#if defined(_MIPS_ARCH)
  gint ret, tmp;
  __asm__ __volatile__(
    ".set	noreorder\n\t"
    "1: ll	%0,%4\n\t"      /* load old */
    "add	%1,%0,%3\n\t"   /* compute tmp=ret+incr */
    "sc		%1,%2\n\t"      /* store new */
    "beqz	%1,1b\n\t"      /* SC failed, retry */
    "sync\n\t"
    ".set	reorder\n\t"
    : "=&r" (ret), "=&r" (tmp), "=m" (*ptr)
    : "r" (incr), "m" (*ptr)
    : "memory");
  return ret;
#elif (GCC_VERSION < 40400) && defined(__ARM_EABI__) && defined(__linux__)
  gint failure, tmp;
  do {
    tmp = *ptr;
    failure = kernel_cmpxchg(tmp, tmp + incr, (int *) ptr);
  } while (failure != 0);
  return tmp;
#else /* try gcc intrinsic */
  return __sync_fetch_and_add(ptr, incr);
#endif
#elif defined(_WIN32)
  return _InterlockedExchangeAdd(ptr, incr);
#else
#error Atomic operations not implemented for this compiler
#endif
}
#endif

/** Atomic fetch and store. Swaps two values.
 */

#if 0 /* unused */
static gint fetch_and_store(volatile gint *ptr, gint val) {
  /* Despite the name, the GCC builtin should just
   * issue XCHG operation. There is no testing of
   * anything, just lock the bus and swap the values,
   * as per Intel's opcode reference.
   *
   * XXX: not available on all compiler targets :-(
   */
#if defined(DUMMY_ATOMIC_OPS)
  gint tmp = *ptr;
  *ptr = val;
  return tmp;
#elif defined(__GNUC__)
#if defined(_MIPS_ARCH)
  gint ret, tmp;
  __asm__ __volatile__(
    ".set	noreorder\n\t"
    "1: ll	%0,%4\n\t"  /* load old */
    "move	%1,%3\n\t"
    "sc		%1,%2\n\t"  /* store new */
    "beqz	%1,1b\n\t"  /* SC failed, retry */
    "sync\n\t"
    ".set	reorder\n\t"
    : "=&r" (ret), "=&r" (tmp), "=m" (*ptr)
    : "r" (val), "m" (*ptr)
    : "memory");
  return ret;
#elif (GCC_VERSION < 40400) && defined(__ARM_EABI__) && defined(__linux__)
  gint failure, oldval;
  do {
    oldval = *ptr;
    failure = kernel_cmpxchg(oldval, val, (int *) ptr);
  } while (failure != 0);
  return oldval;
#else /* try gcc intrinsic */
  return __sync_lock_test_and_set(ptr, val);
#endif
#elif defined(_WIN32)
  return _InterlockedExchange(ptr, val);
#else
#error Atomic operations not implemented for this compiler
#endif
}
#endif

/** Compare and swap. If value at ptr equals old, set it to
 *  new and return 1. Otherwise the function returns 0.
 */

gint wg_compare_and_swap(volatile gint *ptr, gint oldv, gint newv) {
#if defined(DUMMY_ATOMIC_OPS)
  if(*ptr == oldv) {
    *ptr = newv;
    return 1;
  }
  return 0;
#elif defined(__GNUC__)
#if defined(_MIPS_ARCH)
  gint ret;
  __asm__ __volatile__(
    ".set	noreorder\n\t"
    "1: ll	%0,%4\n\t"
    "bne	%0,%2,2f\n\t"   /* *ptr!=oldv, return *ptr */
    "move	%0,%3\n\t"
    "sc		%0,%1\n\t"
    "beqz	%0,1b\n\t"      /* SC failed, retry */
    "move	%0,%2\n\t"      /* return oldv (*ptr==newv now) */
    "2: sync\n\t"
    ".set	reorder\n\t"
    : "=&r" (ret), "=m" (*ptr)
    : "r" (oldv), "r" (newv), "m" (*ptr)
    : "memory");
  return ret == oldv;
#elif (GCC_VERSION < 40400) && defined(__ARM_EABI__) && defined(__linux__)
  gint failure = kernel_cmpxchg(oldv, newv, (int *) ptr);
  return (failure == 0);
#else /* try gcc intrinsic */
  return __sync_bool_compare_and_swap(ptr, oldv, newv);
#endif
#elif defined(_WIN32)
  return (_InterlockedCompareExchange(ptr, newv, oldv) == oldv);
#else
#error Atomic operations not implemented for this compiler
#endif
}

/* ----------- read and write transaction support ----------- */

/*
 * Read and write transactions are currently realized using database
 * level locking. The rest of the db API is implemented independently -
 * therefore use of the locking routines does not automatically guarantee
 * isolation, rather, all of the concurrently accessing clients are expected
 * to follow the same protocol.
 */

/** Start write transaction
 *   Current implementation: acquire database level exclusive lock
 */

gint wg_start_write(void * db) {
  return db_wlock(db, DEFAULT_LOCK_TIMEOUT);
}

/** End write transaction
 *   Current implementation: release database level exclusive lock
 */

gint wg_end_write(void * db, gint lock) {
  return db_wulock(db, lock);
}

/** Start read transaction
 *   Current implementation: acquire database level shared lock
 */

gint wg_start_read(void * db) {
  return db_rlock(db, DEFAULT_LOCK_TIMEOUT);
}

/** End read transaction
 *   Current implementation: release database level shared lock
 */

gint wg_end_read(void * db, gint lock) {
  return db_rulock(db, lock);
}

/*
 * The following functions implement a giant shared/exclusive
 * lock on the database.
 *
 * Algorithms used for locking:
 *
 * 1. Simple reader-preference lock using a single global sync
 *    variable (described by Mellor-Crummey & Scott '92).
 * 2. A writer-preference spinlock based on the above.
 * 3. A task-fair lock implemented using a queue. Similar to
 *    the queue-based MCS rwlock, but uses futexes to synchronize
 *    the waiting processes.
 */

#if (LOCK_PROTO==RPSPIN)

/** Acquire database level exclusive lock (reader-preference spinlock)
 *   Blocks until lock is acquired.
 *   If USE_LOCK_TIMEOUT is defined, may return without locking
 */

#ifdef USE_LOCK_TIMEOUT
gint db_rpspin_wlock(void * db, gint timeout) {
#else
gint db_rpspin_wlock(void * db) {
#endif
  int i;
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  volatile gint *gl;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_wlock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);

  /* First attempt at getting the lock without spinning */
  if(compare_and_swap(gl, 0, WAFLAG))
    return 1;

#ifdef _WIN32
  ts = SLEEP_MSEC;
#else
  ts.tv_sec = 0;
  ts.tv_nsec = SLEEP_NSEC;
#endif

#ifdef USE_LOCK_TIMEOUT
  INIT_SPIN_TIMEOUT(timeout)
#endif

  /* Spin loop */
  for(;;) {
    for(i=0; i<SPIN_COUNT; i++) {
      MM_PAUSE
      if(!(*gl) && compare_and_swap(gl, 0, WAFLAG))
        return 1;
    }

    /* Check if we would time out during next sleep. Note that
     * this is not a real time measurement.
     */
#ifdef USE_LOCK_TIMEOUT
    UPDATE_SPIN_TIMEOUT(timeout, ts)
    if(timeout < 0)
      return 0;
#endif

    /* Give up the CPU so the lock holder(s) can continue */
#ifdef _WIN32
    Sleep(ts);
    ts += SLEEP_MSEC;
#else
    nanosleep(&ts, NULL);
    ts.tv_nsec += SLEEP_NSEC;
#endif
  }

  return 0; /* dummy */
}

/** Release database level exclusive lock (reader-preference spinlock)
 */

gint db_rpspin_wulock(void * db) {

  volatile gint *gl;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_wulock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);

  /* Clear the writer active flag */
  atomic_and(gl, ~(WAFLAG));

  return 1;
}

/** Acquire database level shared lock (reader-preference spinlock)
 *   Increments reader count, blocks until there are no active
 *   writers.
 *   If USE_LOCK_TIMEOUT is defined, may return without locking.
 */

#ifdef USE_LOCK_TIMEOUT
gint db_rpspin_rlock(void * db, gint timeout) {
#else
gint db_rpspin_rlock(void * db) {
#endif
  int i;
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  volatile gint *gl;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_rlock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);

  /* Increment reader count atomically */
  fetch_and_add(gl, RC_INCR);

  /* Try getting the lock without pause */
  if(!((*gl) & WAFLAG)) return 1;

#ifdef _WIN32
  ts = SLEEP_MSEC;
#else
  ts.tv_sec = 0;
  ts.tv_nsec = SLEEP_NSEC;
#endif

#ifdef USE_LOCK_TIMEOUT
  INIT_SPIN_TIMEOUT(timeout)
#endif

  /* Spin loop */
  for(;;) {
    for(i=0; i<SPIN_COUNT; i++) {
      MM_PAUSE
      if(!((*gl) & WAFLAG)) return 1;
    }

    /* Check for timeout. */
#ifdef USE_LOCK_TIMEOUT
    UPDATE_SPIN_TIMEOUT(timeout, ts)
    if(timeout < 0) {
      /* We're no longer waiting, restore the counter */
      fetch_and_add(gl, -RC_INCR);
      return 0;
    }
#endif

#ifdef _WIN32
    Sleep(ts);
    ts += SLEEP_MSEC;
#else
    nanosleep(&ts, NULL);
    ts.tv_nsec += SLEEP_NSEC;
#endif
  }

  return 0; /* dummy */
}

/** Release database level shared lock (reader-preference spinlock)
 */

gint db_rpspin_rulock(void * db) {

  volatile gint *gl;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_rulock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);

  /* Decrement reader count */
  fetch_and_add(gl, -RC_INCR);

  return 1;
}

#elif (LOCK_PROTO==WPSPIN)

/** Acquire database level exclusive lock (writer-preference spinlock)
 *   Blocks until lock is acquired.
 */

#ifdef USE_LOCK_TIMEOUT
gint db_wpspin_wlock(void * db, gint timeout) {
#else
gint db_wpspin_wlock(void * db) {
#endif
  int i;
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  volatile gint *gl, *w;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_wlock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);
  w = (gint *) offsettoptr(db, dbmemsegh(db)->locks.writers);

  /* Let the readers know a writer is present */
  atomic_increment(w, 1);

  /* First attempt at getting the lock without spinning */
  if(compare_and_swap(gl, 0, WAFLAG))
    return 1;

#ifdef _WIN32
  ts = SLEEP_MSEC;
#else
  ts.tv_sec = 0;
  ts.tv_nsec = SLEEP_NSEC;
#endif

#ifdef USE_LOCK_TIMEOUT
  INIT_SPIN_TIMEOUT(timeout)
#endif

  /* Spin loop */
  for(;;) {
    for(i=0; i<SPIN_COUNT; i++) {
      MM_PAUSE
      if(!(*gl) && compare_and_swap(gl, 0, WAFLAG))
        return 1;
    }

    /* Check for timeout. */
#ifdef USE_LOCK_TIMEOUT
    UPDATE_SPIN_TIMEOUT(timeout, ts)
    if(timeout < 0) {
      /* Restore the previous writer count */
      atomic_increment(w, -1);
      return 0;
    }
#endif

    /* Give up the CPU so the lock holder(s) can continue */
#ifdef _WIN32
    Sleep(ts);
    ts += SLEEP_MSEC;
#else
    nanosleep(&ts, NULL);
    ts.tv_nsec += SLEEP_NSEC;
#endif
  }

  return 0; /* dummy */
}

/** Release database level exclusive lock (writer-preference spinlock)
 */

gint db_wpspin_wulock(void * db) {

  volatile gint *gl, *w;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_wulock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);
  w = (gint *) offsettoptr(db, dbmemsegh(db)->locks.writers);

  /* Clear the writer active flag */
  atomic_and(gl, ~(WAFLAG));

  /* writers-- */
  atomic_increment(w, -1);

  return 1;
}

/** Acquire database level shared lock (writer-preference spinlock)
 *   Blocks until there are no active or waiting writers, then increments
 *   reader count atomically.
 */

#ifdef USE_LOCK_TIMEOUT
gint db_wpspin_rlock(void * db, gint timeout) {
#else
gint db_wpspin_rlock(void * db) {
#endif
  int i;
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  volatile gint *gl, *w;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_rlock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);
  w = (gint *) offsettoptr(db, dbmemsegh(db)->locks.writers);

  /* Try locking without spinning */
  if(!(*w)) {
    gint readers = (*gl) & ~WAFLAG;
    if(compare_and_swap(gl, readers, readers + RC_INCR))
      return 1;
  }

#ifdef USE_LOCK_TIMEOUT
  INIT_SPIN_TIMEOUT(timeout)
#endif

  for(;;) {
#ifdef _WIN32
    ts = SLEEP_MSEC;
#else
    ts.tv_sec = 0;
    ts.tv_nsec = SLEEP_NSEC;
#endif

    /* Spin-wait until writers disappear */
    while(*w) {
      for(i=0; i<SPIN_COUNT; i++) {
        MM_PAUSE
        if(!(*w)) goto no_writers;
      }

#ifdef USE_LOCK_TIMEOUT
      UPDATE_SPIN_TIMEOUT(timeout, ts)
      if(timeout < 0)
        return 0;
#endif

#ifdef _WIN32
      Sleep(ts);
      ts += SLEEP_MSEC;
#else
      nanosleep(&ts, NULL);
      ts.tv_nsec += SLEEP_NSEC;
#endif
    }
no_writers:

    do {
      gint readers = (*gl) & ~WAFLAG;
      /* Atomically increment the reader count. If a writer has activated,
       * this fails and the do loop will also exit. If another reader modifies
       * the value, we retry.
       *
       * XXX: maybe MM_PAUSE and non-atomic checking can affect the
       * performance here, like in spin loops (this is more like a
       * retry loop though, not clear how many times it will typically
       * repeat).
       */
      if(compare_and_swap(gl, readers, readers + RC_INCR))
        return 1;
    } while(!(*w));
  }

  return 0; /* dummy */
}

/** Release database level shared lock (writer-preference spinlock)
 */

gint db_wpspin_rulock(void * db) {

  volatile gint *gl;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_rulock");
    return 0;
  }
#endif

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.global_lock);

  /* Decrement reader count */
  atomic_increment(gl, -RC_INCR);

  return 1;
}

#elif (LOCK_PROTO==TFQUEUE)

/** Acquire the queue mutex.
 */
static void lock_queue(void * db) {
  int i;
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  volatile gint *gl;

  /* skip the database pointer check, this function is not called directly */
  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.queue_lock);

  /* First attempt at getting the lock without spinning */
  if(compare_and_swap(gl, 0, 1))
    return;

#ifdef _WIN32
  ts = SLEEP_MSEC;
#else
  ts.tv_sec = 0;
  ts.tv_nsec = SLEEP_NSEC;
#endif

  /* Spin loop */
  for(;;) {
    for(i=0; i<SPIN_COUNT; i++) {
      MM_PAUSE
      if(!(*gl) && compare_and_swap(gl, 0, 1))
        return;
    }

    /* Backoff */
#ifdef _WIN32
    Sleep(ts);
    ts += SLEEP_MSEC;
#else
    nanosleep(&ts, NULL);
    ts.tv_nsec += SLEEP_NSEC;
#endif
  }
}

/** Release the queue mutex
 */
static void unlock_queue(void * db) {
  volatile gint *gl;

  gl = (gint *) offsettoptr(db, dbmemsegh(db)->locks.queue_lock);

  *gl = 0;
}

/** Acquire database level exclusive lock (task-fair queued lock)
 *   Blocks until lock is acquired.
 *   If USE_LOCK_TIMEOUT is defined, may return without locking
 */

#ifdef USE_LOCK_TIMEOUT
gint db_tfqueue_wlock(void * db, gint timeout) {
#else
gint db_tfqueue_wlock(void * db) {
#endif
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  gint lock, prev;
  lock_queue_node *lockp;
  db_memsegment_header* dbh;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_wlock");
    return 0;
  }
#endif

  dbh = dbmemsegh(db);

  lock_queue(db);
  ALLOC_LOCK(db, lock)

  prev = dbh->locks.tail;
  dbh->locks.tail = lock;

  lockp = (lock_queue_node *) offsettoptr(db, lock);
  lockp->class = LOCKQ_WRITE;
  lockp->prev = prev;
  lockp->next = 0;

  if(prev) {
    lock_queue_node *prevp = offsettoptr(db, prev);
    prevp->next = lock;
    lockp->waiting = 1;
  } else {
    lockp->waiting = 0;
  }

  unlock_queue(db);

  if(lockp->waiting) {
#ifdef __linux__
#ifdef USE_LOCK_TIMEOUT
    INIT_QLOCK_TIMEOUT(timeout, ts)
    if(futex_trywait(&lockp->waiting, 1, &ts) == ETIMEDOUT) {
      lock_queue(db);
      DEQUEUE_LOCK(db, dbh, lock, lockp)
      free_lock(db, lock);
      unlock_queue(db);
      return 0;
    }
#else
    futex_wait(&lockp->waiting, 1);
#endif
#else
/* XXX: add support for other platforms */
#error This code needs Linux SYS_futex service to function
#endif
  }

  return lock;
}

/** Release database level exclusive lock (task-fair queued lock)
 */

gint db_tfqueue_wulock(void * db, gint lock) {
  lock_queue_node *lockp;
  db_memsegment_header* dbh;
  volatile gint *syn_addr = NULL;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_wulock");
    return 0;
  }
#endif

  dbh = dbmemsegh(db);
  lockp = (lock_queue_node *) offsettoptr(db, lock);

  lock_queue(db);
  if(lockp->next) {
    lock_queue_node *nextp = offsettoptr(db, lockp->next);
    nextp->waiting = 0;
    nextp->prev = 0; /* we're a writer lock, head of the queue */
    syn_addr = &nextp->waiting;
  } else if(dbh->locks.tail == lock) {
    dbh->locks.tail = 0;
  }
  free_lock(db, lock);
  unlock_queue(db);
  if(syn_addr) {
#ifdef __linux__
    futex_wake(syn_addr, 1);
#else
/* XXX: add support for other platforms */
#error This code needs Linux SYS_futex service to function
#endif
  }

  return 1;
}

/** Acquire database level shared lock (task-fair queued lock)
 *   If USE_LOCK_TIMEOUT is defined, may return without locking.
 */

#ifdef USE_LOCK_TIMEOUT
gint db_tfqueue_rlock(void * db, gint timeout) {
#else
gint db_tfqueue_rlock(void * db) {
#endif
#ifdef _WIN32
  int ts;
#else
  struct timespec ts;
#endif
  gint lock, prev;
  lock_queue_node *lockp;
  db_memsegment_header* dbh;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_rlock");
    return 0;
  }
#endif

  dbh = dbmemsegh(db);

  lock_queue(db);
  ALLOC_LOCK(db, lock)

  prev = dbh->locks.tail;
  dbh->locks.tail = lock;

  lockp = (lock_queue_node *) offsettoptr(db, lock);
  lockp->class = LOCKQ_READ;
  lockp->prev = prev;
  lockp->next = 0;

  if(prev) {
    lock_queue_node *prevp = (lock_queue_node *) offsettoptr(db, prev);
    prevp->next = lock;

    if(prevp->class == LOCKQ_READ && prevp->waiting == 0) {
      lockp->waiting = 0;
    } else {
      lockp->waiting = 1;
    }
  } else {
    lockp->waiting = 0;
  }
  unlock_queue(db);

  if(lockp->waiting) {
    volatile gint *syn_addr = NULL;
#ifdef __linux__
#ifdef USE_LOCK_TIMEOUT
    INIT_QLOCK_TIMEOUT(timeout, ts)
    if(futex_trywait(&lockp->waiting, 1, &ts) == ETIMEDOUT) {
      lock_queue(db);
      DEQUEUE_LOCK(db, dbh, lock, lockp)
      free_lock(db, lock);
      unlock_queue(db);
      return 0;
    }
#else
    futex_wait(&lockp->waiting, 1);
#endif
#else
/* XXX: add support for other platforms */
#error This code needs Linux SYS_futex service to function
#endif
    lock_queue(db);
    if(lockp->next) {
      lock_queue_node *nextp = offsettoptr(db, lockp->next);
      if(nextp->class == LOCKQ_READ && nextp->waiting) {
        nextp->waiting = 0;
        syn_addr = &nextp->waiting;
      }
    }
    unlock_queue(db);
    if(syn_addr) {
#ifdef __linux__
      futex_wake(syn_addr, 1);
#else
/* XXX: add support for other platforms */
#error This code needs Linux SYS_futex service to function
#endif
    }
  }

  return lock;
}

/** Release database level shared lock (task-fair queued lock)
 */

gint db_tfqueue_rulock(void * db, gint lock) {
  lock_queue_node *lockp;
  db_memsegment_header* dbh;
  volatile gint *syn_addr = NULL;

#ifdef CHECK
  if (!dbcheck(db)) {
    show_lock_error(db, "Invalid database pointer in db_rulock");
    return 0;
  }
#endif

  dbh = dbmemsegh(db);
  lockp = (lock_queue_node *) offsettoptr(db, lock);

  lock_queue(db);
  if(lockp->prev) {
    lock_queue_node *prevp = offsettoptr(db, lockp->prev);
    prevp->next = lockp->next;
  }
  if(lockp->next) {
    lock_queue_node *nextp = offsettoptr(db, lockp->next);
    nextp->prev = lockp->prev;
    if(nextp->waiting && (!lockp->prev || nextp->class == LOCKQ_READ)) {
      nextp->waiting = 0;
      syn_addr = &nextp->waiting;
    }
  } else if(dbh->locks.tail == lock) {
    dbh->locks.tail = lockp->prev;
  }
  free_lock(db, lock);
  unlock_queue(db);
  if(syn_addr) {
#ifdef __linux__
    futex_wake(syn_addr, 1);
#else
/* XXX: add support for other platforms */
#error This code needs Linux SYS_futex service to function
#endif
  }

  return 1;
}

#endif /* LOCK_PROTO */

/** Initialize locking subsystem.
 *   Not parallel-safe, so should be run during database init.
 *
 * Note that this function is called even if locking is disabled.
 */
gint wg_init_locks(void * db) {
#if (LOCK_PROTO==TFQUEUE)
  gint i, chunk_wall;
  lock_queue_node *tmp = NULL;
#endif
  db_memsegment_header* dbh;

#ifdef CHECK
  if (!dbcheck(db) && !dbcheckinit(db)) {
    show_lock_error(db, "Invalid database pointer in wg_init_locks");
    return -1;
  }
#endif
  dbh = dbmemsegh(db);

#if (LOCK_PROTO==TFQUEUE)
  chunk_wall = dbh->locks.storage + dbh->locks.max_nodes*SYN_VAR_PADDING;

  for(i=dbh->locks.storage; i<chunk_wall; ) {
    tmp = (lock_queue_node *) offsettoptr(db, i);
    i+=SYN_VAR_PADDING;
    tmp->next_cell = i; /* offset of next cell */
  }
  tmp->next_cell=0; /* last node */

  /* top of the stack points to first cell in chunk */
  dbh->locks.freelist = dbh->locks.storage;

  /* reset the state */
  dbh->locks.tail = 0; /* 0 is considered invalid offset==>no value */
  dbstore(db, dbh->locks.queue_lock, 0);
#else
  dbstore(db, dbh->locks.global_lock, 0);
  dbstore(db, dbh->locks.writers, 0);
#endif
  return 0;
}

#if (LOCK_PROTO==TFQUEUE)

/* ---------- memory management for queued locks ---------- */

/*
 * Queued locks algorithm assumes allocating memory cells
 * for each lock. These cells need to be memory-aligned to
 * allow spinlocks run locally, but more importantly, allocation
 * and freeing of the cells has to be implemented in a lock-free
 * manner.
 *
 * The method used in the initial implementation is freelist
 * with reference counts (generally described by Valois '95,
 * actual code is based on examples from
 * http://www.non-blocking.com/Eng/services-technologies_non-blocking-lock-free.htm)
 *
 * XXX: code untested currently
 * XXX: Mellor-Crummey & Scott algorithm possibly does not need
 *      refcounts. If so, they should be #ifdef-ed out, but
 *      kept for possible future expansion.
 */

/** Allocate memory cell for a lock.
 *   Used internally only, so we assume the passed db pointer
 *   is already validated.
 *
 *   Returns offset to allocated cell.
 */

#if 0
static gint alloc_lock(void * db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  lock_queue_node *tmp;

  for(;;) {
    gint t = dbh->locks.freelist;
    if(!t)
      return 0; /* end of chain :-( */
    tmp = (lock_queue_node *) offsettoptr(db, t);

    fetch_and_add(&(tmp->refcount), 2);

    if(compare_and_swap(&(dbh->locks.freelist), t, tmp->next_cell)) {
      fetch_and_add(&(tmp->refcount), -1); /* clear lsb */
      return t;
    }

    free_lock(db, t);
  }

  return 0; /* dummy */
}

/** Release memory cell for a lock.
 *   Used internally only.
 */

static void free_lock(void * db, gint node) {
  db_memsegment_header* dbh = dbmemsegh(db);
  lock_queue_node *tmp;
  volatile gint t;

  tmp = (lock_queue_node *) offsettoptr(db, node);

  /* Clear reference */
  fetch_and_add(&(tmp->refcount), -2);

  /* Try to set lsb */
  if(compare_and_swap(&(tmp->refcount), 0, 1)) {

/* XXX:
    if(tmp->next_cell) free_lock(db, tmp->next_cell);
*/
    do {
      t = dbh->locks.freelist;
      tmp->next_cell = t;
    } while (!compare_and_swap(&(dbh->locks.freelist), t, node));
  }
}

/** De-reference (release pointer to) a link.
 *   Used internally only.
 */

static gint deref_link(void *db, volatile gint *link) {
  lock_queue_node *tmp;
  volatile gint t;

  for(;;) {
    t = *link;
    if(t == 0) return 0;

    tmp = (lock_queue_node *) offsettoptr(db, t);

    fetch_and_add(&(tmp->refcount), 2);
    if(t == *link) return t;
    free_lock(db, t);
  }
}

#else
/* Simple lock memory allocation (non lock-free) */

static gint alloc_lock(void * db) {
  db_memsegment_header* dbh = dbmemsegh(db);
  gint t = dbh->locks.freelist;
  lock_queue_node *tmp;

  if(!t)
    return 0; /* end of chain :-( */
  tmp = (lock_queue_node *) offsettoptr(db, t);

  dbh->locks.freelist = tmp->next_cell;
  return t;
}

static void free_lock(void * db, gint node) {
  db_memsegment_header* dbh = dbmemsegh(db);
  lock_queue_node *tmp = (lock_queue_node *) offsettoptr(db, node);
  tmp->next_cell = dbh->locks.freelist;
  dbh->locks.freelist = node;
}

#endif

#ifdef __linux__
/* Futex operations */

#ifndef USE_LOCK_TIMEOUT
static void futex_wait(volatile gint *addr1, int val1)
{
  syscall(SYS_futex, (void *) addr1, FUTEX_WAIT, val1, NULL);
}
#endif

static int futex_trywait(volatile gint *addr1, int val1,
  struct timespec *timeout)
{
  if(syscall(SYS_futex, (void *) addr1, FUTEX_WAIT, val1, timeout) == -1)
    return errno; /* On Linux, this is thread-safe. Caution needed however */
  else
    return 0;
}

static void futex_wake(volatile gint *addr1, int val1)
{
  syscall(SYS_futex, (void *) addr1, FUTEX_WAKE, val1);
}
#endif

#endif /* LOCK_PROTO==TFQUEUE */


/* ------------ error handling ---------------- */

static gint show_lock_error(void *db, char *errmsg) {
#ifdef WG_NO_ERRPRINT
#else
  fprintf(stderr,"wg locking error: %s.\n", errmsg);
#endif
  return -1;
}

#ifdef __cplusplus
}
#endif

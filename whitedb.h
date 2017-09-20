#include <stdio.h>
/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Use additional validation checks */
#define CHECK 1

/* Journal file directory */
#define DBLOG_DIR "/tmp"

/* Encoded data is 64-bit */
#define HAVE_64BIT_GINT 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `m' library (-lm). */
#define HAVE_LIBM 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Compile with raptor rdf library */
/* #undef HAVE_RAPTOR */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Select locking protocol: reader-preference spinlock */
#define LOCK_PROTO 3

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "whitedb"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "WhiteDB"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "WhiteDB 0.7.3"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "whitedb"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.7.3"

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* The size of `ptrdiff_t', as computed by sizeof. */
#define SIZEOF_PTRDIFF_T 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* String hash size (% of db size) */
#define STRHASH_SIZE 2

/* Use chained T-tree index nodes */
#define TTREE_CHAINED_NODES 1

/* Use single-compare T-tree mode */
#define TTREE_SINGLE_COMPARE 1

/* Use record banklinks */
#define USE_BACKLINKING 1

/* Enable child database support */
/* #undef USE_CHILD_DB */

/* Use dblog module for transaction logging */
/* #undef USE_DBLOG */

/* Use match templates for indexes */
#define USE_INDEX_TEMPLATE 1

/* Version number of package */
#define VERSION "0.7.3"

/* Package major version */
#define VERSION_MAJOR 0

/* Package minor version */
#define VERSION_MINOR 7

/* Package revision number */
#define VERSION_REV 3

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* #undef YYTEXT_POINTER */
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

#ifndef YAJL_API_H
#define YAJL_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YAJL_MAX_DEPTH 128

#define YAJL_API

/** pointer to a malloc function, supporting client overriding memory
 *  allocation routines */
typedef void * (*yajl_malloc_func)(void *ctx, size_t sz);

/** pointer to a free function, supporting client overriding memory
 *  allocation routines */
typedef void (*yajl_free_func)(void *ctx, void * ptr);

/** pointer to a realloc function which can resize an allocation. */
typedef void * (*yajl_realloc_func)(void *ctx, void * ptr, size_t sz);

/** A structure which can be passed to yajl_*_alloc routines to allow the
 *  client to specify memory allocation functions to be used. */
typedef struct
{
    /** pointer to a function that can allocate uninitialized memory */
    yajl_malloc_func malloc;
    /** pointer to a function that can resize memory allocations */
    yajl_realloc_func realloc;
    /** pointer to a function that can free memory allocated using
     *  reallocFunction or mallocFunction */
    yajl_free_func free;
    /** a context pointer that will be passed to above allocation routines */
    void * ctx;
} yajl_alloc_funcs;

/**
 * \file yajl_parse.h
 * Interface to YAJL's JSON stream parsing facilities.
 */

/** error codes returned from this interface */
typedef enum {
    /** no error was encountered */
    yajl_status_ok,
    /** a client callback returned zero, stopping the parse */
    yajl_status_client_canceled,
    /** An error occured during the parse.  Call yajl_get_error for
     *  more information about the encountered error */
    yajl_status_error
} yajl_status;

/** attain a human readable, english, string for an error */
YAJL_API const char * yajl_status_to_string(yajl_status code);

/** an opaque handle to a parser */
typedef struct yajl_handle_t * yajl_handle;

/** yajl is an event driven parser.  this means as json elements are
 *  parsed, you are called back to do something with the data.  The
 *  functions in this table indicate the various events for which
 *  you will be called back.  Each callback accepts a "context"
 *  pointer, this is a void * that is passed into the yajl_parse
 *  function which the client code may use to pass around context.
 *
 *  All callbacks return an integer.  If non-zero, the parse will
 *  continue.  If zero, the parse will be canceled and
 *  yajl_status_client_canceled will be returned from the parse.
 *
 *  \attention {
 *    A note about the handling of numbers:
 *
 *    yajl will only convert numbers that can be represented in a
 *    double or a 64 bit (long long) int.  All other numbers will
 *    be passed to the client in string form using the yajl_number
 *    callback.  Furthermore, if yajl_number is not NULL, it will
 *    always be used to return numbers, that is yajl_integer and
 *    yajl_double will be ignored.  If yajl_number is NULL but one
 *    of yajl_integer or yajl_double are defined, parsing of a
 *    number larger than is representable in a double or 64 bit
 *    integer will result in a parse error.
 *  }
 */
typedef struct {
    int (* yajl_null)(void * ctx);
    int (* yajl_boolean)(void * ctx, int boolVal);
    int (* yajl_integer)(void * ctx, long long integerVal);
    int (* yajl_double)(void * ctx, double doubleVal);
    /** A callback which passes the string representation of the number
     *  back to the client.  Will be used for all numbers when present */
    int (* yajl_number)(void * ctx, const char * numberVal,
                        size_t numberLen);

    /** strings are returned as pointers into the JSON text when,
     * possible, as a result, they are _not_ null padded */
    int (* yajl_string)(void * ctx, const unsigned char * stringVal,
                        size_t stringLen);

    int (* yajl_start_map)(void * ctx);
    int (* yajl_map_key)(void * ctx, const unsigned char * key,
                         size_t stringLen);
    int (* yajl_end_map)(void * ctx);

    int (* yajl_start_array)(void * ctx);
    int (* yajl_end_array)(void * ctx);
} yajl_callbacks;

/** allocate a parser handle
 *  \param callbacks  a yajl callbacks structure specifying the
 *                    functions to call when different JSON entities
 *                    are encountered in the input text.  May be NULL,
 *                    which is only useful for validation.
 *  \param afs        memory allocation functions, may be NULL for to use
 *                    C runtime library routines (malloc and friends)
 *  \param ctx        a context pointer that will be passed to callbacks.
 */
YAJL_API yajl_handle yajl_alloc(const yajl_callbacks * callbacks,
                                yajl_alloc_funcs * afs,
                                void * ctx);


/** configuration parameters for the parser, these may be passed to
 *  yajl_config() along with option specific argument(s).  In general,
 *  all configuration parameters default to *off*. */
typedef enum {
    /** Ignore javascript style comments present in
     *  JSON input.  Non-standard, but rather fun
     *  arguments: toggled off with integer zero, on otherwise.
     *
     *  example:
     *    yajl_config(h, yajl_allow_comments, 1); // turn comment support on
     */
    yajl_allow_comments = 0x01,
    /**
     * When set the parser will verify that all strings in JSON input are
     * valid UTF8 and will emit a parse error if this is not so.  When set,
     * this option makes parsing slightly more expensive (~7% depending
     * on processor and compiler in use)
     *
     * example:
     *   yajl_config(h, yajl_dont_validate_strings, 1); // disable utf8 checking
     */
    yajl_dont_validate_strings     = 0x02,
    /**
     * By default, upon calls to yajl_complete_parse(), yajl will
     * ensure the entire input text was consumed and will raise an error
     * otherwise.  Enabling this flag will cause yajl to disable this
     * check.  This can be useful when parsing json out of a that contains more
     * than a single JSON document.
     */
    yajl_allow_trailing_garbage = 0x04,
    /**
     * Allow multiple values to be parsed by a single handle.  The
     * entire text must be valid JSON, and values can be seperated
     * by any kind of whitespace.  This flag will change the
     * behavior of the parser, and cause it continue parsing after
     * a value is parsed, rather than transitioning into a
     * complete state.  This option can be useful when parsing multiple
     * values from an input stream.
     */
    yajl_allow_multiple_values = 0x08,
    /**
     * When yajl_complete_parse() is called the parser will
     * check that the top level value was completely consumed.  I.E.,
     * if called whilst in the middle of parsing a value
     * yajl will enter an error state (premature EOF).  Setting this
     * flag suppresses that check and the corresponding error.
     */
    yajl_allow_partial_values = 0x10
} yajl_option;

/** allow the modification of parser options subsequent to handle
 *  allocation (via yajl_alloc)
 *  \returns zero in case of errors, non-zero otherwise
 */
YAJL_API int yajl_config(yajl_handle h, yajl_option opt, ...);

/** free a parser handle */
YAJL_API void yajl_free(yajl_handle handle);

/** Parse some json!
 *  \param hand - a handle to the json parser allocated with yajl_alloc
 *  \param jsonText - a pointer to the UTF8 json text to be parsed
 *  \param jsonTextLength - the length, in bytes, of input text
 */
YAJL_API yajl_status yajl_parse(yajl_handle hand,
                                const unsigned char * jsonText,
                                size_t jsonTextLength);

/** Parse any remaining buffered json.
 *  Since yajl is a stream-based parser, without an explicit end of
 *  input, yajl sometimes can't decide if content at the end of the
 *  stream is valid or not.  For example, if "1" has been fed in,
 *  yajl can't know whether another digit is next or some character
 *  that would terminate the integer token.
 *
 *  \param hand - a handle to the json parser allocated with yajl_alloc
 */
YAJL_API yajl_status yajl_complete_parse(yajl_handle hand);

/** get an error string describing the state of the
 *  parse.
 *
 *  If verbose is non-zero, the message will include the JSON
 *  text where the error occured, along with an arrow pointing to
 *  the specific char.
 *
 *  \returns A dynamically allocated string will be returned which should
 *  be freed with yajl_free_error
 */
YAJL_API unsigned char * yajl_get_error(yajl_handle hand, int verbose,
                                        const unsigned char * jsonText,
                                        size_t jsonTextLength);

/**
 * get the amount of data consumed from the last chunk passed to YAJL.
 *
 * In the case of a successful parse this can help you understand if
 * the entire buffer was consumed (which will allow you to handle
 * "junk at end of input").
 *
 * In the event an error is encountered during parsing, this function
 * affords the client a way to get the offset into the most recent
 * chunk where the error occured.  0 will be returned if no error
 * was encountered.
 */
YAJL_API size_t yajl_get_bytes_consumed(yajl_handle hand);

/** free an error returned from yajl_get_error */
YAJL_API void yajl_free_error(yajl_handle hand, unsigned char * str);

/**
 * \file yajl_gen.h
 * Interface to YAJL's JSON generation facilities.
 */

/** generator status codes */
typedef enum {
    /** no error */
    yajl_gen_status_ok = 0,
    /** at a point where a map key is generated, a function other than
     *  yajl_gen_string was called */
    yajl_gen_keys_must_be_strings,
    /** YAJL's maximum generation depth was exceeded.  see
     *  YAJL_MAX_DEPTH */
    yajl_max_depth_exceeded,
    /** A generator function (yajl_gen_XXX) was called while in an error
     *  state */
    yajl_gen_in_error_state,
    /** A complete JSON document has been generated */
    yajl_gen_generation_complete,
    /** yajl_gen_double was passed an invalid floating point value
     *  (infinity or NaN). */
    yajl_gen_invalid_number,
    /** A print callback was passed in, so there is no internal
     * buffer to get from */
    yajl_gen_no_buf,
    /** returned from yajl_gen_string() when the yajl_gen_validate_utf8
     *  option is enabled and an invalid was passed by client code.
     */
    yajl_gen_invalid_string
} yajl_gen_status;

/** an opaque handle to a generator */
typedef struct yajl_gen_t * yajl_gen;

/** a callback used for "printing" the results. */
typedef void (*yajl_print_t)(void * ctx,
                             const char * str,
                             size_t len);

/** configuration parameters for the parser, these may be passed to
 *  yajl_gen_config() along with option specific argument(s).  In general,
 *  all configuration parameters default to *off*. */
typedef enum {
    /** generate indented (beautiful) output */
    yajl_gen_beautify = 0x01,
    /**
     * Set an indent string which is used when yajl_gen_beautify
     * is enabled.  Maybe something like \\t or some number of
     * spaces.  The default is four spaces ' '.
     */
    yajl_gen_indent_string = 0x02,
    /**
     * Set a function and context argument that should be used to
     * output generated json.  the function should conform to the
     * yajl_print_t prototype while the context argument is a
     * void * of your choosing.
     *
     * example:
     *   yajl_gen_config(g, yajl_gen_print_callback, myFunc, myVoidPtr);
     */
    yajl_gen_print_callback = 0x04,
    /**
     * Normally the generator does not validate that strings you
     * pass to it via yajl_gen_string() are valid UTF8.  Enabling
     * this option will cause it to do so.
     */
    yajl_gen_validate_utf8 = 0x08,
    /**
     * the forward solidus (slash or '/' in human) is not required to be
     * escaped in json text.  By default, YAJL will not escape it in the
     * iterest of saving bytes.  Setting this flag will cause YAJL to
     * always escape '/' in generated JSON strings.
     */
    yajl_gen_escape_solidus = 0x10
} yajl_gen_option;

/** allow the modification of generator options subsequent to handle
 *  allocation (via yajl_alloc)
 *  \returns zero in case of errors, non-zero otherwise
 */
YAJL_API int yajl_gen_config(yajl_gen g, yajl_gen_option opt, ...);

/** allocate a generator handle
 *  \param allocFuncs an optional pointer to a structure which allows
 *                    the client to overide the memory allocation
 *                    used by yajl.  May be NULL, in which case
 *                    malloc/free/realloc will be used.
 *
 *  \returns an allocated handle on success, NULL on failure (bad params)
 */
YAJL_API yajl_gen yajl_gen_alloc(const yajl_alloc_funcs * allocFuncs);

/** free a generator handle */
YAJL_API void yajl_gen_free(yajl_gen handle);

YAJL_API yajl_gen_status yajl_gen_integer(yajl_gen hand, long long int number);
/** generate a floating point number.  number may not be infinity or
 *  NaN, as these have no representation in JSON.  In these cases the
 *  generator will return 'yajl_gen_invalid_number' */
YAJL_API yajl_gen_status yajl_gen_double(yajl_gen hand, double number);
YAJL_API yajl_gen_status yajl_gen_number(yajl_gen hand,
                                         const char * num,
                                         size_t len);
YAJL_API yajl_gen_status yajl_gen_string(yajl_gen hand,
                                         const unsigned char * str,
                                         size_t len);
YAJL_API yajl_gen_status yajl_gen_null(yajl_gen hand);
YAJL_API yajl_gen_status yajl_gen_bool(yajl_gen hand, int boolean);
YAJL_API yajl_gen_status yajl_gen_map_open(yajl_gen hand);
YAJL_API yajl_gen_status yajl_gen_map_close(yajl_gen hand);
YAJL_API yajl_gen_status yajl_gen_array_open(yajl_gen hand);
YAJL_API yajl_gen_status yajl_gen_array_close(yajl_gen hand);

/** access the null terminated generator buffer.  If incrementally
 *  outputing JSON, one should call yajl_gen_clear to clear the
 *  buffer.  This allows stream generation. */
YAJL_API yajl_gen_status yajl_gen_get_buf(yajl_gen hand,
                                          const unsigned char ** buf,
                                          size_t * len);

/** clear yajl's output buffer, but maintain all internal generation
 *  state.  This function will not "reset" the generator state, and is
 *  intended to enable incremental JSON outputing. */
YAJL_API void yajl_gen_clear(yajl_gen hand);

#ifdef __cplusplus
}
#endif

#endif /* YAJL_API_H */
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

#ifndef YAJL_ALL_H
#define YAJL_ALL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file yajl_alloc.h
 * default memory allocation routines for yajl which use malloc/realloc and
 * free
 */

//jl_api.h"

#define YA_MALLOC(afs, sz) (afs)->malloc((afs)->ctx, (sz))
#define YA_FREE(afs, ptr) (afs)->free((afs)->ctx, (ptr))
#define YA_REALLOC(afs, ptr, sz) (afs)->realloc((afs)->ctx, (ptr), (sz))

static void yajl_set_default_alloc_funcs(yajl_alloc_funcs * yaf);

/*
 * Implementation/performance notes.  If this were moved to a header
 * only implementation using #define's where possible we might be
 * able to sqeeze a little performance out of the guy by killing function
 * call overhead.  YMMV.
 */

/**
 * yajl_buf is a buffer with exponential growth.  the buffer ensures that
 * you are always null padded.
 */
typedef struct yajl_buf_t * yajl_buf;

/* allocate a new buffer */
static yajl_buf yajl_buf_alloc(yajl_alloc_funcs * alloc);

/* free the buffer */
static void yajl_buf_free(yajl_buf buf);

/* append a number of bytes to the buffer */
static void yajl_buf_append(yajl_buf buf, const void * data, size_t len);

/* empty the buffer */
static void yajl_buf_clear(yajl_buf buf);

/* get a pointer to the beginning of the buffer */
static const unsigned char * yajl_buf_data(yajl_buf buf);

/* get the length of the buffer */
static size_t yajl_buf_len(yajl_buf buf);

/*
 * A header only implementation of a simple stack of bytes, used in YAJL
 * to maintain parse state.
 */

#define YAJL_BS_INC 128

typedef struct yajl_bytestack_t
{
    unsigned char * stack;
    size_t size;
    size_t used;
    yajl_alloc_funcs * yaf;
} yajl_bytestack;

/* initialize a bytestack */
#define yajl_bs_init(obs, _yaf) {               \
        (obs).stack = NULL;                     \
        (obs).size = 0;                         \
        (obs).used = 0;                         \
        (obs).yaf = (_yaf);                     \
    }                                           \


/* initialize a bytestack */
#define yajl_bs_free(obs)                 \
    if ((obs).stack) (obs).yaf->free((obs).yaf->ctx, (obs).stack);

#define yajl_bs_current(obs)               \
    (assert((obs).used > 0), (obs).stack[(obs).used - 1])

#define yajl_bs_push(obs, byte) {                       \
    if (((obs).size - (obs).used) == 0) {               \
        (obs).size += YAJL_BS_INC;                      \
        (obs).stack = (obs).yaf->realloc((obs).yaf->ctx,\
                                         (void *) (obs).stack, (obs).size);\
    }                                                   \
    (obs).stack[((obs).used)++] = (byte);               \
}

/* removes the top item of the stack, returns nothing */
#define yajl_bs_pop(obs) { ((obs).used)--; }

#define yajl_bs_set(obs, byte)                          \
    (obs).stack[((obs).used) - 1] = (byte);


static void yajl_string_encode(const yajl_print_t printer,
                        void * ctx,
                        const unsigned char * str,
                        size_t length,
                        int escape_solidus);

static void yajl_string_decode(yajl_buf buf, const unsigned char * str,
                        size_t length);

static int yajl_string_validate_utf8(const unsigned char * s, size_t len);


typedef enum {
    yajl_tok_bool,
    yajl_tok_colon,
    yajl_tok_comma,
    yajl_tok_eof,
    yajl_tok_error,
    yajl_tok_left_brace,
    yajl_tok_left_bracket,
    yajl_tok_null,
    yajl_tok_right_brace,
    yajl_tok_right_bracket,

    /* we differentiate between integers and doubles to allow the
     * parser to interpret the number without re-scanning */
    yajl_tok_integer,
    yajl_tok_double,

    /* we differentiate between strings which require further processing,
     * and strings that do not */
    yajl_tok_string,
    yajl_tok_string_with_escapes,

    /* comment tokens are not currently returned to the parser, ever */
    yajl_tok_comment
} yajl_tok;

typedef struct yajl_lexer_t * yajl_lexer;

static yajl_lexer yajl_lex_alloc(yajl_alloc_funcs * alloc,
                          unsigned int allowComments,
                          unsigned int validateUTF8);

static void yajl_lex_free(yajl_lexer lexer);

/**
 * run/continue a lex. "offset" is an input/output parameter.
 * It should be initialized to zero for a
 * new chunk of target text, and upon subsetquent calls with the same
 * target text should passed with the value of the previous invocation.
 *
 * the client may be interested in the value of offset when an error is
 * returned from the lexer.  This allows the client to render useful
n * error messages.
 *
 * When you pass the next chunk of data, context should be reinitialized
 * to zero.
 *
 * Finally, the output buffer is usually just a pointer into the jsonText,
 * however in cases where the entity being lexed spans multiple chunks,
 * the lexer will buffer the entity and the data returned will be
 * a pointer into that buffer.
 *
 * This behavior is abstracted from client code except for the performance
 * implications which require that the client choose a reasonable chunk
 * size to get adequate performance.
 */
static yajl_tok yajl_lex_lex(yajl_lexer lexer, const unsigned char * jsonText,
                      size_t jsonTextLen, size_t * offset,
                      const unsigned char ** outBuf, size_t * outLen);

typedef enum {
    yajl_lex_e_ok = 0,
    yajl_lex_string_invalid_utf8,
    yajl_lex_string_invalid_escaped_char,
    yajl_lex_string_invalid_json_char,
    yajl_lex_string_invalid_hex_char,
    yajl_lex_invalid_char,
    yajl_lex_invalid_string,
    yajl_lex_missing_integer_after_decimal,
    yajl_lex_missing_integer_after_exponent,
    yajl_lex_missing_integer_after_minus,
    yajl_lex_unallowed_comment
} yajl_lex_error;

static const char * yajl_lex_error_to_string(yajl_lex_error error);

/** allows access to more specific information about the lexical
 *  error when yajl_lex_lex returns yajl_tok_error. */
static yajl_lex_error yajl_lex_get_error(yajl_lexer lexer);


typedef enum {
    yajl_state_start = 0,
    yajl_state_parse_complete,
    yajl_state_parse_error,
    yajl_state_lexical_error,
    yajl_state_map_start,
    yajl_state_map_sep,
    yajl_state_map_need_val,
    yajl_state_map_got_val,
    yajl_state_map_need_key,
    yajl_state_array_start,
    yajl_state_array_got_val,
    yajl_state_array_need_val,
    yajl_state_got_value,
} yajl_state;

struct yajl_handle_t {
    const yajl_callbacks * callbacks;
    void * ctx;
    yajl_lexer lexer;
    const char * parseError;
    /* the number of bytes consumed from the last client buffer,
     * in the case of an error this will be an error offset, in the
     * case of an error this can be used as the error offset */
    size_t bytesConsumed;
    /* temporary storage for decoded strings */
    yajl_buf decodeBuf;
    /* a stack of states.  access with yajl_state_XXX routines */
    yajl_bytestack stateStack;
    /* memory allocation routines */
    yajl_alloc_funcs alloc;
    /* bitfield */
    unsigned int flags;
};

static yajl_status
yajl_do_parse(yajl_handle handle, const unsigned char * jsonText,
              size_t jsonTextLen);

static yajl_status
yajl_do_finish(yajl_handle handle);

static unsigned char *
yajl_render_error_string(yajl_handle hand, const unsigned char * jsonText,
                         size_t jsonTextLen, int verbose);

/* A little built in integer parsing routine with the same semantics as strtol
 * that's unaffected by LOCALE. */
static long long
yajl_parse_integer(const unsigned char *number, unsigned int length);

#ifdef __cplusplus
}
#endif

#endif /* YAJL_ALL_H */
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

 /** @file dballoc.h
 * Public headers for database heap allocation procedures.
 */

#ifndef DEFINED_DBALLOC_H
#define DEFINED_DBALLOC_H

/* For gint/wg_int types */
#include <stddef.h>
#ifndef _MSC_VER
#include <stdint.h>
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

#define USE_DATABASE_HANDLE
/*


Levels of allocation used:

- Memory segment allocation: gives a large contiguous area of memory (typically shared memory).
  Could be extended later (has to be contiguous).

- Inside the contiguous memory segment: Allocate usage areas for different heaps
  (data records, strings, doubles, lists, etc).
  Each area is typically not contiguous: can consist of several subareas of different length.

  Areas have different object allocation principles:
  - fixed-length object area (e.g. list cells) allocation uses pre-calced freelists
  - various-length object area (e.g. data records) allocation uses ordinary allocation techniques:
    - objects initialised from next free  / designated victim object, split as needed
    - short freed objects are put into freelists in size-corresponding buckets
    - large freed object lists contain objects of different sizes

- Data object allocation: data records, strings, list cells etc.
  Allocated in corresponding subareas.

list area: 8M  is filled
  16 M area
  32
datarec area:
  8M is filled
  16 M area
  32 M area


Fixlen allocation:

- Fixlen objects are allocated using a pre-calced singly-linked freelist. When one subarea
  is exhausted(freelist empty), a new subarea is taken, it is organised into a long
  freelist and the beginning of the freelist is stored in db_area_header.freelist.

- Each freelist element is one fixlen object. The first gint of the object is an offset of
  the next freelist element. The list is terminated with 0.

Varlen allocation follows the main ideas of the Doug Lea allocator:

- the minimum size to allocate is 4 gints (MIN_VARLENOBJ_SIZE) and all objects
  should be aligned at least to a gint.

- each varlen area contains a number of gint-size buckets for storing different
  doubly-linked freelists. The buckets are:
  - EXACTBUCKETS_NR of buckets for exact object size. Contains an offset of the first
      free object of this size.
  - VARBUCKETS_NR of buckets for variable (interval between prev and next) object size,
      growing exponentially. Contains an offset of the first free object in this size interval.
  - EXACTBUCKETS_NR+VARBUCKETS_NR+1 is a designated victim (marked as in use):
      offset of the preferred place to split off new objects.
      Initially the whole free area is made one big designated victim.
  - EXACTBUCKETS_NR+VARBUCKETS_NR+2 is a size of the designated victim.

- a free object contains gints:
  - size (in bytes) with last two bits marked (i.e. not part of size!):
    - last bits: 00
  - offset of the next element in the freelist (terminated with 0).
  - offset of the previous element in the freelist (can be offset of the bucket!)
  ... arbitrary nr of bytes ...
  - size (in bytes) with last two bits marked as the initial size gint.
    This repeats the initial size gint and is located at the very end of the
    memory block.

- an in-use object contains gints:
  - size (in bytes) with mark bits and assumptions:
     - last 2 bits markers, not part of size:
        - for normal in-use objects with in-use predecessor 00
        - for normal in-use objects with free predecessor 10
        - for specials (dv area and start/end markers) 11
     - real size taken is always 8-aligned (minimal granularity 8 bytes)
     - size gint may be not 8-aligned if 32-bit gint used (but still has to be 4-aligned). In this case:
        - if size gint is not 8-aligned, real size taken either:
           - if size less than MIN_VARLENOBJ_SIZE, then MIN_VARLENOBJ_SIZE
           - else size+4 bytes (but used size is just size, no bytes added)
  - usable gints following

- a designated victim is marked to be in use:
  - the first gint has last bits 11 to differentiate from normal in-use objects (00 or 10 bits)
  - the second gint contains 0 to indicate that it is a dv object, and not start marker (1) or end marker (2)
  - all the following gints are arbitrary and contain no markup.

- the first 4 gints and the last 4 gints of each subarea are marked as in-use objects, although
  they should be never used! The reason is to give a markup for subarea beginning and end.
  - last bits 10 to differentiate from normal in-use objects (00 bits)
  - the next gint is 1 for start marker an 2 for end marker
  - the following 2 gints are arbitrary and contain no markup

 - summary of end bits for various objects:
   - 00  in-use normal object with in-use previous object
   - 10 in-use normal object with a free previous object
   - 01 free object
   - 11 in-use special object (dv or start/end marker)

*/

#define MEMSEGMENT_MAGIC_MARK 1232319011  /** enables to check that we really have db pointer */
#define MEMSEGMENT_MAGIC_INIT 1916950123  /** init time magic */
#define MEMSEGMENT_VERSION ((VERSION_REV<<16)|\
  (VERSION_MINOR<<8)|(VERSION_MAJOR)) /** written to dump headers for compatibilty checking */
#define SUBAREA_ARRAY_SIZE 64      /** nr of possible subareas in each area  */
#define INITIAL_SUBAREA_SIZE 8192  /** size of the first created subarea (bytes)  */
#define MINIMAL_SUBAREA_SIZE 8192  /** checked before subarea creation to filter out stupid requests */
#define SUBAREA_ALIGNMENT_BYTES 8          /** subarea alignment     */
#define SYN_VAR_PADDING 128          /** sync variable padding in bytes */
#if (LOCK_PROTO==3)
#define MAX_LOCKS 64                /** queue size (currently fixed :-() */
#endif

#define EXACTBUCKETS_NR 256                  /** amount of free ob buckets with exact length */
#define VARBUCKETS_NR 32                   /** amount of free ob buckets with varying length */
#define CACHEBUCKETS_NR 2                  /** buckets used as special caches */
#define DVBUCKET EXACTBUCKETS_NR+VARBUCKETS_NR     /** cachebucket: designated victim offset */
#define DVSIZEBUCKET EXACTBUCKETS_NR+VARBUCKETS_NR+1 /** cachebucket: byte size of designated victim */
#define MIN_VARLENOBJ_SIZE (4*(gint)(sizeof(gint)))  /** minimal size of variable length object */

#define SHORTSTR_SIZE 32 /** max len of short strings  */

/* defaults, used when there is no user-supplied or computed value */
#define DEFAULT_STRHASH_LENGTH 10000  /** length of the strhash array (nr of array elements) */
#define DEFAULT_IDXHASH_LENGTH 10000  /** hash index hash size */

#define ANONCONST_TABLE_SIZE 200 /** length of the table containing predefined anonconst uri ptrs */

/* ====== general typedefs and macros ======= */

// integer and address fetch and store

typedef ptrdiff_t gint;  /** always used instead of int. Pointers are also handled as gint. */
#ifndef _MSC_VER /* MSVC on Win32 */
typedef int32_t gint32;    /** 32-bit fixed size storage */
typedef int64_t gint64;    /** 64-bit fixed size storage */
#else
typedef __int32 gint32;    /** 32-bit fixed size storage */
typedef __int64 gint64;    /** 64-bit fixed size storage */
#endif

#ifdef USE_DATABASE_HANDLE
#define dbmemseg(x) ((void *)(((db_handle *) x)->db))
#define dbmemsegh(x) ((db_memsegment_header *)(((db_handle *) x)->db))
#define dbmemsegbytes(x) ((char *)(((db_handle *) x)->db))
#else
#define dbmemseg(x) ((void *)(x))
#define dbmemsegh(x) ((db_memsegment_header *)(x))
#define dbmemsegbytes(x) ((char *)(x))
#endif

#define dbfetch(db,offset) (*((gint*)(dbmemsegbytes(db)+(offset)))) /** get gint from address */
#define dbstore(db,offset,data) (*((gint*)(dbmemsegbytes(db)+(offset)))=data) /** store gint to address */
#define dbaddr(db,realptr) ((gint)(((char*)(realptr))-dbmemsegbytes(db))) /** give offset of real adress */
#define offsettoptr(db,offset) ((void*)(dbmemsegbytes(db)+(offset))) /** give real address from offset */
#define ptrtooffset(db,realptr) (dbaddr((db),(realptr)))
#define dbcheckh(dbh) (dbh!=NULL && *((gint32 *) dbh)==MEMSEGMENT_MAGIC_MARK) /** check that correct db ptr */
#define dbcheck(db) dbcheckh(dbmemsegh(db)) /** check that correct db ptr */
#define dbcheckhinit(dbh) (dbh!=NULL && *((gint32 *) dbh)==MEMSEGMENT_MAGIC_INIT)
#define dbcheckinit(db) dbcheckhinit(dbmemsegh(db))

/* ==== fixlen object allocation macros ==== */

#define alloc_listcell(db) wg_alloc_fixlen_object((db),&(dbmemsegh(db)->listcell_area_header))
#define alloc_shortstr(db) wg_alloc_fixlen_object((db),&(dbmemsegh(db)->shortstr_area_header))
#define alloc_word(db) wg_alloc_fixlen_object((db),&(dbmemsegh(db)->word_area_header))
#define alloc_doubleword(db) wg_alloc_fixlen_object((db),&(dbmemsegh(db)->doubleword_area_header))

/* ==== varlen object allocation special macros ==== */

#define isfreeobject(i)  (((i) & 3)==1) /** end bits 01 */
#define isnormalusedobject(i)  (!((i) & 1)) /** end bits either 00 or 10, i.e. last bit 0 */
#define isnormalusedobjectprevused(i)  (!((i) & 3)) /**  end bits 00 */
#define isnormalusedobjectprevfree(i)  (((i) & 3)==2) /** end bits 10 */
#define isspecialusedobject(i)  (((i) & 3) == 3) /**  end bits 11 */

#define getfreeobjectsize(i) ((i) & ~3) /** mask off two lowest bits: just keep all higher */
/** small size marks always use MIN_VARLENOBJ_SIZE,
* non-8-aligned size marks mean obj really takes 4 more bytes (all real used sizes are 8-aligned)
*/
#define getusedobjectsize(i) (((i) & ~3)<=MIN_VARLENOBJ_SIZE ?  MIN_VARLENOBJ_SIZE : ((((i) & ~3)%8) ? (((i) & ~3)+4) : ((i) & ~3)) )
#define getspecialusedobjectsize(i) ((i) & ~3) /** mask off two lowest bits: just keep all higher */

#define getusedobjectwantedbytes(i) ((i) & ~3)
#define getusedobjectwantedgintsnr(i) (((i) & ~3)>>((sizeof(gint)==4) ? 2 : 3)) /** divide pure size by four or eight */

#define makefreeobjectsize(i)  (((i) & ~3)|1) /** set lowest bits to 01: current object is free */
#define makeusedobjectsizeprevused(i) ((i) & ~3) /** set lowest bits to 00 */
#define makeusedobjectsizeprevfree(i) (((i) & ~3)|2) /** set lowest bits to 10 */
#define makespecialusedobjectsize(i) ((i)|3) /** set lowest bits to 11 */

#define SPECIALGINT1DV 1    /** second gint of a special in use dv area */
#define SPECIALGINT1START 0 /** second gint of a special in use start marker area, should be 0 */
#define SPECIALGINT1END 0 /** second gint of a special in use end marker area, should be 0 */

// #define setpfree(i)  ((i) | 2) /** set next lowest bit to 1: previous object is free ???? */

/* ===  data structures used in allocated areas  ===== */


/** general list cell: a pair of two integers (both can be also used as pointers) */

typedef struct {
  gint car;  /** first element */
  gint cdr;} /** second element, often a pointer to the rest of the list */
gcell;

#define car(cell)  (((gint)((gcell*)(cell)))->car)  /** get list cell first elem gint */
#define cdr(cell)  (((gint)((gcell*)(cell)))->cdr)  /** get list cell second elem gint */


/* index related stuff */
#define MAX_INDEX_FIELDS 10       /** maximum number of fields in one index */
#define MAX_INDEXED_FIELDNR 127   /** limits the size of field/index table */

#ifndef TTREE_CHAINED_NODES
#define WG_TNODE_ARRAY_SIZE 10
#else
#define WG_TNODE_ARRAY_SIZE 8
#endif

/* logging related */
#define maxnumberoflogrows 10

/* external database stuff */
#define MAX_EXTDB   20

/* ====== segment/area header data structures ======== */

/*
memory segment structure:

-------------
db_memsegment_header
- - - - - - -
db_area_header
-   -   -  -
db_subarea_header
...
db_subarea_header
- - - - - - -
...
- - - - - - -
db_area_header
-   -   -  -
db_subarea_header
...
db_subarea_header
----------------
various actual subareas
----------------
*/


/** located inside db_area_header: one single memory subarea header
*
*  alignedoffset should be always used: it may come some bytes after offset
*/

typedef struct _db_subarea_header {
  gint size; /** size of subarea */
  gint offset;          /** subarea exact offset from segment start: do not use for objects! */
  gint alignedsize;     /** subarea object alloc usable size: not necessarily to end of area */
  gint alignedoffset;   /** subarea start as to be used for object allocation */
} db_subarea_header;


/** located inside db_memsegment_header: one single memory area header
*
*/

typedef struct _db_area_header {
  gint fixedlength;        /** 1 if fixed length area, 0 if variable length */
  gint objlength;          /** only for fixedlength: length of allocatable obs in bytes */
  gint freelist;           /** freelist start: if 0, then no free objects available */
  gint last_subarea_index; /** last used subarea index (0,...,) */
  db_subarea_header subarea_array[SUBAREA_ARRAY_SIZE]; /** array of subarea headers */
  gint freebuckets[EXACTBUCKETS_NR+VARBUCKETS_NR+CACHEBUCKETS_NR]; /** array of subarea headers */
} db_area_header;

/** synchronization structures in shared memory
*
* Note that due to the similarity we can keep the memory images
* using the wpspin and rpspin protocols compatible.
*/

typedef struct {
#if !defined(LOCK_PROTO) || (LOCK_PROTO < 3) /* rpspin, wpspin */
  gint global_lock;        /** db offset to cache-aligned sync variable */
  gint writers;            /** db offset to cache-aligned writer count */
  char _storage[SYN_VAR_PADDING*3];  /** padded storage */
#else               /* tfqueue */
  gint tail;        /** db offset to last queue node */
  gint queue_lock;  /** db offset to cache-aligned sync variable */
  gint storage;     /** db offset to queue node storage */
  gint max_nodes;   /** number of cells in queue node storage */
  gint freelist;    /** db offset to the top of the allocation stack */
#endif
} syn_var_area;


/** hash area header
*
*/

typedef struct _db_hash_area_header {
  gint size;           /** size of subarea */
  gint offset;         /** subarea exact offset from segment start: do not use for array! */
  gint arraysize;      /** subarea object alloc usable size: not necessarily to end of area */
  gint arraystart;     /** subarea start as to be used for object allocation */
  gint arraylength;    /** nr of elements in the hash array */
} db_hash_area_header;

/**
 * T-tree specific index header fields
 */
struct __wg_ttree_header {
  gint offset_root_node;
#ifdef TTREE_CHAINED_NODES
  gint offset_max_node;     /** last node in chain */
  gint offset_min_node;     /** first node in chain */
#endif
};

/**
 * Hash-specific index header fields
 */
struct __wg_hashidx_header {
  db_hash_area_header hasharea;
};


/** control data for one index
*
*/
typedef struct {
  gint type;
  gint fields;                            /** number of fields in index */
  gint rec_field_index[MAX_INDEX_FIELDS]; /** field numbers for this index */
  union {
    struct __wg_ttree_header t;
    struct __wg_hashidx_header h;
  } ctl;                    /** shared fields for different index types */
  gint template_offset;     /** matchrec template, 0 if full index */
} wg_index_header;


/** index mask meta-info
*
*/
#ifdef USE_INDEX_TEMPLATE
typedef struct {
  gint fixed_columns;       /** number of fixed columns in the template */
  gint offset_matchrec;     /** offset to the record that stores the fields */
  gint refcount;            /** number of indexes using this template */
} wg_index_template;
#endif


/** highest level index management data
*  contains lookup table by field number and memory management data
*/
typedef struct {
  gint number_of_indexes;       /** unused, reserved */
  gint index_list;              /** master index list */
  gint index_table[MAX_INDEXED_FIELDNR+1];    /** index lookup by column */
#ifdef USE_INDEX_TEMPLATE
  gint index_template_list;     /** sorted list of index masks */
  gint index_template_table[MAX_INDEXED_FIELDNR+1]; /** masks indexed by column */
#endif
} db_index_area_header;


/** Registered external databases
*   Offsets of data in these databases are recognized properly
*   by the data store/retrieve/compare functions.
*/
typedef struct {
  gint count; /** number of records */
  gint offset[MAX_EXTDB];   /** offsets of external databases */
  gint size[MAX_EXTDB];     /** corresponding sizes of external databases */
} extdb_area;


/** logging management
*
*/
typedef struct {
  gint active;          /** logging mode on/off */
  gint dirty;           /** log file is clean/dirty */
  gint serial;          /** incremented when the log file is backed up */
} db_logging_area_header;


/** bitmap area header
*
*/

typedef struct {
  gint offset; /** actual start of bitmap as used */
  gint size; /** actual used size in bytes */  
} db_recptr_bitmap_header;

/** anonconst area header
*
*/

#ifdef USE_REASONER
typedef struct _db_anonconst_area_header {
  gint anonconst_nr;
  gint anonconst_funs;
  gint anonconst_table[ANONCONST_TABLE_SIZE];
} db_anonconst_area_header;
#endif

/** located at the very beginning of the memory segment
*
*/

typedef struct _db_memsegment_header {
  // core info about segment
  /****** fixed size part of the header. Do not edit this without
   * also editing the code that checks the header in dbmem.c
   */
  gint32 mark;       /** fixed uncommon int to check if really a segment */
  gint32 version;    /** db engine version to check dump file compatibility */
  gint32 features;   /** db engine compile-time features */
  gint32 checksum;   /** dump file checksum */
  /* end of fixed size header ******/
  gint size;       /** segment size in bytes  */
  gint free;       /** pointer to first free area in segment (aligned) */
  gint initialadr; /** initial segment address, only valid for creator */
  gint key;        /** global shared mem key */
  // areas
  db_area_header datarec_area_header;
  db_area_header longstr_area_header;
  db_area_header listcell_area_header;
  db_area_header shortstr_area_header;
  db_area_header word_area_header;
  db_area_header doubleword_area_header;
  // hash structures
  db_hash_area_header strhash_area_header;
  // index structures
  db_index_area_header index_control_area_header;
  db_area_header tnode_area_header;
  db_area_header indexhdr_area_header;
  db_area_header indextmpl_area_header;
  db_area_header indexhash_area_header;
  // logging structures
  db_logging_area_header logging;
  // recptr bitmap
  db_recptr_bitmap_header recptr_bitmap;
  // anonconst table
#ifdef USE_REASONER
  db_anonconst_area_header anonconst;
#endif
  // statistics
  // field/table name structures
  syn_var_area locks;   /** currently holds a single global lock */
  extdb_area extdbs;    /** offset ranges of external databases */
} db_memsegment_header;

#ifdef USE_DATABASE_HANDLE
/** Database handle in local memory. Contains the pointer to the
*  shared memory area.
*/
typedef struct {
  db_memsegment_header *db; /** shared memory header */
  void *logdata;            /** log data structure in local memory */
} db_handle;
#endif

/* ---------  anonconsts: special uris with attached funs ----------- */

#ifdef USE_REASONER

#define ACONST_FALSE_STR "false"
#define ACONST_FALSE encode_anonconst(0)
#define ACONST_TRUE_STR "true"
#define ACONST_TRUE encode_anonconst(1)
#define ACONST_IF_STR "if"
#define ACONST_IF encode_anonconst(2)
#define ACONST_NOT_STR "not"
#define ACONST_NOT encode_anonconst(3)
#define ACONST_AND_STR "and"
#define ACONST_AND encode_anonconst(4)
#define ACONST_OR_STR "or"
#define ACONST_OR encode_anonconst(5)
#define ACONST_IMPLIES_STR "implies"
#define ACONST_IMPLIES encode_anonconst(6)
#define ACONST_XOR_STR "xor"
#define ACONST_XOR encode_anonconst(7)

#define ACONST_LESS_STR "<"
#define ACONST_LESS encode_anonconst(8)
#define ACONST_EQUAL_STR "="
#define ACONST_EQUAL encode_anonconst(9)
#define ACONST_GREATER_STR ">"
#define ACONST_GREATER encode_anonconst(10)
#define ACONST_LESSOREQUAL_STR "<="
#define ACONST_LESSOREQUAL encode_anonconst(11)
#define ACONST_GREATEROREQUAL_STR ">="
#define ACONST_GREATEROREQUAL encode_anonconst(12)
#define ACONST_ISZERO_STR "zero"
#define ACONST_ISZERO encode_anonconst(13)
#define ACONST_ISEMPTYSTR_STR "strempty"
#define ACONST_ISEMPTYSTR encode_anonconst(14)
#define ACONST_PLUS_STR "+"
#define ACONST_PLUS encode_anonconst(15)
#define ACONST_MINUS_STR "!-"
#define ACONST_MINUS encode_anonconst(16)
#define ACONST_MULTIPLY_STR "*"
#define ACONST_MULTIPLY encode_anonconst(17)
#define ACONST_DIVIDE_STR "/"
#define ACONST_DIVIDE encode_anonconst(18)
#define ACONST_STRCONTAINS_STR "strcontains"
#define ACONST_STRCONTAINS encode_anonconst(19)
#define ACONST_STRCONTAINSICASE_STR "strcontainsicase"
#define ACONST_STRCONTAINSICASE encode_anonconst(20)
#define ACONST_SUBSTR_STR "substr"
#define ACONST_SUBSTR encode_anonconst(21)
#define ACONST_STRLEN_STR "strlen"
#define ACONST_STRLEN encode_anonconst(22)

#endif

/* ==== Protos ==== */

gint wg_init_db_memsegment(void* db, gint key, gint size); // creates initial memory structures for a new db

gint wg_alloc_fixlen_object(void* db, void* area_header);
gint wg_alloc_gints(void* db, void* area_header, gint nr);

void wg_free_listcell(void* db, gint offset);
void wg_free_shortstr(void* db, gint offset);
void wg_free_word(void* db, gint offset);
void wg_free_doubleword(void* db, gint offset);
void wg_free_tnode(void* db, gint offset);
void wg_free_fixlen_object(void* db, db_area_header *hdr, gint offset);

gint wg_freebuckets_index(void* db, gint size);
gint wg_free_object(void* db, void* area_header, gint object) ;

#if 0
void *wg_create_child_db(void* db, gint size);
#endif
gint wg_register_external_db(void *db, void *extdb);
gint wg_create_hash(void *db, db_hash_area_header* areah, gint size);

gint wg_database_freesize(void *db);
gint wg_database_size(void *db);

/* ------- testing ------------ */

#endif /* DEFINED_DBALLOC_H */

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

 /** @file dbmem.h
 * Public headers for database memory handling.
 */

#ifndef DEFINED_DBMEM_H
#define DEFINED_DBMEM_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

#define DEFAULT_MEMDBASE_KEY 1000
//#define DEFAULT_MEMDBASE_SIZE 1000000  // 1 meg
#define DEFAULT_MEMDBASE_SIZE 10000000  // 10 meg
//#define DEFAULT_MEMDBASE_SIZE 800000000  // 800 meg
//#define DEFAULT_MEMDBASE_SIZE 2000000000

#define MAX_FILENAME_SIZE 100

/* ====== data structures ======== */


/* ==== Protos ==== */

void* wg_attach_database(char* dbasename, gint size); // returns a pointer to the database, NULL if failure
void* wg_attach_existing_database(char* dbasename); // like wg_attach_database, but does not create a new base
void* wg_attach_logged_database(char* dbasename, gint size); // like wg_attach_database, but activates journal logging on creation
void* wg_attach_database_mode(char* dbasename, gint size, int mode);  // like wg_attach_database, set shared segment permissions to "mode"
void* wg_attach_logged_database_mode(char* dbasename, gint size, int mode); // like above, activate journal logging

void* wg_attach_memsegment(char* dbasename, gint minsize,
                            gint size, int create, int logging, int mode); // same as wg_attach_database, does not check contents
int wg_detach_database(void* dbase); // detaches a database: returns 0 if OK
int wg_delete_database(char* dbasename); // deletes a database: returns 0 if OK
int wg_check_header_compat(db_memsegment_header *dbh); // check memory image compatibility
void wg_print_code_version(void);  // show libwgdb version info
void wg_print_header_version(db_memsegment_header *dbh, int verbose); // show version info from header

void* wg_attach_local_database(gint size);
void wg_delete_local_database(void* dbase);

int wg_memmode(void *db);
int wg_memowner(void *db);
int wg_memgroup(void *db);

#endif /* DEFINED_DBMEM_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010
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

 /** @file dbfeatures.h
 * Constructs bit vector of libwgdb compile-time features
 */

#ifndef DEFINED_DBFEATURES_H
#define DEFINED_DBFEATURES_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

/* Used to check for individual features */
#define FEATURE_BITS_64BIT 0x1
#define FEATURE_BITS_QUEUED_LOCKS 0x2
#define FEATURE_BITS_TTREE_CHAINED 0x4
#define FEATURE_BITS_BACKLINK 0x8
#define FEATURE_BITS_CHILD_DB 0x10
#define FEATURE_BITS_INDEX_TMPL 0x20

/* Construct the bit vector */
#ifdef HAVE_64BIT_GINT
  #define FEATURE_BITS_01 FEATURE_BITS_64BIT
#else
  #define FEATURE_BITS_01 0x0
#endif

#if (LOCK_PROTO==3)
  #define FEATURE_BITS_02 FEATURE_BITS_QUEUED_LOCKS
#else
  #define FEATURE_BITS_02 0x0
#endif

#ifdef TTREE_CHAINED_NODES
  #define FEATURE_BITS_03 FEATURE_BITS_TTREE_CHAINED
#else
  #define FEATURE_BITS_03 0x0
#endif

#ifdef USE_BACKLINKING
  #define FEATURE_BITS_04 FEATURE_BITS_BACKLINK
#else
  #define FEATURE_BITS_04 0x0
#endif

#ifdef USE_CHILD_DB
  #define FEATURE_BITS_05 FEATURE_BITS_CHILD_DB
#else
  #define FEATURE_BITS_05 0x0
#endif

#ifdef USE_INDEX_TEMPLATE
  #define FEATURE_BITS_06 FEATURE_BITS_INDEX_TMPL
#else
  #define FEATURE_BITS_06 0x0
#endif

#define MEMSEGMENT_FEATURES (FEATURE_BITS_01 |\
  FEATURE_BITS_02 |\
  FEATURE_BITS_03 |\
  FEATURE_BITS_04 |\
  FEATURE_BITS_05 |\
  FEATURE_BITS_06)

#endif /* DEFINED_DBFEATURES_H */
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

 /** @file dbdata.h
 * Datatype encoding defs and public headers for actual data handling procedures.
 */

#ifndef DEFINED_DBDATA_H
#define DEFINED_DBDATA_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"

// ============= external funs defs ============

#ifndef _WIN32
extern double round(double);
#else
/* round as a macro (no libm equivalent for MSVC) */
#define round(x) ((double) floor((double) x + 0.5))
#endif

// ============= api part starts ================

/* ---  built-in data type numbers ----- */

/* the built-in data types are primarily for api purposes.
   internally, some of these types like int, str etc have several
   different ways to encode along with different bit masks
*/


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
#define WG_ANONCONSTTYPE 13  // not implemented yet
#define WG_VARTYPE 14        // not implemented yet

/* Illegal encoded data indicator */
#define WG_ILLEGAL 0xff

/* prototypes of wg database api functions

*/

typedef ptrdiff_t wg_int;
typedef size_t wg_uint; // used in time enc


/* -------- creating and scanning records --------- */

void* wg_create_record(void* db, wg_int length); ///< returns NULL when error, ptr to rec otherwise
void* wg_create_raw_record(void* db, wg_int length); ///< returns NULL when error, ptr to rec otherwise
wg_int wg_delete_record(void* db, void *rec);  ///< returns 0 on success, non-0 on error

void* wg_get_first_record(void* db);              ///< returns NULL when error or no recs
void* wg_get_next_record(void* db, void* record); ///< returns NULL when error or no more recs

void* wg_get_first_raw_record(void* db);
void* wg_get_next_raw_record(void* db, void* record);

void *wg_get_first_parent(void* db, void *record);
void *wg_get_next_parent(void* db, void* record, void *parent);

/* -------- setting and fetching record field values --------- */

wg_int wg_get_record_len(void* db, void* record); ///< returns negative int when error
wg_int* wg_get_record_dataarray(void* db, void* record); ///< pointer to record data array start

// following field setting functions return negative int when err, 0 when ok
wg_int wg_set_field(void* db, void* record, wg_int fieldnr, wg_int data);
wg_int wg_set_new_field(void* db, void* record, wg_int fieldnr, wg_int data);

wg_int wg_set_int_field(void* db, void* record, wg_int fieldnr, wg_int data);
wg_int wg_set_double_field(void* db, void* record, wg_int fieldnr, double data);
wg_int wg_set_str_field(void* db, void* record, wg_int fieldnr, char* data);

wg_int wg_update_atomic_field(void* db, void* record, wg_int fieldnr, wg_int data, wg_int old_data);
wg_int wg_set_atomic_field(void* db, void* record, wg_int fieldnr, wg_int data);
wg_int wg_add_int_atomic_field(void* db, void* record, wg_int fieldnr, int data);

wg_int wg_get_field(void* db, void* record, wg_int fieldnr);      // returns 0 when error
wg_int wg_get_field_type(void* db, void* record, wg_int fieldnr); // returns 0 when error


/* ---------- general operations on encoded data -------- */

wg_int wg_get_encoded_type(void* db, wg_int data);
char* wg_get_type_name(void* db, wg_int type);
wg_int wg_free_encoded(void* db, wg_int data);

/* -------- encoding and decoding data: records contain encoded data only ---------- */


// null

wg_int wg_encode_null(void* db, char* data);
char* wg_decode_null(void* db, wg_int data);

// int

wg_int wg_encode_int(void* db, wg_int data);
wg_int wg_decode_int(void* db, wg_int data);

// char

wg_int wg_encode_char(void* db, char data);
char wg_decode_char(void* db, wg_int data);


// double

wg_int wg_encode_double(void* db, double data);
double wg_decode_double(void* db, wg_int data);

// fixpoint

wg_int wg_encode_fixpoint(void* db, double data);
double wg_decode_fixpoint(void* db, wg_int data);

// date and time

wg_int wg_encode_date(void* db, int data);
int wg_decode_date(void* db, wg_int data);

wg_int wg_encode_time(void* db, int data);
int wg_decode_time(void* db, wg_int data);

int wg_current_utcdate(void* db);
int wg_current_localdate(void* db);
int wg_current_utctime(void* db);
int wg_current_localtime(void* db);

int wg_strf_iso_datetime(void* db, int date, int time, char* buf);
int wg_strp_iso_date(void* db, char* buf);
int wg_strp_iso_time(void* db, char* inbuf);

int wg_ymd_to_date(void* db, int yr, int mo, int day);
int wg_hms_to_time(void* db, int hr, int min, int sec, int prt);
void wg_date_to_ymd(void* db, int date, int *yr, int *mo, int *day);
void wg_time_to_hms(void* db, int time, int *hr, int *min, int *sec, int *prt);

//record

wg_int wg_encode_record(void* db, void* data);
void* wg_decode_record(void* db, wg_int data);

// str (standard C string: zero-terminated array of chars)
// along with optional attached language indicator str

wg_int wg_encode_str(void* db, char* str, char* lang); ///< let lang==NULL if not used

char* wg_decode_str(void* db, wg_int data);
char* wg_decode_str_lang(void* db, wg_int data);

wg_int wg_decode_str_len(void* db, wg_int data);
wg_int wg_decode_str_lang_len(void* db, wg_int data);
wg_int wg_decode_str_copy(void* db, wg_int data, char* strbuf, wg_int buflen);
wg_int wg_decode_str_lang_copy(void* db, wg_int data, char* langbuf, wg_int buflen);

// xmlliteral (standard C string: zero-terminated array of chars)
// along with obligatory attached xsd:type str

wg_int wg_encode_xmlliteral(void* db, char* str, char* xsdtype);

char* wg_decode_xmlliteral(void* db, wg_int data);
char* wg_decode_xmlliteral_xsdtype(void* db, wg_int data);

wg_int wg_decode_xmlliteral_len(void* db, wg_int data);
wg_int wg_decode_xmlliteral_xsdtype_len(void* db, wg_int data);
wg_int wg_decode_xmlliteral_copy(void* db, wg_int data, char* strbuf, wg_int buflen);
wg_int wg_decode_xmlliteral_xsdtype_copy(void* db, wg_int data, char* strbuf, wg_int buflen);

// uri (standard C string: zero-terminated array of chars)
// along with an optional prefix str


wg_int wg_encode_uri(void* db, char* str, char* prefix);

char* wg_decode_uri(void* db, wg_int data);
char* wg_decode_uri_prefix(void* db, wg_int data);

wg_int wg_decode_uri_len(void* db, wg_int data);
wg_int wg_decode_uri_prefix_len(void* db, wg_int data);
wg_int wg_decode_uri_copy(void* db, wg_int data, char* strbuf, wg_int buflen);
wg_int wg_decode_uri_prefix_copy(void* db, wg_int data, char* strbuf, wg_int buflen);



// blob (binary large object, i.e. any kind of data)
// along with an obligatory length in bytes

wg_int wg_encode_blob(void* db, char* str, char* type, wg_int len);

char* wg_decode_blob(void* db, wg_int data);
char* wg_decode_blob_type(void* db, wg_int data);

wg_int wg_decode_blob_len(void* db, wg_int data);
wg_int wg_decode_blob_copy(void* db, wg_int data, char* strbuf, wg_int buflen);
wg_int wg_decode_blob_type_len(void* db, wg_int data);
wg_int wg_decode_blob_type_copy(void* db, wg_int data, char* langbuf, wg_int buflen);

// anonconst

wg_int wg_encode_anonconst(void* db, char* str);
char* wg_decode_anonconst(void* db, wg_int data);

// var

wg_int wg_encode_var(void* db, wg_int varnr);
wg_int wg_decode_var(void* db, wg_int data);



// ================ api part ends ================

/* Record header structure. Position 0 is always reserved
 * for size.
 */
#define RECORD_HEADER_GINTS 3
#define RECORD_META_POS 1           /** metainfo, reserved for future use */
#define RECORD_BACKLINKS_POS 2      /** backlinks structure offset */

#define LITTLEENDIAN 1  ///< (intel is little-endian) difference in encoding tinystr
//#define USETINYSTR 1    ///< undef to prohibit usage of tinystr

/* Record meta bits. */
#define RECORD_META_NOTDATA 0x1 /** Record is a "special" record (not data) */
#define RECORD_META_MATCH 0x2   /** "match" record (needs NOTDATA as well) */
#define RECORD_META_DOC 0x10    /** schema bits: top-level document */
#define RECORD_META_OBJECT 0x20 /** schema bits: object */
#define RECORD_META_ARRAY 0x40  /** schema bits: array */

#define is_special_record(r) (*((gint *) r + RECORD_META_POS) &\
                            RECORD_META_NOTDATA)
#define is_plain_record(r) (*((gint *) r + RECORD_META_POS) == 0)
#define is_schema_array(r) (*((gint *) r + RECORD_META_POS) &\
                            RECORD_META_ARRAY)
#define is_schema_object(r) (*((gint *) r + RECORD_META_POS) &\
                            RECORD_META_OBJECT)
#define is_schema_document(r) (*((gint *) r + RECORD_META_POS) &\
                            RECORD_META_DOC)

// recognising gint types as gb types: bits, shifts, masks

/*
special value null (unassigned)         integer 0

Pointers to word-len ints end with            ?01  = not eq
Pointers to data records end with             000  = not eq
Pointers to long string records end with      100  = eq
Pointers to doubleword-len doubles end with   010  = not eq
Pointers to 32byte string records end with    110  = not eq


Immediate integers end with                   011  = is eq

(Other immediates                             111 (continued below))
Immediate vars end with                      0111  // not implemented yet
Immediate short fixpoints               0000 1111  = is eq
Immediate chars                         0001 1111  = is eq
Immediate dates                         0010 1111  = is eq
Immediate times                         0011 1111  = is eq
// Immediate tiny strings                  0100 1111  = is eq  // not used yet
Immediate anon constants                0101 1111  = is eq  // not implemented yet
*/


/* --- encoding and decoding basic data ---- */

#define SMALLINTBITS    0x3       ///< int ends with       011
#define SMALLINTSHFT  3
#define SMALLINTMASK  0x7

#define fits_smallint(i)   ((((i)<<SMALLINTSHFT)>>SMALLINTSHFT)==i)
#define encode_smallint(i) (((i)<<SMALLINTSHFT)|SMALLINTBITS)
#define decode_smallint(i) ((i)>>SMALLINTSHFT)

#define FULLINTBITS  0x1      ///< full int ptr ends with       01
#define FULLINTBITSV0  0x1    ///< full int type as 3-bit nr version 0:  001
#define FULLINTBITSV1  0x5    ///< full int type as 3-bit nr version 1:  101
#define FULLINTMASK  0x3

#define encode_fullint_offset(i) ((i)|FULLINTBITS)
#define decode_fullint_offset(i) ((i) & ~FULLINTMASK)

#define DATARECBITS  0x0      ///< datarec ptr ends with       000
#define DATARECMASK  0x7

#define encode_datarec_offset(i) (i)
#define decode_datarec_offset(i) (i)

#define LONGSTRBITS  0x4      ///< longstr ptr ends with       100
#define LONGSTRMASK  0x7

#define encode_longstr_offset(i) ((i)|LONGSTRBITS)
#define decode_longstr_offset(i) ((i) & ~LONGSTRMASK)

#define FULLDOUBLEBITS  0x2      ///< full double ptr ends with       010
#define FULLDOUBLEMASK  0x7

#define encode_fulldouble_offset(i) ((i)|FULLDOUBLEBITS)
#define decode_fulldouble_offset(i) ((i) & ~FULLDOUBLEMASK)

#define SHORTSTRBITS  0x6      ///< short str ptr ends with  110
#define SHORTSTRMASK  0x7

#define encode_shortstr_offset(i) ((i)|SHORTSTRBITS)
#define decode_shortstr_offset(i) ((i) & ~SHORTSTRMASK)

/* --- encoding and decoding other data ---- */

#define VARMASK  0xf
#define VARSHFT  4
#define VARBITS  0x7       ///< var ends with 0111

#define fits_var(i)   ((((i)<<VARSHFT)>>VARSHFT)==i)
#define encode_var(i) (((i)<<VARSHFT)|VARBITS)
#define decode_var(i) ((i)>>VARSHFT)

#define CHARMASK  0xff
#define CHARSHFT  8
#define CHARBITS  0x1f       ///< char ends with 0001 1111

#define encode_char(i) (((i)<<CHARSHFT)|CHARBITS)
#define decode_char(i) ((i)>>CHARSHFT)

#define DATEMASK  0xff
#define DATESHFT  8
#define DATEBITS  0x2f       ///< date ends with 0010 1111

#define MAXDATE  128*255*255
#define MINDATE  -128*255*255

#define fits_date(i)   (((i)<=MAXDATE) && ((i)>=MINDATE))
#define encode_date(i) (((i)<<DATESHFT)|DATEBITS)
#define decode_date(i) ((i)>>DATESHFT)

#define TIMEMASK  0xff
#define TIMESHFT  8
#define TIMEBITS  0x3f       ///< time ends with 0011 1111

#define MAXTIME  24*60*60*100
#define MINTIME  0

#define fits_time(i)   (((i)<=MAXTIME) && ((i)>=MINTIME))
#define encode_time(i) (((i)<<TIMESHFT)|TIMEBITS)
#define decode_time(i) ((int)(((unsigned int)(i))>>TIMESHFT))

#define FIXPOINTMASK  0xff
#define FIXPOINTSHFT  8
#define FIXPOINTBITS  0xf       ///< fixpoint ends with       0000 1111

#define MAXFIXPOINT  800
#define MINFIXPOINT  -800
#define FIXPOINTDIVISOR 10000.0

#define fits_fixpoint(i)   (((i)<=MAXFIXPOINT) && ((i)>=MINFIXPOINT))
#define encode_fixpoint(i) ((((int)(round((i)*(double)FIXPOINTDIVISOR)))<<FIXPOINTSHFT)|FIXPOINTBITS)
#define decode_fixpoint(i) ((double)((double)((i)>>FIXPOINTSHFT)/(double)FIXPOINTDIVISOR))

#define TINYSTRMASK  0xff
#define TINYSTRSHFT  8
#define TINYSTRBITS  0x4f       ///< tiny str ends with 0100 1111

#define ANONCONSTMASK  0xff
#define ANONCONSTSHFT  8
#define ANONCONSTBITS  0x5f       ///< anon const ends with 0101 1111

#define encode_anonconst(i) (((i)<<ANONCONSTSHFT)|ANONCONSTBITS)
#define decode_anonconst(i) ((i)>>ANONCONSTSHFT)

/* --- recognizing data ---- */

#define NORMALPTRMASK 0x7  ///< all pointers except fullint
#define NONPTRBITS 0x3
#define LASTFOURBITSMASK 0xf
#define PRELASTFOURBITSMASK 0xf0
#define LASTBYTEMASK 0xff

#define isptr(i)        ((i) && (((i)&NONPTRBITS)!=NONPTRBITS))

#define isdatarec(i)    (((i)&DATARECMASK)==DATARECBITS)
#define isfullint(i)    (((i)&FULLINTMASK)==FULLINTBITS)
#define isfulldouble(i) (((i)&FULLDOUBLEMASK)==FULLDOUBLEBITS)
#define isshortstr(i)   (((i)&SHORTSTRMASK)==SHORTSTRBITS)
#define islongstr(i)    (((i)&LONGSTRMASK)==LONGSTRBITS)

#define issmallint(i)   (((i)&SMALLINTMASK)==SMALLINTBITS)

#define isvar(i)   (((i)&VARMASK)==VARBITS)
#define ischar(i)   (((i)&CHARMASK)==CHARBITS)
#define isfixpoint(i)   (((i)&FIXPOINTMASK)==FIXPOINTBITS)
#define isdate(i)   (((i)&DATEMASK)==DATEBITS)
#define istime(i)   (((i)&TIMEMASK)==TIMEBITS)
#define istinystr(i)   (((i)&TINYSTRMASK)==TINYSTRBITS)
#define isanonconst(i)   (((i)&ANONCONSTMASK)==ANONCONSTBITS)

#define isimmediatedata(i) ((i)==0 || (!isptr(i) && !isfullint(i)))

/* ------ metainfo and special data items --------- */

#define datarec_size_bytes(i) (getusedobjectwantedbytes(i))
#define datarec_end_ptr(i)


/* --------- record and longstr data object structure ---------- */


/* record data object

gint usage from start:

0:  encodes length in bytes. length is aligned to sizeof gint
1:  pointer to next sibling
2:  pointer to prev sibling or parent
3:  data gints
...



---- conventional database rec ----------

car1:
id: 10
model: ford
licenceplate: 123LGH
owner: 20 (we will have ptr to rec 20)

car2:
id: 11
model: opel
licenceplate: 456RMH
owner: 20 (we will have ptr to rec 20)

person1:
parents: list of pointers to person1?
id: 20
fname: John
lname: Brown


---- xml node -------

<person fname="john" lname="brown">
  <owns>
    <car model="ford">
  </owns>
  <owns>
    <car model="opel">
  </owns>
</person>

xml-corresponding rdf triplets

_10 model ford
_10 licenceplate 123LGH

_11 model opel
_11 licenceplate 456RMH

_20 fname john
_20 lname brown
_20 owns _10
_20 owns _11


(?x fname john) & (?x lname brown) & (?x owns ?y) & (?y model ford) => answer(?y)

solution:

- locate from value index brown
- instantiate ?x with _20
- scan _20 value occurrences with pred lname to find john
- scan _20 subject occurrences with pred owns to find _10
- scan _10 subject occurrences with pred model to find ford

----normal rdf triplets -----

_10 model ford
_10 licenceplate 123LGH
_10 owner _20

_11 model opel
_11 licenceplate 456RMH
_11 owner _20

_20 fname john
_20 lname brown


(?x fname john) & (?x lname brown) & (?y owner ?x) & (?y model ford) => answer(?y)

solution:

- locate from value index brown
- instantiate ?x with _20
- scan _20 value occurrences with pred lname to find john
- scan _20 value occurrences with pred owner to find _10
- scan _10 subject occurrences with pred model to find ford

--------- fromptr structure -------


fld 1 pts to either directly (single) occurrence or rec of occurrences:

single occ case:

- last bit zero indicates direct ptr to rec
- two previous bits indicate position in rec (0-3)

multiple (or far pos) case:

- last bit 1 indicates special pos list array ptr:

pos array:

recsize
position fld nr,
ptr to (single) rec or to corresp list of recs
position fld nr,
ptr to (single) rec or to corresp list o recs
...

where corresp list is made of pairs (list cells):

ptr to rec
ptr to next list cell

alternative:

ptr to rec
ptr to rec
ptr to rec
ptr to rec
ptr to next block


*/

/* record data object

gint usage from start:

0: encodes data obj length in bytes. length is aligned to sizeof gint
1: metainfo, incl object type:
   - last byte object type
   - top-level/dependent bit
   - original/derived bit
2: backlinks
3: actual gints ....
...


*/



/* longstr/xmlliteral/uri/blob data object

gint usage from start:

0:  encodes data obj length in bytes. length is aligned to sizeof gint
1:  metainfo, incl object type (longstr/xmlliteral/uri/blob/datarec etc):
    - last byte object type
    - byte before last: nr to delete from obj length to get real actual-bytes length
2:  refcount
3:  backlinks
4:  pointer to next longstr in the hash bucket, 0 if no following
5:  lang/xsdtype/namespace str (offset):  if 0 not present
6:  actual bytes ....
...


*/


#define LONGSTR_HEADER_GINTS 6 /** including obj length gint */

#define LONGSTR_META_POS 1 /** metainfo, incl object type (longstr/xmlliteral/uri/blob/datarec etc)
   last byte (low 0) object type (WG_STRTYPE,WG_XMLLITERALTYPE, etc)
   byte before last (low 1):
         lendif: nr to delete from obj length to get real actual-bytes length of str
   low 2: unused
   low 3: unused
  */
#define LONGSTR_META_LENDIFMASK 0xFF00 /** second lowest bytes contains lendif*/
#define LONGSTR_META_LENDIFSHFT 8 /** shift 8 bits right to get lendif */
#define LONGSTR_META_TYPEMASK  0xFF /*** lowest byte contains actual subtype: str,uri,xmllliteral */
#define LONGSTR_REFCOUNT_POS 2 /**  reference count, if 0, delete*/
#define LONGSTR_BACKLINKS_POS 3 /**   backlinks structure offset */
#define LONGSTR_HASHCHAIN_POS 4 /**  offset of next longstr in the hash bucket, 0 if no following */
#define LONGSTR_EXTRASTR_POS 5 /**  lang/xsdtype/namespace str (encoded offset):  if 0 not present */


/* --------- error handling ------------ */

#define recordcheck(db,record,fieldnr,opname) { \
  if (!dbcheck(db)) {\
    show_data_error_str(db,"wrong database pointer given to ",opname);\
    return -1;\
  }\
  if (fieldnr<0 || getusedobjectwantedgintsnr(*((gint*)record))<=fieldnr+RECORD_HEADER_GINTS) {\
    show_data_error_str(db,"wrong field number given to ",opname);\
    return -2;\
  }\
}


/* ==== Protos ==== */

//void free_field_data(void* db,gint fielddata, gint fromrecoffset, gint fromrecfield);

gint wg_encode_unistr(void* db, char* str, char* lang, gint type); ///< let lang==NULL if not used
gint wg_encode_uniblob(void* db, char* str, char* lang, gint type, gint len);

char* wg_decode_unistr(void* db, wg_int data, gint type);
char* wg_decode_unistr_lang(void* db, wg_int data, gint type);

gint wg_decode_unistr_len(void* db, wg_int data, gint type);
gint wg_decode_unistr_lang_len(void* db, wg_int data, gint type);
gint wg_decode_unistr_copy(void* db, wg_int data, char* strbuf, wg_int buflen, gint type);
gint wg_decode_unistr_lang_copy(void* db, wg_int data, char* langbuf, wg_int buflen, gint type);

gint wg_encode_external_data(void *db, void *extdb, gint encoded);
#ifdef USE_CHILD_DB
gint wg_translate_hdroffset(void *db, void *exthdr, gint encoded);
void *wg_get_rec_owner(void *db, void *rec);
#endif
#ifdef USE_RECPTR_BITMAP
gint wg_recptr_check(void *db,void *ptr);
#endif

#endif /* DEFINED_DBDATA_H */
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

 /** @file dblog.h
 * Public headers for the recovery journal.
 */

#ifndef DEFINED_DBLOG_H
#define DEFINED_DBLOG_H

#ifndef _WIN32
#define WG_JOURNAL_FILENAME DBLOG_DIR "/wgdb.journal"
#else
#define WG_JOURNAL_FILENAME DBLOG_DIR "\\wgdb_journal"
#endif
#define WG_JOURNAL_FN_BUFSIZE (sizeof(WG_JOURNAL_FILENAME) + 20)
#define WG_JOURNAL_MAX_BACKUPS 10
#define WG_JOURNAL_MAGIC "wgdb"
#define WG_JOURNAL_MAGIC_BYTES 4

#define WG_JOURNAL_ENTRY_ENC ((unsigned char) 0) /* top bits clear |= type */
#define WG_JOURNAL_ENTRY_CRE ((unsigned char) 0x40)
#define WG_JOURNAL_ENTRY_DEL ((unsigned char) 0x80)
#define WG_JOURNAL_ENTRY_SET ((unsigned char) 0xc0)
#define WG_JOURNAL_ENTRY_META ((unsigned char) 0x20)
#define WG_JOURNAL_ENTRY_CMDMASK (0xe0)
#define WG_JOURNAL_ENTRY_TYPEMASK (0x1f)


/* ====== data structures ======== */

typedef struct {
  FILE *f;
  int fd;
  gint serial;
  int umask;
} db_handle_logdata;

/* ==== Protos ==== */

gint wg_init_handle_logdata(void *db);
void wg_cleanup_handle_logdata(void *db);
int wg_log_umask(void *db, int cmask);

void wg_journal_filename(void *db, char *buf, size_t buflen);
gint wg_start_logging(void *db);
gint wg_stop_logging(void *db);
gint wg_replay_log(void *db, char *filename);

gint wg_log_create_record(void *db, gint length);
gint wg_log_delete_record(void *db, gint enc);
gint wg_log_encval(void *db, gint enc);
gint wg_log_encode(void *db, gint type, void *data, gint length,
  void *extdata, gint extlength);
gint wg_log_set_field(void *db, void *rec, gint col, gint data);
gint wg_log_set_meta(void *db, void *rec, gint meta);

#endif /* DEFINED_DBLOG_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Andri Rebane 2009
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

 /** @file dbdump.h
 * Public headers for memory dumping to the disk.
 */

#ifndef DEFINED_DBDUMP_H
#define DEFINED_DBDUMP_H
#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

/* ====== data structures ======== */


/* ==== Protos ==== */

gint wg_dump(void * db,char fileName[]); /* dump shared memory database to the disk */
gint wg_dump_internal(void * db,char fileName[], int locking); /* handle the dump */
gint wg_import_dump(void * db,char fileName[]); /* import database from the disk */
gint wg_check_dump(void *db, char fileName[],
  gint *mixsize, gint *maxsize); /* check the dump file and get the db size */

#endif /* DEFINED_DBDUMP_H */
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

 /** @file dbhash.h
 * Public headers for hash-related procedures.
 */

#ifndef DEFINED_DBHASH_H
#define DEFINED_DBHASH_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif
//alloc.h"

/* ==== Public macros ==== */

#define HASHIDX_META_POS        1
#define HASHIDX_RECLIST_POS     2
#define HASHIDX_HASHCHAIN_POS   3
#define HASHIDX_HEADER_SIZE     4

/* ==== Protos ==== */

int wg_hash_typedstr(void* db, char* data, char* extrastr, gint type, gint length);
gint wg_find_strhash_bucket(void* db, char* data, char* extrastr, gint type, gint size, gint hashchain);
int wg_right_strhash_bucket
            (void* db, gint longstr, char* cstr, char* cextrastr, gint ctype, gint cstrsize);
gint wg_remove_from_strhash(void* db, gint longstr);

gint wg_decode_for_hashing(void *db, gint enc, char **decbytes);
gint wg_idxhash_store(void* db, db_hash_area_header *ha,
  char* data, gint length, gint offset);
gint wg_idxhash_remove(void* db, db_hash_area_header *ha,
  char* data, gint length, gint offset);
gint wg_idxhash_find(void* db, db_hash_area_header *ha,
  char* data, gint length);

void *wg_ginthash_init(void *db);
gint wg_ginthash_addkey(void *db, void *tbl, gint key, gint val);
gint wg_ginthash_getkey(void *db, void *tbl, gint key, gint *val);
void wg_ginthash_free(void *db, void *tbl);

void *wg_dhash_init(void *db, size_t entries);
void wg_dhash_free(void *db, void *tbl);
gint wg_dhash_addkey(void *db, void *tbl, gint key);
gint wg_dhash_haskey(void *db, void *tbl, gint key);

#endif /* DEFINED_DBHASH_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Enar Reilent 2009, Priit Järv 2010,2011,2013
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

 /** @file dblock.h
 * Public headers for indexing routines
 */

#ifndef DEFINED_DBINDEX_H
#define DEFINED_DBINDEX_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

/* For gint data type */
//data.h"

/* ==== Public macros ==== */

#define REALLY_BOUNDING_NODE 0
#define DEAD_END_LEFT_NOT_BOUNDING 1
#define DEAD_END_RIGHT_NOT_BOUNDING 2

#ifdef TTREE_CHAINED_NODES
#define TNODE_SUCCESSOR(d, x) (x->succ_offset)
#define TNODE_PREDECESSOR(d, x) (x->pred_offset)
#else
#define TNODE_SUCCESSOR(d, x) (x->right_child_offset ? \
                    wg_ttree_find_lub_node(d, x->right_child_offset) : \
                    wg_ttree_find_leaf_successor(d, ptrtooffset(d, x)))
#define TNODE_PREDECESSOR(d, x) (x->left_child_offset ? \
                    wg_ttree_find_glb_node(d, x->left_child_offset) : \
                    wg_ttree_find_leaf_predecessor(d, ptrtooffset(d, x)))
#endif

/* Check if record matches index (takes pointer arguments) */
#ifndef USE_INDEX_TEMPLATE
#define MATCH_TEMPLATE(d, h, r) 1
#else
#define MATCH_TEMPLATE(d, h, r) (h->template_offset ? \
        wg_match_template(d, \
        (wg_index_template *) offsettoptr(d, h->template_offset), r) : 1)
#endif

#define WG_INDEX_TYPE_TTREE         50
#define WG_INDEX_TYPE_TTREE_JSON    51
#define WG_INDEX_TYPE_HASH          60
#define WG_INDEX_TYPE_HASH_JSON     61

/* Index header helpers */
#define TTREE_ROOT_NODE(x) (x->ctl.t.offset_root_node)
#ifdef TTREE_CHAINED_NODES
#define TTREE_MIN_NODE(x) (x->ctl.t.offset_min_node)
#define TTREE_MAX_NODE(x) (x->ctl.t.offset_max_node)
#endif
#define HASHIDX_ARRAYP(x) (&(x->ctl.h.hasharea))

/* ====== data structures ======== */

/** structure of t-node
*   (array of data pointers, pointers to parent/children nodes, control data)
*   overall size is currently 64 bytes (cache line?) if array size is 10,
*   with extra node chaining pointers the array size defaults to 8.
*/
struct wg_tnode{
  gint parent_offset;
  gint current_max;     /** encoded value */
  gint current_min;     /** encoded value */
  short number_of_elements;
  unsigned char left_subtree_height;
  unsigned char right_subtree_height;
  gint array_of_values[WG_TNODE_ARRAY_SIZE];
  gint left_child_offset;
  gint right_child_offset;
#ifdef TTREE_CHAINED_NODES
  gint succ_offset;     /** forward (smaller to larger) sequential chain */
  gint pred_offset;     /** backward sequential chain */
#endif
};

/* ==== Protos ==== */

/* API functions (copied in indexapi.h) */

gint wg_create_index(void *db, gint column, gint type,
  gint *matchrec, gint reclen);
gint wg_create_multi_index(void *db, gint *columns, gint col_count,
  gint type, gint *matchrec, gint reclen);
gint wg_drop_index(void *db, gint index_id);
gint wg_column_to_index_id(void *db, gint column, gint type,
  gint *matchrec, gint reclen);
gint wg_multi_column_to_index_id(void *db, gint *columns, gint col_count,
  gint type, gint *matchrec, gint reclen);
gint wg_get_index_type(void *db, gint index_id);
void * wg_get_index_template(void *db, gint index_id, gint *reclen);
void * wg_get_all_indexes(void *db, gint *count);

/* WhiteDB internal functions */

gint wg_search_ttree_index(void *db, gint index_id, gint key);

#ifndef TTREE_CHAINED_NODES
gint wg_ttree_find_glb_node(void *db, gint nodeoffset);
gint wg_ttree_find_lub_node(void *db, gint nodeoffset);
gint wg_ttree_find_leaf_predecessor(void *db, gint nodeoffset);
gint wg_ttree_find_leaf_successor(void *db, gint nodeoffset);
#endif
gint wg_search_ttree_rightmost(void *db, gint rootoffset,
  gint key, gint *result, struct wg_tnode *rb_node);
gint wg_search_ttree_leftmost(void *db, gint rootoffset,
  gint key, gint *result, struct wg_tnode *lb_node);
gint wg_search_tnode_first(void *db, gint nodeoffset, gint key,
  gint column);
gint wg_search_tnode_last(void *db, gint nodeoffset, gint key,
  gint column);

gint wg_search_hash(void *db, gint index_id, gint *values, gint count);

#ifdef USE_INDEX_TEMPLATE
gint wg_match_template(void *db, wg_index_template *tmpl, void *rec);
#endif

gint wg_index_add_field(void *db, void *rec, gint column);
gint wg_index_add_rec(void *db, void *rec);
gint wg_index_del_field(void *db, void *rec, gint column);
gint wg_index_del_rec(void *db, void *rec);


#endif /* DEFINED_DBINDEX_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010
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

 /** @file dbcompare.h
 * Public headers for data comparison functions.
 */

#ifndef DEFINED_DBCOMPARE_H
#define DEFINED_DBCOMPARE_H
#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

/* For gint data type */
//data.h"

/* ==== Public macros ==== */

#define WG_EQUAL 0
#define WG_GREATER 1
#define WG_LESSTHAN -1

/* If backlinking is enabled, records can be compared by their
 * contents instead of just pointers. With no backlinking this
 * is disabled so that records' comparative values do not change
 * when updating their contents.
 */
#ifdef USE_BACKLINKING
#define WG_COMPARE_REC_DEPTH 7 /** recursion depth for record comparison */
#else
#define WG_COMPARE_REC_DEPTH 0
#endif

/* wrapper macro for wg_compare(), if encoded values are
 * equal they will also decode to an equal value and so
 * we can avoid calling the function.
 */
#define WG_COMPARE(d,a,b) (a==b ? WG_EQUAL :\
  wg_compare(d,a,b,WG_COMPARE_REC_DEPTH))

/* ==== Protos ==== */

gint wg_compare(void *db, gint a, gint b, int depth);

#endif /* DEFINED_DBCOMPARE_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010,2011,2013
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

 /** @file dbcompare.h
 * Public headers for WhiteDB query engine.
 */

#ifndef DEFINED_DBQUERY_H
#define DEFINED_DBQUERY_H
#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

//data.h"
//index.h"

/* ==== Public macros ==== */

#define WG_COND_EQUAL       0x0001      /** = */
#define WG_COND_NOT_EQUAL   0x0002      /** != */
#define WG_COND_LESSTHAN    0x0004      /** < */
#define WG_COND_GREATER     0x0008      /** > */
#define WG_COND_LTEQUAL     0x0010      /** <= */
#define WG_COND_GTEQUAL     0x0020      /** >= */

#define WG_QTYPE_TTREE      0x01
#define WG_QTYPE_HASH       0x02
#define WG_QTYPE_SCAN       0x04
#define WG_QTYPE_PREFETCH   0x80

/* ====== data structures ======== */

/** Query argument list object */
typedef struct {
  gint column;      /** column (field) number this argument applies to */
  gint cond;        /** condition (equal, less than, etc) */
  gint value;       /** encoded value */
} wg_query_arg;

typedef struct {
  gint key;         /** encoded key */
  gint value;       /** encoded value */
} wg_json_query_arg;

/** Query object */
typedef struct {
  gint qtype;           /** Query type (T-tree, hash, full scan, prefetch) */
  /* Argument list based query is the only one supported at the moment. */
  wg_query_arg *arglist;    /** check each row in result set against these */
  gint argc;                /** number of elements in arglist */
  gint column;              /** index on this column used */
  /* Fields for T-tree query (XXX: some may be re-usable for
   * other types as well) */
  gint curr_offset;
  gint end_offset;
  gint curr_slot;
  gint end_slot;
  gint direction;
  /* Fields for full scan */
  gint curr_record;         /** offset of the current record */
  /* Fields for prefetch */
  void *mpool;              /** storage for row offsets */
  void *curr_page;          /** current page of results */
  gint curr_pidx;           /** current index on page */
  wg_uint res_count;          /** number of rows in results */
} wg_query;

/* ==== Protos ==== */

wg_query *wg_make_query(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc);
#define wg_make_prefetch_query wg_make_query
wg_query *wg_make_query_rc(void *db, void *matchrec, gint reclen,
  wg_query_arg *arglist, gint argc, wg_uint rowlimit);
wg_query *wg_make_json_query(void *db, wg_json_query_arg *arglist, gint argc);
void *wg_fetch(void *db, wg_query *query);
void wg_free_query(void *db, wg_query *query);

gint wg_encode_query_param_null(void *db, char *data);
gint wg_encode_query_param_record(void *db, void *data);
gint wg_encode_query_param_char(void *db, char data);
gint wg_encode_query_param_fixpoint(void *db, double data);
gint wg_encode_query_param_date(void *db, int data);
gint wg_encode_query_param_time(void *db, int data);
gint wg_encode_query_param_var(void *db, gint data);
gint wg_encode_query_param_int(void *db, gint data);
gint wg_encode_query_param_double(void *db, double data);
gint wg_encode_query_param_str(void *db, char *data, char *lang);
gint wg_encode_query_param_xmlliteral(void *db, char *data, char *xsdtype);
gint wg_encode_query_param_uri(void *db, char *data, char *prefix);
gint wg_free_query_param(void* db, gint data);

void *wg_find_record(void *db, gint fieldnr, gint cond, gint data,
    void* lastrecord);
void *wg_find_record_null(void *db, gint fieldnr, gint cond, char *data,
    void* lastrecord);
void *wg_find_record_record(void *db, gint fieldnr, gint cond, void *data,
    void* lastrecord);
void *wg_find_record_char(void *db, gint fieldnr, gint cond, char data,
    void* lastrecord);
void *wg_find_record_fixpoint(void *db, gint fieldnr, gint cond, double data,
    void* lastrecord);
void *wg_find_record_date(void *db, gint fieldnr, gint cond, int data,
    void* lastrecord);
void *wg_find_record_time(void *db, gint fieldnr, gint cond, int data,
    void* lastrecord);
void *wg_find_record_var(void *db, gint fieldnr, gint cond, gint data,
    void* lastrecord);
void *wg_find_record_int(void *db, gint fieldnr, gint cond, int data,
    void* lastrecord);
void *wg_find_record_double(void *db, gint fieldnr, gint cond, double data,
    void* lastrecord);
void *wg_find_record_str(void *db, gint fieldnr, gint cond, char *data,
    void* lastrecord);
void *wg_find_record_xmlliteral(void *db, gint fieldnr, gint cond, char *data,
    char *xsdtype, void* lastrecord);
void *wg_find_record_uri(void *db, gint fieldnr, gint cond, char *data,
    char *prefix, void* lastrecord);

#endif /* DEFINED_DBQUERY_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2010
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

 /** @file dbutil.h
 * Public headers for miscellaneous functions.
 */

#ifndef DEFINED_DBUTIL_H
#define DEFINED_DBUTIL_H

#ifdef HAVE_RAPTOR
#include <raptor.h>
#endif

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

/* ====== data structures ======== */

#ifdef HAVE_RAPTOR
struct wg_triple_handler_params {
  void *db;
  int pref_fields;  /** number of fields preceeding the triple */
  int suff_fields;  /** number of fields to reserve at the end */
  gint (*callback) (void *, void *);    /** function called after
                                         *the triple is stored */
  raptor_parser *rdf_parser;            /** parser object */
  int count;                            /** return status: rows parsed */
  int error;                            /** return status: error level */
};
#endif

/* ==== Protos ==== */

/* API functions (copied in dbapi.h) */
void wg_print_db(void *db);
void wg_print_record(void *db, gint* rec);
void wg_snprint_value(void *db, gint enc, char *buf, int buflen);
gint wg_parse_and_encode(void *db, char *buf);
gint wg_parse_and_encode_param(void *db, char *buf);
void wg_export_db_csv(void *db, char *filename);
gint wg_import_db_csv(void *db, char *filename);

/* Separate raptor API (copied in rdfapi.h) */
#ifdef HAVE_RAPTOR
gint wg_import_raptor_file(void *db, gint pref_fields, gint suff_fields,
  gint (*callback) (void *, void *), char *filename);
gint wg_import_raptor_rdfxml_file(void *db, gint pref_fields, gint suff_fields,
  gint (*callback) (void *, void *), char *filename);
gint wg_rdfparse_default_callback(void *db, void *rec);
gint wg_export_raptor_file(void *db, gint pref_fields, char *filename,
  char *serializer);
gint wg_export_raptor_rdfxml_file(void *db, gint pref_fields, char *filename);
#endif

void wg_pretty_print_memsize(gint memsz, char *buf, size_t buflen);

#endif /* DEFINED_DBUTIL_H */
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

 /** @file dbmpool.h
 * Public headers for memory pool utilities.
 */

#ifndef DEFINED_DBMPOOL_H
#define DEFINED_DBMPOOL_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif


/* ====== data structures ======== */


/* ==== Protos ==== */

void* wg_create_mpool(void* db, int bytes);             // call this to init pool with initial size bytes
void* wg_alloc_mpool(void* db, void* mpool, int bytes); // call each time you want to "malloc":
                                                        // automatically extends pool if no space left
void wg_free_mpool(void* db, void* mpool);              // remove the whole pool

int wg_ispair(void* db, void* ptr);
void* wg_mkpair(void* db, void* mpool, void* x, void* y);
void* wg_first(void* db, void* ptr);
void* wg_rest(void* db, void *ptr);

int wg_listtreecount(void* db, void *ptr);

int wg_isatom(void* db, void* ptr);
void* wg_mkatom(void* db, void* mpool, int type, char* str1, char* str2);
int wg_atomtype(void* db, void* ptr);
char* wg_atomstr1(void* db, void* ptr);
char* wg_atomstr2(void* db, void* ptr);

void wg_mpool_print(void* db, void* ptr);


#endif /* DEFINED_DBMPOOL_H */
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

 /** @file dbjson.h
 * Public headers for JSON I/O.
 */

#ifndef DEFINED_DBJSON_H
#define DEFINED_DBJSON_H


/* ====== data structures ======== */


/* ==== Protos ==== */

gint wg_parse_json_file(void *db, char *filename);
gint wg_check_json(void *db, char *buf);
gint wg_parse_json_document(void *db, char *buf, void **document);
gint wg_parse_json_fragment(void *db, char *buf, void **document);
gint wg_parse_json_param(void *db, char *buf, void **document);
void wg_print_json_document(void *db, void *cb, void *cb_ctx, void *document);

#endif /* DEFINED_DBJSON_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2009, 2013, 2014
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

 /** @file dblock.h
 * Public headers for concurrent access routines.
 */

#ifndef DEFINED_DBLOCK_H
#define DEFINED_DBLOCK_H

#ifdef _WIN32
///config-w32.h"
#else
///config.h"
#endif

/* ==== Public macros ==== */

/* XXX: move to configure.in / config-xxx.h */
#define USE_LOCK_TIMEOUT 1
#define DEFAULT_LOCK_TIMEOUT 2000 /* in ms */

/* Lock protocol */
#define RPSPIN 1
#define WPSPIN 2
#define TFQUEUE 3

/* ====== data structures ======== */

#if (LOCK_PROTO==TFQUEUE)

/* Queue nodes are stored locally in allocated cells.
 * The size of this structure can never exceed SYN_VAR_PADDING
 * defined in dballoc.h.
 */
typedef struct {
  /* XXX: do we need separate links for stack? Or even, does
   * it break correctness? */
  gint next_cell; /* freelist chain (db offset) */

  gint class; /* LOCKQ_READ, LOCKQ_WRITE */
  volatile gint waiting;  /* sync variable */
  volatile gint next; /* queue chain (db offset) */
  volatile gint prev; /* queue chain */
} lock_queue_node;

#endif

/* ==== Protos ==== */

/* API functions (copied in dbapi.h) */

gint wg_start_write(void * dbase);          /* start write transaction */
gint wg_end_write(void * dbase, gint lock); /* end write transaction */
gint wg_start_read(void * dbase);           /* start read transaction */
gint wg_end_read(void * dbase, gint lock);  /* end read transaction */

/* WhiteDB internal functions */

gint wg_compare_and_swap(volatile gint *ptr, gint oldv, gint newv);
gint wg_init_locks(void * db); /* (re-) initialize locking subsystem */

#if (LOCK_PROTO==RPSPIN)

#ifdef USE_LOCK_TIMEOUT
gint db_rpspin_wlock(void * dbase, gint timeout);
#define db_wlock(d, t) db_rpspin_wlock(d, t)
#else
gint db_rpspin_wlock(void * dbase);             /* get DB level X lock */
#define db_wlock(d, t) db_rpspin_wlock(d)
#endif
gint db_rpspin_wulock(void * dbase);            /* release DB level X lock */
#define db_wulock(d, l) db_rpspin_wulock(d)
#ifdef USE_LOCK_TIMEOUT
gint db_rpspin_rlock(void * dbase, gint timeout);
#define db_rlock(d, t) db_rpspin_rlock(d, t)
#else
gint db_rpspin_rlock(void * dbase);             /* get DB level S lock */
#define db_rlock(d, t) db_rpspin_rlock(d)
#endif
gint db_rpspin_rulock(void * dbase);            /* release DB level S lock */
#define db_rulock(d, l) db_rpspin_rulock(d)

#elif (LOCK_PROTO==WPSPIN)

#ifdef USE_LOCK_TIMEOUT
gint db_wpspin_wlock(void * dbase, gint timeout);
#define db_wlock(d, t) db_wpspin_wlock(d, t)
#else
gint db_wpspin_wlock(void * dbase);             /* get DB level X lock */
#define db_wlock(d, t) db_wpspin_wlock(d)
#endif
gint db_wpspin_wulock(void * dbase);            /* release DB level X lock */
#define db_wulock(d, l) db_wpspin_wulock(d)
#ifdef USE_LOCK_TIMEOUT
gint db_wpspin_rlock(void * dbase, gint timeout);
#define db_rlock(d, t) db_wpspin_rlock(d, t)
#else
gint db_wpspin_rlock(void * dbase);             /* get DB level S lock */
#define db_rlock(d, t) db_wpspin_rlock(d)
#endif
gint db_wpspin_rulock(void * dbase);            /* release DB level S lock */
#define db_rulock(d, l) db_wpspin_rulock(d)

#elif (LOCK_PROTO==TFQUEUE)

#ifdef USE_LOCK_TIMEOUT
gint db_tfqueue_wlock(void * dbase, gint timeout);
#define db_wlock(d, t) db_tfqueue_wlock(d, t)
#else
gint db_tfqueue_wlock(void * dbase);             /* get DB level X lock */
#define db_wlock(d, t) db_tfqueue_wlock(d)
#endif
gint db_tfqueue_wulock(void * dbase, gint lock); /* release DB level X lock */
#define db_wulock(d, l) db_tfqueue_wulock(d, l)
#ifdef USE_LOCK_TIMEOUT
gint db_tfqueue_rlock(void * dbase, gint timeout);
#define db_rlock(d, t) db_tfqueue_rlock(d, t)
#else
gint db_tfqueue_rlock(void * dbase);             /* get DB level S lock */
#define db_rlock(d, t) db_tfqueue_rlock(d)
#endif
gint db_tfqueue_rulock(void * dbase, gint lock); /* release DB level S lock */
#define db_rulock(d, l) db_tfqueue_rulock(d, l)

#else /* undefined or invalid value, disable locking */

#define db_wlock(d, t) (1)
#define db_wulock(d, l) (1)
#define db_rlock(d, t) (1)
#define db_rulock(d, l) (1)

#endif /* LOCK_PROTO */

#endif /* DEFINED_DBLOCK_H */
/*
* $Id:  $
* $Version: $
*
* Copyright (c) Priit Järv 2013
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

 /** @file dbschema.h
 * Public headers for the strucured data functions.
 */

#ifndef DEFINED_DBSCHEMA_H
#define DEFINED_DBSCHEMA_H

/* ==== Public macros ==== */

#define WG_SCHEMA_TRIPLE_SIZE 3
#define WG_SCHEMA_TRIPLE_OFFSET 0
#define WG_SCHEMA_KEY_OFFSET (WG_SCHEMA_TRIPLE_OFFSET + 1)
#define WG_SCHEMA_VALUE_OFFSET (WG_SCHEMA_TRIPLE_OFFSET + 2)

/* ====== data structures ======== */


/* ==== Protos ==== */

void *wg_create_triple(void *db, gint subj, gint prop, gint ob, gint isparam);
#define wg_create_kvpair(db, key, val, ip) \
  wg_create_triple(db, 0, key, val, ip)
void *wg_create_array(void *db, gint size, gint isdocument, gint isparam);
void *wg_create_object(void *db, gint size, gint isdocument, gint isparam);
void *wg_find_document(void *db, void *rec);
gint wg_delete_document(void *db, void *document);

#endif /* DEFINED_DBSCHEMA_H */

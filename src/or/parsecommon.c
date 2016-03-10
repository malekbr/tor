#include "or.h"
#include "memarea.h"
#include "parsecommon.h"
#include "routerlist.h"

#define ALLOC_ZERO(sz) memarea_alloc_zero(area,sz)
#define ALLOC(sz) memarea_alloc(area,sz)
#define STRDUP(str) memarea_strdup(area,str)
#define STRNDUP(str,n) memarea_strndup(area,(str),(n))

#define RET_ERR(msg)                                               \
  STMT_BEGIN                                                       \
    if (tok) token_clear(tok);                                      \
    tok = ALLOC_ZERO(sizeof(directory_token_t));                   \
    tok->tp = ERR_;                                                \
    tok->error = STRDUP(msg);                                      \
    goto done_tokenizing;                                          \
  STMT_END

/*
 * Low-level tokenizer for router descriptors and directories.
 */
/** Free all resources allocated for <b>tok</b> */
// TODO(Malek) figure out if static is needed and how to put it
void
token_clear(directory_token_t *tok)
{
  if (tok->key)
    crypto_pk_free(tok->key);
}

/** Read all tokens from a string between <b>start</b> and <b>end</b>, and add
 * them to <b>out</b>.  Parse according to the token rules in <b>table</b>.
 * Caller must free tokens in <b>out</b>.  If <b>end</b> is NULL, use the
 * entire string.
 */
int
tokenize_string(memarea_t *area,
                const char *start, const char *end, smartlist_t *out,
                token_rule_t *table, int flags)
{
  const char **s;
  directory_token_t *tok = NULL;
  int counts[NIL_];
  int i;
  int first_nonannotation;
  int prev_len = smartlist_len(out);
  tor_assert(area);

  s = &start;
  if (!end) {
    end = start+strlen(start);
  } else {
    /* it's only meaningful to check for nuls if we got an end-of-string ptr */
    if (memchr(start, '\0', end-start)) {
      log_warn(LD_DIR, "parse error: internal NUL character.");
      return -1;
    }
  }
  for (i = 0; i < NIL_; ++i)
    counts[i] = 0;

  SMARTLIST_FOREACH(out, const directory_token_t *, t, ++counts[t->tp]);

  while (*s < end && (!tok || tok->tp != EOF_)) {
    tok = get_next_token(area, s, end, table);
    if (tok->tp == ERR_) {
      log_warn(LD_DIR, "parse error: %s", tok->error);
      token_clear(tok);
      return -1;
    }
    ++counts[tok->tp];
    smartlist_add(out, tok);
    *s = eat_whitespace_eos(*s, end);
  }

  if (flags & TS_NOCHECK)
    return 0;

  if ((flags & TS_ANNOTATIONS_OK)) {
    first_nonannotation = -1;
    for (i = 0; i < smartlist_len(out); ++i) {
      tok = smartlist_get(out, i);
      if (tok->tp < MIN_ANNOTATION || tok->tp > MAX_ANNOTATION) {
        first_nonannotation = i;
        break;
      }
    }
    if (first_nonannotation < 0) {
      log_warn(LD_DIR, "parse error: item contains only annotations");
      return -1;
    }
    for (i=first_nonannotation;  i < smartlist_len(out); ++i) {
      tok = smartlist_get(out, i);
      if (tok->tp >= MIN_ANNOTATION && tok->tp <= MAX_ANNOTATION) {
        log_warn(LD_DIR, "parse error: Annotations mixed with keywords");
        return -1;
      }
    }
    if ((flags & TS_NO_NEW_ANNOTATIONS)) {
      if (first_nonannotation != prev_len) {
        log_warn(LD_DIR, "parse error: Unexpected annotations.");
        return -1;
      }
    }
  } else {
    for (i=0;  i < smartlist_len(out); ++i) {
      tok = smartlist_get(out, i);
      if (tok->tp >= MIN_ANNOTATION && tok->tp <= MAX_ANNOTATION) {
        log_warn(LD_DIR, "parse error: no annotations allowed.");
        return -1;
      }
    }
    first_nonannotation = 0;
  }
  for (i = 0; table[i].t; ++i) {
    if (counts[table[i].v] < table[i].min_cnt) {
      log_warn(LD_DIR, "Parse error: missing %s element.", table[i].t);
      return -1;
    }
    if (counts[table[i].v] > table[i].max_cnt) {
      log_warn(LD_DIR, "Parse error: too many %s elements.", table[i].t);
      return -1;
    }
    if (table[i].pos & AT_START) {
      if (smartlist_len(out) < 1 ||
          (tok = smartlist_get(out, first_nonannotation))->tp != table[i].v) {
        log_warn(LD_DIR, "Parse error: first item is not %s.", table[i].t);
        return -1;
      }
    }
    if (table[i].pos & AT_END) {
      if (smartlist_len(out) < 1 ||
          (tok = smartlist_get(out, smartlist_len(out)-1))->tp != table[i].v) {
        log_warn(LD_DIR, "Parse error: last item is not %s.", table[i].t);
        return -1;
      }
    }
  }
  return 0;
}


/** Helper: parse space-separated arguments from the string <b>s</b> ending at
 * <b>eol</b>, and store them in the args field of <b>tok</b>.  Store the
 * number of parsed elements into the n_args field of <b>tok</b>.  Allocate
 * all storage in <b>area</b>.  Return the number of arguments parsed, or
 * return -1 if there was an insanely high number of arguments. */
static inline int
get_token_arguments(memarea_t *area, directory_token_t *tok,
                    const char *s, const char *eol)
{
/** Largest number of arguments we'll accept to any token, ever. */
#define MAX_ARGS 512
  char *mem = memarea_strndup(area, s, eol-s);
  char *cp = mem;
  int j = 0;
  char *args[MAX_ARGS];
  while (*cp) {
    if (j == MAX_ARGS)
      return -1;
    args[j++] = cp;
    cp = (char*)find_whitespace(cp);
    if (!cp || !*cp)
      break; /* End of the line. */
    *cp++ = '\0';
    cp = (char*)eat_whitespace(cp);
  }
  tok->n_args = j;
  tok->args = memarea_memdup(area, args, j*sizeof(char*));
  return j;
#undef MAX_ARGS
}

/** Helper: make sure that the token <b>tok</b> with keyword <b>kwd</b> obeys
 * the object syntax of <b>o_syn</b>.  Allocate all storage in <b>area</b>.
 * Return <b>tok</b> on success, or a new ERR_ token if the token didn't
 * conform to the syntax we wanted.
 **/
static inline directory_token_t *
token_check_object(memarea_t *area, const char *kwd,
                   directory_token_t *tok, obj_syntax o_syn)
{
  char ebuf[128];
  switch (o_syn) {
    case NO_OBJ:
      /* No object is allowed for this token. */
      if (tok->object_body) {
        tor_snprintf(ebuf, sizeof(ebuf), "Unexpected object for %s", kwd);
        RET_ERR(ebuf);
      }
      if (tok->key) {
        tor_snprintf(ebuf, sizeof(ebuf), "Unexpected public key for %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    case NEED_OBJ:
      /* There must be a (non-key) object. */
      if (!tok->object_body) {
        tor_snprintf(ebuf, sizeof(ebuf), "Missing object for %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    case NEED_KEY_1024: /* There must be a 1024-bit public key. */
    case NEED_SKEY_1024: /* There must be a 1024-bit private key. */
      if (tok->key && crypto_pk_num_bits(tok->key) != PK_BYTES*8) {
        tor_snprintf(ebuf, sizeof(ebuf), "Wrong size on key for %s: %d bits",
                     kwd, crypto_pk_num_bits(tok->key));
        RET_ERR(ebuf);
      }
      /* fall through */
    case NEED_KEY: /* There must be some kind of key. */
      if (!tok->key) {
        tor_snprintf(ebuf, sizeof(ebuf), "Missing public key for %s", kwd);
        RET_ERR(ebuf);
      }
      if (o_syn != NEED_SKEY_1024) {
        if (crypto_pk_key_is_private(tok->key)) {
          tor_snprintf(ebuf, sizeof(ebuf),
               "Private key given for %s, which wants a public key", kwd);
          RET_ERR(ebuf);
        }
      } else { /* o_syn == NEED_SKEY_1024 */
        if (!crypto_pk_key_is_private(tok->key)) {
          tor_snprintf(ebuf, sizeof(ebuf),
               "Public key given for %s, which wants a private key", kwd);
          RET_ERR(ebuf);
        }
      }
      break;
    case OBJ_OK:
      /* Anything goes with this token. */
      break;
  }

 done_tokenizing:
  return tok;
}



/** Helper function: read the next token from *s, advance *s to the end of the
 * token, and return the parsed token.  Parse *<b>s</b> according to the list
 * of tokens in <b>table</b>.
 */
directory_token_t *
get_next_token(memarea_t *area,
               const char **s, const char *eos, token_rule_t *table)
{
  /** Reject any object at least this big; it is probably an overflow, an
   * attack, a bug, or some other nonsense. */
#define MAX_UNPARSED_OBJECT_SIZE (128*1024)
  /** Reject any line at least this big; it is probably an overflow, an
   * attack, a bug, or some other nonsense. */
#define MAX_LINE_LENGTH (128*1024)

  const char *next, *eol, *obstart;
  size_t obname_len;
  int i;
  directory_token_t *tok;
  obj_syntax o_syn = NO_OBJ;
  char ebuf[128];
  const char *kwd = "";

  tor_assert(area);
  tok = ALLOC_ZERO(sizeof(directory_token_t));
  tok->tp = ERR_;

  /* Set *s to first token, eol to end-of-line, next to after first token */
  *s = eat_whitespace_eos(*s, eos); /* eat multi-line whitespace */
  tor_assert(eos >= *s);
  eol = memchr(*s, '\n', eos-*s);
  if (!eol)
    eol = eos;
  if (eol - *s > MAX_LINE_LENGTH) {
    RET_ERR("Line far too long");
  }

  next = find_whitespace_eos(*s, eol);

  if (!strcmp_len(*s, "opt", next-*s)) {
    /* Skip past an "opt" at the start of the line. */
    *s = eat_whitespace_eos_no_nl(next, eol);
    next = find_whitespace_eos(*s, eol);
  } else if (*s == eos) {  /* If no "opt", and end-of-line, line is invalid */
    RET_ERR("Unexpected EOF");
  }

  /* Search the table for the appropriate entry.  (I tried a binary search
   * instead, but it wasn't any faster.) */
  for (i = 0; table[i].t ; ++i) {
    if (!strcmp_len(*s, table[i].t, next-*s)) {
      /* We've found the keyword. */
      kwd = table[i].t;
      tok->tp = table[i].v;
      o_syn = table[i].os;
      *s = eat_whitespace_eos_no_nl(next, eol);
      /* We go ahead whether there are arguments or not, so that tok->args is
       * always set if we want arguments. */
      if (table[i].concat_args) {
        /* The keyword takes the line as a single argument */
        tok->args = ALLOC(sizeof(char*));
        tok->args[0] = STRNDUP(*s,eol-*s); /* Grab everything on line */
        tok->n_args = 1;
      } else {
        /* This keyword takes multiple arguments. */
        if (get_token_arguments(area, tok, *s, eol)<0) {
          tor_snprintf(ebuf, sizeof(ebuf),"Far too many arguments to %s", kwd);
          RET_ERR(ebuf);
        }
        *s = eol;
      }
      if (tok->n_args < table[i].min_args) {
        tor_snprintf(ebuf, sizeof(ebuf), "Too few arguments to %s", kwd);
        RET_ERR(ebuf);
      } else if (tok->n_args > table[i].max_args) {
        tor_snprintf(ebuf, sizeof(ebuf), "Too many arguments to %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    }
  }

  if (tok->tp == ERR_) {
    /* No keyword matched; call it an "K_opt" or "A_unrecognized" */
    if (**s == '@')
      tok->tp = A_UNKNOWN_;
    else
      tok->tp = K_OPT;
    tok->args = ALLOC(sizeof(char*));
    tok->args[0] = STRNDUP(*s, eol-*s);
    tok->n_args = 1;
    o_syn = OBJ_OK;
  }

  /* Check whether there's an object present */
  *s = eat_whitespace_eos(eol, eos);  /* Scan from end of first line */
  tor_assert(eos >= *s);
  eol = memchr(*s, '\n', eos-*s);
  if (!eol || eol-*s<11 || strcmpstart(*s, "-----BEGIN ")) /* No object. */
    goto check_object;

  obstart = *s; /* Set obstart to start of object spec */
  if (*s+16 >= eol || memchr(*s+11,'\0',eol-*s-16) || /* no short lines, */
      strcmp_len(eol-5, "-----", 5) ||           /* nuls or invalid endings */
      (eol-*s) > MAX_UNPARSED_OBJECT_SIZE) {     /* name too long */
    RET_ERR("Malformed object: bad begin line");
  }
  tok->object_type = STRNDUP(*s+11, eol-*s-16);
  obname_len = eol-*s-16; /* store objname length here to avoid a strlen() */
  *s = eol+1;    /* Set *s to possible start of object data (could be eos) */

  /* Go to the end of the object */
  next = tor_memstr(*s, eos-*s, "-----END ");
  if (!next) {
    RET_ERR("Malformed object: missing object end line");
  }
  tor_assert(eos >= next);
  eol = memchr(next, '\n', eos-next);
  if (!eol)  /* end-of-line marker, or eos if there's no '\n' */
    eol = eos;
  /* Validate the ending tag, which should be 9 + NAME + 5 + eol */
  if ((size_t)(eol-next) != 9+obname_len+5 ||
      strcmp_len(next+9, tok->object_type, obname_len) ||
      strcmp_len(eol-5, "-----", 5)) {
    tor_snprintf(ebuf, sizeof(ebuf), "Malformed object: mismatched end tag %s",
             tok->object_type);
    ebuf[sizeof(ebuf)-1] = '\0';
    RET_ERR(ebuf);
  }
  if (next - *s > MAX_UNPARSED_OBJECT_SIZE)
    RET_ERR("Couldn't parse object: missing footer or object much too big.");

  if (!strcmp(tok->object_type, "RSA PUBLIC KEY")) { /* If it's a public key */
    tok->key = crypto_pk_new();
    if (crypto_pk_read_public_key_from_string(tok->key, obstart, eol-obstart))
      RET_ERR("Couldn't parse public key.");
  } else if (!strcmp(tok->object_type, "RSA PRIVATE KEY")) { /* private key */
    tok->key = crypto_pk_new();
    if (crypto_pk_read_private_key_from_string(tok->key, obstart, eol-obstart))
      RET_ERR("Couldn't parse private key.");
  } else { /* If it's something else, try to base64-decode it */
    int r;
    tok->object_body = ALLOC(next-*s); /* really, this is too much RAM. */
    r = base64_decode(tok->object_body, next-*s, *s, next-*s);
    if (r<0)
      RET_ERR("Malformed object: bad base64-encoded data");
    tok->object_size = r;
  }
  *s = eol;

 check_object:
  tok = token_check_object(area, kwd, tok, o_syn);

 done_tokenizing:
  return tok;

#undef RET_ERR
#undef ALLOC
#undef ALLOC_ZERO
#undef STRDUP
#undef STRNDUP
}


/** Find the first token in <b>s</b> whose keyword is <b>keyword</b>; fail
 * with an assert if no such keyword is found.
 */
directory_token_t *
find_by_keyword_(smartlist_t *s, directory_keyword keyword,
                 const char *keyword_as_string)
{
  directory_token_t *tok = find_opt_by_keyword(s, keyword);
  if (PREDICT_UNLIKELY(!tok)) {
    log_err(LD_BUG, "Missing %s [%d] in directory object that should have "
         "been validated. Internal error.", keyword_as_string, (int)keyword);
    tor_assert(tok);
  }
  return tok;
}

/** Find the first token in <b>s</b> whose keyword is <b>keyword</b>; return
 * NULL if no such keyword is found.
 */
directory_token_t *
find_opt_by_keyword(smartlist_t *s, directory_keyword keyword)
{
  SMARTLIST_FOREACH(s, directory_token_t *, t, if (t->tp == keyword) return t);
  return NULL;
}


/** Helper function for <b>router_get_hash_impl</b>: given <b>s</b>,
 * <b>s_len</b>, <b>start_str</b>, <b>end_str</b>, and <b>end_c</b> with the
 * same semantics as in that function, set *<b>start_out</b> (inclusive) and
 * *<b>end_out</b> (exclusive) to the boundaries of the string to be hashed.
 *
 * Return 0 on success and -1 on failure.
 */
int
router_get_hash_impl_helper(const char *s, size_t s_len,
                            const char *start_str,
                            const char *end_str, char end_c,
                            const char **start_out, const char **end_out)
{
  const char *start, *end;
  start = tor_memstr(s, s_len, start_str);
  if (!start) {
    log_warn(LD_DIR,"couldn't find start of hashed material \"%s\"",start_str);
    return -1;
  }
  if (start != s && *(start-1) != '\n') {
    log_warn(LD_DIR,
             "first occurrence of \"%s\" is not at the start of a line",
             start_str);
    return -1;
  }
  end = tor_memstr(start+strlen(start_str),
                   s_len - (start-s) - strlen(start_str), end_str);
  if (!end) {
    log_warn(LD_DIR,"couldn't find end of hashed material \"%s\"",end_str);
    return -1;
  }
  end = memchr(end+strlen(end_str), end_c, s_len - (end-s) - strlen(end_str));
  if (!end) {
    log_warn(LD_DIR,"couldn't find EOL");
    return -1;
  }
  ++end;

  *start_out = start;
  *end_out = end;
  return 0;
}

/** Compute the digest of the substring of <b>s</b> taken from the first
 * occurrence of <b>start_str</b> through the first instance of c after the
 * first subsequent occurrence of <b>end_str</b>; store the 20-byte or 32-byte
 * result in <b>digest</b>; return 0 on success.
 *
 * If no such substring exists, return -1.
 */
int
router_get_hash_impl(const char *s, size_t s_len, char *digest,
                     const char *start_str,
                     const char *end_str, char end_c,
                     digest_algorithm_t alg)
{
  const char *start=NULL, *end=NULL;
  if (router_get_hash_impl_helper(s,s_len,start_str,end_str,end_c,
                                  &start,&end)<0)
    return -1;

  if (alg == DIGEST_SHA1) {
    if (crypto_digest(digest, start, end-start)) {
      log_warn(LD_BUG,"couldn't compute digest");
      return -1;
    }
  } else {
    if (crypto_digest256(digest, start, end-start, alg)) {
      log_warn(LD_BUG,"couldn't compute digest");
      return -1;
    }
  }

  return 0;
}

/** As router_get_hash_impl, but compute all hashes. */
int
router_get_hashes_impl(const char *s, size_t s_len, common_digests_t *digests,
                       const char *start_str,
                       const char *end_str, char end_c)
{
  const char *start=NULL, *end=NULL;
  if (router_get_hash_impl_helper(s,s_len,start_str,end_str,end_c,
                                  &start,&end)<0)
    return -1;

  if (crypto_common_digests(digests, start, end-start)) {
    log_warn(LD_BUG,"couldn't compute digests");
    return -1;
  }

  return 0;
}

/** Return true iff <b>key</b> is allowed to sign directories.
 */
static int
dir_signing_key_is_trusted(crypto_pk_t *key)
{
  char digest[DIGEST_LEN];
  if (!key) return 0;
  if (crypto_pk_get_digest(key, digest) < 0) {
    log_warn(LD_DIR, "Error computing dir-signing-key digest");
    return 0;
  }
  if (!router_digest_is_trusted_dir(digest)) {
    log_warn(LD_DIR, "Listed dir-signing-key is not trusted");
    return 0;
  }
  return 1;
}

/** Check whether the object body of the token in <b>tok</b> has a good
 * signature for <b>digest</b> using key <b>pkey</b>.  If
 * <b>CST_CHECK_AUTHORITY</b> is set, make sure that <b>pkey</b> is the key of
 * a directory authority.  If <b>CST_NO_CHECK_OBJTYPE</b> is set, do not check
 * the object type of the signature object. Use <b>doctype</b> as the type of
 * the document when generating log messages.  Return 0 on success, negative
 * on failure.
 */
int
check_signature_token(const char *digest,
                      ssize_t digest_len,
                      directory_token_t *tok,
                      crypto_pk_t *pkey,
                      int flags,
                      const char *doctype)
{
  char *signed_digest;
  size_t keysize;
  const int check_authority = (flags & CST_CHECK_AUTHORITY);
  const int check_objtype = ! (flags & CST_NO_CHECK_OBJTYPE);

  tor_assert(pkey);
  tor_assert(tok);
  tor_assert(digest);
  tor_assert(doctype);

  if (check_authority && !dir_signing_key_is_trusted(pkey)) {
    log_warn(LD_DIR, "Key on %s did not come from an authority; rejecting",
             doctype);
    return -1;
  }

  if (check_objtype) {
    if (strcmp(tok->object_type, "SIGNATURE")) {
      log_warn(LD_DIR, "Bad object type on %s signature", doctype);
      return -1;
    }
  }

  keysize = crypto_pk_keysize(pkey);
  signed_digest = tor_malloc(keysize);
  if (crypto_pk_public_checksig(pkey, signed_digest, keysize,
                                tok->object_body, tok->object_size)
      < digest_len) {
    log_warn(LD_DIR, "Error reading %s: invalid signature.", doctype);
    tor_free(signed_digest);
    return -1;
  }
  //  log_debug(LD_DIR,"Signed %s hash starts %s", doctype,
  //            hex_str(signed_digest,4));
  if (tor_memneq(digest, signed_digest, digest_len)) {
    log_warn(LD_DIR, "Error reading %s: signature does not match.", doctype);
    tor_free(signed_digest);
    return -1;
  }
  tor_free(signed_digest);
  return 0;
}

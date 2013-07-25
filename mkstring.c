/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org
 */

/*-
 * These string functions are ported from OpenBSD source code and copyrights
 * are stated below:
 *
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

/* str_len() function of D.J.B. */
size_t
mkstrlen(const char *s)
{
	register char *t;

	t = (char *) s;
	for (;;) {
		if (!*t) return (t - s); ++t;
		if (!*t) return (t - s); ++t;
		if (!*t) return (t - s); ++t;
		if (!*t) return (t - s); ++t;
	}
}

char *
mkstrdup(const char *str)
{
	size_t siz;
	char   *copy;

	siz = mkstrlen(str) + 1;
	if ((copy = malloc(siz)) == NULL)
		return (NULL);
	(void) memcpy(copy, str, siz);

	return (copy);
}

size_t
mkstrncat(char *dst, const char *src, size_t size)
{
	register char       *d = dst;
	register const char *s = src;
	register size_t      n = size;
	size_t               dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n    = size - dlen;

	if (n == 0)
		return(dlen + mkstrlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return (dlen + (s - src));	/* count does not include NUL */
}

size_t
mkstrcpy(char *dst, const char *src, size_t size)
{
	register char       *d = dst;
	register const char *s = src;
	register size_t      n = size;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (size != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return (s - src - 1);	/* count does not include NUL */
}

char *
mkstrstr(char *string, char *find)
{
	size_t stringlen, findlen;
	char *cp;

	findlen   = mkstrlen(find);
	stringlen = mkstrlen(string);
	if (findlen > stringlen)
		return (NULL);

	for (cp = string + stringlen - findlen; cp >= string; cp--)
		if (strncmp(cp, find, findlen) == 0)
			return (cp);

	return (NULL);
}

char *
mkstrtok_r(char *s, const char *delim, char **last)
{
	char *spanp;
	int c, sc;
	char *tok;


	if (s == NULL && (s = *last) == NULL)
		return (NULL);

	/*
	 * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
	 */
cont:
	c = *s++;
	for (spanp = (char *)delim; (sc = *spanp++) != 0;) {
		if (c == sc)
			goto cont;
	}

	if (c == 0) {		/* no non-delimiter characters */
		*last = NULL;
		return (NULL);
	}
	tok = s - 1;

	/*
	 * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
	 * Note that delim must have one NUL; we stop if we see that, too.
	 */
	for (;;) {
		c = *s++;
		spanp = (char *)delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*last = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

char *
mkstrtok(char *s, const char *delim)
{
	static char *last;

	return mkstrtok_r(s, delim, &last);
}

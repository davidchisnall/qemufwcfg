/*-
 * Copyright (c) 2023 David Chisnall <theraven@FreeBSD.org>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * This file contains stub implementations of functions from NetBSD's libutil
 * that are sufficient to build mount_qemufwcfg
 */

#pragma once
#include <string.h>

static inline char *
estrdup(const char *str)
{
	char *ret = strdup(str);
	if (ret == NULL)
		abort();
	return ret;
}

static inline char *
estrndup(const char *str, size_t len)
{
	char *ret = strndup(str, len);
	if (ret == NULL)
		abort();
	return ret;
}

static inline void *
emalloc(size_t size)
{
	void *ret = malloc(size);
	if ((ret == NULL) && (size != 0))
		abort();
	return ret;
}

static inline void *
erealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if ((ret == NULL) && (size != 0) && (ptr != NULL))
		abort();
	return ret;
}

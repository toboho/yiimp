/*-
 * Copyright (c) 2018,2019 The IoTE Core Developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h> /* for abort() */

#include "../yespower/sha256.h"
#include "../yespower/yespower.h"
#include "../yespower/sysendian.h"

#include "cryptovantaa.h"

void CryptoVantaa(const uint8_t *src, size_t srclen, yespower_binary_t *dst)
{
	SHA256_CTX sha256ctx;
	uint8_t tmp[32];

	/* Initial personalization */
	SHA256_Init(&sha256ctx);
	SHA256_Update(&sha256ctx, "CryptoVantaa", 12);
	SHA256_Update(&sha256ctx, src, srclen);
	SHA256_Update(&sha256ctx, "CryptoVantaa", 12);
	SHA256_Final(tmp, &sha256ctx);

	static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 4096,
		.r = 32,
		.pers = NULL,
		.perslen = 0
	};

	/* This is similar to yespower_tls(), but lets us access the V array */
	static __thread int initialized = 0;
	static __thread yespower_local_t local;
	if (!initialized) {
		if (yespower_init_local(&local))
			abort();
		initialized = 1;
	}
	if (yespower(&local, tmp, sizeof(tmp), &params, dst))
		abort();

	/*
	 * Depend on 4 arbitrary reads from V, which a yespower-only ASIC not
	 * trying to support CryptoVantaa is unlikely to include support for.
	 */
	uint64_t *V = (uint64_t *)local.aligned + params.r * 16; /* skip B */
	uint32_t mask = params.N * (params.r * 16) - 1;
	uint32_t i;
	uint64_t j = be32dec(dst->uc) | ((mask + 1) >> 1); /* 2nd half of V */
	for (i = 0; i < 32; i++) {
		j = V[j & mask];
		be64enc(&tmp[i], j);
		i += 8;
	}

	/* Final personalization */
	SHA256_Init(&sha256ctx);
	SHA256_Update(&sha256ctx, "CryptoVantaa", 12);
	SHA256_Update(&sha256ctx, tmp, sizeof(tmp));
	SHA256_Update(&sha256ctx, dst, sizeof(*dst));
	SHA256_Update(&sha256ctx, "CryptoVantaa", 12);
	SHA256_Final(dst->uc, &sha256ctx);
}

void CryptoVantaa_hash(const char *input, char *output, uint32_t len)
{
	CryptoVantaa(input, len, (yespower_binary_t *)output);
}

#ifdef TEST_CRYPTOVANTAA
/*
 * Expected output:
 * 0a d2 2b 18 c9 57 d0 0c 92 1a d4 cc 40 00 35 df 34 d9 fb a5 71 ac 7e 6c 85 c3 19 6f 61 87 68 88
 */

#include <stdio.h>

int main(void)
{
	uint8_t src[80];
	yespower_binary_t dst;
	size_t i;

	for (i = 0; i < sizeof(src); i++)
		src[i] = i * 3;

	CryptoVantaa(src, sizeof(src), &dst);

	for (i = 0; i < sizeof(dst); i++)
		printf("%02x%c", dst.uc[i], i < sizeof(dst) - 1 ? ' ' : '\n');

	return 0;
}
#endif

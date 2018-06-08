/* Copyright (c) 2018 the bcoin developers
 * Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _BSTRING_CASHADDR_H
#define _BSTRING_CASHADDR_H 1

#include <stdint.h>

/** Encode a CashAddr
 *
 *  Out: output:   Pointer to a buffer of size 73 (TODO check size) + strlen(prefix)
 *                 that will be updated to contain the null-terminated address.
 *  In:  prefix:   Pointer to the null-terminated human readable prefix to use
 *                 (chain/network specific).
 *       type:     The type of the address 0 or 1 for P2KH and P2SH
 *       hash:     Data bytes for the hash
 *       hash_len: Number of data bytes in hash
 *  Returns true if successful.
 */
bool
bstring_cashaddr_encode(
  char *output,
  const char *prefix,
  int type,
  const uint8_t *hash,
  size_t hash_len
);

/** Decode a CashAddr
 *
 *  Out: type:     Pointer to an int that will be updated to contain the witness
 *                 program version (0 or 1 for P2KH or P2SH).
 *       hash:     Pointer to a buffer of size 40 (TODO check size) that will be
 *                 updated to contain the witness program bytes.
 *       hash_len: Pointer to a size_t that will be updated to contain the length
 *                 of bytes in hash.
 *       prefix:   Pointer to the null-terminated human readable prefix that will
 *                 be updated to contain the string.
 *       addr:     Pointer to the null-terminated address.
 *  Returns true if successful.
 */
bool
bstring_cashaddr_decode(
  int* type,
  uint8_t* hash,
  size_t* hash_len,
  char* prefix,
  const char* addr
);

bool
bstring_cashaddr_test(const char *addr);

#endif
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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cashaddr.h"

static uint64_t
cashaddr_polymod_step(uint64_t pre) {
  uint8_t b = pre >> 35;
  return ((pre & 0x07ffffffff) << 5)
    ^ (-((b >> 0) & 1) & 0x98f2bc8e61ul)
    ^ (-((b >> 1) & 1) & 0x79b76d99e2ul)
    ^ (-((b >> 2) & 1) & 0xf33e5fb3c4ul)
    ^ (-((b >> 3) & 1) & 0xae2eabe2a8ul)
    ^ (-((b >> 4) & 1) & 0x1e4f43e470ul);
}

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static bool
cashaddr_encoded_size(size_t bytes, uint8_t *encoded_size) {
  switch (bytes * 8) {
  case 160:
    *encoded_size = 0;
    break;
  case 192:
    *encoded_size = 1;
    break;
  case 224:
    *encoded_size = 2;
    break;
  case 256:
    *encoded_size = 3;
    break;
  case 320:
    *encoded_size = 4;
    break;
  case 384:
    *encoded_size = 5;
    break;
  case 448:
    *encoded_size = 6;
    break;
  case 512:
    *encoded_size = 7;
    break;
  default:
    return false;
  }
  return true;
}

static int
cashaddr_encode(
  char *output,
  const char *prefix,
  const uint8_t *data,
  size_t data_len
) {
  uint64_t chk = 1;
  size_t i = 0;

  while (prefix[i] != 0) {
    if (!(prefix[i] >> 5))
      return 0;

    chk = cashaddr_polymod_step(chk);
    chk ^= (prefix[i] & 0x1f);
    *(output++) = prefix[i];
    i += 1;
  }

  chk = cashaddr_polymod_step(chk);
  *(output++) = ':';

  for (i = 0; i < data_len; i++) {
    uint8_t ch = data[i];
    if (ch >> 5)
      return 0;

    chk = cashaddr_polymod_step(chk);
    chk ^= ch;
    *(output++) = CHARSET[ch];
  }

  for (i = 0; i < 8; i++)
    chk = cashaddr_polymod_step(chk);

  chk ^= 1;

  for (i = 0; i < 8; i++)
    *(output++) = CHARSET[(chk >> ((7 - i) * 5)) & 0x1f];

  return 1;
}

static int
cashaddr_decode(char *prefix, uint8_t *data, size_t *data_len, const char *input) {
  uint64_t chk = 1;
  size_t i;
  size_t input_len = strlen(input);
  size_t prefix_len;

  int have_lower = 0, have_upper = 0;

  if (input_len < 8 || input_len > 1024) // TODO check max length
    return 0;

  while (prefix_len < input_len && input[prefix_len] != ':')
    prefix_len++;

  *data_len = input_len - (1 + prefix_len);

  // TODO check max and min length
  if (prefix_len < 1 || *data_len < 8)
    return 0;

  *(data_len) -= 8;

  for (i = 0; i < prefix_len; i++) {
    int ch = input[i];

    if (ch < 33 || ch > 126)
      return 0;

    if (ch >= 'a' && ch <= 'z') {
      have_lower = 1;
    } else if (ch >= 'A' && ch <= 'Z') {
      have_upper = 1;
      ch = (ch - 'A') + 'a';
    }

    prefix[i] = ch;
    chk = cashaddr_polymod_step(chk);
    chk ^= (ch | 0x20) & 0x1f;
  }

  chk = cashaddr_polymod_step(chk);

  i += 1;

  while (i < input_len) {
    int v = (input[i] & 0xff80) ? -1 : TABLE[(int)input[i]];

    if (input[i] >= 'a' && input[i] <= 'z')
      have_lower = 1;

    if (input[i] >= 'A' && input[i] <= 'Z')
      have_upper = 1;

    if (v == -1)
      return 0;

    chk = cashaddr_polymod_step(chk) ^ v;

    if (i + 8 < input_len)
      data[i - (1 + prefix_len)] = v;

    i += 1;
  }

  if (have_lower && have_upper)
    return 0;

  return chk == 1;
}

static int
convert_bits(
  uint8_t *out,
  size_t *outlen,
  int outbits,
  const uint8_t *in,
  size_t inlen,
  int inbits,
  int pad
) {
  uint32_t val = 0;
  int bits = 0;
  uint32_t maxv = (((uint32_t)1) << outbits) - 1;

  while (inlen--) {
    val = (val << inbits) | *(in++);
    bits += inbits;
    while (bits >= outbits) {
      bits -= outbits;
      out[(*outlen)++] = (val >> bits) & maxv;
    }
  }

  if (pad) {
    if (bits)
      out[(*outlen)++] = (val << (outbits - bits)) & maxv;
  } else {
    if (bits >= inbits || ((val << (outbits - bits)) & maxv))
      return 0;
  }

  return 1;
}

bool
bstring_cashaddr_encode(
  char *output,
  const char *prefix,
  int type,
  const uint8_t *hash,
  size_t hash_len
) {
  uint8_t encoded_size = 0;

  // There are 4 bits available for the version (2 ^ 4 = 16)
  if (type < 0 || type > 15)
    return false;

  if (!cashaddr_encoded_size(hash_len, &encoded_size))
    return false;

  uint8_t version_byte = type << 3 | encoded_size;

  size_t data_len = hash_len + 1;
  uint8_t data[data_len];
  data[0] = version_byte;
  memcpy(data + 1, hash, hash_len);

  size_t converted_len = 0;
  uint8_t converted[data_len + 8]; // TODO check max len

  if (!convert_bits(converted, &converted_len, 5, data, data_len, 8, 1)) {
    return false;
  }

  return cashaddr_encode(output, prefix, converted, converted_len);
}

bool
bstring_cashaddr_decode(
  int *type,
  uint8_t *hash,
  size_t *hash_len,
  char *prefix,
  const char *addr
) {
  uint8_t data[1024];  // TODO check max length
  memset(&data, 0, 1024);
  size_t data_len = 0;

  if (!cashaddr_decode(prefix, data, &data_len, addr))
    return false;

  // TODO check data_len
  // TODO check type
  // TODO check padding

  uint8_t converted[1024]; // TODO check max length
  memset(&converted, 0, 1024);
  size_t converted_len = 0;

  if (!convert_bits(converted, &converted_len, 8, data, data_len, 5, 0))
    return false;

  *type = (converted[0] >> 3) & 0x1f;
  *hash_len = converted_len - 1;
  // TODO set pointer instead of memcpy?
  memcpy(hash, converted + 1, *hash_len);

  uint8_t size = 20 + 4 * (converted[0] & 0x03);

  if (converted[0] & 0x04)
    size *= 2;

  if (size != *hash_len)
    return false;

  return true;
}

bool
bstring_cashaddr_test(const char *addr) {
  char prefix[84]; // TODO check max length
  uint8_t data[84]; // TODO check max length
  size_t data_len;

  if (!cashaddr_decode(prefix, data, &data_len, addr))
    return false;

  return true;
}

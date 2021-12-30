// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "defs.h"

#define SHA256_HASH_BYTE_LEN 32
#define SHA512_HASH_BYTE_LEN 64

void sha512(OUT uint8_t* dgst,
    IN const uint8_t* data,
    IN size_t         byte_len);
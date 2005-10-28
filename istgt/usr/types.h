/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef TYPES_H
#define TYPES_H

#include <sys/types.h>
#include <byteswap.h>
#include <endian.h>
#include <stdint.h>
#include <inttypes.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be16(x)		(x)
#define be16_to_cpu(x)		(x)
#define cpu_to_be32(x)		(x)
#define be32_to_cpu(x)		(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be16(x)		bswap_16(x)
#define be16_to_cpu(x)		bswap_16(x)
#define cpu_to_be32(x)		bswap_32(x)
#define be32_to_cpu(x)		bswap_32(x)
#else
#error "unknown endianess!"
#endif

typedef uint16_t __be16;
typedef uint32_t __be32;

#endif	/* TYPES_H */

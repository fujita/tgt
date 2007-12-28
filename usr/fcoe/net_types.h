/*
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef _LIBSA_NET_TYPES_H_
#define	_LIBSA_NET_TYPES_H_

/*
 * Type definitions for network order fields in protocol packets.
 * The access functions below do gets and puts on these structures.
 */
typedef unsigned char net8_t;		/* direct use and assignment allowed */

/*
 * Aligned network order types.
 */
typedef struct {
	u_int16_t	net_data;
} net16_t;

typedef struct {
	u_int32_t	net_data;
} net32_t;

/*
 * The 64-bit type only requires 32-bit alignment.
 */
typedef struct {
	u_int32_t	net_data[2];	/* most significant word first */
} net64_t;

/*
 * 24-bit type.  Byte aligned, in spite of the name.
 */
typedef struct {
	unsigned char	net_data[3];
} net24_t;

/*
 * 48-bit type.  Byte aligned.
 */
typedef struct {
	unsigned char	net_data[6];
} net48_t;

/*
 * Unaligned network order types.
 * Any of these structures can be byte aligned.  No padding is implied.
 */
typedef struct {
	unsigned char	net_data[2];
} ua_net16_t;

typedef struct {
	unsigned char	net_data[4];
} ua_net32_t;

typedef struct {
	unsigned char	net_data[8];
} ua_net64_t;

/*
 * Accessor functions.
 */

/**
 * net8_get(net) - fetch from a network-order 8-bit field.
 *
 * @param net pointer to network-order 8-bit data.
 * @return the host-order value.
 */
static inline u_int8_t net8_get(const net8_t *net)
{
	return *net;
}

/**
 * net8_put(net, val) - store to a network-order 8-bit field.
 *
 * @param net pointer to network-order 8-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void net8_put(net8_t *net, u_int8_t val)
{
	*net = val;
}

/**
 * net16_get(net) - fetch from a network-order 16-bit field.
 *
 * @param net pointer to type net16_t, network-order 16-bit data.
 * @return the host-order value.
 */
static inline u_int16_t net16_get(const net16_t *net)
{
	return ntohs(net->net_data);
}

/**
 * net16_put(net, val) - store to a network-order 16-bit field.
 *
 * @param net pointer to a net16_t, network-order 16-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void net16_put(net16_t *net, u_int16_t val)
{
	net->net_data = htons(val);
}

/**
 * ua_net16_get(net) - fetch from an unaligned network-order 16-bit field.
 *
 * @param net pointer to type ua_net16_t, unaligned, network-order 16-bit data.
 * @return the host-order value.
 */
static inline u_int16_t ua_net16_get(const ua_net16_t *net)
{
	return (net->net_data[0] << 8) | net->net_data[1];
}

/**
 * ua_net16_put(net, val) - store to a network-order 16-bit field.
 *
 * @param net pointer to a ua_net16_t, network-order 16-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void ua_net16_put(ua_net16_t *net, u_int16_t val)
{
	net->net_data[0] = (u_int8_t)((val >> 8) & 0xFF);
	net->net_data[1] = (u_int8_t)(val & 0xFF);
}

/**
 * net24_get(net) - fetch from a network-order 24-bit field.
 *
 * @param net pointer to type net24_t, network-order 24-bit data.
 * @return the host-order value.
 */
static inline u_int32_t net24_get(const net24_t *net)
{
	return (net->net_data[0] << 16) |
		(net->net_data[1] << 8) | net->net_data[2];
}

/**
 * net24_put(net, val) - store to a network-order 24-bit field.
 *
 * @param net pointer to a net24_t, network-order 24-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void net24_put(net24_t *net, u_int32_t val)
{
	net->net_data[0] = (u_int8_t)((val >> 16) & 0xFF);
	net->net_data[1] = (u_int8_t)((val >> 8) & 0xFF);
	net->net_data[2] = (u_int8_t)(val & 0xFF);
}

/**
 * net32_get(net) - fetch from a network-order 32-bit field.
 *
 * @param net pointer to type net32_t, network-order 32-bit data.
 * @return the host-order value.
 */
static inline u_int32_t net32_get(const net32_t *net)
{
	return ntohl(net->net_data);
}

/**
 * net32_put(net, val) - store to a network-order 32-bit field.
 *
 * @param net pointer to a net32_t, network-order 32-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void net32_put(net32_t *net, u_int32_t val)
{
	net->net_data = htonl(val);
}

/**
 * ua_net32_get(net) - fetch from an unaligned network-order 32-bit field.
 *
 * @param net pointer to type ua_net32_t, unaligned, network-order 32-bit data.
 * @return the host-order value.
 */
static inline u_int32_t ua_net32_get(const ua_net32_t *net)
{
	return (net->net_data[0] << 24) | (net->net_data[1] << 16) |
		(net->net_data[2] << 8) | net->net_data[3];
}

/**
 * ua_net32_put(net, val) - store to a network-order 32-bit field.
 *
 * @param net pointer to a ua_net32_t, network-order 32-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void ua_net32_put(ua_net32_t *net, u_int32_t val)
{
	net->net_data[0] = (u_int8_t)((val >> 24) & 0xFF);
	net->net_data[1] = (u_int8_t)((val >> 16) & 0xFF);
	net->net_data[2] = (u_int8_t)((val >> 8) & 0xFF);
	net->net_data[3] = (u_int8_t)(val & 0xFF);
}

/**
 * net48_get(net) - fetch from a network-order 48-bit field.
 *
 * @param net pointer to type net48_t, network-order 48-bit data.
 * @return the host-order value.
 */
static inline u_int64_t net48_get(const net48_t *net)
{
	return ((u_int64_t) net->net_data[0] << 40) |
		((u_int64_t) net->net_data[1] << 32) |
		((u_int64_t) net->net_data[2] << 24) |
		((u_int64_t) net->net_data[3] << 16) |
		((u_int64_t) net->net_data[4] << 8) |
		(u_int64_t) net->net_data[5];
}

/**
 * net48_put(net, val) - store to a network-order 48-bit field.
 *
 * @param net pointer to a net48_t, network-order 48-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void net48_put(net48_t *net, u_int64_t val)
{
	net->net_data[0] = (u_int8_t)((val >> 40) & 0xFF);
	net->net_data[1] = (u_int8_t)((val >> 32) & 0xFF);
	net->net_data[2] = (u_int8_t)((val >> 24) & 0xFF);
	net->net_data[3] = (u_int8_t)((val >> 16) & 0xFF);
	net->net_data[4] = (u_int8_t)((val >> 8) & 0xFF);
	net->net_data[5] = (u_int8_t)(val & 0xFF);
}

/**
 * net64_get(net) - fetch from a network-order 64-bit field.
 *
 * @param net pointer to type net64_t, network-order 64-bit data.
 * @return the host-order value.
 */
static inline u_int64_t net64_get(const net64_t *net)
{
	return ((u_int64_t) ntohl(net->net_data[0]) << 32) |
		ntohl(net->net_data[1]);
}

/**
 * net64_put(net, val) - store to a network-order 64-bit field.
 *
 * @param net pointer to a net64_t, network-order 64-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void net64_put(net64_t *net, u_int64_t val)
{
	net->net_data[0] = (u_int32_t)htonl(val >> 32);
	net->net_data[1] = (u_int32_t)htonl((u_int32_t) val);
}

/**
 * ua_net64_get(net) - fetch from an unaligned network-order 64-bit field.
 *
 * @param net pointer to type ua_net64_t, unaligned, network-order 64-bit data.
 * @return the host-order value.
 */
static inline u_int64_t ua_net64_get(const ua_net64_t *net)
{
	return ((u_int64_t) net->net_data[0] << 56) |
		((u_int64_t) net->net_data[1] << 48) |
		((u_int64_t) net->net_data[2] << 40) |
		((u_int64_t) net->net_data[3] << 32) |
		((u_int64_t) net->net_data[4] << 24) |
		((u_int64_t) net->net_data[5] << 16) |
		((u_int64_t) net->net_data[6] << 8) |
		(u_int64_t) net->net_data[7];
}

/**
 * ua_net64_put(net, val) - store to a network-order 64-bit field.
 *
 * @param net pointer to a ua_net64_t, network-order 64-bit data.
 * @param val host-order value to be stored at net.
 */
static inline void ua_net64_put(ua_net64_t *net, u_int64_t val)
{
	net->net_data[0] = (u_int8_t)((val >> 56) & 0xFF);
	net->net_data[1] = (u_int8_t)((val >> 48) & 0xFF);
	net->net_data[2] = (u_int8_t)((val >> 40) & 0xFF);
	net->net_data[3] = (u_int8_t)((val >> 32) & 0xFF);
	net->net_data[4] = (u_int8_t)((val >> 24) & 0xFF);
	net->net_data[5] = (u_int8_t)((val >> 16) & 0xFF);
	net->net_data[6] = (u_int8_t)((val >> 8) & 0xFF);
	net->net_data[7] = (u_int8_t)(val & 0xFF);
}

/*
 * Compile-time initializers for the network-order type structures.
 * Note that the upper byte of these values is not masked so the
 * compiler will catch initializers that don't fit in the field.
 */

/**
 * NET8_INIT(_val) - initialize a net8_t type.
 *
 * @param _val 8-bit value.
 * @return net8_t network-order value.
 */
#define	NET8_INIT(_val)     (_val)

/**
 * NET24_INIT(_val) - initialize a net24_t type.
 *
 * @param _val host-order value.
 * @return net24_t network-order value.
 */
#define	NET24_INIT(_val)    { {				    \
				((_val) >> 16),		    \
				((_val) >> 8) & 0xff,	    \
				((_val) >> 0) & 0xff	    \
			    } }

/**
 * NET48_INIT(_val) - initialize a net48_t type.
 *
 * @param _val host-order value.
 * @return net48_t network-order value.
 */
#define	NET48_INIT(_val)    { {				    \
				((_val) >> 40),		    \
				((_val) >> 32) & 0xff,	    \
				((_val) >> 24) & 0xff,	    \
				((_val) >> 16) & 0xff,	    \
				((_val) >> 8) & 0xff,	    \
				((_val) >> 0) & 0xff	    \
			    } }

/**
 * NET16_INIT(_val) - initialize a net16_t type.
 *
 * @param _val host-order value.
 * @return net16_t network-order value.
 */
#define	NET16_INIT(_val)    {	htons(_val) }

/**
 * UA_NET16_INIT(_val) - initialize an unaligned 16-bit type.
 *
 * @param _val host-order value.
 * @return ua_net24_t network-order value.
 */
#define	UA_NET16_INIT(_val) { {				    \
				((_val) >> 8),		    \
				((_val) >> 0) & 0xff	    \
			    } }

/**
 * NET32_INIT(_val) - initialize a 32-bit type.
 *
 * @param _val host-order value.
 * @return net32_t network-order value.
 */
#define	NET32_INIT(_val)    {	htonl(_val) }

/**
 * UA_NET32_INIT(_val) - initialize an unaligned 32-bit type.
 *
 * @param _val host-order value.
 * @return ua_net32_t network-order value.
 */
#define	UA_NET32_INIT(_val) { {				    \
				((_val) >> 24),		    \
				((_val) >> 16) & 0xff,	    \
				((_val) >> 8) & 0xff,	    \
				((_val) >> 0) & 0xff	    \
			    } }

/**
 * UA_NET48_INIT(_val) - initialize an unaligned 48-bit type.
 *
 * @param _val host-order value.
 * @return ua_net48_t network-order value.
 */
#define	UA_NET48_INIT(_val) { {				    \
				((_val) >> 40),		    \
				((_val) >> 32) & 0xff,	    \
				((_val) >> 24) & 0xff,	    \
				((_val) >> 16) & 0xff,	    \
				((_val) >> 8) & 0xff,	    \
				((_val) >> 0) & 0xff	    \
			    } }

/**
 * NET64_INIT(_val) - initialize an unaligned 64-bit type.
 *
 * @param _val host-order value.
 * @return ua_net64_t network-order value.
 */
#define	NET64_INIT(_val)    { {				    \
				htonl((_val) >> 32),	    \
				htonl((_val) & 0xffffffff)  \
			    } }

/**
 * UA_NET64_INIT(_val) - initialize a 64-bit type.
 *
 * @param _val host-order value.
 * @return net64_t network-order value.
 */
#define	UA_NET64_INIT(_val) { {				     \
				((_val) >> 56),		    \
				((_val) >> 48) & 0xff,	    \
				((_val) >> 40) & 0xff,	    \
				((_val) >> 32) & 0xff,	    \
				((_val) >> 24) & 0xff,	    \
				((_val) >> 16) & 0xff,	    \
				((_val) >> 8) & 0xff,	    \
				((_val) >> 0) & 0xff	    \
			    } }

#endif /* _LIBSA_NET_TYPES_H_ */

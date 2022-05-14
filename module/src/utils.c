/** 
* @file utils.c
* @brief Implements helper utilties for Drawbridge
*
* @author Bradley Landherr
*
* @date 04/11/2018
*/
#include "parser.h"

/**
 *  @brief IPv4 Network to address display format
 *  @param str_ip Destination buffer, must be at least 17 bytes
 *  @param int_ip The address in big endian binary form
 *  @return void
 */
void internal_inet_ntoa(char *str_ip, size_t len, __be32 int_ip)
{
    if (!str_ip || len <= 16)
        return;

    memset(str_ip, 0, 16);
    snprintf(str_ip, len, "%d.%d.%d.%d", (int_ip)&0xFF, (int_ip >> 8) & 0xFF,
            (int_ip >> 16) & 0xFF, (int_ip >> 24) & 0xFF);

    return;
}

/**
 *  @brief IPv6 Network to address display format
 *  @param str_ip Destination buffer, must be at least 17 bytes
 *  @param src_6 The address in big endian binary form
 *  @return void
 */
void internal_inet6_ntoa(char *str_ip, size_t len, struct in6_addr *src_6)
{
    if (!str_ip || len <= 32)
        return;

    memset(str_ip, 0, 32);
    snprintf(
        str_ip,
        len,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        (int)src_6->s6_addr[0], (int)src_6->s6_addr[1], (int)src_6->s6_addr[2],
        (int)src_6->s6_addr[3], (int)src_6->s6_addr[4], (int)src_6->s6_addr[5],
        (int)src_6->s6_addr[6], (int)src_6->s6_addr[7], (int)src_6->s6_addr[8],
        (int)src_6->s6_addr[9], (int)src_6->s6_addr[10],
        (int)src_6->s6_addr[11], (int)src_6->s6_addr[12],
        (int)src_6->s6_addr[13], (int)src_6->s6_addr[14],
        (int)src_6->s6_addr[15]);

    return;
}
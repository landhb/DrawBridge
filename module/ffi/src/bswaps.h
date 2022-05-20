#ifndef USERMODE_BSWAP
#define USERMODE_BSWAP 1

#include <byteswap.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define be16_to_cpup(x)	bswap_16(*x)
# define be32_to_cpup(x)	bswap_32(*x)
# define be64_to_cpup(x)	bswap_64(*x)
#elif BYTE_ORDER == BIG_ENDIAN
# define be16_to_cpup(x)	(x)
# define be32_to_cpup(x)	(x)
# define be64_to_cpup(x)	(x)
#endif

#endif /* USERMODE_BSWAP */ 
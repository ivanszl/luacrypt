#include <lua.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <lauxlib.h>
#include <crypt.h>
#include <stdlib.h>

#define GENERATE_SEED() (((long) (time(0) * getpid())) ^ ((long)1000000.0))
#define CRYPT_RAND get_rand()
#define MIN(m, n)  ((m) < (n)) ? (m) : (n)
#define STD_DES_CRYPT 1
#define MD5_CRYPT 1

#if STD_DES_CRYPT
#define MAX_SALT_LEN 2
#endif

#if EXT_DES_CRYPT
#undef MAX_SALT_LEN
#define MAX_SALT_LEN 9
#endif

#if MD5_CRYPT
#undef MAX_SALT_LEN
#define MAX_SALT_LEN 12
#endif


static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void _to64(char *s, long v, int n)
{
  while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}

}

static long get_rand() {
	long ret;
	srand((unsigned int) GENERATE_SEED());
	ret = rand();
	return ret;
}

static int mycrypt(lua_State *L)
{
	char salt[MAX_SALT_LEN + 1];
	char *crypt_res;
	const char *str, *salt_in = NULL;
	size_t salt_in_len = 0;
	
	salt[0] = salt[MAX_SALT_LEN] = '\0';

    if(lua_gettop(L) < 1)
    {
        lua_pushstring(L, "Bad argument number");
        lua_error(L);
        return 1;
    }

    if((str = lua_tostring(L, 1)) == NULL)
    {
        lua_pushstring(L, "Bad key");
        lua_error(L);
        return 1;
    }

    salt_in = lua_tolstring(L, 2, &salt_in_len);
	
    if (salt_in) {
		memcpy(salt, salt_in, MIN(MAX_SALT_LEN, salt_in_len));
	}
	
	if (!*salt) {
		#if MD5_CRYPT
		strncpy(salt, "$1$", MAX_SALT_LEN);
		_to64(&salt[3], CRYPT_RAND, 4);
		_to64(&salt[7], CRYPT_RAND, 4);
		strncpy(&salt[11], "$", MAX_SALT_LEN - 11);
		#elif STD_DES_CRYPT
		_to64(&salt[0], CRYPT_RAND, 2);
		salt[2] = '\0';
		#endif
		salt_in_len = strlen(salt);
	}
	else {
		salt_in_len = MIN(MAX_SALT_LEN, salt_in_len);
	}
	
	crypt_res = crypt(str, salt);

    lua_pushstring(L, crypt_res);
    return 1;
}


int luaopen_ccrypt(lua_State *L)
{
    luaL_Reg reg[] = {
        { "crypt", mycrypt},
        { NULL, NULL }
    };
    luaL_register(L, "ccrypt", reg);
    return 1;
}


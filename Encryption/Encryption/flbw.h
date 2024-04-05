#ifndef _FLBW_H_
#define _FLBW_H_

#define C_RED "\x1B[31m"
#define C_GRN "\x1B[32m"
#define C_YEL "\x1B[33m"
#define C_BLU "\x1B[34m"
#define C_MAG "\x1B[35m"
#define C_CYN "\x1B[36m"
#define C_WHT "\x1B[37m"
#define C_RESET "\x1B[0m"

#include <cctype>
#include <algorithm>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <ctype.h>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <random>
#include <vector>
#include <string>

class Base64
{
  public:
    std::string base64_encode(unsigned char const *buf, unsigned int bufLen);
    std::vector<unsigned char> base64_decode(std::string const &);
};


/* Help macros */
#define SHA1_ROL(value, bits) (((value) << (bits)) | (((value)&0xffffffff) >> (32 - (bits))))
#define SHA1_BLK(i) (block[i & 15] = SHA1_ROL(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define SHA1_R0(v, w, x, y, z, i)                                      \
    z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + SHA1_ROL(v, 5); \
    w = SHA1_ROL(w, 30);
#define SHA1_R1(v, w, x, y, z, i)                                         \
    z += ((w & (x ^ y)) ^ y) + SHA1_BLK(i) + 0x5a827999 + SHA1_ROL(v, 5); \
    w = SHA1_ROL(w, 30);
#define SHA1_R2(v, w, x, y, z, i)                                 \
    z += (w ^ x ^ y) + SHA1_BLK(i) + 0x6ed9eba1 + SHA1_ROL(v, 5); \
    w = SHA1_ROL(w, 30);
#define SHA1_R3(v, w, x, y, z, i)                                               \
    z += (((w | x) & y) | (w & x)) + SHA1_BLK(i) + 0x8f1bbcdc + SHA1_ROL(v, 5); \
    w = SHA1_ROL(w, 30);
#define SHA1_R4(v, w, x, y, z, i)                                 \
    z += (w ^ x ^ y) + SHA1_BLK(i) + 0xca62c1d6 + SHA1_ROL(v, 5); \
    w = SHA1_ROL(w, 30);


class SHA1
{
  public:
    SHA1();
    void update(const std::string &s);
    void update(std::istream &is);
    std::string final();
    static std::string from_file(const std::string &filename);

  private:
    typedef unsigned int uint32;  /* just needs to be at least 32bit */
    typedef unsigned long uint64; /* just needs to be at least 64bit */

    static const unsigned int DIGEST_INTS = 5; /* number of 32bit integers per SHA1 digest */
    static const unsigned int BLOCK_INTS = 16; /* number of 32bit integers per SHA1 block */
    static const unsigned int BLOCK_BYTES = BLOCK_INTS * 4;

    uint32 digest[DIGEST_INTS];
    std::string buffer;
    uint64 transforms;

    void reset();
    void transform(uint32 block[BLOCK_BYTES]);

    static void buffer_to_block(const std::string &buffer, uint32 block[BLOCK_BYTES]);
    static void read(std::istream &is, std::string &s, int max);
};


class SHA256
{
  protected:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long uint64;

    const static uint32 sha256_k[];
    static const unsigned int SHA224_256_BLOCK_SIZE = (512 / 8);

  public:
    void init();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int DIGEST_SIZE = (256 / 8);

  protected:
    void transform(const unsigned char *message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2 * SHA224_256_BLOCK_SIZE];
    uint32 m_h[8];
};

#define SHA2_SHFR(x, n) (x >> n)
#define SHA2_ROTR(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n) ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z) ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x, 2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x, 6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x, 7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x, 3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)              \
    {                                      \
        *((str) + 3) = (uint8)((x));       \
        *((str) + 2) = (uint8)((x) >> 8);  \
        *((str) + 1) = (uint8)((x) >> 16); \
        *((str) + 0) = (uint8)((x) >> 24); \
    }
#define SHA2_PACK32(str, x)                                                                                                                \
    {                                                                                                                                      \
        *(x) = ((uint32) * ((str) + 3)) | ((uint32) * ((str) + 2) << 8) | ((uint32) * ((str) + 1) << 16) | ((uint32) * ((str) + 0) << 24); \
    }


class SHA512
{
  protected:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long long uint64;

    const static uint64 sha512_k[];
    static const unsigned int SHA384_512_BLOCK_SIZE = (1024 / 8);

  public:
    void init();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int DIGEST_SIZE = (512 / 8);

  protected:
    void transform(const unsigned char *message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2 * SHA384_512_BLOCK_SIZE];
    uint64 m_h[8];
};

#define SHA2_SHFR(x, n) (x >> n)
#define SHA2_ROTR(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n) ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z) ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_F1(x) (SHA2_ROTR(x, 28) ^ SHA2_ROTR(x, 34) ^ SHA2_ROTR(x, 39))
#define SHA512_F2(x) (SHA2_ROTR(x, 14) ^ SHA2_ROTR(x, 18) ^ SHA2_ROTR(x, 41))
#define SHA512_F3(x) (SHA2_ROTR(x, 1) ^ SHA2_ROTR(x, 8) ^ SHA2_SHFR(x, 7))
#define SHA512_F4(x) (SHA2_ROTR(x, 19) ^ SHA2_ROTR(x, 61) ^ SHA2_SHFR(x, 6))
#define SHA2_UNPACK32(x, str)              \
    {                                      \
        *((str) + 3) = (uint8)((x));       \
        *((str) + 2) = (uint8)((x) >> 8);  \
        *((str) + 1) = (uint8)((x) >> 16); \
        *((str) + 0) = (uint8)((x) >> 24); \
    }
#define SHA2_UNPACK64(x, str)              \
    {                                      \
        *((str) + 7) = (uint8)((x));       \
        *((str) + 6) = (uint8)((x) >> 8);  \
        *((str) + 5) = (uint8)((x) >> 16); \
        *((str) + 4) = (uint8)((x) >> 24); \
        *((str) + 3) = (uint8)((x) >> 32); \
        *((str) + 2) = (uint8)((x) >> 40); \
        *((str) + 1) = (uint8)((x) >> 48); \
        *((str) + 0) = (uint8)((x) >> 56); \
    }
#define SHA2_PACK64(str, x)                                                                                                                                                                                                                                                    \
    {                                                                                                                                                                                                                                                                          \
        *(x) = ((uint64) * ((str) + 7)) | ((uint64) * ((str) + 6) << 8) | ((uint64) * ((str) + 5) << 16) | ((uint64) * ((str) + 4) << 24) | ((uint64) * ((str) + 3) << 32) | ((uint64) * ((str) + 2) << 40) | ((uint64) * ((str) + 1) << 48) | ((uint64) * ((str) + 0) << 56); \
    }


typedef struct s_de_de_de
{
  double i_f;
  double i_s;
  double i_t;
} t_de_de_de;

class FLBW
{
private:
  std::string _base_array;
  std::string _result_hash;
  std::string _message;
  std::string _version;
  clock_t _time_start, _time_end;
  int _base_size;
  int _error;
  int _bruteforce_difficulty;
  bool _bruteforce_protection;

  std::string strtr(std::string &source, std::string &toReplace, std::string &replaceWith);
  std::string str_rot(std::string str, int number);
  int rand_vals(int min, int max);
  std::vector<std::string> explode(char delim, std::string const &s);
  bool is_number(const std::string &s);

  std::string flbw_hash(std::string password);
  std::string flbw_hash_challenge(std::string password);
  t_de_de_de ascii_to_10(std::string str);
  std::string generate_array(int key);
  std::string crypt_word(std::string mot, std::string key_arr);
  std::vector<unsigned char> xor_encrypt(std::string str, std::string key);
  std::string xor_decrypt(std::vector<unsigned char> str, std::string key);
  std::string crypt_word_inv(std::string str, std::string key_arr, int key);
  std::string set_error_message(std::string message);
  void reset(void);

public:
  FLBW(void);
  int get_error();
  std::string get_message();
  std::string get_version();
  bool get_bruteforce_protection();
  int get_bruteforce_difficulty();
  float get_execution_time();
  std::string get_result_hash();
  void set_bruteforce_protection(bool activated);
  void set_bruteforce_difficulty(int value);
  std::string fn_sha1(std::string str);
  std::string fn_sha256(std::string str);
  std::string fn_sha512(std::string str);
  std::string flbw_encrypt(std::string data, std::string password);
  std::string flbw_decrypt(std::string data, std::string password);
};

#endif /* _FLBW_H_ */
#include "flbw.h"

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Base64::base64_encode(unsigned char const *buf, unsigned int bufLen)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (bufLen--)
    {
        char_array_3[i++] = *(buf++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::vector<unsigned char> Base64::base64_decode(std::string const &encoded_string)
{
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}


SHA1::SHA1()
{
    reset();
}

void SHA1::update(const std::string &s)
{
    std::istringstream is(s);
    update(is);
}

void SHA1::update(std::istream &is)
{
    std::string rest_of_buffer;
    read(is, rest_of_buffer, BLOCK_BYTES - buffer.size());
    buffer += rest_of_buffer;

    while (is)
    {
        uint32 block[BLOCK_INTS];
        buffer_to_block(buffer, block);
        transform(block);
        read(is, buffer, BLOCK_BYTES);
    }
}

/*
 * Add padding and return the message digest.
 */

std::string SHA1::final()
{
    /* Total number of hashed bits */
    uint64 total_bits = (transforms * BLOCK_BYTES + buffer.size()) * 8;

    /* Padding */
    buffer += (char)0x80;
    unsigned int orig_size = buffer.size();
    while (buffer.size() < BLOCK_BYTES)
    {
        buffer += (char)0x00;
    }

    uint32 block[BLOCK_INTS];
    buffer_to_block(buffer, block);

    if (orig_size > BLOCK_BYTES - 8)
    {
        transform(block);
        for (unsigned int i = 0; i < BLOCK_INTS - 2; i++)
        {
            block[i] = 0;
        }
    }

    /* Append total_bits, split this uint64 into two uint32 */
    block[BLOCK_INTS - 1] = total_bits;
    block[BLOCK_INTS - 2] = (total_bits >> 32);
    transform(block);

    /* Hex std::string */
    std::ostringstream result;
    for (unsigned int i = 0; i < DIGEST_INTS; i++)
    {
        result << std::hex << std::setfill('0') << std::setw(8);
        result << (digest[i] & 0xffffffff);
    }

    /* Reset for next run */
    reset();

    return result.str();
}

std::string SHA1::from_file(const std::string &filename)
{
    std::ifstream stream(filename.c_str(), std::ios::binary);
    SHA1 checksum;
    checksum.update(stream);
    return checksum.final();
}

void SHA1::reset()
{
    /* SHA1 initialization constants */
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    /* Reset counters */
    transforms = 0;
    buffer = "";
}

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */

void SHA1::transform(uint32 block[BLOCK_BYTES])
{
    /* Copy digest[] to working vars */
    uint32 a = digest[0];
    uint32 b = digest[1];
    uint32 c = digest[2];
    uint32 d = digest[3];
    uint32 e = digest[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    SHA1_R0(a, b, c, d, e, 0);
    SHA1_R0(e, a, b, c, d, 1);
    SHA1_R0(d, e, a, b, c, 2);
    SHA1_R0(c, d, e, a, b, 3);
    SHA1_R0(b, c, d, e, a, 4);
    SHA1_R0(a, b, c, d, e, 5);
    SHA1_R0(e, a, b, c, d, 6);
    SHA1_R0(d, e, a, b, c, 7);
    SHA1_R0(c, d, e, a, b, 8);
    SHA1_R0(b, c, d, e, a, 9);
    SHA1_R0(a, b, c, d, e, 10);
    SHA1_R0(e, a, b, c, d, 11);
    SHA1_R0(d, e, a, b, c, 12);
    SHA1_R0(c, d, e, a, b, 13);
    SHA1_R0(b, c, d, e, a, 14);
    SHA1_R0(a, b, c, d, e, 15);
    SHA1_R1(e, a, b, c, d, 16);
    SHA1_R1(d, e, a, b, c, 17);
    SHA1_R1(c, d, e, a, b, 18);
    SHA1_R1(b, c, d, e, a, 19);
    SHA1_R2(a, b, c, d, e, 20);
    SHA1_R2(e, a, b, c, d, 21);
    SHA1_R2(d, e, a, b, c, 22);
    SHA1_R2(c, d, e, a, b, 23);
    SHA1_R2(b, c, d, e, a, 24);
    SHA1_R2(a, b, c, d, e, 25);
    SHA1_R2(e, a, b, c, d, 26);
    SHA1_R2(d, e, a, b, c, 27);
    SHA1_R2(c, d, e, a, b, 28);
    SHA1_R2(b, c, d, e, a, 29);
    SHA1_R2(a, b, c, d, e, 30);
    SHA1_R2(e, a, b, c, d, 31);
    SHA1_R2(d, e, a, b, c, 32);
    SHA1_R2(c, d, e, a, b, 33);
    SHA1_R2(b, c, d, e, a, 34);
    SHA1_R2(a, b, c, d, e, 35);
    SHA1_R2(e, a, b, c, d, 36);
    SHA1_R2(d, e, a, b, c, 37);
    SHA1_R2(c, d, e, a, b, 38);
    SHA1_R2(b, c, d, e, a, 39);
    SHA1_R3(a, b, c, d, e, 40);
    SHA1_R3(e, a, b, c, d, 41);
    SHA1_R3(d, e, a, b, c, 42);
    SHA1_R3(c, d, e, a, b, 43);
    SHA1_R3(b, c, d, e, a, 44);
    SHA1_R3(a, b, c, d, e, 45);
    SHA1_R3(e, a, b, c, d, 46);
    SHA1_R3(d, e, a, b, c, 47);
    SHA1_R3(c, d, e, a, b, 48);
    SHA1_R3(b, c, d, e, a, 49);
    SHA1_R3(a, b, c, d, e, 50);
    SHA1_R3(e, a, b, c, d, 51);
    SHA1_R3(d, e, a, b, c, 52);
    SHA1_R3(c, d, e, a, b, 53);
    SHA1_R3(b, c, d, e, a, 54);
    SHA1_R3(a, b, c, d, e, 55);
    SHA1_R3(e, a, b, c, d, 56);
    SHA1_R3(d, e, a, b, c, 57);
    SHA1_R3(c, d, e, a, b, 58);
    SHA1_R3(b, c, d, e, a, 59);
    SHA1_R4(a, b, c, d, e, 60);
    SHA1_R4(e, a, b, c, d, 61);
    SHA1_R4(d, e, a, b, c, 62);
    SHA1_R4(c, d, e, a, b, 63);
    SHA1_R4(b, c, d, e, a, 64);
    SHA1_R4(a, b, c, d, e, 65);
    SHA1_R4(e, a, b, c, d, 66);
    SHA1_R4(d, e, a, b, c, 67);
    SHA1_R4(c, d, e, a, b, 68);
    SHA1_R4(b, c, d, e, a, 69);
    SHA1_R4(a, b, c, d, e, 70);
    SHA1_R4(e, a, b, c, d, 71);
    SHA1_R4(d, e, a, b, c, 72);
    SHA1_R4(c, d, e, a, b, 73);
    SHA1_R4(b, c, d, e, a, 74);
    SHA1_R4(a, b, c, d, e, 75);
    SHA1_R4(e, a, b, c, d, 76);
    SHA1_R4(d, e, a, b, c, 77);
    SHA1_R4(c, d, e, a, b, 78);
    SHA1_R4(b, c, d, e, a, 79);

    /* Add the working vars back into digest[] */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;

    /* Count the number of transformations */
    transforms++;
}

void SHA1::buffer_to_block(const std::string &buffer, uint32 block[BLOCK_BYTES])
{
    /* Convert the std::string (byte buffer) to a uint32 array (MSB) */
    for (unsigned int i = 0; i < BLOCK_INTS; i++)
    {
        block[i] = (buffer[4 * i + 3] & 0xff) | (buffer[4 * i + 2] & 0xff) << 8 | (buffer[4 * i + 1] & 0xff) << 16 | (buffer[4 * i + 0] & 0xff) << 24;
    }
}

void SHA1::read(std::istream &is, std::string &s, int max)
{
    char *buf = new char[max];
    is.read(buf, max);
    s.assign(buf, is.gcount());
}

const unsigned int SHA256::sha256_k[64] = //UL = uint32
    {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int)block_nb; i++)
    {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++)
        {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++)
        {
            w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++)
        {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++)
        {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++)
        {
            m_h[j] += wv[j];
        }
    }
}

void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE)
    {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0; i < 8; i++)
    {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}

const unsigned long long SHA512::sha512_k[80] = //ULL = uint64
    {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
     0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
     0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
     0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
     0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
     0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
     0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
     0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
     0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
     0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
     0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
     0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
     0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
     0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
     0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
     0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
     0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
     0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
     0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
     0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
     0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
     0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
     0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
     0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
     0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
     0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
     0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
     0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
     0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
     0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
     0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
     0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
     0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
     0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
     0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
     0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
     0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
     0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
     0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
     0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

void SHA512::transform(const unsigned char *message, unsigned int block_nb)
{
    uint64 w[80];
    uint64 wv[8];
    uint64 t1, t2;
    const unsigned char *sub_block;
    int i, j;
    for (i = 0; i < (int)block_nb; i++)
    {
        sub_block = message + (i << 7);
        for (j = 0; j < 16; j++)
        {
            SHA2_PACK64(&sub_block[j << 3], &w[j]);
        }
        for (j = 16; j < 80; j++)
        {
            w[j] = SHA512_F4(w[j - 2]) + w[j - 7] + SHA512_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++)
        {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 80; j++)
        {
            t1 = wv[7] + SHA512_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6]) + sha512_k[j] + w[j];
            t2 = SHA512_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++)
        {
            m_h[j] += wv[j];
        }
    }
}

void SHA512::init()
{
    m_h[0] = 0x6a09e667f3bcc908ULL;
    m_h[1] = 0xbb67ae8584caa73bULL;
    m_h[2] = 0x3c6ef372fe94f82bULL;
    m_h[3] = 0xa54ff53a5f1d36f1ULL;
    m_h[4] = 0x510e527fade682d1ULL;
    m_h[5] = 0x9b05688c2b3e6c1fULL;
    m_h[6] = 0x1f83d9abfb41bd6bULL;
    m_h[7] = 0x5be0cd19137e2179ULL;
    m_len = 0;
    m_tot_len = 0;
}

void SHA512::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA384_512_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA384_512_BLOCK_SIZE)
    {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA384_512_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA384_512_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 7], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 7;
}

void SHA512::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = 1 + ((SHA384_512_BLOCK_SIZE - 17) < (m_len % SHA384_512_BLOCK_SIZE));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 7;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0; i < 8; i++)
    {
        SHA2_UNPACK64(m_h[i], &digest[i << 3]);
    }
}

FLBW::FLBW(void)
{
    reset();
    _base_array = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ;";
    _base_size = _base_array.length();
    _version = "0.7.1";
    _bruteforce_protection = false;  // Will increase computing time both for enc. and dec.
    _bruteforce_difficulty = 250000; // Put your custom number here to secure your encryption.
}

/*
 * FLBW extern functions.
 */

std::vector<std::string> FLBW::explode(char delim, std::string const &s)
{
    std::vector<std::string> result;
    std::istringstream iss(s);
    std::size_t found = s.find(delim);

    if (found != std::string::npos)
        for (std::string token; std::getline(iss, token, delim);)
            result.push_back(std::move(token));
    else
        result.push_back(s);
    return (result);
}

std::string FLBW::strtr(std::string &source, std::string &toReplace, std::string &replaceWith)
{
    size_t pos = 0;
    size_t cursor = 0;
    int repLen = toReplace.length();
    std::stringstream builder;
    do
    {
        pos = source.find(toReplace, cursor);

        if (std::string::npos != pos)
        {
            builder << source.substr(cursor, pos - cursor);
            builder << replaceWith;
            cursor = pos + repLen;
        }
    } while (std::string::npos != pos);
    builder << source.substr(cursor);

    return (builder.str());
}

std::string FLBW::str_rot(std::string str, int number)
{
    std::string static letters = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
    std::string rep = "";

    number = (int)number % 26;
    if (!number)
        return str;
    if (number < 0)
        number += 26;

    rep = letters.substr(number * 2) + letters.substr(0, number * 2);
    str = strtr(str, letters, rep);
    return str;
}

std::string FLBW::fn_sha1(std::string str)
{
    SHA1 checksum;

    checksum.update(str);
    return (checksum.final());
}

std::string FLBW::fn_sha256(std::string str)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest, 0, SHA256::DIGEST_SIZE);
    SHA256 ctx = SHA256();

    ctx.init();
    ctx.update((unsigned char *)str.c_str(), str.length());
    ctx.final(digest);
    char buf[2 * SHA256::DIGEST_SIZE + 1];
    buf[2 * SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf + i * 2, "%02x", digest[i]);
    return (std::string(buf));
}

std::string FLBW::fn_sha512(std::string str)
{
    unsigned char digest[SHA512::DIGEST_SIZE];
    memset(digest, 0, SHA512::DIGEST_SIZE);
    SHA512 ctx = SHA512();
    ctx.init();
    ctx.update((unsigned char *)str.c_str(), str.length());
    ctx.final(digest);

    char buf[2 * SHA512::DIGEST_SIZE + 1];
    buf[2 * SHA512::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA512::DIGEST_SIZE; i++)
        sprintf(buf + i * 2, "%02x", digest[i]);
    return (std::string(buf));
}

int FLBW::rand_vals(int min, int max)
{
    std::random_device seeder;
    std::mt19937 engine(seeder());
    std::uniform_int_distribution<int> dist(min, max);
    return dist(engine);
}

bool FLBW::is_number(const std::string &s)
{
    return !s.empty() && std::find_if(s.begin(),
                                      s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

/*
 * FLBW intern functions.
 */

void FLBW::reset(void)
{
    _time_start = clock();
    _time_end = clock();
    _result_hash = "0000000000000000000000000000000000000000";
    _error = 0;
    _message = "";
}

bool FLBW::get_bruteforce_protection()
{
    return (_bruteforce_protection);
}

int FLBW::get_bruteforce_difficulty()
{
    return (_bruteforce_difficulty);
}

std::string FLBW::get_version()
{
    return (_version);
}

int FLBW::get_error()
{
    return (_error);
}

std::string FLBW::get_message()
{
    return (_message);
}

float FLBW::get_execution_time()
{
    return (((float)_time_end - (float)_time_start) / CLOCKS_PER_SEC);
}

std::string FLBW::get_result_hash()
{
    return (_result_hash);
}

void FLBW::set_bruteforce_protection(bool activated)
{
    _bruteforce_protection = activated;
}

void FLBW::set_bruteforce_difficulty(int value)
{
    _bruteforce_difficulty = value;
}

std::string FLBW::set_error_message(std::string message)
{
    _error = 1;
    _message = std::string(C_RED) + message + std::string(C_RESET);
    return (_message);
}

std::string FLBW::flbw_hash(std::string password)
{
    std::string step = fn_sha512(str_rot("flbw" + password, 5));
    step = str_rot(step, 42);
    return (fn_sha512(step + '%'));
}

std::string FLBW::flbw_hash_challenge(std::string password)
{
    std::string n_password = password;

    for (int i = 0; i < _bruteforce_difficulty; i++)
        n_password = fn_sha512(n_password);
    return (n_password);
}

t_de_de_de FLBW::ascii_to_10(std::string str)
{
    double sum = 0.0;
    t_de_de_de v_return;

    for (int i = 0; i < str.length(); i++)
        sum += (double)((int)str[i] - 48);
    v_return.i_f = sum;
    v_return.i_s = (sum / (double)str.length());
    v_return.i_t = (v_return.i_s * v_return.i_f);
    return (v_return);
}

std::string FLBW::generate_array(int key)
{
    std::string rpl = "";
    int i = 0;
    int np = 0;

    for (i = 0; i < _base_size; i++)
        if (i + key < _base_size)
            rpl += _base_array[i + key];
        else
        {
            np = abs(_base_size - i - key);
            rpl += _base_array[np];
        }
    return (rpl);
}

std::string FLBW::crypt_word(std::string str, std::string key_arr)
{
    std::string me = "";
    int a = 0;
    bool eb = false;

    if (key_arr.length() != _base_size)
    {
        set_error_message("Array error in crypt_word. Please report this bug.");
        exit;
    }
    for (int i = 0, l = str.length(); i < l; i++)
    {
        a = 0;
        eb = false;
        while (str[i] != _base_array[a] && eb != true)
            if (((i + 1) > (str.length() - 1)) || ((a + 1) > (key_arr.length() - 1)))
                eb = true;
            else
                a++;
        me += (str[i] == _base_array[a]) ? key_arr[a] : str[i];
    }
    return (me);
}

std::vector<unsigned char> FLBW::xor_encrypt(std::string str, std::string key)
{
    std::vector<unsigned char> r(str.length());
    for (size_t i = 0; i < str.length(); ++i)
        r[i] = str[i] ^ key[i % key.length()];
    return (r);
}

std::string FLBW::xor_decrypt(std::vector<unsigned char> str, std::string key)
{
    std::string rst;

    for (int i = 0; i != str.size(); i++)
        rst += str[i] ^ key[i % key.length()];
    return (rst);
}

std::string FLBW::crypt_word_inv(std::string str, std::string key_arr, int key)
{
    std::string rst = "";
    int a = 0;
    bool eb = false;
    const char *find;
    int index;

    if (key_arr.length() != _base_size)
    {
        set_error_message("Array error in crypt_word_inv. Please report this bug.");
        return (rst);
    }

    for (int i = 0, l = str.length(); i < l; i++)
    {
        a = 0;
        eb = false;
        while (str[i] != key_arr[a] && eb != true)
            if (((i + 1) > (str.length() - 1)) || ((a + 1) > (key_arr.length() - 1)))
                eb = true;
            else
                a++;
        if (str[i] == key_arr[a])
            rst += _base_array[a];
        else
        {
            if (_base_array.find(str[i]) != std::string::npos)
            {

                find = strchr(key_arr.c_str(), str[i]);
                index = (int)(find - key_arr.c_str());
                rst += _base_array[index];
            }
            else
                rst += str[i];
        }
    }
    return (rst);
}

std::string FLBW::flbw_encrypt(std::string data, std::string password)
{
    reset();
    Base64 base64;
    int key = rand_vals(1, 61);
    int stm = 0;
    int i;
    std::vector<unsigned char> rst_b;
    unsigned char *rst_b_c;
    std::string rst = "";
    std::string step = "";
    std::string needle;

    if (data.length())
    {
        password = (_bruteforce_protection) ? flbw_hash_challenge(password) : password;
        password = flbw_hash(password);
        t_de_de_de atod = ascii_to_10(password);
        std::string aotd_pass = fn_sha256(std::to_string(atod.i_t));
        std::string key_a = generate_array(key);
        std::vector<std::string> sst = explode(' ', data);
        for (i = 0; i < sst.size(); i++)
            if (stm != 0 || stm != sst.size())
                step += crypt_word(sst[i] + " ", key_a);
            else
            {
                step = crypt_word(sst[i], key_a);
                stm++;
            }
        needle = std::to_string(key) + ";" + step;
        rst_b = xor_encrypt(needle, password);
        rst_b_c = (unsigned char *)malloc(sizeof(rst_b) * rst_b.size());
        for (i = 0; i < rst_b.size(); i++)
            rst_b_c[i] = (unsigned char)rst_b[i];
        rst = base64.base64_encode(rst_b_c, rst_b.size());
        _result_hash = fn_sha1(rst);
    }
    else
        set_error_message("Can't cipher empty data.");
    _time_end = clock();
    return (rst);
}

std::string FLBW::flbw_decrypt(std::string data, std::string password)
{
    reset();
    Base64 base64;
    std::string key_a;
    std::string rst = "";
    _time_start = clock();
    int i, key;
    std::string bf_str, password_bf;

    if (data.length())
    {
        password = (_bruteforce_protection) ? flbw_hash_challenge(password) : password;
        password = flbw_hash(password);
        t_de_de_de atod = ascii_to_10(password);
        std::string aotd_pass = fn_sha256(std::to_string(atod.i_t));
        std::vector<unsigned char> str_b = base64.base64_decode(data);
        std::vector<unsigned char> bf_str_b;
        std::string str;
        str = xor_decrypt(str_b, password);
        std::size_t found = str.find(";");
        std::string right;

        if (found != std::string::npos)
        {
            std::vector<std::string> sst = explode(';', str);
            if (sst.size() >= 2 && is_number(sst[0]))
            {
                key = std::stoi(sst[0]);
                right = "";
                if (sst.size() > 2)
                    for (i = 1; i < sst.size(); i++)
                        right += (sst.size() - 1 == i) ? sst[i] : sst[i] + ';';
                else
                    right = sst[1];
                key_a = generate_array(key);
                if (key_a.length())
                {
                    rst = crypt_word_inv(right, key_a, key);
                    if (rst[rst.length() - 1] == ' ')
                        rst = rst.substr(0, rst.length() - 1);
                    _result_hash = fn_sha1(rst);
                }
                else
                    rst = "";
            }
            else
                set_error_message("Invalid decode : wrong password suspected.");
        }
        else
            set_error_message("Wrong password.");
    }
    else
        set_error_message("Can't decipher empty data.");
    _time_end = clock();
    return (rst);
}

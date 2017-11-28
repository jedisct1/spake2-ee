static inline void
_push16(unsigned char *out, size_t *i_p, uint16_t v)
{
    memcpy(&out[*i_p], &v, 2);
    (*i_p) += 2;
}

static inline void
_push64(unsigned char *out, size_t *i_p, uint64_t v)
{
    memcpy(&out[*i_p], &v, 8);
    (*i_p) += 8;
}

static inline void
_push128(unsigned char *out, size_t *i_p, const unsigned char v[16])
{
    memcpy(&out[*i_p], v, 16);
    (*i_p) += 16;
}

static inline void
_push256(unsigned char *out, size_t *i_p, const unsigned char v[32])
{
    memcpy(&out[*i_p], v, 32);
    (*i_p) += 32;
}

static inline void
_pop16(uint16_t *v, const unsigned char *in, size_t *i_p)
{
    memcpy(v, &in[*i_p], 2);
    (*i_p) += 2;
}

static inline void
_pop64(uint64_t *v, const unsigned char *in, size_t *i_p)
{
    memcpy(v, &in[*i_p], 8);
    (*i_p) += 8;
}

static inline void
_pop128(unsigned char v[32], const unsigned char *in, size_t *i_p)
{
    memcpy(v, &in[*i_p], 16);
    (*i_p) += 16;
}

static inline void
_pop256(unsigned char v[32], const unsigned char *in, size_t *i_p)
{
    memcpy(v, &in[*i_p], 32);
    (*i_p) += 32;
}


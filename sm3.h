#ifndef SM3_H
#define SM3_H

//#define R(v,n)(((v)<<(n))|((v)>>(32-(n))))
#define F(n)for(i=0;i<n;i++)

// #define rev32(x) __builtin_bswap32(x)
// #define rev64(x) __builtin_bswap64(x)


#define rev32(x) bswap32(x)
#define rev64(x) bswap64(x)

typedef unsigned long long Q;
typedef unsigned int W;
typedef unsigned char B;

typedef struct _sm3_ctx {
    W s[8];
    union {
      B b[64];
      W w[16];
      Q q[8];
    }x;
    Q len;
}sm3_ctx;

#ifdef __cplusplus
extern "C" {
#endif



__global__ 
void gpu_sm3(void* d_m, int len_m ,unsigned char* d_h);
__global__
void find_valid_nounce(int n, const unsigned char* boundry, const char* msg, int msg_len);
void host_find_valid_nounce(Q N, const unsigned char* boundry, const char* msg);
// void sm3_init(sm3_ctx *c);
// void sm3_update(sm3_ctx *c, const void *in, W len);
// void sm3_final(void *out,sm3_ctx *c);



#ifdef __cplusplus
}
#endif

#endif

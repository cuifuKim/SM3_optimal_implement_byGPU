#ifndef SM3_H
#define SM3_H

#define F(n)for(i=0;i<n;i++)

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

__global__ void gpu_sm3(void* d_m, int len_m ,unsigned char* d_h);
__global__  void find_valid_nounce(int n, const unsigned char* boundry, const char* msg, int msg_len);
void host_find_valid_nounce(Q N, const unsigned char* boundry, const char* msg);

#ifdef __cplusplus
}
#endif

#endif

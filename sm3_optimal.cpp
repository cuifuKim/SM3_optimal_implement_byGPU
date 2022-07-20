#define MAX_CHAR_NUM 1024*512
#define MAXSIZE 1024*MAX_CHAR_NUM	//Assume that the maximum encrypted file size is 2KB

unsigned int hash_all = 0;
unsigned int hash_rate = 0;//Total message block
unsigned int t[64];//Calculate the value of constant T in advance for storage

static const int endianTest = 1;/*Determine whether the operating environment is a small end*/

#define IsLittleEndian() (*(char *)&endianTest == 1)
#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )//Left cyclic shift

unsigned int *ReverseWord(unsigned int *word){//Reverse four byte integer byte order
	unsigned char *byte, temp;

	byte = (unsigned char *)word;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;

	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return word;
}

unsigned int T(int i){
	if (i >= 0 && i <= 15)	return 0x79CC4519;
	else if (i >= 16 && i <= 63)	return 0x7A879D8A;
	else	return 0;
}

void caculT(){//Precalculate
	for (int i = 0; i < 64; i++)	t[i] = LeftRotate(T(i),i);
	return ;
}

unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i){
	if (i >= 0 && i <= 15)		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)	return (X & Y) | (X & Z) | (Y & Z);
	else				return 0;
}

unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i){
	if (i >= 0 && i <= 15)		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)	return (X & Y) | (~X & Z);
	else				return 0;
}

unsigned int P0(unsigned int X):	return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);//P0
unsigned int P1(unsigned int X):	return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);//P1

void SM3Init(SM3::SM3Context *context) {//initial function
	context->intermediateHash[0] = 0x7380166F;	context->intermediateHash[1] = 0x4914B2B9;
	context->intermediateHash[2] = 0x172442D7;	context->intermediateHash[3] = 0xDA8A0600;
	context->intermediateHash[4] = 0xA96F30BC;	context->intermediateHash[5] = 0x163138AA;
	context->intermediateHash[6] = 0xE38DEE4D;	context->intermediateHash[7] = 0xB0FB0E4E;
}

void one_round(int i,unsigned int &A, unsigned int &B, unsigned int &C, unsigned int &D,unsigned int &E, unsigned int &F, unsigned int &G, unsigned int &H, unsigned int W[68],SM3::SM3Context *context){//new compress func
	unsigned int SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
	if (i < 12) {
		W[i+4] = *(unsigned int *)(context->messageBlock + (i+4) * 4);
		if (IsLittleEndian())	ReverseWord(W + i + 4);
	}
	else 	W[i+4] = ((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)) ^ LeftRotate((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)), 15) ^ LeftRotate((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)), 23))^ LeftRotate(W[i - 9], 7)^ W[i - 2];

	//cal mid val TT1 and TT2
	TT2 = LeftRotate(A, 12);
	TT1 = TT2 + E + t[i];
	TT1 = LeftRotate(TT1, 7);
	TT2 ^= TT1;

	//only update byte register B、D、F、H
	D = D + FF(A, B, C, i) + TT2 + (W[i] ^ W[i + 4]);
	H = H + GG(E, F, G, i) + TT1 + W[i];
	B = LeftRotate(B, 9);
	F = LeftRotate(F, 19);
	H = H ^ LeftRotate(H, 9) ^ LeftRotate(H, 17);
}

void SM3ProcessMessageBlock(SM3::SM3Context *context){
	int i;
	unsigned int W[68];
	unsigned int A, B, C, D, E, F, G, H;

	for (i = 0; i < 4; i++)	{
		W[i] = *(unsigned int *)(context->messageBlock + i * 4);
		if (IsLittleEndian())	ReverseWord(W + i);
	}
	A = context->intermediateHash[0];	B = context->intermediateHash[1];
	C = context->intermediateHash[2];	D = context->intermediateHash[3];
	E = context->intermediateHash[4];	F = context->intermediateHash[5];
	G = context->intermediateHash[6];	H = context->intermediateHash[7];
	for (i = 0; i <= 60; i+=4){
		one_round(i, A, B, C, D, E, F, G, H, W, context);
		one_round(i+1, D, A, B, C, H, E, F, G, W, context);
		one_round(i+2, C, D, A, B, G, H, E, F, W, context);
		one_round(i+3, B, C, D, A, F, G, H, E, W, context);
	}
	context->intermediateHash[0] ^= A;	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;	context->intermediateHash[7] ^= H;
}

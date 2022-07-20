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


/*新的一轮压缩算法*/
void one_round(int i,unsigned int &A, unsigned int &B, unsigned int &C, unsigned int &D,
	unsigned int &E, unsigned int &F, unsigned int &G, unsigned int &H, unsigned int W[68],SM3::SM3Context *context)
{
	unsigned int SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
	//计算消息扩展字Wi+4
	if (i < 12) {
		W[i+4] = *(unsigned int *)(context->messageBlock + (i+4) * 4);
		if (IsLittleEndian())
			ReverseWord(W + i + 4);
	}
	else {
		/*P1*/
		W[i+4] = ((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)) ^ LeftRotate((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)), 15) ^ LeftRotate((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)), 23))
			^ LeftRotate(W[i - 9], 7)
			^ W[i - 2];
		}

	//计算中间变量TT1和TT2
	TT2 = LeftRotate(A, 12);
	TT1 = TT2 + E + t[i];
	TT1 = LeftRotate(TT1, 7);
	TT2 ^= TT1;

	//仅更新字寄存器B、D、F、H
	D = D + FF(A, B, C, i) + TT2 + (W[i] ^ W[i + 4]);
	H = H + GG(E, F, G, i) + TT1 + W[i];
	B = LeftRotate(B, 9);
	F = LeftRotate(F, 19);
	H = H ^ LeftRotate(H, 9) ^ LeftRotate(H, 17);
}

/* 处理消息块*/
void SM3ProcessMessageBlock(SM3::SM3Context *context)
{
	int i;
	unsigned int W[68];
	//A-H是8个字寄存器
	unsigned int A, B, C, D, E, F, G, H;

	/* 消息扩展 */

	for (i = 0; i < 4; i++)
	{
		W[i] = *(unsigned int *)(context->messageBlock + i * 4);
		if (IsLittleEndian())
			ReverseWord(W + i);
		//        printf("%d: %x\n", i, W[i]);
	}

	/* 消息压缩 */
	A = context->intermediateHash[0];
	B = context->intermediateHash[1];
	C = context->intermediateHash[2];
	D = context->intermediateHash[3];
	E = context->intermediateHash[4];
	F = context->intermediateHash[5];
	G = context->intermediateHash[6];
	H = context->intermediateHash[7];
	for (i = 0; i <= 60; i+=4)
	{
		one_round(i, A, B, C, D, E, F, G, H, W, context);
		one_round(i+1, D, A, B, C, H, E, F, G, W, context);
		one_round(i+2, C, D, A, B, G, H, E, F, W, context);
		one_round(i+3, B, C, D, A, F, G, H, E, W, context);

	}
	context->intermediateHash[0] ^= A;
	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;
	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;
	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;
	context->intermediateHash[7] ^= H;
}

/*
* SM3算法主函数:
	message代表需要加密的消息字节串;
	messagelen是消息的字节数;
	digset表示返回的哈希值
*/
unsigned char *SM3::SM3Calc(const unsigned char *message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
	SM3::SM3Context context;
	unsigned int i, remainder, bitLen;

	/* 初始化上下文 */
	SM3Init(&context);//设置IV的初始值
	hash_all = messageLen / 64 + 1;//计算总块数
	remainder = messageLen % 64;
	if (remainder > 55) {
		hash_all += 1;//总块数还要+1
	}
	/* 对前面的消息分组进行处理 */
	for (i = 0; i < messageLen / 64; i++)
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		hash_rate = i + 1;//每处理一个512bit的消息块，进度就+1
		SM3ProcessMessageBlock(&context);
	}

	/* 填充消息分组，并处理 */
	bitLen = messageLen * 8;
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;//添加bit‘0x1000 0000’到末尾
	if (remainder <= 55)//如果剩下的bit数少于440
	{
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		hash_rate += 1;//计算最后一个短块
		SM3ProcessMessageBlock(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		hash_rate += 1;//计算短块
		SM3ProcessMessageBlock(&context);
		/* 长度按照大端法占8个字节，只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		hash_rate += 1;//计算最后一个短块
		SM3ProcessMessageBlock(&context);
	}

	/* 返回结果 */
	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);

	return digest;
}

/*
* call_hash_sm3函数
	输入参数：文件地址字符串
	输出：向量vector<unit32_t> hash_result(32)
*/
std::vector<uint32_t> SM3::call_hash_sm3(char *filepath)
{
	std::vector<uint32_t> hash_result(32, 0);
	std::ifstream infile;
	uint32_t FILESIZE = 0;
	unsigned char * buffer = new unsigned char[MAXSIZE];
	unsigned char hash_output[32];
	/*获取文件大小*/
	struct _stat info;
	_stat(filepath, &info);
	FILESIZE = info.st_size;
	/*打开文件*/
	infile.open(filepath, std::ifstream::binary);
	infile >> buffer;
	/*	printf("Message:\n");
		printf("%s\n", buffer);
	*/
	auto start = std::chrono::high_resolution_clock::now();
	SM3::SM3Calc(buffer, FILESIZE, hash_output);
	auto end = std::chrono::high_resolution_clock::now();
	// 以毫秒为单位，返回所用时间
	std::cout << "in millisecond time:";
	std::chrono::duration<double, std::ratio<1, 1000>> diff = end - start;
	std::cout << "Time is " << diff.count() << " ms\n";
	/*	printf("Hash:\n   ");
		for (int i = 0; i < 32; i++)
		{
			printf("%02x", hash_output[i]);
			if (((i + 1) % 4) == 0) printf(" ");
		}
		printf("\n");
	*/
	hash_result.assign(&hash_output[0], &hash_output[32]);
	/*	for (int i = 0; i < 32; i++) {
			std::cout <<std::hex << std::setw(2) << std::setfill('0') << hash_result[i];
			if (((i + 1) % 4) == 0) std::cout <<" ";
		}
		std::cout << std::endl;
	*/
	delete[]buffer;
	return hash_result;
}

/*计算当前哈希进度*/
double progress() {
	return (double(hash_rate) / hash_all);
}

/*创建固定大小的文件*/
void CreatTxt(char* pathName, int length)//创建txt文件
{
	ofstream fout(pathName);
	char char_list[] = "abcdefghijklmnopqrstuvwxyz";
	int n = 26;
	if (fout) { // 如果创建成功
		for (int i = 0; i < length; i++)
		{
			fout << char_list[rand() % n]; // 使用与cout同样的方式进行写入
		}

		fout.close();  // 执行完操作后关闭文件句柄
	}
}

/*测试函数*/
int main() {
	char filepath[] = "test.txt";
	CreatTxt(filepath, MAX_CHAR_NUM);
	std::vector<uint32_t> hash_result;
	caculT();
	hash_result = SM3::call_hash_sm3(filepath);
	for (int i = 0; i < 32; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << hash_result[i];
		if (((i + 1) % 4) == 0) std::cout << " ";
	}
	std::cout << std::endl;

	double rate = progress();
	printf("\n当前进度: %f", rate);

	return 0;
}

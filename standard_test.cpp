
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

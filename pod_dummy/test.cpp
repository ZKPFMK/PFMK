#include <iostream>
int main()
{
	int stack[2097152]; //2097152*4=8192k(申请内存太大，出错)
	//int stack[2000000];  // 正确
	stack[0]=1;
	
	return 0;
}

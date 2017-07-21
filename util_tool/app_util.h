/* app_util.h -- internal utility state
 * Copyright (C++) forever zhangcl 791398105@qq.com
 * welcome to use freely
 */

#ifndef TEMPLATE_APP_UTIL
#define TEMPLATE_APP_UTIL

#include "c_util.h"


// CBase64 for Base64's Encoding and Decoding
class CBase64
{
	typedef struct str_type_enc
	{
		int length;				
		unsigned char remainchr[2];		
		int linetime;			
	}STelem_enc;

	typedef struct str_type_dec
	{
		int length;				
		unsigned char remainchr[3];		
	}STelem_dec;
private:
	static int m_DelimiterSet;
public:
	static void setDelimiterSet(int DelimiterSet);
private:
	static void encodeini(unsigned char **e);
	static long  encodeupdate(unsigned char *bufferA, long strlength, unsigned char *bufferB, unsigned char *tem);
	static long  encodefinish(unsigned char *bufferC, unsigned char *temp);
	static long  decodeini(unsigned char **e );
	static long  decodeupdate(unsigned char *bufferA, long strlength, unsigned char *bufferB, unsigned char *tem);
	static long  decodefinish(unsigned char *bufferC, unsigned char **temp);
protected:
	static unsigned char* Base64(const unsigned char *pData, long Length, long *OutLen);
	static unsigned char* Unbase64(const unsigned char *pData, long Length, long *OutLen);
public:
	static CMemBlock<unsigned char> Encode(const unsigned char *pData, long Length);
	static CMemBlock<unsigned char> Decode(const unsigned char *pData, long Length);
};

// Der Decode
typedef struct _TLVNode
{
	unsigned char T;
	size_t L;
	CMemBlock<unsigned char> V;
	_TLVNode()
	{
		T = 0;
		L = 0;
	}
	_TLVNode(const _TLVNode &tlvNode)
	{
		T = tlvNode.T;
		L = tlvNode.L;
		V = tlvNode.V;
	}
	_TLVNode& operator=(const _TLVNode &tlvNode)
	{
		T = tlvNode.T;
		L = tlvNode.L;
		V = tlvNode.V;
		return *this;
	}
}TLVNode;

class CTLVOf1Level
{
public:
	static bool Decode(const unsigned char* pEncode, const size_t len, std::vector<TLVNode> &nodeList);
	static CMemBlock<unsigned char> Encode(unsigned char Tag, size_t Len, CMemBlock<unsigned char> &Value);
};

#ifdef __cplusplus
extern "C" {
#endif
const unsigned char* MemFind(const unsigned char* pSrc, size_t srcLen, const unsigned char* pDes, size_t desLen);
const unsigned char* MemFindLast(const unsigned char* pSrc, size_t srcLen, const unsigned char* pDes, size_t desLen);
#ifdef __cplusplus
}
#endif

class CHexByte
{
	CMemBlock<char> m_Byte;
	CMemBlock<char> m_Hex;
	CMemBlock<char> m_ByteStr;
	CMemBlock<char> m_HexStr;
public:
	CHexByte(const char* pByte, size_t size_byte);
	CHexByte(size_t size_hex, const char* pHex);
	~CHexByte();	
public:
	CMemBlock<char> getByte();
	CMemBlock<char> getHex();
	CMemBlock<char> getByteStr();
	CMemBlock<char> getHexStr();
};

#ifdef __cplusplus
extern "C" {
#endif
void IntEncode(const unsigned int i, size_t& len, char* p);
unsigned int IntDecode(const char* p, size_t len);
void Int64Encode(const unsigned long long ll, size_t& len, char* p);
unsigned long long Int64Decode(const char* p, size_t len);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
bool OIDEncode(const long* oid, size_t& len, char* p);
bool OIDDecode(const char* e, size_t& len, long* p);
#ifdef __cplusplus
}
#endif



#endif

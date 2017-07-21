/* app_util.cpp -- internal utility state
 * Copyright (C++) forever zhangcl 791398105@qq.com
 * welcome to use freely
 */

#include "app_util.h"

template<typename T>
void finteger2char256(CMemBlock<char>& res, T t)
{
	if (0==t)
	{
		res.Reverse();
		return;
	}
	else
	{
		T surp = t/256;
		char tmp = (char)(t%256);
		size_t l = res.GetSize();
		res.Resize(l+1);
		res[l] = tmp;
		finteger2char256(res, surp);
	}
}

// CBase64 implementaion
int CBase64::m_DelimiterSet = 1;

void CBase64::setDelimiterSet(int DelimiterSet)
{
	m_DelimiterSet = DelimiterSet;
}

void CBase64::encodeini(unsigned char **e)
{
	STelem_enc *elem;
	elem=(STelem_enc *)malloc(sizeof(STelem_enc));
	elem->length = 0;
	elem->remainchr[0] = 0;
	elem->remainchr[1] = 0;
	elem->linetime = 1;
	*e = (unsigned char *)elem;
}

long CBase64::encodeupdate(unsigned char *bufferA, long strlength, unsigned char *bufferB, unsigned char *tem)
{
	long i=0,j=0,k=0,count=0;
	long num=0;
	unsigned char chr=0;
	unsigned char buffer[3]={0,0};
	unsigned char decode[256];
	unsigned char temp=0;
	unsigned char result1[4]={0,0,0,0};

	memset((unsigned char *)decode , 0 ,256);

	STelem_enc *y;
	y=(STelem_enc *)tem;
	memset(decode,0,256);
	memset(result1,0,4);
	memset(buffer,0,3);
	j=0;
	k=0;
	for(chr=65,num=0;chr<=90;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x1A;
	for(chr=97;chr<=122;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x34;
	for(chr=48;chr<=57;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	decode[0x3E]=43;
	decode[0x3F]=47;
	decode[0x40]=61;

	while(j<strlength)
	{
		for(count=0;(count<=2)&&(j<strlength);count++)
		{
			if (y->length==0)
			{
				temp=bufferA[j];
				buffer[count]=temp;
				j=j+1;
			}
			else if(y->length==2)
			{
				buffer[count]=(y->remainchr[0]);
				count=count+1;
				buffer[count]=(y->remainchr[1]);
				count=count+1;
				temp=bufferA[j];
				buffer[count]=temp;
				j=j+1;
				(y->remainchr[0])=0;
				(y->remainchr[1])=0;
				y->length=0;

			}
			else
			{
				buffer[count]=(y->remainchr[0]);
				count=count+1;
				temp=bufferA[j];
				buffer[count]=temp;
				count=count+1;
				j=j+1;
				temp=bufferA[j];
				buffer[count]=temp;
				j=j+1;
				(y->remainchr[0])=0;
				y->length=0;
			}
		}
		if( count == 3 ) 
		{
			result1[0]=buffer[0]>>2;
			result1[1]=((buffer[0]&0x03)<<4)|(buffer[1]>>4);
			result1[2]=((buffer[1]&0x0F)<<2)|(buffer[2]>>6);
			result1[3]=buffer[2]&0x3F;
			for( i = 0;i<=3;i++)
			{
				bufferB[k]=decode[result1[i]];
				k=k+1;
				y->linetime=y->linetime+1;
				if(y->linetime>76)
				{
					y->linetime=1;
				}	
			}
			memset(buffer,0,3);
		}
		else if( count == 2 )
		{	
			(y->remainchr[0])=buffer[0];
			(y->remainchr[1])=buffer[1];
			y->length=2;
			memset(buffer,0,3);

		}
		else if( count == 1 )
		{	
			(y->remainchr[0])=buffer[0];
			(y->remainchr[1])=0;
			y->length=1;
			memset(buffer,0,3);
		}
		else {}
	}
	return (k);
}

long CBase64::encodefinish(unsigned char *bufferC, unsigned char *temp)
{
	unsigned char result1[4]={0,0,0,0};
	long i=0,j=0;
	long num=0;
	unsigned char chr=0;
	unsigned char decode[256];
	STelem_enc *y=NULL;

	memset((unsigned char *) decode , 0 ,256);

	y=(STelem_enc *)temp;
	memset(decode,0,256);
	memset(result1,0,4);
	j=0;
	for(chr=65,num=0;chr<=90;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x1A;
	for(chr=97;chr<=122;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	num=0x34;
	for(chr=48;chr<=57;chr++)
	{
		decode[num]=chr;
		num=num+1;
	}
	decode[0x3E]=43;
	decode[0x3F]=47;
	decode[0x40]=61;
	if(y->length==2)
	{	
		result1[0]=((y->remainchr[0]))>>2;
		result1[1]=((((y->remainchr[0]))&0x03)<<4)|(((y->remainchr[1]))>>4);
		result1[2]=((((y->remainchr[1]))&0x0F)<<2);
		result1[3]=0x40;

		for( i = 0;i<=3;i++)
		{
			bufferC[j]=decode[result1[i]];
			j=j+1;
			y->linetime=y->linetime+1;
			if(y->linetime>76)
			{
				y->linetime=1;
			}						
		}
		memset((y->remainchr),0,2);
	}
	else if(y->length==1)
	{	
		result1[0]=((y->remainchr[0]))>>2;
		result1[1]=(((y->remainchr[0]))&0x03)<<4;
		result1[2]=0x40;
		result1[3]=0x40;

		for( i = 0;i<=3;i++)
		{
			bufferC[j]=decode[result1[i]];
			j=j+1;
			y->linetime=y->linetime+1;
			if(y->linetime>76)
			{
				y->linetime=1;
			}						
		}
		memset(y->remainchr,0,2);
	}
	else{}

	return(j);
}

long CBase64::decodeini(unsigned char **e)
{
	STelem_dec *elem=NULL;
	elem=(STelem_dec *)malloc(sizeof(STelem_dec));
	if(elem==NULL) return -1;
	elem->length=0;
	elem->remainchr[0]=0;
	elem->remainchr[1]=0;
	elem->remainchr[2]=0;
	*e = (unsigned char *)elem;
	return 0;
}

long CBase64::decodeupdate(unsigned char *bufferA, long strlength, unsigned char *bufferB, unsigned char *tem)
{
	unsigned char buffer[4]={0,0,0,0};
	unsigned char bak[4]={0,0,0,0};
	unsigned char encode[256];
	unsigned char resultA[3]={0,0,0};
	unsigned char resultB[2]={0,0};
	unsigned char resultC[1]={0};
	long count=0,i=0,j=0,k=0;
	unsigned char temp=0;
	STelem_dec *y=NULL;	

	memset((unsigned char *)encode , 0x00 , 256);

	if(tem==NULL) return 0; // none characters decode.
	if(bufferA == NULL) return 0; // no input , no output
	if(bufferB==NULL) return strlength ; // need atmost strlength memory.

	y=(STelem_dec *)tem;
	j=0;
	k=0;
	memset(buffer,0,4);
	memset(bak,0,4);
	memset(resultA,0,3);
	memset(resultB,0,2);
	memset(resultC,0,1);
	memset(encode,0,256);
	i=0;
	for(count=65;count<=90;count++)
	{
		encode[count]=0x00+(unsigned char)i;
		i++;
	}
	i=0;
	for(count=97;count<=122;count++)
	{	
		encode[count]=0x1A+(unsigned char)i;
		i++;
	}
	i=0;
	for(count=48;count<=57;count++)
	{
		encode[count]=0x34+(unsigned char)i;
		i++;
	}
	encode[43]=0x3E;
	encode[47]=0x3F;
	encode[61]=0x40;

	while(j<strlength)
	{
		for(count=0;(count<=3)&&(j<strlength);count++)
		{
			temp=bufferA[j];
			if (((encode[temp]==0)&&(temp!=65))|(temp==0x0a))
			{
				count=count-1;
				j=j+1;
			}
			else
			{
				if(y->length==3)
				{
					buffer[count]=(y->remainchr[0]);
					bak[count]=encode[buffer[count]];
					count=count+1;
					buffer[count]=(y->remainchr[1]);
					bak[count]=encode[buffer[count]];
					count=count+1;
					buffer[count]=(y->remainchr[2]);
					bak[count]=encode[buffer[count]];

					y->remainchr[0]=0;
					y->remainchr[1]=0;
					y->remainchr[2]=0;
					y->length=0;
				}
				else if(y->length==2)
				{
					buffer[count]=(y->remainchr[0]);
					bak[count]=encode[buffer[count]];
					count=count+1;
					buffer[count]=(y->remainchr[1]);
					bak[count]=encode[buffer[count]];

					(y->remainchr[0])=0;
					(y->remainchr[1])=0;
					y->length=0;
				}
				else if(y->length==1)
				{
					buffer[count]=(y->remainchr[0]);
					bak[count]=encode[buffer[count]];

					(y->remainchr[0])=0;
					y->length=0;	
				}
				else // include (y->length==0) , so update by pengcd.
				{
					buffer[count]=temp;
					bak[count]=encode[buffer[count]];
					j=j+1;
				}
			}
		}
		if (count==4)
		{
			if((buffer[0]!=61)&&(buffer[1]!=61)&&(buffer[2]!=61)&&(buffer[3]!=61))		
			{
				resultA[0]=(bak[0]<<2)|((bak[1]&0xf0)>>4);
				resultA[1]=((bak[1]&0x0F)<<4)|((bak[2]&0xfc)>>2);
				resultA[2]=((bak[2]&0x03)<<6)|bak[3];
				for( i = 0;i<=2;i++)
				{
					bufferB[k]=resultA[i];
					k=k+1;
				}
				memset(buffer,0,4);
				memset(bak,0,4);
			}
			else if((buffer[0]!=61)&&(buffer[1]!=61)&&(buffer[2]!=61)&&(buffer[3]==61))
			{
				resultB[0]=(bak[0]<<2)|((bak[1]&0xf0)>>4);
				resultB[1]=((bak[1]&0x0F)<<4)|((bak[2]&0xfc)>>2);
				for( i = 0;i<=1;i++)
				{
					bufferB[k]=resultB[i];
					k=k+1;
				}
				memset(buffer,0,4);
				memset(bak,0,4);
				break; // packge end for detect the '='.
			}
			else if ((buffer[0]!=61)&&(buffer[1]!=61)&&(buffer[2]==61)&&(buffer[3]==61))
			{
				resultC[0]=(bak[0]<<2)|((bak[1]&0xf0)>>4);
				bufferB[k]=resultC[0];
				k=k+1;	
				memset(buffer,0,4);
				memset(bak,0,4);
				break; // packge end for detect the '='.
			}
			else
			{
				// when '=' is present in other place , maybe error occured , update by pengcd.
				k=0;
				break;
			}

		}
		else if( count == 3 ) 
		{	
			y->remainchr[0]=buffer[0];
			y->remainchr[1]=buffer[1];
			y->remainchr[2]=buffer[2];
			y->length=3;
			memset(buffer,0,4);
		}
		else if( count == 2 )
		{	
			(y->remainchr[0])=buffer[0];
			(y->remainchr[1])=buffer[1];
			y->length=2;
			memset(buffer,0,4);

		}
		else if( count == 1 )
		{	
			y->remainchr[0]=buffer[0];
			y->length=1;
			memset(buffer,0,4);
		}
		else {}

	}

	// k is the deocde length.
	return (k); 
}

long CBase64::decodefinish(unsigned char *bufferC, unsigned char **temp)
{
	long i=0,len=0;
	STelem_dec *y=NULL;	

	if(temp == NULL) return 0;
	if(*temp == NULL) return 0;

	y=(STelem_dec *)*temp;
	if(y->length > 0 && y->length <4)
	{
		for(i=0;i<y->length;i++)
			bufferC[i]=y->remainchr[i];
		len = y->length;
	}
	else
	{
		len = 0;
	}
	free(*temp);
	*temp=NULL;

	return len;
}

unsigned char* CBase64::Base64(const unsigned char *pData, long Length, long *OutLen)
{
	if (OutLen)
	{
		*OutLen = 0;
	}

	if (pData && Length > 0)
	{
		long i=0, j=0, k=0;
		unsigned char *x = NULL;
		unsigned char *tmp = NULL;
		long tmpLen = 0;

		tmp =(unsigned char*)malloc((Length+2)/3*4);
		if (tmp == 0)
		{
			return NULL;
		}

		encodeini(&x);

		j = encodeupdate((unsigned char*)pData, Length,(unsigned char*)tmp, x);

		k = encodefinish((unsigned char*)tmp + j, x);

		tmpLen = k + j;

		free(x);

		unsigned char *pRet = NULL;

		if(!m_DelimiterSet)
		{
			if (pRet = (unsigned char*)malloc(tmpLen))
			{
				if (OutLen)
				{
					*OutLen = tmpLen;
				}
				memmove(pRet, tmp, tmpLen);
			}
		}
		else
		{
			long desLen = tmpLen + (tmpLen/64 + 1) ;
			if (pRet = (unsigned char*)malloc(desLen))
			{
				if (OutLen)
				{
					*OutLen = desLen;
				}
				for(i = 0, j = 0; i < tmpLen; i++)
				{
					*(pRet + j) = *(tmp + i);
					j++;
					if((i + 1)%64 == 0) 
					{
						// '\n' == 0x0a
						*(pRet + j)='\n';  
						j++;
					}
				}
				*(pRet + j)='\n';
			}
		}

		free(tmp);

		return pRet;
	}

	return NULL;
}

unsigned char* CBase64::Unbase64(const unsigned char *pData, long Length, long *OutLen)
{
	if (OutLen)
	{
		*OutLen = 0;
	}

	if (pData && Length > 0)
	{
		long j = 0, k = 0;

		unsigned char *x = NULL;

		if(0 != decodeini(&x))
		{
			return NULL; //no memory
		}

		unsigned char *desData = (unsigned char*)malloc(Length);
		if (desData)
		{
			j = decodeupdate((unsigned char*)pData, Length, (unsigned char*)desData, x);

			k = decodefinish((unsigned char*)&desData[j], &x);

			unsigned char *pRet = NULL;
			if (k == 0)
			{
				long desLen = j;
				if (pRet = (unsigned char*)malloc(desLen))
				{
					if (OutLen)
					{
						*OutLen = desLen;
					}
					memmove(pRet, desData, desLen);
				}
			}
			free(desData);

			return pRet;
		}
	}

	return NULL;
}

CMemBlock<unsigned char> CBase64::Encode(const unsigned char *pData, long Length)
{
	long l;
	unsigned char *p = Base64(pData, Length, &l);
	CMemBlock<unsigned char> ret;
	ret.SetMem(p, l);
	
	return ret;
}

CMemBlock<unsigned char> CBase64::Decode(const unsigned char *pData, long Length)
{
	long l;
	unsigned char* p = Unbase64(pData, Length, &l);
	CMemBlock<unsigned char> ret;
	ret.SetMem(p, l);

	return ret;
}

// CTLVOf1Level implementation
bool CTLVOf1Level::Decode(const unsigned char* pEncode, const size_t len, std::vector<TLVNode> &nodeList)
{
	const unsigned char *p = pEncode;
	size_t _len = 0;
	unsigned char Tag = 0;
	unsigned char PrLen = 0;
	size_t factvlen = 0;
	while(_len < len)
	{
		Tag = *p++;_len++;
		if (_len >= len) return false;
		PrLen = *p++;_len++;
		if (_len > len) return false;
		factvlen = 0;
		if (PrLen&0x80)
		{
			unsigned char bcount = PrLen&0x7f;
			if (bcount > 8) return false;
			if ((_len+bcount) >= len) return false;
			for(unsigned char b = 0; b < bcount; b++)
			{
				factvlen <<= 8;
				factvlen |= *p++;_len++;
			}
		}
		else
		{
			factvlen = PrLen;
		}
		if ((_len+factvlen) > len) return false;
		TLVNode node;
		node.T = Tag;
		node.L = factvlen;
		node.V.Resize(factvlen);
		memcpy(node.V, p, factvlen);
		nodeList.push_back(node);
		p += factvlen;
		_len += factvlen;
	}
	return true;
}

CMemBlock<unsigned char> CTLVOf1Level::Encode(unsigned char Tag, size_t Len, CMemBlock<unsigned char> &Value)
{
	CMemBlock<unsigned char> ret;
	if (Len < 128)
	{
		size_t len = 1+1+Value.GetSize();
		ret.Resize(len);
		ret[(size_t)0] = Tag;
		ret[(size_t)1] = (unsigned char)Len;
		memcpy(ret+(size_t)2, Value, Value.GetSize());
	}
	else
	{
		CMemBlock<char> res;
		finteger2char256<size_t>(res, Len);
		size_t _len = 1+1+res.GetSize()+Value.GetSize();
		ret.Resize(_len);
		ret[(size_t)0] = Tag;
		char __len = (char)res.GetSize();
		ret[(size_t)1] = 0x80|__len;
		memcpy(ret+(size_t)2, res, res.GetSize());
		memcpy(ret+(size_t)2+res.GetSize(), Value, Value.GetSize());
	}

	return ret;
}

const unsigned char* MemFind(const unsigned char* pSrc, size_t srcLen, const unsigned char* pDes, size_t desLen)
{
	const unsigned char* ret = (unsigned char*)(void*)-1;
	if (srcLen > desLen)
	{
		size_t index = 0;
		while(index <= (srcLen-desLen))
		{
			if (0 == memcmp(pSrc+index, pDes, desLen))
			{
				ret = pSrc+index;
				break;
			}
			index++;
		}
	}

	return ret;
}

const unsigned char* MemFindLast(const unsigned char* pSrc, size_t srcLen, const unsigned char* pDes, size_t desLen)
{
	const unsigned char* ret = (unsigned char*)(void*)-1;
	if (srcLen > desLen)
	{
		long long index = srcLen-desLen;
		while(index >= 0)
		{
			if (0 == memcmp(pSrc+index, pDes, desLen))
			{
				ret = pSrc+index;
				break;
			}
			index--;
		}
	}

	return ret;
}

CHexByte::CHexByte(const char* pByte, size_t size_byte)
{
	if (!pByte || 0==size_byte)
	{
		return;
	}
	if (pByte && 0<size_byte)
	{
		m_Byte.Resize(size_byte);
		memcpy(m_Byte, pByte, size_byte);
	}
}

CHexByte::CHexByte(size_t size_hex, const char* pHex)
{
	if (!pHex || 0==size_hex)
	{
		return;
	}
	if (pHex && 0<size_hex && 0==(size_hex%2))
	{
		m_Hex.Resize(size_hex);
		memcpy(m_Hex, pHex, size_hex);
	}
}

CHexByte::~CHexByte()
{

}

CMemBlock<char> CHexByte::getByte()
{
	CMemBlock<char> ret;
	if (0!=m_Byte.GetSize())
	{
		ret.Resize(m_Byte.GetSize());
		memcpy(ret, m_Byte, m_Byte.GetSize());
	}
	else
	{
		if (0!=m_Hex.GetSize())
		{
			size_t count = m_Hex.GetSize()/2;
			m_Byte.Resize(count);
			size_t index = 0;
			for(size_t i=0; i<count; i++)
			{
				index = 2*i;
				char high = m_Hex[index];
				char low = m_Hex[index+1];
				char _high = 0, _low = 0;
				if ('0'<=high && high<='9')
				{
					_high = high-'0';
				}
				else if ('a'<=high && high<='f')
				{
					_high = high-'a'+10;
				}
				else if ('A'<=high && high<='F')
				{
					_high = high-'A'+10;
				}
				if ('0'<=low && low<='9')
				{
					_low = low-'0';
				}
				else if ('a'<=low && low<='f')
				{
					_low = low-'a'+10;
				}
				else if ('A'<=low && low<='F')
				{
					_low = low-'A'+10;
				}
				m_Byte[i] = _high<<4|_low;
			}
			ret.Resize(count);
			memcpy(ret, m_Byte, count);
		}
	}

	return ret;
}

CMemBlock<char> CHexByte::getHex()
{
	CMemBlock<char> ret;
	if (0!=m_Hex.GetSize())
	{
		ret.Resize(m_Hex.GetSize());
		memcpy(ret, m_Hex, m_Hex.GetSize());
	}
	else
	{
		if (0!=m_Byte.GetSize())
		{
			char tmp[3] = {0};
			size_t len = m_Byte.GetSize();
			size_t count = 2*len;
			m_Hex.Resize(count);
			size_t index = 0;
			for(size_t i=0; i<len; i++)
			{
				sprintf(tmp, "%02X", m_Byte[i]);
				index = 2*i;
				m_Hex[index] = tmp[0];
				m_Hex[index+1] = tmp[1];
			}
			ret.Resize(count);
			memcpy(ret, m_Hex, count);
		}
	}

	return ret;
}

CMemBlock<char> CHexByte::getByteStr()
{
	CMemBlock<char> ret;
	if (0!=m_ByteStr.GetSize())
	{
		ret.Resize(m_ByteStr.GetSize());
		memcpy(ret, m_ByteStr, m_ByteStr.GetSize());
	}
	else
	{
		CMemBlock<char> Byte = getByte();
		if (0!=Byte.GetSize())
		{
			size_t count = Byte.GetSize();
			m_ByteStr.Resize(count+1);
			m_ByteStr[count] = 0;
			memcpy(m_ByteStr, Byte, count);
			count = m_ByteStr.GetSize();
			ret.Resize(count);
			memcpy(ret, m_ByteStr, count);
		}
	}

	return ret;
}

CMemBlock<char> CHexByte::getHexStr()
{
	CMemBlock<char> ret;
	if (0!=m_HexStr.GetSize())
	{
		ret.Resize(m_HexStr.GetSize());
		memcpy(ret, m_HexStr, m_HexStr.GetSize());
	}
	else
	{
		CMemBlock<char> Hex = getHex();
		if (0!=Hex.GetSize())
		{
			size_t count = Hex.GetSize();
			m_HexStr.Resize(count+1);
			m_HexStr[count] = 0;
			memcpy(m_HexStr, Hex, count);
			count = m_HexStr.GetSize();
			ret.Resize(count);
			memcpy(ret, m_HexStr, count);
		}
	}

	return ret;
}

template<typename T>
void fint2char256(CMemBlock<char>& res, T t)
{
	if (0==t)
	{
		res.Reverse();
		return;
	}
	else
	{
		T surp = t/256;
		char tmp = (char)(t%256);
		size_t l = res.GetSize();
		res.Resize(l+1);
		res[l] = tmp;
		fint2char256(res, surp);
	}
}

void IntEncode(const unsigned int i, size_t& len, char* p)
{
	CMemBlock<char> tmp;
	fint2char256<unsigned int>(tmp, i);
	if (!p && 0==len)
	{
		len = tmp.GetSize();
		return;
	}
	else if (p && 0<len)
	{
		if (tmp.GetSize()<=len)
		{
			memcpy(p, tmp, tmp.GetSize()*sizeof(char));
			len = tmp.GetSize();
			return;
		}
	}
}

unsigned int IntDecode(const char* p, size_t len)
{
	unsigned int total = 0;
	for(size_t i=0; i<len; i++)
	{
		total *= 256;
		total += (unsigned char)p[i];
	}

	return total;
}

void Int64Encode(const unsigned long long ll, size_t& len, char* p)
{
	CMemBlock<char> tmp;
	fint2char256<unsigned long long>(tmp, ll);
	if (!p && 0==len)
	{
		len = tmp.GetSize();
		return;
	}
	else if (p && 0<len)
	{
		if (tmp.GetSize()<=len)
		{
			memcpy(p, tmp, tmp.GetSize()*sizeof(char));
			len = tmp.GetSize();
			return;
		}
	}
}

unsigned long long Int64Decode(const char* p, size_t len)
{
	unsigned long long total = 0;
	for(size_t i=0; i<len; i++)
	{
		total *= 256;
		total += (unsigned char)p[i];
	}

	return total;
}

/* seperator */

void flong2char128(CMemBlock<char>& res, long value)
{
	if (0==value)
	{
		size_t count = res.GetSize();
		for(size_t i=1; i<count; i++)
		{
			res[i] = 0x80|res[i];
		}
		res.Reverse();
		return;
	}
	else if(0<value)
	{
		long surp = value/128;
		char tmp = (char)(value%128);
		size_t l = res.GetSize();
		res.Resize(l+1);
		res[l] = tmp;
		flong2char128(res, surp);
	}	
}

long fchar2long128(CMemBlock<char>& res)
{
	long ret = 0;
	res.Reverse();
	size_t count = res.GetSize();
	for(size_t i=1; i<count; i++)
	{
		res[i] = 0x7F&res[i];
	}
	res.Reverse();
	for(size_t i=0; i<count; i++)
	{
		ret *= 128;
		ret += res[i];
	}

	return ret;
}

bool OIDEncode(const long* oid, size_t& len, char* p)
{
	if (!oid || 0==len)
	{
		return false;
	}
	if (oid && 0<len)
	{
		CMemBlock<long> _oid(len-1);
		for(size_t i=0; i<_oid.GetSize(); i++)
		{
			if (0==i)
			{
				_oid[(size_t)0] = 40*oid[(size_t)0]+oid[(size_t)1]; 
			}
			else
			{
				_oid[i] = oid[i+1];
			}
		}
		size_t count = 0;
		CMemBlock<char> retMem;
		for(size_t i=0; i<len-1; i++)
		{
			CMemBlock<char> res;
			flong2char128(res, _oid[i]);
			if (0<res.GetSize())
			{
				size_t l = res.GetSize();
				size_t l_retTmp = retMem.GetSize();
				retMem.Resize(l_retTmp+l);
				memcpy(retMem+l_retTmp, res, l*sizeof(char));
				count += l;
			}
		}
		if (!p)
		{
			len = count;
		}
		else
		{
			len = count;
			memcpy(p, retMem, len*sizeof(char));
		}
	}

	return true;
}

bool OIDDecode(const char* e, size_t& len, long* p)
{
	if (!e || 0==len)
	{
		return false;
	}
	if (e && 0<len)
	{
		CMemBlock<long> loid;
		CMemBlock<char> tmp;
		size_t count = len;
		for(size_t i=0; i<count; i++)
		{
			size_t l = tmp.GetSize();
			tmp.Resize(l+1);
			tmp[l] = e[i];
			if (!(0x80&e[i]))
			{
				long lo = fchar2long128(tmp);
				loid.push_back(lo);
				tmp.Clear();
			}
		}
		CMemBlock<long> ret(loid.GetSize()+1);
		count = ret.GetSize();
		for(size_t i=0; i<count; i++)
		{
			if (0==i)
			{
				char a1 = loid[(size_t)0]/40;
				char a2 = loid[(size_t)0]%40;
				ret[(size_t)0] = (long)a1;
				ret[(size_t)1] = (long)a2;
			}
			else if(1<i)
			{
				ret[i] = loid[i-1];
			}
		}
		if (!p)
		{
			len = count;
		}
		else
		{
			len = count;
			memcpy(p, ret, count*sizeof(long));
		}
	}

	return true;
}

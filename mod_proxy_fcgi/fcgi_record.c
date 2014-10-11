/* Copyright 1999-2006 Mathieu CARBONNEAUX
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include <sys/types.h>
#include "http_log.h"


extern server_rec *ap_server_conf;


#include "fcgi_record.h"
/****************************/
/* HEADER Zone manipulation */
/****************************/

void inline FCGI_Record_HeaderSetVersion(FCGI_Header * ptrHeader, uint8_t nVersion)
{
   ptrHeader->version = nVersion;
}

uint8_t inline FCGI_Record_HeaderGetVersion(FCGI_Header * ptrHeader)
{
   return ptrHeader->version;
}

void inline FCGI_Record_HeaderSetType(FCGI_Header * ptrHeader, uint8_t nType)
{
   ptrHeader->type = nType;
}

uint8_t  inline FCGI_Record_HeaderGetType(FCGI_Header * ptrHeader)
{
   return ptrHeader->type;
}

void inline FCGI_Record_HeaderSetRequestId(FCGI_Header * ptrHeader, uint16_t  nRequestId)
{
   FCGI_SetTwoBytes(ptrHeader,requestId,nRequestId);
}

uint16_t inline FCGI_Record_HeaderGetRequestId(FCGI_Header * ptrHeader)
{
   return FCGI_GetTwoBytes(ptrHeader,requestId);
}

void inline FCGI_Record_HeaderSetContentLength(FCGI_Header * ptrHeader, uint16_t nContentLength)
{
   FCGI_SetTwoBytes(ptrHeader,contentLength,nContentLength);
}

uint16_t inline FCGI_Record_HeaderGetContentLength(FCGI_Header * ptrHeader)
{
   return FCGI_GetTwoBytes(ptrHeader,contentLength);
}

void inline FCGI_Record_HeaderSetPaddingLength(FCGI_Header * ptrHeader, uint8_t nPaddingLength)
{
   ptrHeader->paddingLength = nPaddingLength;
}

uint8_t inline FCGI_Record_HeaderGetPaddingLength(FCGI_Header * ptrHeader)
{
   return ptrHeader->paddingLength;
}

void inline FCGI_Record_HeaderSetReserved(FCGI_Header * ptrHeader)
{
   ptrHeader->reserved = 0;
}

/* set all FastCGI record header field */
void inline FCGI_Record_HeaderSetAllField(FCGI_Header * ptrHeader, uint8_t nVersion, uint8_t nType, uint16_t nRequestId, uint16_t nContentLength, uint8_t nPaddingLength) 
{
   FCGI_Record_HeaderSetVersion(ptrHeader,nVersion); /* set by default to v1 */
   FCGI_Record_HeaderSetType(ptrHeader,nType);	
   FCGI_Record_HeaderSetRequestId(ptrHeader,nRequestId);
   FCGI_Record_HeaderSetContentLength(ptrHeader,nContentLength);
   FCGI_Record_HeaderSetPaddingLength(ptrHeader,nPaddingLength);
   FCGI_Record_HeaderSetReserved(ptrHeader); /* alway set to zero in v1 */
}

/*****************************************************/
/* BODY Zone manipulation of type FCGI_BEGIN_REQUEST */
/*****************************************************/

uint16_t  inline FCGI_Record_BeginRequestBodyGetRole(FCGI_BeginRequestBody *ptrBeginRequestBody)
{
    return FCGI_GetTwoBytes(ptrBeginRequestBody,role);
}

uint8_t inline FCGI_Record_BeginRequestBodyGetFlags(FCGI_BeginRequestBody *ptrBeginRequestBody)
{
    return ptrBeginRequestBody->flags;
}

void inline FCGI_Record_BeginRequestBodySetRole(FCGI_BeginRequestBody *ptrBeginRequestBody, uint16_t nRole)
{
    FCGI_SetTwoBytes(ptrBeginRequestBody,role,nRole);
}

void inline FCGI_Record_BeginRequestBodySetFlags(FCGI_BeginRequestBody *ptrBeginRequestBody, uint8_t nFlags)
{
    ptrBeginRequestBody->flags = nFlags;
}

void inline FCGI_Record_BeginRequestBodySetReserved(FCGI_BeginRequestBody *ptrBeginRequestBody)
{
    memset(ptrBeginRequestBody->reserved, 0, sizeof(ptrBeginRequestBody->reserved));
}

void inline FCGI_Record_BeginRequestBodySetAll(FCGI_BeginRequestBody *ptrBeginRequestBody, uint16_t nRole, uint8_t nFlags)
{
    FCGI_Record_BeginRequestBodySetRole(ptrBeginRequestBody,nRole);
    FCGI_Record_BeginRequestBodySetFlags(ptrBeginRequestBody,nFlags); 
    FCGI_Record_BeginRequestBodySetReserved(ptrBeginRequestBody); /* alway set to 0 */
}

/**********************************************/
/* BODY Zone manipulation of type FCGI_PARAMS */
/**********************************************/

/* get name/value pairs using §3.4 of the FastCGI specification 
   return the name/value struct len, and set szName and szValue pointer to the position in ptrEnvData zone
   and set in ptrnNameLen and ptrnValueLen the respective name/value len.
*/

uint16_t FCGI_Record_ParamsGet(const byte_t* ptrEnvData, char** szName, uint16_t* ptrnNameLen, char** szValue, uint16_t* ptrnValueLen) 
{
	byte_t* ptrData = (byte_t*)ptrEnvData;
	uint32_t nNameLen=0,nValueLen=0;
	int nPos=0;

	if (((*ptrData)>>7) == 0 && ((*(ptrData+1))>>7) == 0)
	{
          nNameLen   = *ptrData++;
	  nValueLen  = *ptrData++;          
	  nPos+=2;
	}
	else if (((*ptrData)>>7) == 0 && ((*(ptrData+1))>>7) == 1)
	{
	  nNameLen   = *ptrData++;
	  
	  nValueLen  = (*ptrData++)<<24;
	  nValueLen |= (*ptrData++)<<16;
	  nValueLen |= (*ptrData++)<<8;
	  nValueLen |= (*ptrData++);
	  nPos+=5;
	}
	else if (((*ptrData)>>7) == 1 && ((*(ptrData+4))>>7) == 0)
	{
	  nNameLen   = (*ptrData++)<<24;
	  nNameLen  |= (*ptrData++)<<16;
	  nNameLen  |= (*ptrData++)<<8;
	  nNameLen  |= (*ptrData++);

	  nValueLen += (*ptrData++);
	  nPos+=5;
	}
	else if (((*ptrData)>>7) == 1 && ((*(ptrData+4))>>7) == 1)
	{
	  nNameLen   = (*ptrData++)<<24;
	  nNameLen  |= (*ptrData++)<<16;
	  nNameLen  |= (*ptrData++)<<8;
	  nNameLen  |= (*ptrData++);

	  nValueLen  = (*ptrData++)<<24;
	  nValueLen |= (*ptrData++)<<16;
	  nValueLen |= (*ptrData++)<<8;
	  nValueLen |= (*ptrData++);
	  nPos+=8;
	}
	*szName=(char*)(ptrEnvData+nPos);
	*szValue=(char*)((*szName)+nNameLen);

	/* must be lower than FCGI_MAX_LENGTH */
	if ((nNameLen+nValueLen+FCGI_HEADER_LEN)>FCGI_MAX_LENGTH) return 0;

	*ptrnNameLen=nNameLen;
	*ptrnValueLen=nValueLen;
	return nPos+nNameLen+nValueLen;
}

/* set name/value pairs using §3.4 of the FastCGI specification from szName and szValue using nNameLen and nValueLen len
   at starting of ptrEnvData and return the total name/value struct len
*/

uint16_t FCGI_Record_ParamsSet(const byte_t* ptrEnvData, const char *szName, uint16_t nNameLen, const char *szValue, uint16_t nValueLen) 
{
        uint16_t nLen;
	byte_t* ptrData=(byte_t*)ptrEnvData;

        if (!szName || !szValue || !ptrData) return 0;
	if ((nNameLen+nValueLen+FCGI_HEADER_LEN)>FCGI_MAX_LENGTH) return 0;

        nLen = nNameLen + nValueLen;

        nLen += nNameLen > 127 ? 4 : 1;
        nLen += nValueLen > 127 ? 4 : 1;

        if (nNameLen > 127) 
        {
	  *(ptrData++) = ((nNameLen >> 24) & 0xff) | 0x80;
	  *(ptrData++) =  (nNameLen >> 16) & 0xff;
	  *(ptrData++) =  (nNameLen >> 8 ) & 0xff;
	  *(ptrData++) =  (nNameLen >> 0 ) & 0xff;
        } 
	else 
	{
	  *(ptrData++) =  (nNameLen >> 0) & 0xff;
        }

        if (nValueLen > 127) 
	{
	  *(ptrData++) = ((nValueLen >> 24) & 0xff) | 0x80;
	  *(ptrData++) =  (nValueLen >> 16) & 0xff;
	  *(ptrData++) =  (nValueLen >> 8 ) & 0xff;
	  *(ptrData++) =  (nValueLen >> 0 ) & 0xff;
        } 
	else 
	{
	  *(ptrData++) =  (nValueLen >> 0) & 0xff;
        }

        memcpy(ptrData, szName, nNameLen);
        memcpy(ptrData+nNameLen, szValue, nValueLen);

        return nLen;
}

/* set all FCGI_PARAMS from environement table ptrData zone */
uint16_t FCGI_Record_ParamsSetAll(byte_t *ptrData, char **ptrEnvironement)
{

        char *szName, *szValue;
	uint16_t nNameLen,nValueLen;
	uint16_t nLen=0;
	uint32_t nPos=0;

        for (; *ptrEnvironement != NULL; ptrEnvironement++) 
	{
	  szName=*ptrEnvironement;
	  szValue = ap_strchr(*ptrEnvironement, '=');
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, "SetEnv to PARAMS Record '%s'",szName);
	  if (szValue == NULL)
		  continue;
	  szValue++; /* skip '=' */

	  nNameLen = szValue - szName -1;
	  nValueLen = strlen(szValue);

          nLen=FCGI_Record_ParamsSet(ptrData+nPos, szName, nNameLen, szValue, nValueLen);
	  if (nLen==0) return 0;
	  nPos+=nLen;
	  if ((nPos+FCGI_HEADER_LEN)>FCGI_MAX_LENGTH) return 0;
	}
	return nPos;
}

/* calculate the name/value structure len based on §3.4 of the FastCGI specification */
uint16_t inline FCGI_Record_ParamsCalcLen(uint16_t nNameLen, uint16_t nValueLen) 
{
        uint16_t nLen = nNameLen + nValueLen;
        nLen += nNameLen > 127 ? 4 : 1;
        nLen += nValueLen > 127 ? 4 : 1;
        return nLen;
}

/***************************************************/
/* BODY Zone manipulation of type FCGI_END_REQUEST */
/***************************************************/

u_int32_t inline FCGI_Record_EndRequestBodyGetAppStatus(FCGI_EndRequestBody *ptrEndRequestBody)
{
    return FCGI_GetFourBytes(ptrEndRequestBody,appStatus);
}

uint8_t inline FCGI_Record_EndRequestBodyGetProtocolStatus(FCGI_EndRequestBody *ptrEndRequestBody)
{
    return ptrEndRequestBody->protocolStatus;
}

void inline FCGI_Record_EndRequestBodySetAppStatus(FCGI_EndRequestBody *ptrEndRequestBody, u_int32_t nAppStatus)
{
    FCGI_SetFourBytes(ptrEndRequestBody,appStatus,nAppStatus);
}

void inline FCGI_Record_EndRequestBodySetProtocolStatus(FCGI_EndRequestBody *ptrEndRequestBody, uint8_t nProtocolStatus)
{
    ptrEndRequestBody->protocolStatus = nProtocolStatus;
}

void inline FCGI_Record_EndRequestBodySetReserved(FCGI_EndRequestBody *ptrEndRequestBody)
{
    memset(ptrEndRequestBody->reserved, 0, sizeof(ptrEndRequestBody->reserved));
}

void inline FCGI_Record_EndRequestBodySetAll(FCGI_EndRequestBody *ptrEndRequestBody, u_int32_t nAppStatus, uint8_t nProtocolStatus)
{
    FCGI_Record_EndRequestBodySetAppStatus(ptrEndRequestBody,nAppStatus);
    FCGI_Record_EndRequestBodySetProtocolStatus(ptrEndRequestBody,nProtocolStatus); 
    FCGI_Record_EndRequestBodySetReserved(ptrEndRequestBody); /* alway set to 0 */
}

/****************************************************/
/* BODY Zone manipulation of type FCGI_UNKNOWN_TYPE */
/****************************************************/

uint8_t inline FCGI_Record_UnknownTypeBodyGetType(FCGI_UnknownTypeBody *ptrUnknownTypeBody)
{
    return ptrUnknownTypeBody->type;
}

void inline FCGI_Record_UnknownTypeBodySetType(FCGI_UnknownTypeBody *ptrUnknownTypeBody, uint8_t nType)
{
    ptrUnknownTypeBody->type=nType;
}

void inline FCGI_Record_UnknownTypeBodySetReserved(FCGI_UnknownTypeBody *ptrUnknownTypeBody)
{
    memset(ptrUnknownTypeBody->reserved, 0, sizeof(ptrUnknownTypeBody->reserved));
}

void inline FCGI_Record_UnknownTypeBodySetAll(FCGI_UnknownTypeBody *ptrUnknownTypeBody, uint8_t nType)
{
    FCGI_Record_UnknownTypeBodySetType(ptrUnknownTypeBody,nType);
    FCGI_Record_UnknownTypeBodySetReserved(ptrUnknownTypeBody); /* alway set to 0 */
}


/**************************************/
/* Complete Record Build manipulation */
/**************************************/

/* build FCGI_BEGIN_REQUEST v1 record type */
void inline FCGI_Build_BeginRequestRecord_v1(FCGI_BeginRequestRecord * ptrBeginRequestRecord,
					    uint16_t  nRequestId, 
                                            uint32_t  nRole,
					    uint8_t nFlags)
{
   FCGI_Record_HeaderSetAllField(&ptrBeginRequestRecord->header, FCGI_VERSION_1,FCGI_BEGIN_REQUEST,nRequestId,sizeof(FCGI_BeginRequestBody),0);
   FCGI_Record_BeginRequestBodySetAll(&ptrBeginRequestRecord->body, nRole,nFlags);
}

/* build FCGI_END_REQUEST v1 record type */
void inline FCGI_Build_EndRequestRecord_v1(FCGI_EndRequestRecord * ptrEndRequestRecord,
					    uint16_t  nRequestId, 
                                            uint32_t  nAppStatus,
					    uint8_t nProtocolStatus)
{
   FCGI_Record_HeaderSetAllField(&ptrEndRequestRecord->header, FCGI_VERSION_1,FCGI_END_REQUEST,nRequestId,sizeof(FCGI_EndRequestBody),0);
   FCGI_Record_EndRequestBodySetAll(&ptrEndRequestRecord->body, nAppStatus,nProtocolStatus);
}

/* build FCGI_UNKNOWN_TYPE v1 record type */
void inline FCGI_Build_UnknownTypeRecord_v1(FCGI_UnknownTypeRecord * ptrUnknownTypeRecord,
                                            uint8_t  nType)
{
   FCGI_Record_HeaderSetAllField(&ptrUnknownTypeRecord->header, FCGI_VERSION_1,FCGI_UNKNOWN_TYPE,0,sizeof(FCGI_UnknownTypeBody),0);
   FCGI_Record_UnknownTypeBodySetAll(&ptrUnknownTypeRecord->body, nType);
}

/* build Record with data of type FCGI_PARAMS,FCGI_STDIN,FCGI_STDOUT,FCGI_STDERR,FCGI_GET_VALUES and FCGI_DATA v1 record */
apr_status_t inline FCGI_Build_ParamsRecord_v1(FCGI_Header *ptrHeaderRecord,
					    uint16_t  nRequestId, 
					    char  **ptrEnvironment)
{
   uint8_t nPaddingLength=0;
   uint16_t nContentLength=0;
   byte_t *ptrDataRecord=(byte_t*)(ptrHeaderRecord)+FCGI_HEADER_LEN;

   if (ptrEnvironment!=NULL) 
   {
     /* copy all environement variable from ptrEnvironment table to ptrDataRecord+FCGI_HEADER_LEN zone */
     nContentLength=FCGI_Record_ParamsSetAll(ptrDataRecord,ptrEnvironment);
     if (nContentLength==0) return -1;
     
     /* pad record with 8 bytes aligned */
     nPaddingLength=nContentLength%8;
     nPaddingLength=nPaddingLength==0 ? 0 : 8-nPaddingLength;
   }
 
   FCGI_Record_HeaderSetAllField(ptrHeaderRecord, FCGI_VERSION_1,FCGI_PARAMS,nRequestId,nContentLength,nPaddingLength);

   /* set padding zone to zero */
   if (nPaddingLength>0) 
      memset(ptrDataRecord+nContentLength,'\0',nPaddingLength);
   return APR_SUCCESS;
}

/* build Record with data of type FCGI_STDIN,FCGI_STDOUT,FCGI_STDERR,FCGI_GET_VALUES and FCGI_DATA v1 record */
uint32_t inline FCGI_Build_DataRecord_v1(FCGI_Header *ptrHeaderRecord,
					    uint16_t  nRequestId, 
					    uint8_t  nStreamType, 
					    uint16_t  nContentLength)
{
   uint8_t nPaddingLength=0;
   byte_t *ptrDataRecord=(byte_t*)(ptrHeaderRecord)+FCGI_HEADER_LEN;

   if (nContentLength!=0) 
   {
     /* pad record with 8 bytes aligned */
     nPaddingLength=nContentLength%8;
     nPaddingLength=nPaddingLength==0 ? 0 : 8-nPaddingLength;
   }
   else
   {
     nPaddingLength=0;
   }
    

   /* set nRequestId to zero for managment type of reecord */
   if (nStreamType==FCGI_GET_VALUES) nRequestId=0;

   FCGI_Record_HeaderSetAllField(ptrHeaderRecord, FCGI_VERSION_1, nStreamType, nRequestId, nContentLength, nPaddingLength);

   /* set padding zone to zero */
   if (nPaddingLength>0) 
      memset(ptrDataRecord+nContentLength,'\0',nPaddingLength);

   return nContentLength+FCGI_HEADER_LEN+nPaddingLength;
}


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

#ifndef FCGI_RECORD_H
#define FCGI_RECORD_H

#include <sys/types.h>
#include "fastcgi.h"
#ifndef u_char_t
#define u_char_t u_char
#endif
#ifndef byte_t
#define byte_t u_char
#endif

/****************************/
/* HEADER Zone manipulation */
/****************************/

#define FCGI_SetTwoBytes(ptrStruct,szField,nVal) (ptrStruct)->szField##B0=nVal&0xff;(ptrStruct)->szField##B1=(nVal>>8)&0xff
#define FCGI_GetTwoBytes(ptrStruct,szField) ((ptrStruct->szField##B0&0xff)|(((ptrStruct)->szField##B1&0xff)<<8))

#define FCGI_SetFourBytes(ptrStruct,szField,nVal) (ptrStruct)->szField##B0=nVal&0xff;(ptrStruct)->szField##B1=(nVal>>8)&0xff;(ptrStruct)->szField##B2=(nVal>>16)&0xff;(ptrStruct)->szField##B3=(nVal>>24)&0xff
#define FCGI_GetFourBytes(ptrStruct,szField) ((ptrStruct->szField##B0&0xff)|(((ptrStruct)->szField##B1&0xff)<<8)|(((ptrStruct)->szField##B1&0xff)<<16)|(((ptrStruct)->szField##B1&0xff)<<24))

/* set/get version */
void inline FCGI_Record_HeaderSetVersion(FCGI_Header * ptrHeader, uint8_t nVersion);
uint8_t inline FCGI_Record_HeaderGetVersion(FCGI_Header * ptrHeader);

/* set/get type */
void inline FCGI_Record_HeaderSetType(FCGI_Header * ptrHeader, uint8_t nType);
uint8_t  inline FCGI_Record_HeaderGetType(FCGI_Header * ptrHeader);

/* set/get requestid */
void inline FCGI_Record_HeaderSetRequestId(FCGI_Header * ptrHeader, uint16_t  nRequestId);
uint16_t inline FCGI_Record_HeaderGetRequestId(FCGI_Header * ptrHeader);

/* set/get contentlength */
void inline FCGI_Record_HeaderSetContentLength(FCGI_Header * ptrHeader, uint16_t nContentLength);
uint16_t inline FCGI_Record_HeaderGetContentLength(FCGI_Header * ptrHeader);

/* set/get paddinglength */
void inline FCGI_Record_HeaderSetPaddingLength(FCGI_Header * ptrHeader, uint8_t nPaddingLength);
uint8_t inline FCGI_Record_HeaderGetPaddingLength(FCGI_Header * ptrHeader);

/* set reserved zone to zero */
void inline FCGI_Record_HeaderSetReserved(FCGI_Header * ptrHeader);

/* set all record header field at same time */
void inline FCGI_Record_HeaderSetAllField(FCGI_Header * ptrHeader, uint8_t nVersion, uint8_t nType, uint16_t nRequestId, uint16_t nContentLength, uint8_t nPaddingLength);

/*****************************************************/
/* BODY Zone manipulation of type FCGI_BEGIN_REQUEST */
/*****************************************************/

uint16_t  inline FCGI_Record_BeginRequestBodyGetRole(FCGI_BeginRequestBody *ptrBeginRequestBody);
uint8_t inline FCGI_Record_BeginRequestBodyGetFlags(FCGI_BeginRequestBody *ptrBeginRequestBody);
void inline FCGI_Record_BeginRequestBodySetRole(FCGI_BeginRequestBody *ptrBeginRequestBody, uint16_t nRole);
void inline FCGI_Record_BeginRequestBodySetFlags(FCGI_BeginRequestBody *ptrBeginRequestBody, uint8_t nFlags);
void inline FCGI_Record_BeginRequestBodySetReserved(FCGI_BeginRequestBody *ptrBeginRequestBody);
void inline FCGI_Record_BeginRequestBodySetAll(FCGI_BeginRequestBody *ptrBeginRequestBody, uint16_t nRole, uint8_t nFlags);

/***************************************************/
/* BODY Zone manipulation of type FCGI_END_REQUEST */
/***************************************************/

uint32_t inline FCGI_Record_EndRequestBodyGetAppStatus(FCGI_EndRequestBody *ptrEndRequestBody);
uint8_t inline FCGI_Record_EndRequestBodyGetProtocolStatus(FCGI_EndRequestBody *ptrEndRequestBody);
void inline FCGI_Record_EndRequestBodySetAppStatus(FCGI_EndRequestBody *ptrEndRequestBody, uint32_t nAppStatus);
void inline FCGI_Record_EndRequestBodySetProtocolStatus(FCGI_EndRequestBody *ptrEndRequestBody, uint8_t nProtocolStatus);
void inline FCGI_Record_EndRequestBodySetReserved(FCGI_EndRequestBody *ptrEndRequestBody);
void inline FCGI_Record_EndRequestBodySetAll(FCGI_EndRequestBody *ptrEndRequestBody, uint32_t nAppStatus, uint8_t nProtocolStatus);

/**********************************************/
/* DATA Zone manipulation of type FCGI_PARAMS */
/**********************************************/

/* set/get Env name/value from/to FCGI_PARAMS record data zone */
uint16_t FCGI_Record_ParamsGet(const byte_t* ptrEnvData, char **szName, uint16_t *ptrnNameLen, char **szValue, uint16_t *ptrnValueLen);
uint16_t FCGI_Record_ParamsSet(const byte_t* ptrEnvData, const char *szName, uint16_t nNameLen, const char *szValue, uint16_t nValueLen);

/* caculate Envronement structure size of name/value of FCGI_PARAMS record data zone */
uint16_t inline FCGI_Record_ParamsCalcLen(uint16_t nNameLen, uint16_t nValueLen);

/* set all FCGI_PARAMS from environement table ptrData zone */
uint16_t FCGI_Record_ParamsSetAll(byte_t *ptrData, char **ptrEnvironement);

/****************************************************/
/* BODY Zone manipulation of type FCGI_UNKNOWN_TYPE */
/****************************************************/

uint8_t inline FCGI_Record_UnknownTypeBodyGetType(FCGI_UnknownTypeBody *ptrUnknownTypeBody);
void inline FCGI_Record_UnknownTypeBodySetType(FCGI_UnknownTypeBody *ptrUnknownTypeBody, uint8_t nType);
void inline FCGI_Record_UnknownTypeBodySetReserved(FCGI_UnknownTypeBody *ptrUnknownTypeBody);
void inline FCGI_Record_UnknownTypeBodySetAll(FCGI_UnknownTypeBody *ptrUnknownTypeBody, uint8_t nType);

/**************************************/
/* Complete Record Build manipulation */
/**************************************/

/* build FCGI_BEGIN_REQUEST v1 record type */
void inline FCGI_Build_BeginRequestRecord_v1(FCGI_BeginRequestRecord * ptrBeginRequestRecord,
					    uint16_t  nRequestId, 
                                            uint32_t  nRole,
					    uint8_t   nFlags);

/* build FCGI_END_REQUEST v1 record type */
void inline FCGI_Build_EndRequestRecord_v1(FCGI_EndRequestRecord * ptrEndRequestRecord,
					    uint16_t  nRequestId, 
                                            uint32_t  nAppStatus,
					    uint8_t   nProtocolStatus);

/* build FCGI_UNKNOWN_TYPE v1 record type */
void inline FCGI_Build_UnknownTypeRecord_v1(FCGI_UnknownTypeRecord * ptrUnknownTypeRecord,
                                            uint8_t   nType);

/* build FCGI_PARAMS v1 record type with environement table */
apr_status_t inline FCGI_Build_ParamsRecord_v1(FCGI_Header *ptrHeaderRecord,
					    uint16_t  nRequestId, 
					    char  **ptrEnvironment);

/* build Record with data of type FCGI_STDIN,FCGI_STDOUT,FCGI_STDERR,FCGI_GET_VALUES and FCGI_DATA v1 record */
uint32_t inline FCGI_Build_DataRecord_v1(FCGI_Header *ptrDataRecord,
					    uint16_t  VnRequestId, 
					    uint8_t   nStreamType, 
					    uint16_t  nContentLength);
#endif

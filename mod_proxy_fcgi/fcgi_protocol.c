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
#include "util_script.h"
#include "arch/unix/apr_arch_networkio.h"
#include "apr_errno.h"

#include "mod_proxy.h"
#include "mod_proxy_fcgi.h"
#include "fcgi_protocol.h"
#include "fcgi_record.h"

/* Clear all connection-based headers from the incoming headers table */
static void ap_proxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    const char *name;
    char *next = apr_pstrdup(p, apr_table_get(headers, "Connection"));

    apr_table_unset(headers, "Proxy-Connection");
    if (!next) return;

    while (*next) 
    {
        name = next;

        while (*next && !apr_isspace(*next) && (*next != ',')) 
            ++next;

        while (*next && (apr_isspace(*next) || (*next == ','))) 
	{
            *next = '\0';
            ++next;
        }
        apr_table_unset(headers, name);
    }
    apr_table_unset(headers, "Connection");
}


/* Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static char *fcgi_original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL) 
    {
        return (char *) apr_pcalloc(r->pool, 1);
    }

    first = r->the_request;     /* use the request-line */

    /* skip over the method */
    while (*first && !apr_isspace(*first)) ++first;                

    /*   and the space(s)   */
    while (apr_isspace(*first)) ++first;               

    last = first;

    /* end at next whitespace */
    while (*last && !apr_isspace(*last)) ++last;                 

    return apr_pstrmemdup(r->pool, first, last - first);
}


/* Based on Apache's ap_add_cgi_vars() in util_script.c.
 * Apache's spins in sub_req_lookup_uri() trying to setup PATH_TRANSLATED,
 * so we just don't do that part.
 */
static apr_status_t fcgi_add_cgi_vars(request_rec *r, const int compat)
{
    apr_table_t *e = r->subprocess_env;
    const char *szDocumentRoot=apr_table_get(e,"DOCUMENT_ROOT");
    const char *szScriptName;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars r->protocol:'%s'",r->protocol);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars r->method:'%s'",r->method);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars r->args:'%s'",r->args);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars r->uri:'%s'",r->uri);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars r->path_info:'%s'",r->path_info);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars fcgi_original_uri(r):'%s'",fcgi_original_uri(r));
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars DOCUMENT_ROOT: '%s'",szDocumentRoot);

    apr_table_setn(e, "GATEWAY_INTERFACE", "CGI/1.1");
    apr_table_setn(e, "SERVER_PROTOCOL", r->protocol);
    apr_table_setn(e, "REQUEST_METHOD", r->method);
    apr_table_setn(e, "QUERY_STRING", r->args ? r->args : "");
    apr_table_setn(e, "REQUEST_URI", fcgi_original_uri(r));

    if (!r->path_info || !*r->path_info)
    {
        apr_table_setn(e, "SCRIPT_NAME", r->uri);
        apr_table_setn(e, "PATH_INFO", r->uri);
	r->path_info=r->uri;
    }
    else 
    {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);

        apr_table_setn(e, "SCRIPT_NAME", apr_pstrndup(r->pool, r->uri, path_info_start));
        apr_table_setn(e, "PATH_INFO", r->path_info);
    }
    szScriptName=apr_table_get(e,"SCRIPT_NAME");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Internal Apache vars SCRIPT_NAME: '%s'",szScriptName);
    apr_table_setn(e, "SCRIPT_FILENAME",apr_pstrcat(r->pool,szDocumentRoot,szScriptName,NULL));
    apr_table_setn(e, "PATH_TRANSLATED",apr_pstrcat(r->pool,szDocumentRoot,szScriptName,NULL));

    //apr_table_setn(e,"HTTP_CONNECTION","keep-alive");
    //apr_table_setn(e,"HTTP_KEEP_ALIVE","300");

    //apr_table_unset(e,"HTTP_MAX_FORWARDS");
    //apr_table_unset(e,"SCRIPT_URL");
    //apr_table_unset(e,"SCRIPT_URI");

    /* TODO: sending X-FORWARDER- value in place of REMOTE_ value to FastCGI server if flag in conf has been positionned */

    return APR_SUCCESS;
}


void add_pass_header_vars(apr_pool_t * p,request_rec *r);
void add_pass_header_vars(apr_pool_t * p,request_rec *r)
{
  char szName[512];
  char *szValue;
  uint16_t nNameLen;
  char **ptrEnvironement=ap_create_environment(p,r->headers_in);

  for (; *ptrEnvironement != NULL; ptrEnvironement++) 
  {
    szValue = ap_strchr(*ptrEnvironement, '=');
    if (szValue == NULL)
	    continue;
    szValue++; /* skip '=' */

    nNameLen = szValue - szName -1;

    strncpy(szName,*ptrEnvironement,nNameLen);

    apr_table_setn(r->subprocess_env, szName, szValue);
  }
}


/* send data with use of bucket brigade to output filter */
static apr_status_t fcgi_filter_fflush(apr_pool_t * p, ap_filter_t *ptrOutputFilter, char *ptrData,apr_size_t nLen) 
{
    apr_status_t 		status;
    apr_bucket_brigade*		ptrBucketBrigade	= apr_brigade_create(p, ptrOutputFilter->c->bucket_alloc); /* create empty brigade */
    apr_bucket 			*ptrLocalBucket		= apr_bucket_pool_create(ptrData, nLen, p, ptrOutputFilter->c->bucket_alloc); /* create bucket from ptrData */
    server_rec			*ptrServer		= ptrOutputFilter->c->base_server;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: fcgi_filter_fflush: Begin sending data connection...");

    /* add bucket to the tail of the brigade */
    APR_BRIGADE_INSERT_TAIL(ptrBucketBrigade, ptrLocalBucket);

    /* send "FCGI_PARAMS" Record to FastCgi server */ 
    status = ap_fflush(ptrOutputFilter,ptrBucketBrigade);
    if (status!=APR_SUCCESS) 
    {
     char szErrMsg[100];
     apr_strerror(status,szErrMsg,sizeof(szErrMsg));
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, ptrServer, "proxy: FCGI: connection sending error... apr_status:%u errmsg:%s",status,szErrMsg);
     return status;
    }
    apr_brigade_destroy(ptrBucketBrigade);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: fcgi_filter_fflush: End...");
    return APR_SUCCESS;
}

/* receved data with use of bucket brigade from input filter */
static apr_status_t fcgi_filter_recv(apr_pool_t * p, ap_filter_t *ptrInputFilter, char *ptrData,apr_size_t *nLen) 
{
    apr_status_t 		status=APR_SUCCESS;

    apr_bucket 			*ptrLocalBucket;
    apr_bucket_brigade		*ptrBucketBrigade = apr_brigade_create(p, ptrInputFilter->c->bucket_alloc); /* create empty brigade */
    server_rec			*ptrServer=ptrInputFilter->c->base_server;

    apr_size_t 			nRecvLen=0;
    const char 			*ptrRecvData;
    uint32_t   			nBufferLen=0;

    apr_off_t			nBrigadeSize=0;
    int 			nBucketNb=0;
    apr_size_t 			nDataReadFromBrigade=0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: fcgi_filter_recv: Begin reading data from connection...");
    status = ap_get_brigade(ptrInputFilter, ptrBucketBrigade, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
    if ((status!=APR_EOF) && (status!=APR_SUCCESS))
    {
     char szErrMsg[100];
     apr_strerror(status,szErrMsg,sizeof(szErrMsg));
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, ptrServer, "proxy: FCGI: Socket reading STDOUT/STDERR record Error... apr_status:%u errmsg:%s",status,szErrMsg);
     return status;
    }

    apr_brigade_length(ptrBucketBrigade,1,&nBrigadeSize);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: Brigade total length... nBrigadeSize:%lu",nBrigadeSize);
    if (status==APR_EOF&&nBrigadeSize==0) 
    {
      apr_brigade_destroy(ptrBucketBrigade);
      *nLen=0;
      return status;
    }

    APR_BRIGADE_FOREACH(ptrLocalBucket,ptrBucketBrigade)
    {
      /* end of stream ? */
      if (APR_BUCKET_IS_EOS(ptrLocalBucket)) 
      {
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: End of stream... ");
	  status=APR_EOF;
	  break;
      }

      /* We can't do much with this. */
      if (APR_BUCKET_IS_FLUSH(ptrLocalBucket)) continue;

      /* read data from brigade */
      apr_bucket_read(ptrLocalBucket,&ptrRecvData,&nRecvLen,APR_BLOCK_READ);

      if (nRecvLen>0)
      {
	/* copy data on buffer */
	memcpy(ptrData+nBufferLen,ptrRecvData,nRecvLen);

	/* inc buffer len with receved data len */
	nBufferLen+=nRecvLen; 
	nDataReadFromBrigade+=nRecvLen;
	nBucketNb++;
      }
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: fcgi_filter_recv: readed bucket...");
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: Readed data from brigade... nDataReadFromBrigade:%u nb Nb Bucket readed:%u nBufferLen:%u",nDataReadFromBrigade,nBucketNb,nBufferLen);

    apr_brigade_destroy(ptrBucketBrigade);

    *nLen=nDataReadFromBrigade;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ptrServer, "proxy: FCGI: fcgi_filter_recv: Begin reading data from connection...");
    return status;
}


/*
 * allocate buffer, build "FCGI_BEGIN_REQUEST" Record, create bucket, send it to the backend connexion 
 */
static apr_status_t fcgi_send_begin_record(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, proxy_fcgi_conn_t *ptrBackend, byte_t *ptrRecordBuffer) 
{
    apr_status_t 		status;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: ==> STEP 1 - Begin send FCGI_BEGIN_REQUEST id:%u",nRequestId);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: FCGI_BEGIN_REQUEST record FCGI_KEEP_CONN mode:%u id:%u",ptrBackend->close,nRequestId);

    /* build record nto this buffer */
    FCGI_Build_BeginRequestRecord_v1((FCGI_BeginRequestRecord *)ptrRecordBuffer, nRequestId , FCGI_RESPONDER, (unsigned char) ((ptrBackend->close) ? FCGI_KEEP_CONN : 0));

    /* send data to backend server */
    status=fcgi_filter_fflush(p,ptrBackend->connection->output_filters,(char*)ptrRecordBuffer,sizeof(FCGI_BeginRequestRecord));
    if (status!=APR_SUCCESS)
    {
     char szErrMsg[100];
     apr_strerror(status,szErrMsg,sizeof(szErrMsg));
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Sending Begin Record to backend server Error... id:%u apr_status:%u errmsg:%s",nRequestId,status,szErrMsg);
     return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: FCGI_BEGIN_REQUEST record sended id:%u",nRequestId);
    return APR_SUCCESS;
}

/*
 * allocate buffer, build "FCGI_PARAMS" Record, create bucket, send it to the backend connexion 
 */
static apr_status_t fcgi_send_params_record(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, proxy_fcgi_conn_t *ptrBackend, byte_t *ptrRecordBuffer) 
{
    apr_status_t status;
    apr_size_t			nLen			= 0;
    char**			ptrEnvironment;


    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: ==> STEP 2 - Begin send FCGI_PARAMS id:%u",nRequestId);

    /* add all environement variable to destination fastcgi server (r->subprocess_env) */
    ap_add_common_vars(r); 

    /* set cgi environement variable for destination fastcgi server (r->subprocess_env) */
    /*     apache mod_cgi ap_add_cgi_vars(r) are replaced by fcgi_add_cgi_vars who based on */
    fcgi_add_cgi_vars(r,FALSE); 

    /* passe some http header in to destination fastcgi server environement */
    /*add_pass_header_vars(p,r); */

    /* set FastCGI role in environement sent to FastCGI server (as is made by original mod_fastcgi) */
    apr_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", "RESPONDER");

    /* with this method (already used in other FastCGI implementation) we are limited to 65kb-8Bytes (FastCGI max Record size) Environment variable size */
    /* in the specification is not to clear, but "FCGI_PARAMS" record are stream record...*/
    /* i'm not sure but i think that i can be possible to send more than one "FCGI_PARAMS" record to overcome this limitation ... */

    /* build FCGI_PARAMS record based on apache environement */
    ptrEnvironment=ap_create_environment(p,r->subprocess_env);
    status=FCGI_Build_ParamsRecord_v1((FCGI_Header *)ptrRecordBuffer,nRequestId,ptrEnvironment);
    if (status!=APR_SUCCESS) 
    {
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Building Params Record Error... id:%u",nRequestId);
     return HTTP_INTERNAL_SERVER_ERROR;
    }

    nLen=FCGI_Record_HeaderGetContentLength((FCGI_Header *)ptrRecordBuffer)+
     		FCGI_Record_HeaderGetPaddingLength((FCGI_Header *)ptrRecordBuffer)+
		FCGI_HEADER_LEN;

    status=fcgi_filter_fflush(p,ptrBackend->connection->output_filters,(char*)ptrRecordBuffer,nLen);
    if (status!=APR_SUCCESS) 
    {
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Sending Params Record to backend server Error... id:%u apr_status:%u",nRequestId,status);
     return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: FCGI_PARAMS record sended of %u bytes id:%u",nLen,nRequestId);


    /* build and send  VOID FCGI_PARAMS record */
    status=FCGI_Build_ParamsRecord_v1((FCGI_Header *)ptrRecordBuffer,nRequestId,NULL);
    if (status!=APR_SUCCESS) 
    {
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Building Params Record Error... id:%u",nRequestId);
     return HTTP_INTERNAL_SERVER_ERROR;
    }

    status=fcgi_filter_fflush(p,ptrBackend->connection->output_filters,(char*)ptrRecordBuffer,FCGI_HEADER_LEN);
    if (status!=APR_SUCCESS) 
    {
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Flushing Params Record to backend server Error... id:%u apr_status:%u",nRequestId,status);
     return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: VOID FCGI_PARAMS record sended id:%u",nRequestId);

    return APR_SUCCESS;
}

/*
 * Transfer any put/post args, CERN style...
 * Read from input filter(from request connexion), allocate buffer, build "FCGI_STDIN" Record, create bucket, send it to the backend connexion 
 */
static apr_status_t fcgi_send_stdin_record(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, proxy_fcgi_conn_t *ptrBackend, byte_t *ptrRecordBuffer) 
{
    apr_status_t status=APR_SUCCESS;
    apr_size_t	nDataLen = 0;
    apr_size_t	nTotalDataLen = 0;
    int seen_eos=0, child_stopped_reading=0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: ==> STEP 3 - Begin send FCGI_STDIN Stream ... id:%u",nRequestId);

    while(!seen_eos&&!child_stopped_reading)
    {
	/* read from client connexion per 8kb max */
        status = fcgi_filter_recv(p, r->input_filters,(char*)(ptrRecordBuffer+FCGI_HEADER_LEN),&nDataLen);
	if (status==APR_EOF) 
	{
	  status=APR_SUCCESS;
	  seen_eos=1;
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: client End of stream reach... id:%u size:%u",nRequestId,nDataLen);
	  if (nDataLen==0) break;
	}

	if (status!=APR_SUCCESS) 
	{
	 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: reading put/post from client in getting brigade Error... id:%u apr_status:%u",nRequestId,status);
	 return HTTP_INTERNAL_SERVER_ERROR;
	}

	nTotalDataLen+=nDataLen;
            
	if (nDataLen>0) 
	{
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Have readed data from input client stream ... id:%u size:%u",nRequestId,nDataLen);

	  /* build "FCGI_STDIN" record */
	  /* set header and return the real len */
	  nDataLen=FCGI_Build_DataRecord_v1((FCGI_Header*)ptrRecordBuffer, nRequestId,FCGI_STDIN, nDataLen); 

	  /* send "FCGI_STDIN" Record to FastCgi server */ 
	  status=fcgi_filter_fflush(p,ptrBackend->connection->output_filters,(char*)ptrRecordBuffer,nDataLen);
	  if (status!=APR_SUCCESS)
	  {
	    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Sending STDIN Record to backend server Error... id:%u apr_status:%u",nRequestId,status);
	    child_stopped_reading = 1;
	  }
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: FCGI_STDIN Record %u bytes Sended to backend ... id:%u",nDataLen,nRequestId);
	}
    } 
    if (status!=APR_SUCCESS&&child_stopped_reading==1) return HTTP_INTERNAL_SERVER_ERROR;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: %u bytes FCGI_STDIN Record sended to backend ... id:%u",nTotalDataLen,nRequestId);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Sending void FCGI_STDIN Record to backend ... id:%u",nRequestId);
    /* build viod "FCGI_STDIN" record */
    FCGI_Record_HeaderSetAllField((FCGI_Header*)ptrRecordBuffer, FCGI_VERSION_1, FCGI_STDIN, nRequestId, 0, 0);
    /* send data to backend */
    status=fcgi_filter_fflush(p,ptrBackend->connection->output_filters,(char*)ptrRecordBuffer,FCGI_HEADER_LEN);
    if (status!=APR_SUCCESS) 
    {
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Sending STDIN record to backend error... id:%u apr_status:%u",nRequestId,status);
     return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: void FCGI_STDIN Record Sended to backend ... id:%u",nRequestId);

    return APR_SUCCESS;
}

/* check FastCGI Record header on each record receved */
static apr_status_t fcgi_recev_check_header(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, FCGI_Header *ptrHeader,
						    u_int8_t  *nVersion,
						    u_int8_t  *nType,
						    u_int16_t *nContentLength,
						    u_int8_t  *nPaddingLength,
						    u_int16_t *nRecevedRequestId,
						    uint32_t  *nTotalRecordLength,
						    uint32_t  nBufferLen) 
{
	 /* get record version */
	 *nVersion=FCGI_Record_HeaderGetVersion(ptrHeader);
	 if (*nVersion!=FCGI_VERSION_1) 
	 {
	  ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Header Receved - FastCGI Version not supported error... version:%u id:%u",*nVersion,nRequestId);
	  return HTTP_VERSION_NOT_SUPPORTED;
	 }

	 /* get record type */
	 *nType=FCGI_Record_HeaderGetType(ptrHeader);

	 if (*nType!=FCGI_END_REQUEST&&*nType!=FCGI_STDOUT&&*nType!=FCGI_STDERR)
	 {
	      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: receved record of unknown or bad type... type:%u id:%u",*nType,nRequestId);
	      return HTTP_INTERNAL_SERVER_ERROR;
	 }

	 /* get receve request id */
	 *nRecevedRequestId=FCGI_Record_HeaderGetRequestId(ptrHeader);
	 if (*nRecevedRequestId!=nRequestId) 
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Header Receved of type %u ... with diffrent request id - sended id:%u receved id:%u",*nType,nRequestId,*nRecevedRequestId);

	 /* get content and padding length of the record from header */
	 *nContentLength=FCGI_Record_HeaderGetContentLength(ptrHeader);
	 *nPaddingLength=FCGI_Record_HeaderGetPaddingLength(ptrHeader);
	 
	 *nTotalRecordLength=*nContentLength+*nPaddingLength+FCGI_HEADER_LEN;

	 ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: => RECORD HEADER Readed... id:%u nVersion:%u nType:%u nRecevedRequestId:%u nContentLength:%u nPaddingLength:%u nTotalRecordLength:%u nBufferLen:%u",nRequestId,*nVersion,*nType,*nRecevedRequestId,*nContentLength,*nPaddingLength,*nTotalRecordLength,nBufferLen);
	 return APR_SUCCESS;
}

/* send "FCGI_STDOUT" Record to client */ 
static apr_status_t fcgi_stdout_send_data(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, 
  					        byte_t *ptrRecordBuffer, u_int16_t nContentLength) 
{
   apr_status_t status;

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: sending STDOUT record to client ... id:%u length:%u",nRequestId,nContentLength);
   status=fcgi_filter_fflush(p,r->output_filters,(char*)ptrRecordBuffer,nContentLength);
   if (status!=APR_SUCCESS) 
   {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Writing (STDOUT) data to Client Error... id:%u apr_status:%u",nRequestId,status);
    return HTTP_INTERNAL_SERVER_ERROR;
   }
   return status;
}

/* parse cgi stdout for double new lignes that is the end of cgi header */
/* and add each ligne to brigade and send briagade */
static apr_status_t fcgi_stdout_cgi_header(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, char *ptrRecordBuffer,
						    int *nNewLigneSize,
						    int *nNewLigneChar,
						    int *nPrevChar,
						    int *nFlagCgiHeader,
						    int *nFlagStep,
						    apr_bucket_brigade	*ptrCGIHeaderBucketBrigade,
						    uint16_t  *nContentLength) 
{
   int status;
   char *ptrCGIHeaderPos=ptrRecordBuffer;
   char *ptrRecordBufferEnd=(char*)(ptrRecordBuffer+*nContentLength);
   char *ptrCGIHeaderCurrentLineBuffer=ptrCGIHeaderPos;
   apr_size_t nLen;
   apr_bucket *ptrLocalBucket;
   char sbuf[MAX_STRING_LEN];
   const char *location;
   char *szBuff;
   
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: parse CGI Header: Begin ... id:%u",nRequestId);

   for(;ptrCGIHeaderPos<ptrRecordBufferEnd;ptrCGIHeaderPos++)
   {
      /* good 1: .....CR......CR....CRCR
       * good 2: .....LF......LF....LFLF
       * good 3: .....CRLF....CRLF..CRLFCRLF
       * bad  1: .....CR......LF
       * bad  2: .....LF......CR
       * bad  3: .....CR......CRLF
       * bad  4: .....LF......CRLF
       * bad  5: .....LFCR
       * bad  6: .....CRLF....LF
       * bad  7: .....CRLF....CRCR....
       * bad  8: .....CRLF....CR.
       * bad  9: .....CRLF....CRLFLF
       */
      
      /* detect a double new ligne of 1 byte - 2*CR or 2*LF step 2 */
      if (*nPrevChar!=0&&ptrCGIHeaderPos[0]==*nPrevChar&&*nPrevChar==*nNewLigneChar&&*nNewLigneSize!=2&&*nFlagStep==1)
      {
         *nFlagCgiHeader=1;
	 szBuff=apr_pstrndup(p,(char*)ptrCGIHeaderCurrentLineBuffer,1);
	 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: '%s'...id:%u",szBuff,nRequestId);
	 ptrLocalBucket = apr_bucket_pool_create(szBuff, 1, p, r->connection->bucket_alloc); /* create bucket from ptrData */
	 /* add bucket to the tail of the brigade */
	 APR_BRIGADE_INSERT_TAIL(ptrCGIHeaderBucketBrigade, ptrLocalBucket);
	 ptrCGIHeaderPos++;
	 break;
      }

      /*  detect a double newligne of 2 bytes - 2*CRLF step 4 */
      if (ptrCGIHeaderPos[0]==LF&&*nNewLigneSize==2&&*nFlagStep==3)
      {
         *nFlagCgiHeader=1;
	 szBuff=apr_pstrndup(p,(char*)ptrCGIHeaderCurrentLineBuffer,2);
	 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: '%s'...id:%u",szBuff,nRequestId);
	 ptrLocalBucket = apr_bucket_pool_create(szBuff, 2, p, r->connection->bucket_alloc); /* create bucket from ptrData */
	 /* add bucket to the tail of the brigade */
	 APR_BRIGADE_INSERT_TAIL(ptrCGIHeaderBucketBrigade, ptrLocalBucket);
	 ptrCGIHeaderPos++;
	 break;
      }
      
      /* bad case 1,2,3,4 and 5 */
      if (ptrCGIHeaderPos[0]!=*nNewLigneChar&&(ptrCGIHeaderPos[0]==CR||ptrCGIHeaderPos[0]==LF)&&*nNewLigneSize==1&&*nFlagStep==0)
      {
	 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: newligne of 1 bytes (CR or LF step 0) CR newligne follow LF newligne error...id:%u",nRequestId);
         return HTTP_INTERNAL_SERVER_ERROR;
      }
         
      /* bad case 6 and 9 */
      if (ptrCGIHeaderPos[0]==LF&&(*nFlagStep==0||*nFlagStep==2)&&*nNewLigneSize==2)
      {
	 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: newligne of 2 bytes (2*CRLF step 3 or step 0) LF follow CRLF error...id:%u",nRequestId);
         return HTTP_INTERNAL_SERVER_ERROR;
      }
         
      /* bad case 7 and 8 */
      if (ptrCGIHeaderPos[0]!=LF&&*nFlagStep==3&&*nNewLigneSize==2)
      {
	 ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: newligne of 2 bytes (2*CRLF step 4) LF no follow CRLFCR error...id:%u",nRequestId);
         return HTTP_INTERNAL_SERVER_ERROR;
      }
         
      /* init - detect the begining of the first NewLigne (CR or LF) - step 0 arming reconition */
      if ((ptrCGIHeaderPos[0]==CR||ptrCGIHeaderPos[0]==LF)&&*nFlagStep==0)  
      {
	 if (*nNewLigneChar==0) *nNewLigneChar=ptrCGIHeaderPos[0];
	 if (ptrCGIHeaderPos[0]==LF&&*nNewLigneSize==0) *nNewLigneSize=1; /* if LF the newlignesize is 1 byte only */
	 *nFlagStep=1; /* pass to step 1 */
      }
      /* 1 byte new ligne effectively detect if the next char are diff 
       * than CR or LF and prevchar are one of it for 1st time 
       */
      else if ((ptrCGIHeaderPos[0]!=CR&&ptrCGIHeaderPos[0]!=LF)&&*nPrevChar!=0&&*nFlagStep==1)  
      {
	 *nNewLigneSize=1;
	 *nFlagStep=0; /* reset step */
	 nLen=ptrCGIHeaderPos-ptrCGIHeaderCurrentLineBuffer;
         if (nLen>0) 
	 {
	   szBuff=apr_pstrndup(p,(char*)ptrCGIHeaderCurrentLineBuffer,nLen);
	   ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: '%s'...id:%u",szBuff,nRequestId);
	   ptrLocalBucket = apr_bucket_pool_create(szBuff, nLen, p, r->connection->bucket_alloc); /* create bucket from ptrData */
	   /* add bucket to the tail of the brigade */
	   APR_BRIGADE_INSERT_TAIL(ptrCGIHeaderBucketBrigade, ptrLocalBucket);
	 }
	 ptrCGIHeaderCurrentLineBuffer=ptrCGIHeaderPos;
      }
      /* detect 2 bytes NewLigne (CRLF) - 2*CRLF step 2 */
      else if (*nPrevChar==CR&&ptrCGIHeaderPos[0]==LF&&*nNewLigneSize!=1&&*nFlagStep==1)
      {
         *nNewLigneSize=2; 
	 *nFlagStep=2;
	 nLen=ptrCGIHeaderPos-ptrCGIHeaderCurrentLineBuffer+1;
         if (nLen>0) 
	 {
	   szBuff=apr_pstrndup(p,(char*)ptrCGIHeaderCurrentLineBuffer,nLen);
	   ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: parse CGI Header: '%s'...id:%u",szBuff,nRequestId);
	   ptrLocalBucket = apr_bucket_pool_create(szBuff, nLen, p, r->connection->bucket_alloc); /* create bucket from ptrData */
	   /* add bucket to the tail of the brigade */
	   APR_BRIGADE_INSERT_TAIL(ptrCGIHeaderBucketBrigade, ptrLocalBucket);
	 }
	 ptrCGIHeaderCurrentLineBuffer=ptrCGIHeaderPos+1;
      }
      /*  detect a start of double newligne of 2 bytes - 2*CRLF step 3 */
      else if (ptrCGIHeaderPos[0]==CR&&*nNewLigneSize==2&&*nFlagStep==2)
      {
	 *nFlagStep=3;
      }
      else
         *nFlagStep=0;
      
      *nPrevChar=ptrCGIHeaderPos[0];
   }

   /* dup header in pool and create a bucket */
   if (ptrCGIHeaderPos<=ptrRecordBufferEnd)
     nLen=ptrCGIHeaderPos-ptrRecordBuffer;
   else
     nLen=*nContentLength;

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: parse CGI Header: Header receved %u bytes ... id:%u",nLen,nRequestId);
   if (*nFlagCgiHeader==1)
   {
     /* scan cgi header and set request header out */
     status = ap_scan_script_header_err_brigade(r,ptrCGIHeaderBucketBrigade,sbuf);
     if (status!=OK) return status;

     location = apr_table_get(r->headers_out, "Location");

     if (location && location[0] == '/' && r->status == 200) {
	 /* This redirect needs to be a GET no matter what the original
	  * method was.
	  */
	 r->method = apr_pstrdup(r->pool, "GET");
	 r->method_number = M_GET;

	 /* We already read the message body (if any), so don't allow
	  * the redirected request to think it has one.  We can ignore 
	  * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
	  */
	 apr_table_unset(r->headers_in, "Content-Length");

	 ap_internal_redirect_handler(location, r);
	 return OK;
     }
     else if (location && r->status == 200) {
	 /* XX Note that if a script wants to produce its own Redirect
	  * body, it now has to explicitly *say* "Status: 302"
	  */
	 return HTTP_MOVED_TEMPORARILY;
     }

     /* check and correct content type before sending data to client if content type are "text/html" 
      * to try to correct badly fastcgi that send systematiquely text/html content type 
      */
     if (strncmp(r->content_type,"text/html",17)==0)
     {
       status = ap_run_type_checker(r);
       if (status!=OK) return status;
     }
     

     nLen=ptrRecordBufferEnd-ptrCGIHeaderPos;
     if (nLen>=0)
       *nContentLength=nLen;
     else
       *nContentLength=0;

     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: parse CGI Header: CGI Header end detected ... id:%u",nRequestId);

     if (ptrCGIHeaderPos<ptrRecordBufferEnd)
     {
       return fcgi_stdout_send_data(p,r,nRequestId,(byte_t*)ptrCGIHeaderPos,nLen);
     }
   }
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: parse CGI Header: End ... id:%u",nRequestId);
   return APR_SUCCESS;
}

/*
 * Handle script return... 
 * Read from input filter(from backend connexion), allocate buffer, build "FCGI_STDOUT" and "FCGI_STDERR" Record, create bucket, send it to the client connexion 
 */
static apr_status_t fcgi_recev_stdout_stderr_record(apr_pool_t * p, request_rec *r, u_int16_t nRequestId, proxy_fcgi_conn_t *ptrBackend, byte_t *ptrRecordBuffer) 
{
    apr_status_t 		status=OK;

    /* STDERR variable */
    u_int16_t	nPos,nLen;
    byte_t *ptrRecordBufferPos;


    /* current record header information */
    int       nFlagHeader=1;
    u_int8_t  nVersion=0;
    u_int8_t  nType=FCGI_UNKNOWN_TYPE;
    u_int16_t nContentLength=0;
    u_int8_t  nPaddingLength=0;
    u_int16_t nRecevedRequestId=0;

    /* globale buffer manipulation */
    int        seen_eos=0; /* end of stream loop flag */
    apr_size_t nRecvLen=0;
    uint32_t   nBufferLen=0;
    uint32_t   nTotalRecordLength=0;
    uint32_t   nTotalRecevedData=0;
    uint32_t   nPageContentLength=0;

    /* cgi header parsing */
    int 		nFlagStep=0;
    int        		nFlagCgiHeader=0;
    int        		nPrevChar=0;
    int        		nNewLigneSize=0;
    int        		nNewLigneChar=0;
    apr_bucket_brigade	*ptrCGIHeaderBucketBrigade = apr_brigade_create(p, r->connection->bucket_alloc); /* create empty brigade */

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: ==> STEP 4 - Begin receve FCGI_STDOUT/FCGI_STDERR Stream ... id:%u",nRequestId);
    /* read HUGE_STRING_LEN bytes from backend server connexion */
    do
    {
	while ((nBufferLen<FCGI_HEADER_LEN||nBufferLen<nTotalRecordLength)&&!seen_eos)
	{
	    /* read from client connexion per 8kb max */
	    nRecvLen=HUGE_STRING_LEN;
	    status = fcgi_filter_recv(p, ptrBackend->connection->input_filters,(char*)(ptrRecordBuffer+nBufferLen),&nRecvLen);
	    if (status==APR_EOF) 
	    {
	      seen_eos=1;
	      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: reached end of stream... id:%u",nRequestId);
	    }
	    else if (status!=APR_SUCCESS) 
	    {
	     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Socket reading STDOUT/STDERR record Error... id:%u apr_status:%u",nRequestId,status);
	     return HTTP_INTERNAL_SERVER_ERROR;
	    }

	    /* inc buffer len with receved data len */
	    nBufferLen+=nRecvLen; 

	    /* inc total receved data */
	    nTotalRecevedData+=nRecvLen;

	    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: Readed data from brigade... id:%u nRecvLen:%u nBufferLen:%u",nRequestId,nRecvLen,nBufferLen);

	    if (nBufferLen<FCGI_HEADER_LEN&&seen_eos)
	    {
	      ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: need more data and End of stream error... id:%u nBufferLen:%u headerlen:%u",nRequestId,nBufferLen,FCGI_HEADER_LEN);
	      return HTTP_INTERNAL_SERVER_ERROR;
	    }
	    /* cannot reading first FCGI_HEADER_LEN bytes ! continue reading */
	    if (nBufferLen<FCGI_HEADER_LEN)
	      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: need more data for reading header information... id:%u nBufferLen:%u headerlen:%u",nRequestId,nBufferLen,FCGI_HEADER_LEN);
	}

	/* if is header zone and nBufferLen >= FCGI_HEADER_LEN */
	if (nFlagHeader)
	{

	 /* header read complete ! */
	 /* reset flag */
	 nFlagHeader=0; 
	 status = fcgi_recev_check_header(p, r, nRequestId, (FCGI_Header*)ptrRecordBuffer, &nVersion, &nType, &nContentLength,
						    &nPaddingLength, &nRecevedRequestId, &nTotalRecordLength, nBufferLen) ;
	 if (status!=APR_SUCCESS) return status;
	}

	if (nBufferLen<nTotalRecordLength&&seen_eos)
	{
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: NEED MORE DATA, but reach end of stream error... id:%u actuel readed:%u need :%u",nRequestId,nBufferLen,nTotalRecordLength);
	  return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (nBufferLen<nTotalRecordLength)
	{
	 ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: NEED MORE DATA, data readed are below nTotalRecordLength... id:%u actuel readed:%u need :%u",nRequestId,nBufferLen,nTotalRecordLength);
	 continue;
	}

	switch(nType)
	{
	   case FCGI_END_REQUEST:
              ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: => RECORD FCGI_END_REQUEST Receved ... id:%u",nRequestId);
	      seen_eos=1; /* end of dialog with FastCGI server */
	      break;

	   case FCGI_STDOUT:
	      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: => RECORD STDOUT Receved ... id:%u nContentLength:%u nPaddingLength:%u",nRequestId,nContentLength,nPaddingLength);
	      if (nFlagCgiHeader!=0)  /* data zone */
	      {
	        nPageContentLength+=nContentLength;
		status = fcgi_stdout_send_data(p, r, nRequestId, ptrRecordBuffer+FCGI_HEADER_LEN, nContentLength);
		if (status!=APR_SUCCESS) return status;
	      }
	      else /* CGI Header zone */
	      {
	        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: => RECORD STDOUT Receved PARSING CGI HEADER ... id:%u nContentLength:%u nPaddingLength:%u",nRequestId,nContentLength,nPaddingLength);
		status = fcgi_stdout_cgi_header(p, r, nRequestId, (char*)ptrRecordBuffer+FCGI_HEADER_LEN, &nNewLigneSize,
						  &nNewLigneChar, &nPrevChar, &nFlagCgiHeader, &nFlagStep, ptrCGIHeaderBucketBrigade,&nContentLength);
		if (status!=APR_SUCCESS) return status;
		nPageContentLength+=nContentLength;
	      }
	      break;
	   case FCGI_STDERR:
	      ptrRecordBufferPos=ptrRecordBuffer+FCGI_HEADER_LEN;

              ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: => RECORD STDERR receved ... id:%u nContentLength:%u nPaddingLength:%u",nRequestId,nContentLength,nPaddingLength);

	      /* set all \r and \n to \0 and log to apache error log all ligne that have more than zero charaters */
	      for(nPos=0;nPos<nContentLength;nPos++)
	      { 
		if ((ptrRecordBuffer[nPos]='\n')||(ptrRecordBuffer[nPos]='\r'))
		{
		   ptrRecordBuffer[nPos]='\0'; 
		   nLen=ptrRecordBufferPos-ptrRecordBuffer+nPos;
		   if (nLen>0)
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "proxy: FCGI: STDERR>%s", ptrRecordBufferPos);
		   ptrRecordBufferPos=ptrRecordBuffer+nPos+1; 
		}
	      } 
	      break;
	}


	if (nBufferLen>=nTotalRecordLength)
	{
	  nBufferLen=nBufferLen-nTotalRecordLength;
	  if (nBufferLen>0)
	  {
	     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: nBufferLen readed more then nTotalRecordLength move data the start of the buffer... id:%u nTotalRecordLength:%u nBufferLen:%u",nRequestId,nTotalRecordLength,nBufferLen);
	     memcpy(ptrRecordBuffer,ptrRecordBuffer+nTotalRecordLength,nBufferLen);
	     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: moved data the start of the buffer... id:%u nTotalRecordLength:%u nBufferLen:%u",nRequestId,nTotalRecordLength,nBufferLen);
	  }
	  else
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: nBufferLen reach nTotalRecordLength... id:%u ",nRequestId);
          nTotalRecordLength=0;
	  nContentLength=0;
	  nPaddingLength=0;
	  nFlagHeader=1;
	}

    } while(!seen_eos);

    if (status!=APR_SUCCESS) 
    {
     char szErrMsg[100];
     apr_strerror(status,szErrMsg,sizeof(szErrMsg));
     ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "proxy: FCGI: Socket reading STDOUT/STDERR record Error... id:%u apr_status:%u errmsg:%s",nRequestId,status,szErrMsg);
     return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "proxy: FCGI: End of the request... id:%u fcgi server data sent:%u page len:%u",nRequestId,nTotalRecevedData,nPageContentLength);
    return APR_SUCCESS;
}

/*
 * process the request and write the response.
 */
apr_status_t fcgi_process_request(apr_pool_t * p, request_rec *r,
					   proxy_server_conf *conf,
					   apr_uri_t *uri, 
					   char *url, 
					   proxy_fcgi_conn_t *ptrBackend) 
{
    apr_status_t status;
    int	nServerPort;
    char szServerPort[32];
    unsigned int 		nRequestId		= (r->connection->id & 0xffff) + 1;

    /* allocate buffer FCGI_MAX_LENGTH+FCGI_HEADER_LEN sized that is the max size of FastCGI record * 2 for security */
    byte_t 			*ptrRecordBuffer	= apr_pcalloc(p, (FCGI_MAX_LENGTH + FCGI_HEADER_LEN + 1)*2);

    /* Get the server port for the Via headers */
    nServerPort = ap_get_server_port(r);
    if (ap_is_default_port(nServerPort, r)) 
	strcpy(szServerPort,"");
    else 
	apr_snprintf(szServerPort, sizeof(szServerPort)-1, ":%d", nServerPort);

    /* strip connection listed hop-by-hop headers from the request */
    /* even though in theory a connection: close coming from the client
     * should not affect the connection to the server, it's unlikely
     * that subsequent client requests will hit this thread/process, so
     * we cancel server keepalive if the client does.
     */
    ptrBackend->close += ap_proxy_liststr(apr_table_get(r->headers_in,
                                                     "Connection"), "close");
    /* sub-requests never use keepalives */
    if (r->main) 
    {
        ptrBackend->close++;
    }

    /* force close at each request,keep alive not supported by many FastCGI server implementation */
    /* TODO: correct this to support keepalive (fix server implementation!) */
    ptrBackend->close++;

    ap_proxy_clear_connection(p, r->headers_in);
    if (ptrBackend->close) 
    {
        apr_table_setn(r->headers_in, "Connection", "close");
        ptrBackend->connection->keepalive = AP_CONN_CLOSE;
    }

    if ( apr_table_get(r->subprocess_env,"proxy-nokeepalive")) 
    {
        apr_table_unset(r->headers_in, "Connection");
        ptrBackend->connection->keepalive = AP_CONN_CLOSE;
        ptrBackend->close++;
    }

    
    /*
     * build and send "FCGI_BEGIN_REQUEST" Record to the backend connexion 
     */
    status = fcgi_send_begin_record(p,r,nRequestId,ptrBackend,ptrRecordBuffer);
    if (status!=APR_SUCCESS) return status;


    /*
     * build and send "FCGI_PARAMS" Record to the backend connexion 
     */
    status = fcgi_send_params_record(p,r,nRequestId,ptrBackend,ptrRecordBuffer);
    if (status!=APR_SUCCESS) return status;

    /*
     * Transfer any put/post args, CERN style (formated as "FCGI_STDIN" Record) to the backend connexion...
     */
    status = fcgi_send_stdin_record(p,r,nRequestId,ptrBackend,ptrRecordBuffer);
    if (status != APR_SUCCESS) return status;

    /*
     * Handle script return (unformat "FCGI_STDOUT" and "FCGI_STDERR" Record)... 
     * and send it to the client connexion 
     */
    status = fcgi_recev_stdout_stderr_record(p,r,nRequestId,ptrBackend,ptrRecordBuffer);
    if (status != APR_SUCCESS) return status;

    return OK;
}



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

/* FastCGI routines for Apache proxy */

#include <mod_proxy.h>
#include "mod_proxy_fcgi.h"
#include "fcgi_protocol.h"


module AP_MODULE_DECLARE_DATA proxy_fcgi_module;


/*
 * Canonicalise http-like URLs.
 */
static int proxy_fcgi_canon(request_rec *r, char *szUrl)
{
    char *szHost, *szPath, *szSearch, szSrcPort[7];
    const char *szErr;
    apr_port_t nPort = 0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: FCGI: canonicalising URL='%s'", szUrl);

    /* ap_port_of_scheme() */
    if (strncasecmp(szUrl, "fcgi:", 4) == 0) 
    {
        szUrl += 5;
    }
    else 
    {
        return DECLINED;
    }

    /*
     * do syntactic check.
     * We break the URL into szHost, nPort, szPath, szSearch
     */
    szErr = ap_proxy_canon_netloc(r->pool, &szUrl, NULL, NULL, &szHost, &nPort);
    if (szErr) 
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL='%s': %s",
                      szUrl, szErr);
        return HTTP_BAD_REQUEST;
    }

    if (!nPort) 
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL='%s': %s - you must provide destination port",
                      szUrl, szErr);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse szPath/szSearch args, according to rfc1738
     *
     * N.B. if this isn't a true proxy request, then the URL _path_
     * has already been decoded.  True proxy requests have
     * r->uri == r->unparsed_uri, and no others have that property.
     */
    if (r->uri == r->unparsed_uri) 
    {
        szSearch = strchr(szUrl, '?');
        if (szSearch != NULL)
            *(szSearch++) = '\0';
    }
    else
        szSearch = r->args;

    /* process szPath */
    szPath = ap_proxy_canonenc(r->pool, szUrl, strlen(szUrl), enc_path, r->proxyreq);
    if (szPath == NULL)
        return HTTP_BAD_REQUEST;

    apr_snprintf(szSrcPort, sizeof(szSrcPort), ":%d", nPort);

    if (ap_strchr_c(szHost, ':')) 
    {
        /* if literal IPv6 address */
        szHost = apr_pstrcat(r->pool, "[", szHost, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:fcgi://", szHost, szSrcPort,
                              "/", szPath, (szSearch) ? "?" : "",
                              (szSearch) ? szSearch : "", NULL);
    return OK;
}

/* Break up the URL to determine the host to connect to */
static apr_status_t proxy_fcgi_parse_normalize_url(apr_pool_t *p,
						      request_rec *r,
						      apr_uri_t **ptrUri,
						      char **szUrl)
{

    /* we break the URL into host, port, uri */
    if (apr_uri_parse(p, *szUrl, *ptrUri) != APR_SUCCESS) 
    {
        return ap_proxyerror(r, HTTP_BAD_REQUEST,
                             apr_pstrcat(p,"URI cannot be parsed: ", *szUrl,
                                         NULL));
    }

    /* port must but set, not default port for fastcgi protocol */
    if (!(*ptrUri)->port) 
    {
        return ap_proxyerror(r, HTTP_BAD_REQUEST,
                             apr_pstrcat(p,"Port note defined in the URI: ", *szUrl,
                                         NULL));
    }

    /* reconstruct url with uri struct */
    *szUrl = apr_pstrcat(p, (*ptrUri)->path, (*ptrUri)->query ? "?" : "",
		       (*ptrUri)->query ? (*ptrUri)->query : "",
		       (*ptrUri)->fragment ? "#" : "",
		       (*ptrUri)->fragment ? (*ptrUri)->fragment : "", NULL);

    return OK;
}

static apr_status_t proxy_fcgi_get_backend_connection(apr_pool_t *p, 
							 request_rec *r,
							 proxy_server_conf *ptrProxyConf,
							 apr_uri_t *ptrUri,
						         char *szUrl,
							 proxy_fcgi_conn_t **ptrPtrBackendConnection) 
{
    apr_status_t 	nErr;
    conn_rec 		*c 			= r->connection;
    apr_port_t		nPort			= ptrUri->port;
    char		*szHostname		= apr_pstrdup(p, ptrUri->hostname);
    int 		failed			= 0;
    int 		new			= 1;
    conn_rec 		*ptrOriginalConnection	= NULL;
    apr_sockaddr_t 	*ptrUriAddr		= NULL;
    apr_socket_t 	*client_socket 		= NULL;
    proxy_fcgi_conn_t 	*ptrBackend 	= NULL;
     
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FastCGI serving %s to %s:%d", szUrl, ptrUri->hostname,
                 ptrUri->port);

    /* try to get the previous backend connexion if in keepalive mode.
     * and only use stored info for top-level pages. Sub requests don't share 
     * in keepalives
     */
    if (!r->main) 
        ptrBackend = (proxy_fcgi_conn_t *) ap_get_module_config(c->conn_config, &proxy_fcgi_module);
    /* create space for state information */
    if (!ptrBackend) 
    {
        ptrBackend = apr_pcalloc(p, sizeof(proxy_fcgi_conn_t));
        if (!r->main) ap_set_module_config(c->conn_config, &proxy_fcgi_module, ptrBackend);
    }

    /* do a DNS lookup for the url destination host */
    nErr = apr_sockaddr_info_get(&ptrUriAddr, ptrUri->hostname, APR_UNSPEC, ptrUri->port, 0, p);
    if (nErr != APR_SUCCESS) 
    {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             apr_pstrcat(p, "DNS lookup failure for: ",
                                         szHostname, NULL));
    }

    *ptrPtrBackendConnection=ptrBackend;
    
    /* the check on c->id makes sure that this string does not get accessed
     * past the connection lifetime. 
     * get all the possible IP addresses for the destname and loop through them
     * until we get a successful connection.
     * if a keepalive socket is already open, check whether it must stay
     * open, or whether it should be closed and a new socket created.
     */

    /* get a socket - either a keepalive one, or a new one */
    if (ptrBackend->connection) 
    {
	/* check backend id with connexion id, if mismatch close backend socket */
        client_socket = ap_get_module_config(ptrBackend->connection->conn_config, &core_module);
        if ((ptrBackend->connection->id == c->id) &&
            (ptrBackend->port == nPort) &&
            (ptrBackend->hostname) &&
            (!apr_strnatcasecmp(ptrBackend->hostname, szHostname))) 
	{
	    apr_size_t buffer_len = 1;
	    char test_buffer[1]; 
	    apr_status_t socket_status;
	    apr_interval_time_t current_timeout;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: keepalive address match (keep original socket)");

	    /* use previous keepalive socket and check if closed */
	    ptrBackend->sock = client_socket;

	    /* save timeout */
	    apr_socket_timeout_get(ptrBackend->sock, &current_timeout);
	    /* set no timeout */
	    apr_socket_timeout_set(ptrBackend->sock, 0);
	    socket_status = apr_recv(ptrBackend->sock, test_buffer, &buffer_len);
	    /* put back old timeout */
	    apr_socket_timeout_set(ptrBackend->sock, current_timeout);
	    if ( APR_STATUS_IS_EOF(socket_status) ) 
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
			     "proxy: FastCGI: previous connection is closed");
	    else
		new = 0;
        } 
	else 
	{
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: keepalive address mismatch / connection has"
                         " changed (close old socket (%s/%s, %d/%d))", 
                         szHostname, ptrBackend->hostname, nPort,
                         ptrBackend->port);
            apr_socket_close(client_socket);
            ptrBackend->connection = NULL;
        }
    }
    if (new) 
    {

        /* create a new socket */
        ptrBackend->connection = NULL;

        /*
         * At this point we have a list of one or more IP addresses of
         * the machine to connect to. If configured, reorder this
         * list so that the "best candidate" is first try. "best
         * candidate" could mean the least loaded server, the fastest
         * responding server, whatever.
         *
         * For now we do nothing, ie we get DNS round robin.
         * XXX FIXME
         */
        failed = ap_proxy_connect_to_backend(&ptrBackend->sock, "FastCGI",
                                             ptrUriAddr, szHostname,
                                             ptrProxyConf, r->server, p);

        /* handle a permanent error on the connect */
        if (failed) 
	{
                return HTTP_BAD_GATEWAY;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: socket is connected");

        /* the socket is now open, create a new backend server connection (call "create_connection" hook) */
        ptrOriginalConnection = ap_run_create_connection(p, r->server, ptrBackend->sock,
                                           r->connection->id,
                                           r->connection->sbh, c->bucket_alloc);
        if (!ptrOriginalConnection) 
	{
        /* the peer reset the connection already; ap_run_create_connection() 
         * closed the socket
         */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                         r->server, "proxy: an error occurred creating a "
                         "new connection to %pI (%s)", ptrUriAddr,
                         szHostname);
            apr_socket_close(ptrBackend->sock);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ptrBackend->connection = ptrOriginalConnection;
        ptrBackend->hostname = apr_pstrdup(p, szHostname);
        ptrBackend->port = nPort;

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: connection complete to %pI (%s)",
                     ptrUriAddr, szHostname);

        /* set up the connection filters (call "pre_connection" hook) */
        ap_run_pre_connection(ptrBackend->connection, ptrBackend->sock);
    }

    return OK;
}

static apr_status_t proxy_fcgi_cleanup(request_rec *r, proxy_fcgi_conn_t *ptrBackend) 
{
    /* If there are no KeepAlives, or if the connection has been signalled
     * to close, close the socket and clean up
     */

    /* if the connection is < HTTP/1.1, or Connection: close,
     * we close the socket, otherwise we leave it open for KeepAlive support
     */
    if (ptrBackend->close || (r->proto_num < HTTP_VERSION(1,1))) 
    {
        if (ptrBackend->sock) 
	{
            apr_socket_close(ptrBackend->sock);
            ptrBackend->sock = NULL;
            ptrBackend->connection = NULL;
        }
    }
    return OK;
}

/*
 * This handles fcgi:// URLs
 */
static int proxy_fcgi_handler(request_rec *r, proxy_server_conf *ptrProxyConf,
                             char *szUrl, const char *szProxyName,
                             apr_port_t nProxyPort)
{
    int 		status;
    proxy_fcgi_conn_t 	*ptrBackend 	= NULL;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: serving URL %s", szUrl);

    /* reverse proxy mode only */
    if ((szProxyName)||(r->proxyreq!=PROXYREQ_REVERSE)) 
       return DECLINED;

    /* decline if scheme are not "fcgi:" */
    if (strncasecmp(szUrl, "fcgi:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: FCGI: declining URL %s", szUrl);
        return DECLINED;
    }

    /*
     * Note: Memory pool allocation.
     * A downstream (to the backend server) keepalive connection is always connected to the existence
     * (or not) of an upstream keepalive connection. If this is not done then
     * load balancing against multiple backend servers breaks (one backend
     * server ends up taking 100% of the load), and the risk is run of
     * downstream keepalive connections being kept open unnecessarily. This
     * keeps webservers busy and ties up resources.
     *
     * As a result, we allocate all sockets out of the upstream connection
     * pool, and when we want to reuse a socket, we check first whether the
     * connection ID of the current upstream connection is the same as that
     * of the connection when the backend socket was opened.
     */
    apr_pool_t 		*p 			= r->connection->pool;

    apr_uri_t 		*ptrUri			= apr_pcalloc(p, sizeof(*ptrUri));


    /* Step one: Break up the URL to determine the host to connect to */
    status = proxy_fcgi_parse_normalize_url(p,r,&ptrUri,&szUrl);
    if ( status != OK ) return status;

    /* Step Two: Make or get the backend Connection in resquest pool */
    status = proxy_fcgi_get_backend_connection(r->pool, r, 
						  ptrProxyConf,
						  ptrUri,
						  szUrl,
						  &ptrBackend);
    if ( status != OK ) 
    {
      proxy_fcgi_cleanup(r, ptrBackend);
      return status;
    }

    /* Step Tree: process request */
    status = fcgi_process_request(p, r, 
				  ptrProxyConf, 
				  ptrUri, 
				  szUrl, 
				  ptrBackend);
    if ( status != OK ) 
    {
      proxy_fcgi_cleanup(r, ptrBackend);
      return status;
    }

    /* Step Four: Clean Up */
    status = proxy_fcgi_cleanup(r, ptrBackend);
    if ( status != OK ) return status;

    return OK;
}

static void proxy_fcgi_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_fcgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_fcgi_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_fcgi_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    proxy_fcgi_register_hook    /* register hooks */
};


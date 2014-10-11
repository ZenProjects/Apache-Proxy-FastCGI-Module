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

#ifndef FCGI_PROTOCOL_H
#define FCGI_PROTOCOL_H

#include "mod_proxy.h"
#include "mod_proxy_fcgi.h"
#include "fcgi_record.h"

apr_status_t fcgi_process_request(apr_pool_t * p, request_rec *r,
					   proxy_server_conf *conf,
					   apr_uri_t *uri, 
					   char *url, 
					   proxy_fcgi_conn_t *ptrBackend);

#endif

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

#ifndef MOD_PROXY_FCGI_H
#define MOD_PROXY_FCGI_H

typedef struct {
    conn_rec*	    connection;
    apr_socket_t*   sock;
    char* 	    hostname;
    apr_port_t 	    port;
    int 	    is_ssl;
    int             close;
} proxy_fcgi_conn_t;


#endif

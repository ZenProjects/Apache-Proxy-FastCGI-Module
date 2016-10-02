[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

Apache Proxy FastCGI Module
==============

"mod_proxy_fcgi" is an Apache v2.0 proxy sheme module that implement "fcgi:" scheme to handle reverse proxy protocole FastCGI.

It's complete rewrite of the old mod_fastcgi module developt by OpenMarket, based on FastCGI and CGI specification.

My goal is to implement a suitable implementation of FastCGI (who work correctly with PHP!) with fully open source licence (have maked the module with Apache 2.0 Licence).

And that are simple to use (only need actualy PassReverse command!) in external server mode (like FastCgiExternalServer).

And work only in remote mode (i dont need processus manager, i execute PHP separatly on other machine!).

And the old module has been freeze from 2004...no evolution in way i need seen...

And mod_fcgid are only in processus manager axis...

have been inspired from mod_proxy_ajp of Apache 2.2 version in way to achive this.

but have developt it for Apache 2.0 for the moment beceause is the production environment at my work and have no need of load balancing to FastCGI server for the moment, but i port it later to Apache 2.2...

All the documentations are [here](http://zenprojects.github.io/Apache-Proxy-FastCGI-Module/)

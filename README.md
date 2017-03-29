[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

--------

# WARNING
## _This project are completely experimental_
## Prefere to use [mod_proxy_fcgi from apache 2.4](https://httpd.apache.org/docs/2.4/mod/mod_proxy_fcgi.html) ...

--------

# What is "mod_proxy_fcgi"?

"mod_proxy_fcgi" is an Apache v2.0 proxy sheme module that implement "fcgi:" scheme to handle reverse proxy protocole FastCGI.

It complete rewrite of the old mod_fastcgi module developt by OpenMarket, based on FastCGI and CGI specification.

My goal is to implement a suitable implementation of FastCGI (who work correctly with PHP!) with fully open source licence (have maked the module with Apache 2.0 Licence).

And that are simple to use (only need actualy PassReverse command!) in external server mode (like FastCgiExternalServer).

And work only in remote mode (i dont need processus manager, i execute PHP separatly on other machine!).

And the old module has been freeze from 2004...no evolution in way y need seen...

And mod_fcgid are only in processus manager axis...

have been inspired from mod_proxy_ajp of Apache 2.2 version in way to achive this.

but have developt it for Apache 2.0 for the moment beceause is the production environment at my work and have no need of load balancing to FastCGI server for the moment, but i port it later to Apache 2.2...

# How it Works

This module add the possibility to user "fcgi:" scheme in "ProxyPass" command in place of "http:" or "ftp:" scheme natively implemented in Apache proxy.

In that way you can use Apache in proxy mode for FastCGI external server.

You can make different DMZ to separate http proxy from server execution logic.

Like this:
firewall -> http proxy fastcgi -> firewall -> fastcgi server (ex: php) -> firewall -> mysql

You can execute all this one in different virtual machine like xen...

You can add mod_security on http proxy to reinforce security.

You can chroot php FastCGI server instance for more security.

# Build dependency

You must have installed "[makepp](http://makepp.sourceforge.net/)" before building this module.

# Compilation

You must modify Makefile:
- Set correctly the MY_APXS variable to point to the apache "apxs" scripts.
- Add the Apache include path  in MY_CFLAGS variable if necessary (-I <apache includes path>)

How to compile:

    # makepp
    # makepp install


After that the "mod_proxy_fcgi.so" is generated in apache "modules" directory.

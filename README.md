pam_utorauth
============

Minimalist PAM module for accessing the University of Toronto's UTORauth system

	cc -shared -lpam -lkrb5 -o pam_utorauth.so pam_utorauth.c

As of 2013-08-05 this has been tested **only** on Mac OS X 10.8.4 … be warned! The lack of ```./configure``` should indicate the extent of the kludging that has taken place.
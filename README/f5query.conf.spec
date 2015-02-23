# This file contains possible attributes and values you can use to configure f5query,
# sets connections string, user, name which is distributed to search heads.
#
# This is an f5query.conf in $SPLUNK_HOME/etc/f5query/default.  To set custom configurations,
# place an f5query.conf $SPLUNK_HOME/etc/f5query/local.


#*******
# GENERAL SETTINGS:
# This following attribute/value pairs are valid for all stanzas.  The [f5query] stanza
# is required.
#*******

[f5query]
user = F5 iControl User
* sets user for F5 iControl, required.

password = F5 iControl User password
* set password for F5 iControl, required.  Must define user.

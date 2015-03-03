Copyright (C) 2006-2015 Zillow Group, Inc. All Rights Reserved.

F5 Query - A Splunk Search Command for Service Now
=================

F5 Query now is a Splunk Search command that uses the iControl api  and a json object converted from SOAP.
This Splunk utilizes requests python modules.

##Supports:
* Supports multiple F5 devices.





Requirements
---------

* This version has been test on 6.x and should work on 5.x.

* App is known to work on Linux,and Mac OS X, but has not been tested on other operating systems. Window should work

* App requires network access to Service Now instance

* Miminum of 2 GB RAM and 1.8 GHz CPU.



Prerequisites
---------
* F5 iControl 10.x or Higher

* Splunk version 6.x or Higher

You can download it [Splunk][splunk-download].  And see the [Splunk documentation][] for instructions on installing and more.
[Splunk]:http://www.splunk.com
[Splunk documentation]:http://docs.splunk.com/Documentation/Splunk/latest/User
[splunk-download]:http://www.splunk.com/download


Installation instructions
---------

1) copy repo into $SPLUNK_HOME/etc/apps/.

2) create $SPLUNK_HOME/etc/apps/f5query/local/f5query.conf.

3) configure [f5query] stanza with url to graphite instance. Note: if proxy look at README for proxy config.

Example Command
---------

`| f5Query pool="common/splunk_443_pool,common/splunk_80_pool" poolOnly=True partition="common" device="f5.com"
    OR
`| f5Query vservers="/Common/trans.mycompany_86_vs,/Common/post.mycompany_81_vs" stats=True partition="common" device="f5.com"

Recommendations
---------

It is recommend that this be installed on an Search head.

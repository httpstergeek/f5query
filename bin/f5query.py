# encoding: utf-8
# Author: Bernardo Macias <bmacias@httpstergeek.com>
#
#
# All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'Bernardo Macias '
__credits__ = ['Bernardo Macias']
__license__ = "ASF"
__version__ = "2.0"
__maintainer__ = "Bernardo Macias"
__email__ = 'bmacias@httpstergeek.com'
__status__ = 'Production'

import os
import logging
import logging.handlers
import sys
import json
import threading
from datetime import datetime
import time
from platform import system
from splunk.clilib import cli_common as cli
from splunklib.searchcommands import \
    dispatch, GeneratingCommand, Configuration, Option

platform = system().lower()

# Loading eggs into python execution path
if platform == 'darwin':
    platform = 'macosx'
running_dir = os.path.dirname(os.path.realpath(__file__))
egg_dir = os.path.join(running_dir, 'eggs')
for filename in os.listdir(egg_dir):
    file_segments = filename.split('-')
    if filename.endswith('.egg'):
        filename = os.path.join(egg_dir, filename)
        if len(file_segments) <= 3:
            sys.path.append(filename)
        else:
            if platform in filename:
                sys.path.append(filename)

import suds
import bigsuds

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')

def setup_logger(level):
    """
    :param level: Logging level
    :type level: logger object
    :return : logger object
    """
    logger = logging.getLogger('f5query')
    logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)
    file_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, 'var', 'log', 'splunk', 'f5query.log'),
                                                        maxBytes=5000000,
                                                        backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    consolehandler = logging.StreamHandler()
    consolehandler.setFormatter(formatter)
    logger.addHandler(consolehandler)
    return logger


logger = setup_logger(logging.INFO)


def get_stanza(conf, stanza):
    """
    Returns dict object of config file settings
    :param conf: Splunk conf file name
    :param stanza: stanza (entry) from conf file
    :return: returns dictionary of setting
    """
    appdir = os.path.dirname(os.path.dirname(__file__))
    conf = "%s.conf" % conf
    apikeyconfpath = os.path.join(appdir, "default", conf)
    apikeyconf = cli.readConfFile(apikeyconfpath)
    localconfpath = os.path.join(appdir, "local", conf)
    if os.path.exists(localconfpath):
        localconf = cli.readConfFile(localconfpath)
        for name, content in localconf.items():
            if name in apikeyconf:
                apikeyconf[name].update(content)
            else:
                apikeyconf[name] = content
    return apikeyconf[stanza]


def tojson(jmessage):
    jmessage = json.dumps(json.loads(json.JSONEncoder().encode(jmessage)),
                          indent=4,
                          sort_keys=True,
                          ensure_ascii=True)
    return jmessage


def convert_64bit(signed_high, signed_low):
    """
        Converts two 32 bit signed integers to a 64-bit unsigned integer
        :param signed_high: signed 32bit integer.
        :type signed_high: int
        :param signed_low: signed 32bit integer.
        :type signed_low: int
        :return: int
    """
    # x << n operation x shifted left by n bits
    if signed_high < 0:
        signed_high += (1 << 32)
    if signed_low < 0:
        signed_low += (1 << 32)
    unsigned_value = long((signed_high << 32) | signed_low)
    assert (unsigned_value >= 0)
    return unsigned_value


class Threads(threading.Thread):
    """
    Simple Threading Class
    """
    def __init__(self):
        self.jobs = list()

    def run(self, target=None, args=None):
        """
        starts thread and adds to job list
        :param target: function or method.
        :type target: object
        :return: None
        """
        if target:
            job = threading.Thread(target=target, args=args)
            self.jobs.append(job)
            job.start()


class Worker(threading.Thread):
    """
    Simple Threading Class
    """
    # TODO rewrite to use daemon and exception handling
    def __init__(self):
        self.jobs = list()

    def run(self, target=None):
        """
        starts thread and adds to job list
        :param target: function or method.
        :type target: object
        :return: None
        """
        if target:
            job = threading.Thread(target=target)
            self.jobs.append(job)
            job.start()


class ThreadPool:
    """
    Pool of threads consuming tasks from a queue
    """
    # TODO add add_task and wait_completion methods
    pass


class F5Client():
    """
    Connects to F5 iControl interface.  Methods allow for short hand.
    """

    def __init__(self, user, passwd, host):
        self.f5 = bigsuds.BIGIP(
            hostname=host,
            username=user,
            password=passwd
        )
        self.plist = None
        self.pstatus = None
        self.pmembers = None
        self.pmember_status = None
        self.pmember_stats = None
        self.vlist = None
        self.vservers = None
        self.vdests = None
        self.vpools = None
        self.vstats = None

    def set_partition(self, partition):
        """
        Set active partition for methods.
        :param partition: F5 partition name.
        :type partition: str
        :return: str
        """
        activeparition = self.f5.Management.Partition.get_active_partition()
        if partition != activeparition:
            self.f5.Management.Partition.set_active_partition(partition)
        return self.f5.Management.Partition.get_active_partition()

    def pool_list(self, pools=None):
        """
        Splits pools by comma, if None gets all F5 Pools
        :param pools: comma separated string for each pool
        :type pools: string
        :return: list
        """
        self.plist = pools.split(',') if pools else self.f5.LocalLB.Pool.get_list()

    def pool_status(self, pools=None):
        """
        Returns Pool status
        :param pools: F5 Pools
        :type pools: list
        :return: list
        """
        pools = pools if pools else self.plist
        if pools:
            self.pstatus = self.f5.LocalLB.Pool.get_object_status(pools)


    def pool_members(self, pools=None):
        """
        Returns list of all pool members
        :param pools: F5 Pools
        :type pools: list
        :return: list
        """
        pools = pools if pools else self.plist
        if pools:
            self.pmembers = self.f5.LocalLB.Pool.get_member_v2(pools)

    def pool_member_status(self, pools=None):
        """
        Returns list of all pool members status
        :param pools: F5 Pools
        :type pools: list
        :return: list
        """
        pools = pools if pools else self.plist
        if pools:
            self.pmember_status = self.f5.LocalLB.PoolMember.get_object_status(pools)


    def pool_member_stats(self, pools=None):
        """
        Returns list of all pool members statistics
        :param pools: F5 Pools
        :type pools: list
        :return: list
        """
        pools = pools if pools else self.plist
        if pools:
            self.pmember_stats = self.f5.LocalLB.Pool.get_all_member_statistics(pools)

    def vserver_list(self, vservers=None):
        """
        Splits vservers by comma, if None gets all F5 virtual servers
        :param vservers: comma separated string for each virtual server
        :type vservers: string
        :return: list
        """
        self.vlist = vservers.split(',') if vservers else self.f5.LocalLB.VirtualServer.get_list()

    def vserver_dest(self, vservers=None):
        """
        Returns virtual servers ip and port
        :param vservers: virtual servers
        :type vservers: list
        :return: list
        """
        vservers = vservers if vservers else self.vlist
        if vservers:
            self.vdests = self.f5.LocalLB.VirtualServer.get_destination_v2(vservers)

    def vserver_pool(self, vservers=None):
        """
        Returns virtual servers default pool association
        :param vservers: virtual servers
        :type vservers: list
        :return: list
        """
        vservers = vservers if vservers else self.vlist
        if vservers:
            self.vpools = self.f5.LocalLB.VirtualServer.get_default_pool_name(vservers)

    def vserver_stats(self, vservers=None):
        """
        Returns virtual servers statistics
        :param vservers: virtual servers
        :type vservers: list
        :return: list
        """
        vservers = vservers if vservers else self.vlist
        if vservers:
            self.vstats = self.f5.LocalLB.VirtualServer.get_statistics(vservers)

    def pools_output(self, members=None, membersstatuses=None, poolstatistics=None):
        timestamp = time.time()
        timeoffset = (time.mktime(time.localtime()) - time.mktime(time.gmtime()))
        for n, pool in enumerate(self.plist):
            partition, pool = pool.strip('/').split('/')
            if self.pmembers:
                for i, member in enumerate(self.pmembers[n]):
                    poolinfo = dict()
                    poolinfo['_time'] = timestamp
                    poolinfo['pool_partition'] = partition
                    poolinfo['pool_name'] = pool
                    xpool, poolinfo['pool_member'] = member['address'].strip('/').split('/')
                    if self.pmember_status:
                        poolinfo['pool_member_address'] = self.pmember_status[n][i]['member']['address']
                        poolinfo['pool_member_port'] = self.pmember_status[n][i]['member']['port']
                        poolinfo['pool_member_availability_status'] = self.pmember_status[n][i]['object_status']['availability_status']
                        poolinfo['pool_member_enabled_status'] = self.pmember_status[n][i]['object_status']['enabled_status']
                    if self.pmember_stats:
                        for stats in self.pmember_stats[n]['statistics'][i]['statistics']:
                            poolinfo[stats['type'].replace('STATISTIC_', 'pool_member_').lower()] = convert_64bit(
                                stats['value']['high'],
                                stats['value']['low'])
                            stattime = self.pmember_stats[n]['time_stamp']
                            time_struct = datetime(stattime['year'], stattime['month'], stattime['day'],
                                                   stattime['hour'], stattime['second']).timetuple()
                            poolinfo['_time'] = time.mktime(time_struct) + timeoffset
                    poolinfo['pool_availability_status'] = self.pstatus[n]['availability_status']
                    poolinfo['pool_enabled_status'] = self.pstatus[n]['enabled_status']
                    poolinfo['_raw'] = tojson(poolinfo)
                    yield poolinfo
            else:
                poolinfo = dict()
                poolinfo['_time'] = timestamp
                poolinfo['partition'] = partition
                poolinfo['pool_name'] = pool
                poolinfo['pool_availability_status'] = self.pstatus[n]['availability_status']
                poolinfo['pool_enabled_status'] = self.pstatus[n]['enabled_status']
                poolinfo['_raw'] = tojson(poolinfo)
                yield poolinfo

    def vserver_output(self):
        timestamp = time.time()
        timeoffset = (time.mktime(time.localtime()) - time.mktime(time.gmtime()))
        if self.vlist:
            for n, server in enumerate(self.vlist):
                vserverinfo = dict()
                vserverinfo['_time'] = timestamp
                partition, vAddress = self.vdests[n]['address'].strip('/').split('/')
                vpartition, vServer = server.strip('/').split('/')
                if self.vpools[n] != '':
                    pool_partition, pool = self.vpools[n].strip('/').split('/')
                    vserverinfo['pool_partition'] = pool_partition
                    vserverinfo['pool_name'] = pool
                vserverinfo['virtual_server_name'] = vServer
                vserverinfo['virtual_address'] = vAddress
                vserverinfo['virtual_server_partition'] = partition
                if self.vstats:
                    stattime = self.vstats['time_stamp']
                    time_struct = datetime(stattime['year'], stattime['month'], stattime['day'], stattime['hour'],
                                           stattime['second']).timetuple()
                    vserverinfo['_time'] = time.mktime(time_struct) + timeoffset
                    vserverinfo['virtual_sever_protocol'] = self.vstats['statistics'][n]['virtual_server'][
                        'protocol']
                    vserverinfo['virtual_sever_port'] = self.vstats['statistics'][n]['virtual_server']['port']
                    for stats in self.vstats['statistics'][n]['statistics']:
                        vserverinfo[stats['type'].replace('STATISTIC_', 'virtual_server_').lower()] = convert_64bit(
                            stats['value']['high'],
                            stats['value']['low'])

                vserverinfo['_raw'] = tojson(vserverinfo)
                yield vserverinfo


@Configuration()
class f5QueryCommand(GeneratingCommand):
    """ %(synopsis)

    ##Syntax

    .. code-block::
    f5Query pools=<comma_separated_list> poolOnly=<boolean> partition=<string>

    ##Description

    Return a list of all or some pools as well as members from the F5.  Use the poolOnly to list pool information.
    Results include statistics.

    ##Example

    Return a list of all or some pools as well as members from the F5.  Use the poolOnly to list pool information.

    .. code-block::
        | f5Query pool="common/splunk_443_pool,common/splunk_80_pool" poolOnly=True partition="common" device="f5.com"
        | f5Query vserver="/Common/trans.mycompany_86_vs','/Common/post.mycompany_81_vs'" stats=True partition="common" device="f5.com"

    """

    pools = Option(
        doc='''**Syntax:** **pools=***<string>*
         **Description:** Comma separated list pools. ''',
        require=False)

    poolOnly = Option(
        doc='''**Syntax:** **poolOnly=***<boolean>*
         **Description:** Flag that only pool names ''',
        require=False)

    vservers = Option(
        doc='''**Syntax:** **virtualServers=***<string>*
         **Description:** Comma separated list virtual Servers.''',
        require=False)

    stats = Option(
        doc='''**Syntax:** **stats=***boolean*
         **Description:** Set get stats flag. default False. ''',
        require=False)

    partition = Option(
        doc='''**Syntax:** **partition=***<string>*
         **Description:** F5 partition name. Defaults to common ''',
        require=False)

    device = Option(
        doc='''**Syntax:** **device=***<string>*
         **Description:** IP Address or Full Qualified Domain Name (FQDN)''',
        require=True)


    def generate(self):
        try:
            conf = get_stanza('f5query', 'f5query')
            user = conf['user']
            password = conf['password']

            f5 = F5Client(user,
                          password,
                          self.device)
        except Exception as e:
            self.logger.debug('f5QueryCommand: %s, %s' % e, self)
            exit(1)
        # Creating threading object
        f5threads = Worker()

        # F5 virtual server
        if self.vservers:
            if self.vservers.lower() == 'all':
                f5.vserver_list()
            else:
                f5.vserver_list(self.vservers)
            if self.stats:
                f5threads.run(target=f5.vserver_stats)
            f5threads.run(target=f5.vserver_dest)
            f5threads.run(target=f5.vserver_pool)

        # F5 pool information requests
        if self.pools:
            if self.pools.lower() == 'all':
                f5.pool_list()
            else:
                f5.pool_list(self.pools)
            f5threads.run(target=f5.pool_status)
            poolOnly = self.poolOnly.lower() if self.poolOnly else self.poolOnly
            if poolOnly != 'true':
                stats = self.stats.lower() if self.stats else self.stats
                if stats == 'true':
                    f5threads.run(target=f5.pool_member_stats)
                f5threads.run(target=f5.pool_members)
                f5threads.run(target=f5.pool_member_status)

        # waiting for threads to return
        for thread in f5threads.jobs:
            thread.join()

        if self.pools:
            for pool in f5.pools_output():
                pool['source'] = 'f5'
                pool['sourcetype'] = 'icontrol'
                yield pool

        # if self.virtualServer is define get virtual Server information
        if self.vservers:
            for vserver in f5.vserver_output():
                vserver['source'] = 'f5'
                vserver['sourcetype'] = 'icontrol'
                yield vserver

dispatch(f5QueryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
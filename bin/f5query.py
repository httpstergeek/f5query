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
    dispatch, GeneratingCommand, Configuration, Option, validators

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


def setup_logger(level):
    """
        :param level: Logging level
        :type level: logger object
        :return : logger object
    """
    logger = logging.getLogger('splunk_cycle')
    logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)
    file_handler = logging.handlers.RotatingFileHandler(os.path.join('splunk_cycle.log'), maxBytes=5000000,
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

def pools_output(pools, poolstatuses, members=None, membersstatuses=None, poolstatistics=None):
    timestamp = time.time()
    output = list()
    timeoffset = (time.mktime(time.localtime()) - time.mktime(time.gmtime()))
    for n, pool in enumerate(pools):
        partition, pool = pool.strip('/').split('/')
        if members:
            for i, member in enumerate(members[n]):
                poolinfo = dict()
                poolinfo['_time'] = timestamp
                poolinfo['pool_partition'] = partition
                poolinfo['pool_name'] = pool
                xpool, poolinfo['pool_member'] = member['address'].strip('/').split('/')
                if membersstatuses:
                    poolinfo['pool_member_address'] = membersstatuses[n][i]['member']['address']
                    poolinfo['pool_member_port'] = membersstatuses[n][i]['member']['port']
                    poolinfo['pool_member_availability_status'] = membersstatuses[n][i]['object_status']['availability_status']
                    poolinfo['pool_member_enabled_status'] = membersstatuses[n][i]['object_status']['enabled_status']
                if poolstatistics:
                    for stats in poolstatistics[n]['statistics'][i]['statistics']:
                        poolinfo[stats['type'].replace('STATISTIC_', 'pool_member_').lower()] = convert_64bit(
                            stats['value']['high'],
                            stats['value']['low'])
                        stattime = poolstatistics[n]['time_stamp']
                        time_struct = datetime(stattime['year'], stattime['month'], stattime['day'],
                                               stattime['hour'], stattime['second']).timetuple()
                        poolinfo['_time'] = time.mktime(time_struct) + timeoffset
                poolinfo['pool_availability_status'] = poolstatuses[n]['availability_status']
                poolinfo['pool_enabled_status'] = poolstatuses[n]['enabled_status']
                poolinfo['_raw'] = tojson(poolinfo)
                yield poolinfo
        else:
            poolinfo = dict()
            poolinfo['_time'] = timestamp
            poolinfo['partition'] = partition
            poolinfo['pool_name'] = pool
            poolinfo['pool_availability_status'] = poolstatuses[n]['availability_status']
            poolinfo['pool_enabled_status'] = poolstatuses[n]['enabled_status']
            poolinfo['_raw'] = tojson(poolinfo)
            yield poolinfo

def vserver_output(virtualServers, virtualserverdestination, virtualserverpool, virtualserverstats=None):
    timestamp = time.time()
    timeoffset = (time.mktime(time.localtime()) - time.mktime(time.gmtime()))
    if virtualServers:
        for n, server in enumerate(virtualServers):
            vserverinfo = dict()
            vserverinfo['_time'] = timestamp
            partition, vAddress = virtualserverdestination[n]['address'].strip('/').split('/')
            vpartition, vServer = server.strip('/').split('/')
            if virtualserverpool[n] != '':
                pool_partition, pool = virtualserverpool[n].strip('/').split('/')
                vserverinfo['pool_partition'] = pool_partition
                vserverinfo['pool_name'] = pool
            vserverinfo['virtual_server_name'] = vServer
            vserverinfo['virtual_address'] = vAddress
            vserverinfo['virtual_server_partition'] = partition
            if virtualserverstats:
                stattime = virtualserverstats['time_stamp']
                time_struct = datetime(stattime['year'], stattime['month'], stattime['day'], stattime['hour'],
                                       stattime['second']).timetuple()
                vserverinfo['_time'] = time.mktime(time_struct) + timeoffset
                vserverinfo['virtual_sever_protocol'] = virtualserverstats['statistics'][n]['virtual_server'][
                    'protocol']
                vserverinfo['virtual_sever_port'] = virtualserverstats['statistics'][n]['virtual_server']['port']
                for stats in virtualserverstats['statistics'][n]['statistics']:
                    vserverinfo[stats['type'].replace('STATISTIC_', 'virtual_server_').lower()] = convert_64bit(
                        stats['value']['high'],
                        stats['value']['low'])

            vserverinfo['_raw'] = tojson(vserverinfo)
            yield vserverinfo


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

class F5Client():
    """
        Connects to F5 iControl interface
    """

    def __init__(self, user, passwd, host):
        self.f5 = bigsuds.BIGIP(
            hostname=host,
            username=user,
            password=passwd
        )
        self.Management = self.f5.Management
        self.Pool = self.f5.LocalLB.Pool
        self.PoolMember = self.f5.LocalLB.PoolMember
        self.VirtualAddressV2 = self.f5.LocalLB.VirtualAddressV2
        self.VirtualServer = self.f5.LocalLB.VirtualServer

    def set_partition(self, partition):
        """
            Set active partition for methods.
            :param partition: F5 partition name.
            :type partition: str
            :return: str
        """
        activeparition = self.Management.Partition.get_active_partition()
        if partition != activeparition:
            self.Management.Partition.set_active_partition(partition)
        return self.Management.Partition.get_active_partition()


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
        | f5Query virtualServers="/Common/trans.mycompany_86_vs','/Common/post.mycompany_81_vs'" getStats=True partition="common" device="f5.com"

    """

    pools = Option(
        doc='''**Syntax:** **pools=***<string>*
         **Description:** Comma separated list pools. ''',
        require=False)

    poolOnly = Option(
        doc='''**Syntax:** **poolOnly=***<boolean>*
         **Description:** Flag that only pool names ''',
        require=False)

    virtualServers = Option(
        doc='''**Syntax:** **virtualServers=***<string>*
         **Description:** Comma separated list virtual Servers.''',
        require=False)

    getStats = Option(
        doc='''**Syntax:** **getStats=***boolean*
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

        getstats = True if self.getStats == 'true' else False
        # find GMT Offset from local time
        timeoffset = (time.mktime(time.localtime()) - time.mktime(time.gmtime()))
        if isinstance(self.pools, str):
            self.logger.debug('f5QueryCommand: %s' % 'Getting Pool List')
            poollist = f5.Pool.get_list() if self.pools.lower() == 'all' else self.pools.split(',')
            poolonly = True if self.poolOnly == 'True' else False
            self.logger.debug('f5QueryCommand: %s' % 'Getting Pool List')
            poolstatuses = f5.Pool.get_object_status(poollist)
            members = f5.Pool.get_member_v2(poollist) if not poolonly else ''
            membersstatuses = f5.PoolMember.get_object_status(poollist) if not poolonly else False
            poolstatistics = f5.Pool.get_all_member_statistics(poollist) if getstats else False
            timestamp = time.time()
            for pool in pools_output(poollist, poolstatuses):
                yield pool

        # if self.virtualServer is define get virtual Server information
        if isinstance(self.virtualServers, str):
            virtualserverlist = f5.VirtualServer.get_list() if self.virtualServers.lower() == 'all' else self.virtualServers.split(',')
            virtualserverdestination = f5.VirtualServer.get_destination_v2(virtualserverlist)
            virtualserverpool = f5.VirtualServer.get_default_pool_name(virtualserverlist)
            virtualserverstats = f5.VirtualServer.get_statistics(virtualserverlist) if getstats else False
            for vserver in vserver_output(virtualserverlist, virtualserverdestination, virtualserverpool, virtualserverstats=virtualserverstats):
                yield vserver

dispatch(f5QueryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
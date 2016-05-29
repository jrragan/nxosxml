import functools
import itertools
import traceback
from vdcnetconf import VDCNxosConnect

__version__ = '2014.5.10.1'

#@todo show mod
#@todo show portchannel
#@todo add vpc information to interface objects
#@todo switching between VDCs
#@todo bring up a vpc
#@todo vrfs
#@todo threading
#@todo checkpoints and rollback
#@todo IP Address objects

"""
5/10/14 - minor name and logging changes
3/18/14 - fixed bugs in set_interface and set_portchannel, added exception handling to catch xml server errors
3/3/14 - modified get_interface to modify an interface object if it already exists, rather than always creating a new
object when called, corrected a bug in the port-channel interface parser, tweaked namespace handlers
3/2/14 - added neighbor object and cdp parser, a cdp object is created and added to the interface container
3/1/14 - Modified parsers to use parse_get_nsmap so that documents returned with incorrect namespaces can be
parsed
2/28/14 - added show_command_multiple to allow repeatedly running the same show command with different args
2/21/14 - modified set_interface to allow multiple interfaces by providing a string that is standard nx-os
interface notation. added set_portchannel. 
2/20/14 - modifed set_vlan method to create multiple vlans specified in list, e.g. '2-4, 9, 10', interface methods
modified to check existence of an interface only if it is an Ethernet - cannot assume prior existence of other kinds of
interfaces
2/18/14 - added set_interface method for configuration of interfaces
2/17/14 - added vdc object, made it a container for the vlan and interface objects, but the APIs do not change for non-vdc
platforms. added framework to most methods to accomodate multiple vdcs, added mode option to set_vlan method
2/13/14 - added show_vlan_list, show_interface_list methods
2/12/14 - created vlan object, vlans are stored in switch object as a dictionary of objects, like interfaces,implement vdc
objects and get_vdcs method, will only be run on 7ks, vdcs will be stored as a dictionary of objects
2/11/14 - added methods for getting and showing hostname, chassis id and os version and for saving the configuration
1/27/14 - initial release
"""

from lxml import etree
import sys
from netconf import NxosConnect
from nxosXmlFunctions import buildshowvlancommand, VLANSCHEMA, buildshowintcommand, buildshowcommand, find_element, VDCSCHEMA, SYSMGRCLISCHEMA, parse_xml_heirarchy, parse_get_nsmap, INTSCHEMA, ETHPCMDC3SCHEMA, IPSCHEMA, HSRPSCHEMA

import logging

__author__ = 'rragan'

#Stolen from Google ipaddr
class AddressValueError(ValueError):
    """A Value Error related to the address."""

class NetmaskValueError(ValueError):
    """A Value Error related to the netmask."""

class VDCError(ValueError):
    """A Value Error related to being in an expected vdc."""


def xmlbuilder(func):
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        if self.connected:
            self.logger.debug('instance %s of class %s is now decorated whee!' % (self, self.__class__))
            self.logger.debug("Building xml element to send to " + self.host)
            try:
                nxosmessage = func(self, *args, **kwargs)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.error("Error with the XML command ")
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
            return nxosmessage
        else:
            self.logger.critical(
                "The netconf connection to {} is currently closed. Please reconnect and try again.".format(self.host))
            return None

    return decorator


def vdchandler(func):
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        self.logger.debug('instance %s of class %s is now decorated whee!' % (self, self.__class__))
        self.logger.debug("VDC checks for {}".format(self.host))
        if 'vdc' not in kwargs:
            vpar = self.current_vdc
            vdc = [self.current_vdc]
        elif kwargs['vdc'].lower() == 'all':
            vpar = 'all'
            vdc = self.vdcs.keys()
        else:
            vpar = kwargs['vdc']
            vdc = [kwargs['vdc']]
        self.logger.debug('vdc list is {}'.format(str(vdc)))
        if 'vlan' in func.func_name and 'get_vlans_detail' not in func.func_name:
            for v in vdc:
                if self.vdcs[v].vlans is None:
                    self.logger.debug('Running get_vlans_detail on host {}'.format(self.host))
                    self.get_vlans_detail([v])
        if 'interface' in func.func_name and func.func_name != 'get_interfaces':
            for v in vdc:
                if self.vdcs[v].interfaces is None:
                    self.logger.debug('Running and get_interfaces on host {}'.format(self.host))
                    self.get_interfaces([v])
        try:
            kwargs['vdc'] = vdc
            self.logger.debug('Running {} on host {}'.format(func.func_name, self.host))
            vdcmessage = func(self, *args, **kwargs)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Error with the decorated function {} on host {}".format(func.func_name, self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        return vdcmessage

    return decorator


def _netmask_from_mask_len(mask_len):
    """

    @param mask_len: string
    """
    masks = {0: '0', 1: '128', 2: '192', 3: '224', 4: '240', 5: '248', 6: '252', 7: '254'}
    _len = int(mask_len)
    _masklist = []
    while _len > 0:
        if _len >= 8:
            _masklist.append('255')
            _len -= 8
        else:
            _masklist.append(masks[_len])
            break
    while len(_masklist) < 4:
        _masklist.append(masks[0])
    return '.'.join(_masklist)


def _mask_len_from_netmask(netmask):
    lengths = {'255': 8, '254': 7, '252': 6, '248': 5, '240': 4, '224': 3, '192': 2, '128': 1, '0': 0}
    _masklist = netmask.split('.')
    _masklen = 0
    for m in _masklist:
        _masklen = _masklen + lengths[m]
    return str(_masklen)


class NxosSwitch(object):
    """
    Class to connect to nx-os device and carry out configurations
    """

    def __init__(self, host, prompt=None):
        """
        Connect via SSH and initialize the NETCONF session.

            *host* is the hostname or IP address to connect to the Nexus

        """

        self.host = host
        self.hostname = None
        self.system_version = None
        self.chassis_id = None
        self.logger = logging.getLogger('nexusswitch.NxosSwitch')
        self.logger.debug("Instantiating NxosSwitch object for {}".format(self.host))

        self._ncc = NxosConnect(host)
        self.vlans = None
        self.interfaces = None
        self.connected = False
        self.vdcs = None
        self.current_vdc = 'default'
        self.default_vdc = 'default'

        #Regular expression for the prompt to look for in 7k shells
        self.prompt = prompt

    def connect(self, username, password, *args, **kwargs):
        """
        Opens XML connection to device
        @param args:
        @param kwargs:

        Must be called with a minimum of username and password

        @return: SSH ncconnect object
        """
        if not self.connected:
            self.logger.debug("Opening SSH XML Connection to " + self.host)
            self._ncc.nc_sshconnect(username=username, password=password, *args, **kwargs)
            self.connected = True
        self.logger.debug("Connection opened for {}, getting version information.".format(self.host))
        self.get_version()
        #Check if device is a 7k, if it is change to an object type that can handle switching between vdcs
        if self._check_for_7k():
            self.logger.debug("{} is a 7k".format(self.host))
            self.get_vdcs()
            self.get_current_vdc()
            self.disconnect()
            self.logger.debug("Switching to ssh shell object")
            self._ncc = VDCNxosConnect(self.host, self.host.partition('.')[0])
            self._ncc.nc_sshconnect(username=username, password=password, *args, **kwargs)
            self.connected = True
        else:
            self.vdcs = {'default': VDC('1', 'default')}

    def _check_for_7k(self):
        return '7000' in self.chassis_id or '7700' in self.chassis_id

    def disconnect(self):
        if self.connected:
            self._ncc.closesession()
            self.connected = False

    @vdchandler
    @xmlbuilder
    def get_vlans_detail(self, vdc=None):
        """
        method to get the output of show vlan from device
        builds vlansdict: dict of the form {str:tuple}, where the key is the vlan id and the tuple is of the form (name,
        status, shut/noshut, interfaces)

        @param vdc:
        @return: None
        """

        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            self.logger.debug("Getting vlan dictionary from vdc {} on {}".format(self.current_vdc, self.host))
            self.logger.debug(
                "Building show vlan command and sending to host {} for vdc {}".format(self.host, self.current_vdc))
            devicevlansxml = self._ncc.nxosget(buildshowvlancommand(), schema="vlan_mgr_cli", getfilter="subtree")
            self.logger.debug("Received XML from server {} for vdc {}".format(self.host, self.current_vdc))
            self.logger.debug(devicevlansxml)
            vlansdict = Vlan.parseshowvlancommand(devicevlansxml)
            vlans = {}
            for v in vlansdict:
                vlans[v['vlanshowinfo_vlanid']] = Vlan(**v)
            self.vdcs[self.current_vdc].set_vlans(vlans)
            self.logger.debug(self.vdcs[self.current_vdc].vlans)

    @vdchandler
    def get_vlans_list(self, vdc=None):
        """
        Returns a list of all of the vlans on the device

        @return: list of vlans
        """
        vlans = []
        for vdcname in vdc:
            vlans.append(self.vdcs[vdcname].get_vlans_list())
        return vlans

    @vdchandler
    def check_vlan(self, vlan, vdc=None):
        """
        @param vlan: a str, vlan, e.g. '2'
        @return: True if vlan exists, False if it doesn't exist
        """

        checkflag = False
        for vdcname in vdc:
            checkflag = checkflag or vlan in self.vdcs[vdcname].get_vlans_list()
        return checkflag

    @vdchandler
    def check_interface(self, interface, vdc=None):
        """

        @param interface: str, e.g. 'ethernet2/1'
        @return:True if interface exists, False if it doesn't exist
        """

        interface = interface.title()

        checkflag = False
        for vdcname in vdc:
            checkflag = checkflag or interface in self.vdcs[vdcname].interfaces
        return checkflag

    @vdchandler
    def check_interface_vlan(self, interface, vlan, vdc=None):
        """
        @param vdc is a list of vdcs to check
        @param interface:
        @param vlan:
        """
        assert isinstance(vlan, str)
        assert isinstance(interface, str)
        interface = interface.title()

        checkflag = False
        for vdcname in vdc:
            checkflag = checkflag or self.vdcs[vdcname].check_interface_vlan(interface, vlan)
        return checkflag

    @vdchandler
    def set_vlan_interface(self, interface, vlan, vdc=None):
        """

        Method to configure a vlan on an interface, interface can be access or trunk
        If vlan does not exist, it creates
        The interface is assumed to already exist

        -    @rtype : None if vlan already exists, vlan if the vlan was created
        -    @param vlan: string of vlan number, e.g. '2'
        -    @param interface: string of interface, e.g. 'ethernet2/1'

        """

        assert isinstance(vlan, str)
        assert isinstance(interface, str)
        assert isinstance(vdc, list)

        self.logger.debug("Adding vlan {} on interface {} on {}".format(vlan, interface, self.host))
        interface = interface.title()
        vlan_created = None

        if len(vdc) != 1:
            raise ValueError("Interface {} cannot exist in multiple vdcs {}".format(interface, self.host))
        vdc = vdc[0]
        if not self.vdcs[vdc].check_interface(interface):
            raise ValueError(
                "Interface {} does not exist in vdc {} on {}".format(interface, vdc, self.host))
        if not self.vdcs[vdc].check_vlan(vlan):
            self.set_vlan(vlan)
            vlan_created = [vlan]

        self.switchto_vdc(vdc)

        commands = ['config t ; interface {}'.format(interface)]
        configured = False

        if not self.vdcs[vdc].check_interface_vlan(interface, vlan):
            if self.vdcs[vdc].interfaces[interface].switchport == 'access':
                commands.append('switchport access vlan {}'.format(vlan))
            elif self.vdcs[vdc].interfaces[interface].switchport == 'trunk':
                commands.append('switchport trunk allowed vlan add {}'.format(vlan))
            else:
                raise ValueError(
                    "Interface {} in vdc {} on {} is not access or trunk".format(interface, self.current_vdc,
                                                                                 self.host))
        else:
            configured = True

        if not configured:
            try:
                self._send_xml_cli(commands)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.error("VLAN {} configuration for interface {} on {} failed".format(vlan, interface, self.host))
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
            else:
                self.get_interfaces(vdc=vdc)

        return vlan_created

    @vdchandler
    def set_vlan(self, vlan, name=None, state='active', mode=None, shutstate=None, vdc=None):
        """
        Creates a vlan on nx-os device

        -    @param vdc:
        -    @param state: optional, str, 'active' or 'suspend'
        -    @param name: optional, str, name of the vlan
        -    @param vlan: string, e.g. '2' or a list of vlans e.g. '2-4, 5, 6'

        """

        assert isinstance(vlan, str)
        assert isinstance(vdc, list)

        self.logger.debug("Creating vlan {} on {}".format(vlan, self.host))

        vlan = _vlanexpand(vlan)
        vlanlist = vlan.split(',')
        failed_vlans = None

        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            for v in vlanlist:
                self.logger.debug("Creating vlan {} in vdc {} on {}".format(v, self.current_vdc, self.host))
                commands = ["config t ; vlan {}".format(v)]
                if name is not None:
                    commands.append("name {}".format(name))
                if state != 'active':
                    commands.append("state {}".format(state))
                if mode is not None:
                    commands.append("mode {}".format(mode))
                if shutstate is not None:
                    if shutstate:
                        commands.append("shutdown")
                    else:
                        commands.append("no shutdown")

                try:
                    self._send_xml_cli(commands)
                except:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    stacktrace = traceback.extract_tb(exc_traceback)
                    self.logger.error("VLAN configuration for vlan {} on {} failed".format(vlan, self.host))
                    self.logger.debug(sys.exc_info())
                    self.logger.debug(stacktrace)
            self.get_vlans_detail(vdc=vdcname)

    @vdchandler
    def set_interface(self, interface, vrf=None, speed=None, duplex=None, switchport=None, host=None, routed=None,
                      accessvlan=None, allowedvlans=None,
                      nativevlan=None, allowedvlansadd=None, allowedvlansremove=None, shutdown=None, mtu=None,
                      description=None, channelgroup=None, channelgroupmode=None,
                      vpc=None, norefresh=False, vdc=None):
        """

        -    @param interface: string, multiple interfaces can be represented using standard nx-os notation
        -    @param vrf: string
        -    @param speed: string
        -    @param duplex: string
        -    @param switchport: string, switchport mode, access, trunk, fabricpath
        -    @param host: boolean, True to configure host mode
        -    @param routed: boolean, True to configure interface as routed port
        -    @param accessvlan: string
        -    @param allowedvlans: string
        -    @param allowedvlansadd: string
        -    @param allowedvlansremove: string
        -    @param shutdown: boolean
        -    @param mtu: string
        -    @param description: string
        -    @param channelgroup: string
        -    @param channelgroupmode: string, passive, active or on
        -    @param vpc: string, vpc number for port-channel interface
        -    @param norefresh: boolean, True to override refresh of interface objects after configuration changes
        -    @param vdc: string, vdc where configuration takes place

        """

        parameters = locals()
        self.logger.debug(str(parameters))
        assert isinstance(interface, str)

        interface = interface.title()

        self.logger.debug("Configuring interface {} on {}".format(interface, self.host))
        if len(vdc) != 1:
            raise ValueError("Interface {} cannot exist in multiple vdcs {}".format(interface, self.host))
        vdc = vdc[0]
        self.logger.debug("Configuring interface {} in vdc {} on {}".format(interface, vdc, self.host))
        if 'eth' in interface and (',' not in interface and '-' not in interface) and not self.vdcs[
            vdc].check_interface(interface):
            raise ValueError(
                "Interface {} does not exist in vdc {} on {}".format(interface, vdc, self.host))

        self.switchto_vdc(vdc)

        if channelgroupmode is not None and channelgroup is None:
            raise ValueError(
                "If channelgroupmode is specified, channelgroup must also be specified for interface {} in vdc {} on {}".format(
                    interface, self.current_vdc, self.host))

        commandlist = {'vrf': 'vrf {}'.format(vrf),
                       'speed': 'speed {}'.format(speed),
                       'duplex': 'duplex {}'.format(duplex),
                       'switchport': 'switchport ; switchport mode {}'.format(switchport),
                       'host': 'switchport host',
                       'routed': 'no switchport',
                       'accessvlan': 'switchport access vlan {}'.format(accessvlan),
                       'nativevlan': 'switchport trunk native vlan {}'.format(nativevlan),
                       'allowedvlans': 'switchport trunk allowed vlan {}'.format(allowedvlans),
                       'allowedvlansadd': 'switchport trunk allowed vlan add {}'.format(allowedvlansadd),
                       'allowedvlansremove': 'switchport trunk allowed vlan remove {}'.format(allowedvlansremove),
                       'shutdown': 'shutdown',
                       'mtu': 'mtu {}'.format(mtu),
                       'description': 'description {}'.format(description),
                       'channelgroup': 'channel-group {}'.format(channelgroup),
                       'channelgroupmode': 'channel-group {} mode {}'.format(channelgroup, channelgroupmode),
                       'vpc': 'vpc {}'.format(vpc)}

        commands = ['config t ; interface {}'.format(interface)]
        for c in parameters:
            if parameters[c] is not None:
                if c == 'host' and not host:
                    commandlist[c] = 'no switchport host'
                elif c == 'routed' and not routed:
                    commandlist[c] = 'switchport'
                elif c == 'shutdown' and not shutdown:
                    commandlist[c] = 'no shutdown'
                elif c == 'interface' or c == 'vdc' or c == 'self' or c == 'norefresh':
                    continue
                commands.append(commandlist[c])

        self.logger.debug(str(commands))

        try:
            self._send_xml_cli(commands)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Interface configuration for interfaces {} failed on {}".format(interface, self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        else:
            if not norefresh:
                self.get_interfaces(vdc=vdc)

    @vdchandler
    def set_portchannel(self, channelgroup, interface, podescription=None, vpc=None, vdc=None, *args, **kwargs):
        """

        -    @param pogroup: the portchannel group, a portchannel interface will be created with this number
        -    @param interface: a string listing the physical interfaces to be included in the port channel. Can include any options that can be applied to an interface. These options will be applied to the physical interfaces.
        -    @param interface:
        -    @param vrf:
        -    @param speed:
        -    @param duplex:
        -    @param switchport:
        -    @param accessvlan:
        -    @param allowedvlans:
        -    @param allowedvlansadd:
        -    @param shutdown:
        -    @param mtu:
        -    @param description:
        -    @param channelgroup:
        -    @param channelgroupmode:
        -    @param vpc:
        -    @param vdc:
        -    @raise ValueError:

        """
        assert isinstance(interface, str)
        assert isinstance(channelgroup, str)
        interface = interface.title()

        self.logger.debug(
            "Configuring portchannel group on interfaces {} on {}".format(channelgroup, interface, self.host))
        if len(vdc) != 1:
            raise ValueError("Interface {} cannot exist in multiple vdcs {}".format(interface, self.host))
        vdc = vdc[0]
        self.logger.debug(
            "Configuring portchannel group on interface {} in vdc {} on {}".format(channelgroup, interface, vdc,
                                                                                   self.host))
        if 'eth' in interface and (',' not in interface and '-' not in interface) and not self.vdcs[
            vdc].check_interface(interface):
            raise ValueError(
                "Interface {} does not exist in vdc {} on {}".format(interface, vdc, self.host))

        shutdown = None
        if 'shutdown' in kwargs:
            shutdown = kwargs['shutdown']

        try:
            self.set_interface('port-channel {}'.format(channelgroup), description=podescription, vpc=vpc, shutdown=shutdown,
                           vdc=vdc, norefresh=True)
            self.set_interface(interface, channelgroup=channelgroup, *args, **kwargs)
        except:
            self.logger.error('port-channel {} configuration failed on {}'.format(channelgroup, self.host))
            raise

    @vdchandler
    def set_interface_ip(self, interface, ip, vdc=None):
        """


        @param interface: string, e.g. 'vlan100'
        @param ip: string, can be of the form ip/netmask_len or ip/netmask, e.g. '192.168.1.1/24' or '192.168.1.1/255.255.255.0'

        assigns the IP address to the given interface

        """
        # Assume input argument to be string or any object representation
        # which converts into a formatted IP prefix string.
        assert isinstance(ip, str)
        assert isinstance(interface, str)

        interface = interface.title()

        self.logger.debug("Adding IP {} on interface {} on {}".format(ip, interface, self.host))
        if len(vdc) != 1:
            raise ValueError("Interface {} cannot exist in multiple vdcs {}".format(interface, self.host))
        vdc = vdc[0]
        self.logger.debug(
            "Adding IP {} on interface {} in vdc {} on {}".format(ip, interface, self.current_vdc, self.host))
        if 'eth' in interface and not self.vdcs[vdc].check_interface(interface):
            raise ValueError(
                "Interface {} does not exist in vdc {} on {}".format(interface, self.current_vdc, self.host))

        self.switchto_vdc(vdc)

        addr = str(ip).split('/')

        if len(addr) != 2:
            raise AddressValueError(ip)

        mask = addr[1].split('.')
        if len(mask) == 4:
            # We have dotted decimal netmask.
            _netmask = addr[1]
            _prefixlen = _mask_len_from_netmask(_netmask)
        elif len(mask) == 1:
            # We have a netmask in prefix length form.
            self._prefixlen = int(addr[1])
        else:
            raise NetmaskValueError('%s is not a valid netmask' % addr[1])

        _ip = addr[0]

        if interface in self.vdcs[vdc].interfaces:
            if self.vdcs[vdc].interfaces[interface].ip_address is not None and self.vdcs[vdc].interfaces[
                interface].ip_mask_len is not None:
                if self.vdcs[vdc].interfaces[interface].ip_address == _ip and self.vdcs[vdc].interfaces[
                    interface].ip_mask_len == _prefixlen:
                    return None

        _ipaddr = _ip + '/' + _prefixlen
        commands = ['config t ; interface {} ; ip address {}'.format(interface, _ipaddr)]

        try:
            self._send_xml_cli(commands)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("IP Address configuration for interface {} on {} failed".format(interface, self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        else:
            self.get_interfaces(vdc=vdc)

    @vdchandler
    def set_interface_hsrp(self, interface, group, vip, name=None, priority=None, preempt='disabled', vdc=None):
        """

        Adds HSRP configuration to a l3 interface.

        @param vdc:
        @param preempt: string, 'enabled' or 'disabled'
        @param interface: string
        @param group: string
        @param vip: string
        @param priority: string
        @param name: string
        """
        assert isinstance(interface, str)
        assert isinstance(group, str)
        assert isinstance(vip, str)
        assert isinstance(vdc, list)

        interface = interface.title()

        self.logger.debug("Adding HSRP configuration on interface {} on {}".format(interface, self.host))

        if len(vdc) != 1:
            raise ValueError("Interface {} cannot exist in multiple vdcs {}".format(interface, self.host))
        vdc = vdc[0]
        self.logger.debug(
            "Adding HSRP configuration {} on interface {} in vdc {} on {}".format(vip, interface, self.current_vdc,
                                                                                  self.host))
        if 'eth' in interface and not self.vdcs[vdc].check_interface(interface):
            raise ValueError(
                "Interface {} does not exist in vdc {} on {}".format(interface, self.current_vdc, self.host))

        self.switchto_vdc(vdc)

        commandlist = ['config t', 'interface {}'.format(interface), 'hsrp {}'.format(group), 'ip {}'.format(vip)]

        if name is not None:
            commandlist.append('name {}'.format(name))
        if priority is not None:
            commandlist.append('priority {}'.format(priority))
        if preempt == 'enabled':
            commandlist.append('preempt')
        configure = False

        #Check if interface already exists and if this HSRP config is already on it

        if interface in self.vdcs[vdc].interfaces:
            if self.vdcs[vdc].interfaces[interface].hsrp_groups is not None and group in self.vdcs[vdc].interfaces[
                interface].hsrp_groups:
                if self.vdcs[vdc].interfaces[interface].hsrp_groups[group].hsrp_group_preempt != preempt:
                    if preempt == 'disabled':
                        commandlist.pop()
                        commandlist.append('no preempt')
                        configure = True
                    else:
                        configure = True
                if priority is not None and self.vdcs[vdc].interfaces[interface].hsrp_groups[
                    group].hsrp_group_pri != priority:
                    configure = True
                elif priority is not None:
                    commandlist.remove('priority {}'.format(priority))
                if self.vdcs[vdc].interfaces[interface].hsrp_groups[group].hsrp_group_vip != vip:
                    configure = True
                else:
                    commandlist.remove('ip {}'.format(vip))
                if name is not None and self.vdcs[vdc].interfaces[interface].hsrp_groups[group].hsrp_group_name != name:
                    configure = True
                elif name is not None:
                    commandlist.remove('name {}'.format(name))

        if len(commandlist) > 3:
            try:
                self._send_xml_cli([' ; '.join(commandlist)])
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.error("HSRP configuration for interface {} on {} failed".format(interface, self.host))
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
            else:
                self.get_interfaces()

    @xmlbuilder
    def _send_xml_cli(self, commands, no_end=False):
        """
        Method for sending configuration commands to the device
        @param commands: list of commands
        @param no_end: flag, if False, "end" is appended to the list of commands
        @return: None
        """
        if isinstance(commands, str):
            commands = [commands]
        if not no_end:
            commands.append("end")
        self.logger.debug("Sending commands {} to {}".format(str(commands), self.host))
        try:
            self._ncc.nxoscli(commands)
        except:
            raise

    @xmlbuilder
    def _send_xml_cli_show(self, command):
        """
        Method for sending a show command to the device
        @param command: single show command, nx-os does not allow more than one
        @return: string of xml output from the server
        """
        assert isinstance(command, str)
        self.logger.debug("Sending show command {} to {}".format(str(command), self.host))
        return self._ncc.nxoscli(command)

    @vdchandler
    def show_interface(self, interface=None, vdc=None):
        """
        prints interface configuration to the console
        if interface is provided, prints that interface's information
        else, it prints all interface information

        @param interface: str, e.g. 'Ethernet2/1'
        """

        if interface is not None:
            interface = interface.title()

        for vdcname in vdc:
            print "vdc: {}".format(vdcname)
            if interface is not None and interface in self.vdcs[vdcname].interfaces:
                print self.vdcs[vdcname].interfaces[interface]
            else:
                for i in self.vdcs[vdcname].interfaces:
                    print self.vdcs[vdcname].interfaces[i]

    @vdchandler
    def show_vlan(self, vlan=None, vdc=None):
        """
        prints vlan configuration to the console
        if vlan id is provided, prints that vlan's information
        else, it prints all vlan information

        @param vlan: str, e.g. '2'
        """
        for vdcname in vdc:
            print "VDC: {}".format(vdcname)
            if vlan is not None and vlan in self.vdcs[vdcname].get_vlans_list():
                print self.vdcs[vdcname].vlans[vlan]
            else:
                for v in self.vdcs[vdcname].vlans:
                    print self.vdcs[vdcname].vlans[v]

    @xmlbuilder
    def _interfaces_xml_builder(self):
        showcommands = {'deviceintstatusxml': [buildshowintcommand, ('status',), INTSCHEMA],
                        'deviceinttrunkxml': [buildshowintcommand, ('trunk',), INTSCHEMA],
                        'deviceposummxml': [buildshowcommand, (('port-channel', 'summary'),), ETHPCMDC3SCHEMA],
                        'devicel3intxml': [buildshowcommand, (('ip', 'interface'),), IPSCHEMA],
                        'devicehsrpxml': [buildshowcommand, (('hsrp',),), HSRPSCHEMA]}
        xmlresponse = {}
        self.interfaces = {}
        self.logger.debug("Getting interface information from " + self.host)
        for s in showcommands.keys():
            key = s
            self.logger.debug(
                "Building {} {} command and sending to host {}".format(s, showcommands[key][1], self.host))
            xmlresponse[key] = self._ncc.nxosget(showcommands[key][0](*showcommands[key][1]),
                                                 schema=showcommands[key][2], getfilter="subtree")
            self.logger.debug(
                "Received XML for show {} {} command from server {}".format(s, showcommands[key][1], self.host))
            self.logger.debug(xmlresponse[key])
        self.logger.debug("XML Response: {}".format(xmlresponse))
        return xmlresponse

    @vdchandler
    def get_interfaces(self, vdc=None):
        """
        Method to get result of show int status from device
        Calls _interfaces_xml_builder() method to get XML from server
        Calls Interface._parseallinterface class method to parse the xml, returns a dictionary
        This method iterates through the dictionary and creates a dictionary of Interface objects

        """

        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            self.logger.debug("Getting interfaces in vdc {} on {}".format(self.current_vdc, self.host))
            intdict = Interface._parseallinterface(**self._interfaces_xml_builder())
            self.logger.debug('intdict: {}'.format(str(intdict)))
            if self.vdcs[vdcname].interfaces is None:
                intobj = {}
                for interface in intdict:
                    self.logger.debug(
                        "Creating interface object: {} for vdc {}".format(str(intdict[interface]), self.current_vdc))
                    intobj[interface.title()] = Interface(**intdict[interface])
                self.vdcs[self.current_vdc].set_interfaces(intobj)
                self.logger.debug(self.vdcs[self.current_vdc].interfaces)
            else:
                for interface in intdict:
                    self.logger.debug(
                        "Updating interface object: {} for vdc {}".format(str(intdict[interface]), self.current_vdc))
                    if interface.title() in self.vdcs[self.current_vdc].interfaces:
                        self.vdcs[self.current_vdc].interfaces[interface.title()].update(**intdict[interface])
                    else:
                        self.vdcs[self.current_vdc].interfaces[interface.title()] = Interface(**intdict[interface])

    @vdchandler
    def get_interfaces_list(self, vdc=None):
        intlist = []
        for vdcname in vdc:
            intlist.append(self.vdcs[vdcname].interfaces.keys())
        return intlist

    @vdchandler
    def show_interfaces_list(self, vdc=None):
        for vdcname in vdc:
            self.vdcs[vdcname].show_interfaces_list()

    @vdchandler
    def show_vlans_list(self, vdc=None):
        for vdcname in vdc:
            print "VDC {}:".format(vdcname)
            self.vdcs[vdcname].show_vlans_list()

    def get_version(self):
        """
        Gets the show version of the device

        """
        verxml = self._ncc.nxoscli('show version')
        self.logger.debug(verxml)
        verparsed = _begin_parse(verxml)
        sysmgrclischema = parse_get_nsmap(verparsed)
        self.logger.debug("NSMAP: {}".format(sysmgrclischema))
        showversion = find_element(['sys_ver_str', 'chassis_id', 'host_name', 'loader_ver_str'], sysmgrclischema,
                                   verparsed)
        self.logger.debug(str(showversion))
        self.hostname = showversion['host_name']
        self.chassis_id = showversion['chassis_id']
        self.system_version = showversion['sys_ver_str']

    def show_hostname(self):
        """
        returns the hostname of the device

        """
        if self.hostname is None:
            self.get_version()
        print self.hostname

    def show_system_version(self):
        if self.system_version is None:
            self.get_version()
        print self.system_version

    def show_chassis_id(self):
        if self.chassis_id is None:
            self.get_version()
        print self.chassis_id

    def save_config(self):
        """
        copy run start
        """
        self._send_xml_cli('copy run start', True)

    @vdchandler
    def show_command_multiple(self, command, arglist, vdc=None, parser=None, optdict={}):
        """
        Runs command one for each argument in arglist

        -    @param parser: a function to parse the xml output returned by each running of the command. The parser can return None indicating that looked-for data was not found, in which case the method will append the string "Command returned no output" to output
        -    @param optdict: a dictionary that will be expanded to arguments to be passed to the parser function
        -    @param command, str, command to run
        -    @param agrlist, string with on argument or tuple containing multiple arguments, each argument is a string
        -    @param vdc, string
        -    @return: output, string concatenating the xml output of each run of the command or the parsed output if a parser is provided

        Example:
        ::
        def macparser(xmldoc, switch=None):
        ::
            parser = etree.XMLParser(remove_blank_text=True)
            macparsed = etree.fromstring(xmldoc, parser=parser)
            macschema = parse_get_nsmap(macparsed)
            macdict = find_element(['disp_mac_addr', 'disp_vlan', 'disp_type', 'disp_port'], macschema, macparsed)
            if 'disp_mac_addr' in macdict:
                macstr = "Mac address {} in vlan {} on port {}, type {}\n".format(macdict['disp_mac_addr'], macdict['disp_vlan'], macdict['disp_port'], macdict['disp_type'])
                if 'po' in macdict['disp_port']:
                    macstr = macstr + "    {} ports: {}\n".format(macdict['disp_port'], switch.vdcs[switch.current_vdc].interfaces[macdict['disp_port'].title()].port_channel_members)
                return macstr
            else:
                return None

        ::
        print "atl-za-nf02-sw01.homedepot.com"
        print sw1.show_command_multiple('show mac address-table address', ('0010.0401.3394', '0010.0401.3395', '0010.0401.3384',
                                                             '0010.0401.3385', '90:e2:ba:36:47:f8',
                                                             '90:e2:ba:36:47:f9', '90:e2:ba:36:50:30', '90:e2:ba:36:50:31',
                                                             '0025.9097.0fac', '0025.9097.0fad', '0025.9061.1604',
                                                             '0025.9061.1605', '0025.9097.0f56', '0025.9097.0f57',
                                                             '0025.9096.5efe', '0025.9096.5eff', '0025.9097.10d6',
                                                             '0025.9097.10d7', '0025.9097.0e14', '0025.9097.0e15',
                                                             '0025.9069.860e', '0025.9069.860f', '0025.9091.1710',
                                                             '0025.9091.1711', '0025.9091.6576', '0025.9091.6577',
                                                             '90e2.ba2c.a048', '90e2.ba2c.a049', '90e2.ba2c.a024',
                                                             '90e2.ba2c.a025', '90e2.ba2c.9e58', '90e2.ba2c.9e59',
                                                             '0025.9091.1772', '0025.9091.1773', '0025.9091.1724',
                                                             '0025.9091.170a', '0025.9091.170b'), parser=macparser, optdict={'switch' : sw1})

        Mac address 0010.0401.3394 in vlan 2403 on port Ethernet109/1/11, type Primary_entry
        Mac address 0010.0401.3395 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0010.0401.3384 in vlan 2403 on port Ethernet109/1/12, type Primary_entry
        Mac address 0010.0401.3385 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 90e2.ba36.47f8 in vlan 3029 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Command 'show mac address-table address 90:e2:ba:36:47:f9' returned no output
        Mac address 90e2.ba36.5030 in vlan 3029 on port port-channel25, type Primary_entry
            port-channel25 ports: ['Ethernet109/1/10']
        Command 'show mac address-table address 90:e2:ba:36:50:31' returned no output
        Mac address 0025.9097.0fac in vlan 2403 on port Ethernet103/1/19, type Primary_entry
        Mac address 0025.9097.0fad in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9061.1604 in vlan 2403 on port Ethernet103/1/18, type Primary_entry
        Mac address 0025.9061.1605 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9097.0f56 in vlan 2403 on port Ethernet103/1/17, type Primary_entry
        Mac address 0025.9097.0f57 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9096.5efe in vlan 2403 on port Ethernet103/1/16, type Primary_entry
        Mac address 0025.9096.5eff in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9097.10d6 in vlan 2403 on port Ethernet103/1/15, type Primary_entry
        Mac address 0025.9097.10d7 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9097.0e14 in vlan 2403 on port Ethernet103/1/14, type Primary_entry
        Mac address 0025.9097.0e15 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9069.860e in vlan 2403 on port Ethernet103/1/6, type Primary_entry
        Mac address 0025.9069.860f in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9091.1710 in vlan 2403 on port Ethernet109/1/8, type Primary_entry
        Mac address 0025.9091.1711 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9091.6576 in vlan 2403 on port Ethernet109/1/7, type Primary_entry
        Mac address 0025.9091.6577 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 90e2.ba2c.a048 in vlan 2403 on port Ethernet109/1/6, type Primary_entry
        Mac address 90e2.ba2c.a049 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 90e2.ba2c.a024 in vlan 2403 on port Ethernet109/1/5, type Primary_entry
        Mac address 90e2.ba2c.a025 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 90e2.ba2c.9e58 in vlan 2403 on port Ethernet109/1/4, type Primary_entry
        Mac address 90e2.ba2c.9e59 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9091.1772 in vlan 2403 on port Ethernet109/1/3, type Primary_entry
        Mac address 0025.9091.1773 in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']
        Mac address 0025.9091.1724 in vlan 2403 on port Ethernet109/1/2, type Primary_entry
        Mac address 0025.9091.170a in vlan 2403 on port Ethernet109/1/1, type Primary_entry
        Mac address 0025.9091.170b in vlan 2404 on port port-channel1, type Primary_vPC
            port-channel1 ports: ['Ethernet1/31', 'Ethernet1/32', 'Ethernet2/6']

        """
        self.logger.debug("run multiple show commands {} {}".format(command, str(arglist)))
        output = ""
        if isinstance(arglist, str):
            arglist = [arglist]
        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            if len(vdc) > 1:
                output = output + "\nvdc {}: \n".format(self.get_current_vdc())
            for a in arglist:
                self.logger.debug("run show commands {} {} in vdc {}".format(command, a, vdcname))
                if parser is not None:
                    scratch = parser(self._send_xml_cli_show("{} {}".format(command, a)), **optdict)
                    if scratch is None:
                        output = output + "Command '{} {}' returned no output\n".format(command, a)
                    else:
                        output = output + scratch
                else:
                    output = output + self._send_xml_cli_show("{} {}".format(command, a))
        self.logger.debug("multiple show commands output {}".format(output))
        return output

    def get_vdcs(self):
        """
        On a 7k, gets the list of vdcs currently configured. Runs automatically when the object is instantiated

        Populates self.vdcs

        """
        if self._check_for_7k():
            self.logger.debug('Getting VDC information from {}'.format(self.host))
            vdcxml = self._ncc.nxoscli('show vdc')
            vdcparsed = _begin_parse(vdcxml)
            vdcschema = parse_get_nsmap(vdcparsed)
            showvdc = parse_xml_heirarchy('ROW_vdc', ['vdc_id', 'vdc_name', 'state'], vdcschema,
                                          vdcparsed)
            vdcs = {}
            for v in showvdc:
                self.logger.debug(
                    'VDC {} {} {} on {}'.format(v['vdc_id'], v['vdc_name'], v['state'], self.host))
                vdcs[v['vdc_name']] = VDC(**v)
                if v['vdc_id'] == '1':
                    self.default_vdc = v['vdc_name']
            self.vdcs = vdcs
            self.logger.debug(vdcs)

    def show_vdcs(self):
        """
        Prints the vdcs currently configured on the device

        """
        for v in self.vdcs:
            print v

    def show_vdcs_detail(self):
        """

        Prints the details of the vdcs currently configured on the device

        """
        for v in self.vdcs:
            print self.vdcs[v]

    @xmlbuilder
    def get_current_vdc(self):
        """
        Is run to update the current_vdc attribute

        """
        if self._check_for_7k():
            vdcxml = self._ncc.nxoscli('show vdc current-vdc')
            vdcparsed = _begin_parse(vdcxml)
            vdcschema = parse_get_nsmap(vdcparsed)
            showvdc = find_element(['name'], vdcschema,
                                   vdcparsed)
            self.logger.debug("get_current_vdc: {}".format(str(showvdc)))
            self.current_vdc = showvdc['name']

    def show_current_vdc(self):
        """
        Prints the vdc the object is currently in

        """
        if self._check_for_7k():
            self.get_current_vdc()
        print self.current_vdc

    def switchto_vdc(self, vdc):
        """
        switch to desired vdc

        @param vdc: string, name of vdc to switch to

        """
        if self._check_for_7k():
            self.get_current_vdc()
            self.logger.debug("Switching from vdc {} to vdc {} on {}".format(self.current_vdc, vdc, self.host))
            switchtodefault = False
            if self.current_vdc != vdc:
                switchtodefault = self.current_vdc != self.default_vdc
                self.logger.debug(str(switchtodefault))
                self._ncc.switchto_vdc(vdc=vdc, vdcnotdefault=switchtodefault)
            self.get_current_vdc()
            if self.current_vdc != vdc:
                self.logger.critical("Instead of vdc {}, we find ourselves in vdc {} on {}".format(vdc, self.current_vdc, self.host))
                raise VDCError("Instead of default vdc {}, we find ourselves in {}".format(self.default_vdc, self.current_vdc))


    def switchto_default_vdc(self):
        """
        switch back to the default vdc
        the default vdc is assumed to be the one with an id of 1

        """
        if self._check_for_7k():
            self.logger.debug("Switching from vdc {} to default vdc on {}".format(self.current_vdc, self.host))
            self._ncc.switchto_vdc()
            self.get_current_vdc()
            if self.current_vdc != self.default_vdc:
                self.logger.critical("Instead of default vdc {}, we find ourselves in vdc {} on {}".format(self.default_vdc, self.current_vdc, self.host))
                raise VDCError("Instead of default vdc {}, we find ourselves in {}".format(self.default_vdc, self.current_vdc))


    @vdchandler
    def get_cdp_detail(self, interface=None, vdc='all'):
        """

        @param interface:
        @param vdc:

        """
        if interface is not None:
            assert isinstance(interface, str)
            interface = interface.title()

        self.logger.debug("Getting CDP interface information on {}".format(self.host))
        if interface is not None and len(vdc) != 1:
            raise ValueError("Interface {} cannot exist in multiple vdcs {}".format(interface, self.host))

        if interface is not None and self.vdcs[vdc[0]]:
            self.logger.debug("Getting CDP on interface {} in vdc {} on {}".format(interface, vdc[0], self.host))
            if self.vdcs[vdc].interfaces is None:
                self.get_interfaces(vdc=vdc[0])
            if 'eth' in interface and (',' not in interface and '-' not in interface) and not self.vdcs[
                vdc[0]].check_interface(interface):
                raise ValueError(
                    "Interface {} does not exist in vdc {} on {}".format(interface, vdc[0], self.host))

        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            self.logger.debug('Getting CDP information from vdc {} in {}'.format(vdcname, self.host))
            command = 'show cdp neighbor'
            if interface is not None:
                command = "{} interface {} detail".format(command, interface)
            else:
                command = "{} detail".format(command)
            self.logger.debug('Sending VDC command {} to {}'.format(command, self.host))
            cdpxml = nxostest._ncc.nxoscli(command)
            cdpdict = Neighbor.cdp_parser(cdpxml)
            for cdp in cdpdict:
                self.logger.debug(
                    'CDP Entry {}'.format(str(cdp)))
                neighborobj = Neighbor(**cdp)
                if neighborobj.cdp_neighbor_local_interface.title() in self.vdcs[vdcname].interfaces:
                    self.vdcs[vdcname].interfaces[neighborobj.cdp_neighbor_local_interface.title()].neighbor = neighborobj
                else:
                     if self.vdcs[vdcname].interfaces is None:
                         self.vdcs[vdcname].interfaces = {}
                     self.vdcs[vdcname].interfaces[neighborobj.cdp_neighbor_local_interface.title()] = Interface(neighborobj.cdp_neighbor_local_interface.title())
                     self.vdcs[vdcname].interfaces[neighborobj.cdp_neighbor_local_interface.title()].neighbor = neighborobj

    def __str__(self):
        strobject = "{}\n{}\n{}".format(self.hostname, self.chassis_id, self.system_version)
        return strobject

def _vlanexpand(vlans):
    """

    @param vlans: string of a list of vlans, for example
    '35,45,55,73,78,82,166,1200-1220,1510-1516,1518-1536,1596-1599,1601-1602,1604-1605,1614-1624,1699,1830-1831'
    @return: string of vlans with dashes removed and intermediate vlans inserted, for example
    '35, 45, 55, 73, 78, 82, 166, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220, 1510, 1511, 1512, 1513, 1514, 1515, 1516, 1518, 1519, 1520, 1521, 1522, 1523, 1524, 1525, 1526, 1527, 1528, 1529, 1530, 1531, 1532, 1533, 1534, 1535, 1536, 1596, 1597, 1598, 1599, 1601, 1602, 1604, 1605, 1614, 1615, 1616, 1617, 1618, 1619, 1620, 1621, 1622, 1623, 1624, 1699, 1830, 1831'

    """

    vlanlist = ""
    for v in vlans.split(','):
        if '-' in v:
            vtemp = range(int(v.split('-')[0]), int(v.split('-')[1]) + 1)
            vlanlist = vlanlist + ', ' + ', '.join([str(i) for i in vtemp])
        else:
            vlanlist = vlanlist + ', ' + v
    return vlanlist.lstrip(' ,')


def _intwrapper(prefix, intstring):
    temp = _vlanexpand(intstring)
    templist = temp.split(', ')
    intlist = [prefix + i.strip() for i in templist]
    return ', '.join(intlist)


def _intexpand(interfaces):
    intlist = ""
    for i in interfaces.split(','):
        irange = i
        if 'port-channel' in i and i.count('-') == 2:
            itemp = i.lstrip('port-channel')
            irange = _intwrapper('port-channel', itemp)
        elif 'port-channel' not in i and '-' in i:
            itemp = i.split('/')
            irange = _intwrapper(itemp[0] + '/', itemp[1])
        intlist = intlist + ', ' + irange
    return intlist.lstrip(' ,')


class Interface(object):
    """
    Class to encapsulate interface information


    -    @param stpfwd_vlans: string, stp forwarding vlans for
    -    @param port-channel: string, port channel this interface belongs to
    -    @param name: string, interface description
    -    @param state: string, e.g. 'disabled'
    -    @param switchport: string, 'access' or 'routed' or 'trunk'
    -    @param vlan: string, access vlan for access ports
    -    @param type: string, e.g. '10Gbase-SR'
    -    @param ipaddress: string, IP Address of L3 interface
    -    @param native: string, native vlan for trunk interfaces
    -    @param allowedvlans: allowed vlans for trunk interfaces
    -    @param erroredvlans: errored vlans for trunk interfaces
    -    @param interface: string of interface, e.g. 'Ethernet2/1'
    -    @param portchannel: string
    -    @param pogroup: string
    -    @param polayer: string
    -    @param postatus: string
    -    @param poprotocol: string
    -    @param ports: list of strings, list of portchannel members
    -    @param ipprefix: string
    -    @param ipsubnet: string
    -    @param ipmasklen: string
    -    @param ipdisabled: string
    -    @param hsrp: dictionary of HSRP objects

    interface attributes that can be accessed:

    -    interface = interface
    -    name = name, interface description
    -    state
    -    switchport = switchport type, 'access' or 'routed' or 'trunk'
    -    vlan = access vlan
    -    native_vlan = native vlan of trunk interface
    -    type
    -    ipaddress = ipaddress
    -    port_channel_members = a list of the members of the portchannel
    -    po_group = portchannel group
    -    portchannel
    -    po_status
    -    po_protocol
    -    po_layer
    -    allowed_vlans = allowed vlans on trunk port
    -    errored_vlans = errored vlans on trunk port
    -    stp_fwd_vlans = stp forwarding vlans on trunk interface
    -    ip_address
    -    ip_subnet
    -    ip_mask_len
    -    ip_disabled
    -    hsrp_groups = dictionary of hsrp group objects of the form {group number : obj}
    -     attributes in the hsrp object is
    -     Attributes are
    -      hsrp_group
    -      hsrp_group_state
    -      hsrp_group_pri
    -      hsrp_group_vip
    -      hsrp_group_active = IP of active router
    -      hsrp_group_standby = IP of standby router
    -      hsrp_name

    """

    def __init__(self, interface, name=None, state='connected', switchport='routed', vlan=None, type=None,
                 native=None, allowedvlans=None, erroredvlans=None, stpfwd_vlans=None,
                 portchannel=None, pogroup=None, polayer=None, postatus=None, poprotocol=None, ports=None,
                 ipprefix=None, ipsubnet=None, masklen=None, ipdisabled=True, hsrp=None, neighbor=None, **kwargs):
        """

        @param stpfwd_vlans: string, stp forwarding vlans for
        @param port-channel: string, port channel this interface belongs to
        @param name: string, interface description
        @param state: string, e.g. 'disabled'
        @param switchport: string, 'access' or 'routed' or 'trunk'
        @param vlan: string, access vlan for access ports
        @param type: string, e.g. '10Gbase-SR'
        @param ipaddress: string, IP Address of L3 interface
        @param native: string, native vlan for trunk interfaces
        @param allowedvlans: allowed vlans for trunk interfaces
        @param erroredvlans: errored vlans for trunk interfaces
        @param interface: string of interface, e.g. 'Ethernet2/1'
        @param portchannel: string
        @param pogroup: string
        @param polayer: string
        @param postatus: string
        @param poprotocol: string
        @param ports: list of strings, list of portchannel members
        @param ipprefix: string
        @param ipsubnet: string
        @param ipmasklen: string
        @param ipdisabled: string
        @param hsrp: dictionary of HSRP objects

        
        interface attributes that can be accessed:

        -    interface = interface

        -    name = name, interface description

        -    state

        -    switchport = switchport type, 'access' or 'routed' or 'trunk'

        -    vlan = access vlan

        -    native_vlan = native vlan of trunk interface

        -    type

        -    ipaddress = ipaddress

        -    port_channel_members = a list of the members of the portchannel

        -    po_group = portchannel group
        -    portchannel

        -    po_status

        -    po_protocol

        -    po_layer

        -    allowed_vlans = allowed vlans on trunk port

        -    errored_vlans = errored vlans on trunk port

        -    stp_fwd_vlans = stp forwarding vlans on trunk interface

        -    ip_address

        -    ip_subnet

        -    ip_mask_len

        -    ip_disabled

        -    hsrp_groups = dictionary of hsrp group objects of the form {group number : obj}
        -     attributes in the hsrp object is
        -     Attributes are
        -      hsrp_group
        -      hsrp_group_state
        -      hsrp_group_pri
        -      hsrp_group_vip
        -      hsrp_group_active = IP of active router
        -      hsrp_group_standby = IP of standby router
        -      hsrp_name

        """
        self.interface = interface
        self.name = name
        self.state = state
        self.switchport = switchport
        self.vlan = vlan
        self.native_vlan = native
        self.type = type
        self.port_channel_members = ports       #This is a list
        self.portchannel = portchannel
        self.po_group = pogroup
        self.po_status = postatus
        self.po_protocol = poprotocol
        self.po_layer = polayer
        self.allowed_vlans = allowedvlans
        self.errored_vlans = erroredvlans
        self.stp_fwd_vlans = stpfwd_vlans
        self.ip_address = ipprefix
        self.ip_subnet = ipsubnet
        self.ip_mask_len = masklen
        self.ip_disabled = ipdisabled
        self.hsrp_groups = hsrp
        self.neighbor = None

    def __str__(self):
        strobject = str(self.interface) + '\n'
        strobject += 'description: ' + str(self.name) + '\n'
        strobject += 'state: ' + str(self.state) + '\n'
        strobject += 'switchport type: ' + str(self.switchport) + '\n'
        if self.switchport == 'access':
            strobject += 'vlan: ' + str(self.vlan) + '\n'
        strobject += 'type: ' + str(self.type) + '\n'
        if self.switchport == 'routed':
            strobject += 'IP address: ' + str(self.ip_address) + '\n'
            strobject += 'IP subnet: ' + str(self.ip_subnet) + '\n'
            strobject += 'IP mask length: ' + str(self.ip_mask_len) + '\n'
            strobject += 'IP disabled: ' + str(self.ip_disabled) + '\n'
        if self.portchannel is not None:
            strobject += 'member of port channel: ' + str(self.portchannel) + '\n'
            strobject += 'member status: ' + str(self.po_status) + '\n'
        if self.po_group is not None:
            strobject += 'port-channel group: ' + str(self.po_group) + '\n'
            strobject += 'port-channel protocol: ' + str(self.po_protocol) + '\n'
            strobject += 'port-channel status: ' + str(self.po_status) + '\n'
            strobject += 'port-channel layer: ' + str(self.po_layer) + '\n'
            strobject += 'port-channel interfaces: ' + str(self.port_channel_members) + '\n'
        if self.switchport == 'trunk':
            strobject += 'native vlan: ' + str(self.native_vlan) + '\n'
            strobject += 'allowed vlans: ' + str(self.allowed_vlans) + '\n'
            strobject += 'stp forwarding vlans: ' + str(self.stp_fwd_vlans) + '\n'
            strobject += 'errored vlans: ' + str(self.errored_vlans) + '\n'
        if self.hsrp_groups is not None:
            for group in self.hsrp_groups:
                strobject += 'HSRP group: ' + str(group) + '\n'
                strobject += 'HSRP vip: ' + self.hsrp_groups[group].hsrp_group_vip + '\n'
                strobject += 'HSRP pri: ' + self.hsrp_groups[group].hsrp_group_pri + '\n'
                strobject += 'HSRP preempt: ' + self.hsrp_groups[group].hsrp_group_preempt + '\n'
                strobject += 'HSRP group state: ' + self.hsrp_groups[group].hsrp_group_state + '\n'
                strobject += 'HSRP group active: ' + self.hsrp_groups[group].hsrp_group_active + '\n'
                strobject += 'HSRP group standby: ' + self.hsrp_groups[group].hsrp_group_standby + '\n'
                strobject += 'HSRP group name: ' + self.hsrp_groups[group].hsrp_group_name + '\n'
        return strobject

    def update(self, interface, name=None, state='connected', switchport='routed', vlan=None, type=None,
                 native=None, allowedvlans=None, erroredvlans=None, stpfwd_vlans=None,
                 portchannel=None, pogroup=None, polayer=None, postatus=None, poprotocol=None, ports=None,
                 ipprefix=None, ipsubnet=None, masklen=None, ipdisabled=None, hsrp=None, neighbor=None, **kwargs):

        if name is not None:
            self.name = name
        if state is not None:
            self.state = state
        if switchport is not None:
            self.switchport = switchport
        if vlan is not None:
            self.vlan = vlan
        if native is not None:
            self.native_vlan = native
        if type is not None:
            self.type = type
        if ports is not None:
            self.port_channel_members = ports       #This is a list
        if portchannel is not None:
            self.portchannel = portchannel
        if pogroup is not None:
            self.po_group = pogroup
        if postatus is not None:
            self.po_status = postatus
        if poprotocol is not None:
            self.po_protocol = poprotocol
        if polayer is not None:
            self.po_layer = polayer
        if allowedvlans is not None:
            self.allowed_vlans = allowedvlans
        if erroredvlans is not None:
            self.errored_vlans = erroredvlans
        if self.stp_fwd_vlans is not None:
            self.stp_fwd_vlans = stpfwd_vlans
        if ipprefix is not None:
            self.ip_address = ipprefix
        if ipsubnet is not None:
            self.ip_subnet = ipsubnet
        if masklen is not None:
            self.ip_mask_len = masklen
        if ipdisabled is not None:
            self.ip_disabled = ipdisabled
        if hsrp:
            self.hsrp_groups = hsrp
        if neighbor is not None:
            self.neighbor = neighbor

    @classmethod
    def _parseallinterface(cls, deviceintstatusxml=None, deviceinttrunkxml=None, deviceposummxml=None,
                           devicel3intxml=None, devicehsrpxml=None):
        """



        @param deviceposummxml: XML output for show port-channel summary
        @param devicel3intxml: XML output for show ip interface
        @param devicehsrpxml: XML output for show hsrp
        @param deviceinttrunkxml: XML output for show int trunk
        @param deviceintstatusxml:XML output for show int status
        """
        elementlist = {}
        trunklist = {}
        posummlist = {}
        ipintlist = {}
        hsrplist = {}
        intstatusparsed = _begin_parse(deviceintstatusxml)
        inttrunkparsed = _begin_parse(deviceinttrunkxml)
        intposummparsed = _begin_parse(deviceposummxml)
        ipintparsed = _begin_parse(devicel3intxml)
        hsrpparsed = _begin_parse(devicehsrpxml)

        hsrpschema = parse_get_nsmap(hsrpparsed)
        intschema = parse_get_nsmap(intstatusparsed)
        ipschema = parse_get_nsmap(ipintparsed)
        ethpcmdc3schema = parse_get_nsmap(intposummparsed)

        intstatuslist = cls._parseshowintstatuscommand(intstatusparsed, intschema)
        trunklist = cls._parseinttrunkxml(inttrunkparsed, intschema)
        if trunklist is None:
            trunklist = {}
        posummlist = cls._parseposummxml(intposummparsed, ethpcmdc3schema)
        if posummlist is None:
            posummlist = {}
        ipintlist = cls._parseipintxml(ipintparsed, ipschema)
        if ipintlist is None:
            ipintlist = {}
        hsrplist = HSRPGroup._parsehsrpxml(hsrpparsed, hsrpschema)
        if hsrplist is None:
            hsrplist = {}
        for interface in intstatuslist:
            if interface in trunklist:
                intstatuslist[interface].update(trunklist[interface])
            if interface in posummlist:
                intstatuslist[interface].update(posummlist[interface])
            if interface in ipintlist:
                intstatuslist[interface].update(ipintlist[interface])
                del ipintlist[interface]
            if interface in hsrplist:
                intstatuslist[interface]['hsrp'] = {}
                for group in hsrplist[interface]:
                    intstatuslist[interface]['hsrp'][group] = HSRPGroup(**hsrplist[interface][group])
        if ipintlist:
            for interface in ipintlist:
                ipintlist[interface]['interface'] = interface
                intstatuslist[interface] = ipintlist[interface]
                if interface in hsrplist:
                    intstatuslist[interface]['hsrp'] = {}
                    for group in hsrplist[interface]:
                        intstatuslist[interface]['hsrp'][group] = HSRPGroup(**hsrplist[interface][group])

        return intstatuslist

    @classmethod
    def _parseshowintstatuscommand(cls, intstatusparsed, intschema):
        """

        @rtype : dictionary
        """
        intstatuslist = {}
        for element in intstatusparsed.iter("{}ROW_interface".format(intschema)):
            elementlist = {}
            elelist = [i.tag for i in list(element)]
            elementlist['interface'] = element.find("{}interface".format(intschema)).text
            if "{}name".format(intschema) in elelist:
                elementlist['name'] = element.find("{}name".format(intschema)).text
            elementlist['state'] = element.find("{}state".format(intschema)).text
            if element.find("{}vlan".format(intschema)).text.isdigit():
                elementlist['switchport'] = 'access'
                elementlist['vlan'] = element.find("{}vlan".format(intschema)).text
            else:
                elementlist['switchport'] = element.find("{}vlan".format(intschema)).text
            if "{}type".format(intschema) in elelist:
                elementlist['type'] = element.find("{}type".format(intschema)).text
            intstatuslist[elementlist['interface']] = elementlist
        return intstatuslist

    @classmethod
    def _parseinttrunkxml(cls, inttrunkparsed, intschema):
        """
        @return: nested dictionary of form {interface : {native : string, etc}}
        dictionary entries are of the form:
        ::

            trunkdict['Ethernet3/7']
            {'erroredvlans': 'none', 'stpfwd_vlans': '35,45,55,73,78,82,166,1200-1220,1510-1516,1518-1536,1596-1599,1601-1602,1604-1605,1614-1624,1699,1830-1831', 'allowedvlans': '35,45,55,73,77-80,82,166,1200-1220,1510-1699,1830-1831', 'native': '1'}
        """
        trunkdict = {}
        context = inttrunkparsed.iter()
        for element in context:
            if element.tag == "{}interface".format(intschema):
                interface = element.text
                if interface not in trunkdict:
                    trunkdict[interface] = {}
                for element in context:
                    if element.tag == "{}native".format(intschema):
                        trunkdict[interface]['native'] = element.text
                    elif element.tag == "{}allowedvlans".format(intschema):
                        trunkdict[interface]['allowedvlans'] = _vlanexpand(element.text)
                        break
                    elif element.tag == "{}erroredvlans".format(intschema):
                        trunkdict[interface]['erroredvlans'] = _vlanexpand(element.text)
                        break
                    elif element.tag == "{}stpfwd_vlans".format(intschema):
                        trunkdict[interface]['stpfwd_vlans'] = _vlanexpand(element.text)
                        break
                    if element.tag == "{}portchannel".format(intschema):
                        #trunkdict[interface]['portchannel'] = element.text
                        break
                    if element.tag == "{}TABLE_vtp_pruning".format(intschema):
                        break
        return trunkdict

    @classmethod
    def _parseposummxml(cls, intpoparsed, ethpcmdc3schema):
        """

        @param intpoparsed:
        @return: A dictionary with entries of the form:

        ::

            >>> portchannel['port-channel73']
            {'status': 'U', 'protocol': 'LACP', 'layer': 'R', 'group': '73', 'ports': ['Ethernet3/13', 'Ethernet3/14']}
            >>> portchannel['Ethernet3/23']
            {'status': 'P', 'port-channel': 'port-channel104'}
        """
        portchannel = {}
        for element in intpoparsed.iter("{}ROW_channel".format(ethpcmdc3schema)):
            elelist = [i.tag for i in list(element)]
            group = element.find("{}group".format(ethpcmdc3schema)).text
            point = element.find("{}port-channel".format(ethpcmdc3schema)).text
            portchannel[point] = {'pogroup': group}
            portchannel[point]['polayer'] = element.find("{}layer".format(ethpcmdc3schema)).text
            portchannel[point]['postatus'] = element.find("{}status".format(ethpcmdc3schema)).text
            portchannel[point]['poprotocol'] = element.find("{}prtcl".format(ethpcmdc3schema)).text
            if "{}TABLE_member".format(ethpcmdc3schema) in elelist:
                interfaces = element.find("{}TABLE_member".format(ethpcmdc3schema))
                ports = []
                for i in interfaces.iter("{}ROW_member".format(ethpcmdc3schema)):
                    ints = i.find("{}port".format(ethpcmdc3schema))
                    ports.append(ints.text)
                    portchannel[ints.text] = {'portchannel': point}
                    portstatus = i.find("{}port-status".format(ethpcmdc3schema))
                    portchannel[ints.text]['postatus'] = portstatus.text
                portchannel[point]['ports'] = ports
        return portchannel

    @classmethod
    def _parseipintxml(cls, ipintparsed, ipschema):
        """
        returns dictionary with entries of the form:

        ::

            >>> ipintdict['Ethernet2/3']
            {'ipdisabled': 'FALSE', 'masklen': '30', 'ipsubnet': '172.29.170.8', 'ipprefix': '172.29.170.9'}

        @type ipintparsed: object

        @todo secondary addresses
        """
        ipintdict = {}
        for element in ipintparsed.iter("{}ROW_intf".format(ipschema)):
            ipint = element.find("{}intf-name".format(ipschema)).text
            ippre = element.find("{}prefix".format(ipschema)).text
            ipsub = element.find("{}subnet".format(ipschema)).text
            ipmasklen = element.find("{}masklen".format(ipschema)).text
            ipdisabled = element.find("{}ip-disabled".format(ipschema)).text
            ipintdict[ipint] = {'ipprefix': ippre, 'ipsubnet': ipsub, 'masklen': ipmasklen, 'ipdisabled': ipdisabled}
        return ipintdict


class HSRPGroup(object):
    """
    HSRP Group object

    -    @type hsrpgrouppre: string
    -    @param hsrpgroup: string
    -    @param hsrpgroupstate: string
    -    @param hsrpgrouppri: string
    -    @param hsrpvip: string
    -    @param hsrpactive: string
    -    @param hsrpstandby: string
    -    @param hsrpname: string

    Attributes are

    -    hsrp_group

    -    hsrp_group_state

    -    hsrp_group_pri

    -    hsrp_group_vip

    -    hsrp_group_active = IP of active router

    -    hsrp_group_standby = IP of standby router

    -    hsrp_group_name


    """

    def __init__(self, hsrpgroup=None, hsrpgroupstate=None, hsrpgrouppri=None, hsrpgrouppre='disabled', hsrpvip=None,
                 hsrpactive=None,
                 hsrpstandby=None, hsrpname=None):
        """


        @type hsrpgrouppre: string
        @param hsrpgroup: string
        @param hsrpgroupstate: string
        @param hsrpgrouppri: string
        @param hsrpvip: string
        @param hsrpactive: string
        @param hsrpstandby: string
        @param hsrpname: string

        Attributes are

        -    hsrp_group

        -    hsrp_group_state

        -    hsrp_group_pri

        -    hsrp_group_vip

        -    hsrp_group_active = IP of active router

        -    hsrp_group_standby = IP of standby router

        -    hsrp_group_name
        """
        self.hsrp_group = hsrpgroup
        self.hsrp_group_state = hsrpgroupstate
        self.hsrp_group_pri = hsrpgrouppri
        self.hsrp_group_preempt = hsrpgrouppre
        self.hsrp_group_vip = hsrpvip
        self.hsrp_group_active = hsrpactive
        self.hsrp_group_standby = hsrpstandby
        self.hsrp_group_name = hsrpname

    @classmethod
    def _parsehsrpxml(cls, hsrpparsed, hsrpschema):
        """
        returns dictionary with entries of the form:

        ::

            hsrpdict['Vlan100']
            {'200': {'hsrpname': 'hsrp-Vlan100-200', 'hsrpgrouppri': '100', 'hsrpactive': '0.0.0.0', 'hsrpgroupstate': 'Initial', 'hsrpstandby': '0.0.0.0', 'hsrpvip': '100.100.100.2'}, '100': {'hsrpname': 'hsrp-Vlan100-100', 'hsrpgrouppri': '100', 'hsrpactive': '0.0.0.0', 'hsrpgroupstate': 'Initial', 'hsrpstandby': '0.0.0.0', 'hsrpvip': '100.100.100.1'}}
        """
        hsrpdict = {}
        for element in hsrpparsed.iter("{}ROW_grp_detail".format(hsrpschema)):
            ipint = element.find("{}sh_if_index".format(hsrpschema)).text
            hsrpgroup = element.find("{}sh_group_num".format(hsrpschema)).text
            hsrpgroupstate = element.find("{}sh_group_state".format(hsrpschema)).text
            hsrpgrouppri = element.find("{}sh_cfg_prio".format(hsrpschema)).text
            hsrpgrouppre = element.find("{}sh_preempt".format(hsrpschema)).text
            hsrpvip = element.find("{}sh_vip".format(hsrpschema)).text
            hsrpactive = element.find("{}sh_active_router_addr".format(hsrpschema)).text
            hsrpstandby = element.find("{}sh_standby_router_addr".format(hsrpschema)).text
            hsrpname = element.find("{}sh_ip_redund_name".format(hsrpschema)).text
            groupdict = {
                hsrpgroup: {'hsrpgroupstate': hsrpgroupstate, 'hsrpgrouppri': hsrpgrouppri,
                            'hsrpgrouppre': hsrpgrouppre,
                            'hsrpvip': hsrpvip,
                            'hsrpactive': hsrpactive, 'hsrpstandby': hsrpstandby, 'hsrpname': hsrpname}}
            if ipint not in hsrpdict:
                hsrpdict[ipint] = groupdict
            else:
                hsrpdict[ipint].update(groupdict)
        return hsrpdict


class Vlan(object):
    def __init__(self, vlanshowbr_vlanname=None, vlanshowinfo_vlanid=None, vlanshowinfo_vlanmode=None,
                 vlanshowbr_vlanstate=None, vlanshowbr_shutstate=None, vlanshowplist_ifidx=None):
        """

        @param vlanshowbr_vlanname:
        @param vlanshowinfo_vlanid:
        @param vlanshowinfo_vlanmode:
        @param vlanshowbr_vlanstate:
        @param vlanshowbr_shutstate:
        @param vlanshowplist_ifidx:
        """
        self.vlan_name = vlanshowbr_vlanname
        self.vlan_id = vlanshowinfo_vlanid
        self.vlan_mode = vlanshowinfo_vlanmode
        self.vlan_state = vlanshowbr_vlanstate
        self.vlan_shutstate = vlanshowbr_shutstate
        self.vlan_intlist = vlanshowplist_ifidx

    def __str__(self):
        strobj = "Vlan ID: {}\n\tName: {}\n\tMode: {}\n\tState: {}\n\tShut State: {}\n\tInterfaces: {}\n".format(
            self.vlan_id, self.vlan_name, self.vlan_mode, self.vlan_state, self.vlan_shutstate, self.vlan_intlist)
        return strobj

    @staticmethod
    def parseshowvlancommand(message):
        """
        Parses XML reply to show vlan
        @param message: XML string from server
        @return:list of dictinaries, each dictionary describing a vlan
        """

        vlanparsed = _begin_parse(message)
        vlanschema = parse_get_nsmap(vlanparsed)
        vlans = parse_xml_heirarchy('ROW_mtuinfo', ['vlanshowinfo-vlanid', 'vlanshowinfo-vlanmode'], vlanschema,
                                    vlanparsed)

        elements = parse_xml_heirarchy('ROW_vlanbrief',
                                       ['vlanshowbr-vlanname', 'vlanshowbr-vlanstate', 'vlanshowbr-shutstate',
                                        'vlanshowplist-ifidx'], vlanschema, vlanparsed)
        for d in elements:
            if 'vlanshowplist-ifidx' in d:
                d['vlanshowplist-ifidx'] = _intexpand(d['vlanshowplist-ifidx'])

        [v.update(e) for v, e in zip(vlans, elements)]
        return vlans


class VDC(object):
    def __init__(self, vdc_id=None, vdc_name=None, state=None):
        """
        'vdc_id', 'vdc_name', 'state'


        """
        self.vdc_id = vdc_id
        self.vdc_name = vdc_name
        self.vdc_state = state
        self.interfaces = None
        self.vlans = None

    def __str__(self):
        strobj = "VDC Name: {}\n\tID: {}\n\tState: {}\n".format(self.vdc_name, self.vdc_id, self.vdc_state)
        return strobj

    def set_interfaces(self, intdict):
        """

        @param intdict: dictionary of interface objects
        """
        self.interfaces = intdict

    def set_vlans(self, vlandict):
        """


        @param vlandict: vlandict: dictionary of vlan objects
        """
        self.vlans = vlandict

    def show_interface(self, interface=None):
        """
        prints interface configuration to the console
        if interface is provided, prints that interface's information
        else, it prints all interface information

        @param interface: str, e.g. 'Ethernet2/1'
        """

        interface = interface.title()

        if interface is not None and interface in self.interfaces:
            print self.interfaces[interface]
        else:
            for i in self.interfaces:
                print self.interfaces[i]

    def show_vlan(self, vlan=None):
        """
        prints vlan configuration to the console
        if vlan id is provided, prints that vlan's information
        else, it prints all vlan information

        @param vlan: str, e.g. '2'
        """

        if vlan is not None and vlan in self.get_vlans_list():
            print self.vlans[vlan]
        else:
            for v in self.vlans:
                print self.vlans[v]

    def get_vlans_list(self):
        """
        Returns a list of the vlans in the vdc

        @return: list of vlans
        """
        return self.vlans.keys()

    def check_vlan(self, vlan):

        """
        @param vlan: a str, vlan, e.g. '2'
        @return: True if vlan exists, False if it doesn't exist
        """

        return vlan in self.get_vlans_list()

    def check_interface(self, interface):
        """

        @param interface: str, e.g. 'ethernet2/1'
        @return:True if interface exists, False if it doesn't exist
        """

        interface = interface.title()

        return interface in self.interfaces

    def check_interface_vlan(self, interface, vlan):
        """

        @param interface:
        @param vlan:
        """
        assert isinstance(vlan, str)
        assert isinstance(interface, str)

        interface = interface.title()

        if self.check_interface(interface) and self.check_vlan(vlan):
            if self.interfaces[interface].switchport == 'access':
                return self.interfaces[interface].vlan != vlan
            elif self.interfaces[interface].switchport == 'trunk':
                return vlan in self.interfaces[interface].allowed_vlans
            else:
                return False
        return False

    def show_interface(self, interface=None):
        """
        prints interface configuration to the console
        if interface is provided, prints that interface's information
        else, it prints all interface information

        @param interface: str, e.g. 'Ethernet2/1'
        """

        interface = interface.title()

        if interface is not None and interface in self.interfaces:
            print self.interfaces[interface]
        else:
            for i in self.interfaces:
                print self.interfaces[i]

    def show_vlan(self, vlan=None):
        """
        prints vlan configuration to the console
        if vlan id is provided, prints that vlan's information
        else, it prints all vlan information

        @param vlan: str, e.g. '2'
        """

        if vlan is not None and vlan in self.get_vlans_list():
            print self.vlans[vlan]
        else:
            for v in self.vlans:
                print self.vlans[v]

    def get_interfaces_list(self):
        return self.interfaces.keys()

    def show_interfaces_list(self):
        print self.get_interfaces_list()

    def show_vlans_list(self):
        print self.get_vlans_list()


class Neighbor(object):
    def __init__(self, device_id=None, serialnumber=None, v4addr=None, platform_id=None, intf_id=None, port_id=None,
                 version=None, v4mgmtaddr=None):
        self.cdp_neighor_device_id = device_id
        self.cdp_neighbor_device_serialnumber = serialnumber
        self.cdp_neighbor_v4addr = v4addr
        self.cdp_neighbor_platform_id = platform_id
        self.cdp_neighbor_local_interface = intf_id
        self.cdp_neighbor_port_id = port_id
        self.cdp_neighbor_version = version
        self.cdp_neighbor_v4mgmt_addr = v4mgmtaddr

    def __str__(self):
        strobj = 'Local interface : {}\n'.format(self.cdp_neighbor_local_interface)
        strobj = strobj + "Neighbor port id: {}\n".format(self.cdp_neighbor_port_id)
        strobj = strobj + "    Device id: {}\n".format(self.cdp_neighor_device_id)
        strobj = strobj + "    Platform id: {}\n".format(self.cdp_neighbor_platform_id)
        strobj = strobj + "    Version;: {}\n".format(self.cdp_neighbor_version)
        strobj = strobj + "    IP Address: {}\n".format(self.cdp_neighbor_v4addr)

    @classmethod
    def cdp_parser(cls, cdpxml):
        """

        @param cdpxml:
        """
        cdpparsed = _begin_parse(cdpxml)
        cdpschema = parse_get_nsmap(cdpparsed)

        cdplist = parse_xml_heirarchy('ROW_cdp_neighbor_detail_info',
                                      ['device_id', 'v4addr', 'platform_id', 'intf_id', 'port_id', 'version',
                                       'v4mgmtaddr'], cdpschema, cdpparsed)

        for element in cdplist:
            if '(' in element['device_id']:
                index = element['device_id'].find('(')
                device_id = element['device_id']
                element['device_id'] = element['device_id'][:index]
                element['serialnumber'] = device_id[index+1:-1]

        return cdplist


def _begin_parse(message):
    parser = etree.XMLParser(remove_blank_text=True)
    return etree.fromstring(message, parser=parser)


if __name__ == "__main__":
    LOGFILE = "netconflog.log"
    SCREENLOGLEVEL = logging.INFO
    FILELOGLEVEL = logging.DEBUG

    logger = logging.getLogger()
    logger.setLevel(SCREENLOGLEVEL)
    logformat = logging.Formatter('%(asctime)s: %(threadName)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s')
    logh = logging.FileHandler(LOGFILE)
    logh.setLevel(FILELOGLEVEL)

    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(SCREENLOGLEVEL)

    logh.setFormatter(logformat)

    ch.setFormatter(logformat)

    logger.addHandler(logh)
    logger.addHandler(ch)

    logger.info("Started")

    nxostest = NxosSwitch(host="192.168.133.250")
    nxostest.connect(username='admin', password='cisco')
    nxostest.show_hostname()
    nxostest.show_chassis_id()
    nxostest.show_system_version()
    nxostest.get_vlans_detail()
    nxostest.show_vlan()
    nxostest.get_interfaces()
    nxostest.show_interface()

##    nxostest.set_vlan('3600')
##    nxostest.show_vlan('3600')
##
##    nxostest.show_interface('Ethernet2/1')
##
##    print nxostest.check_interface_vlan('Ethernet2/1', '3600')
##
##    nxostest.set_vlan_interface('Ethernet2/1', '3600')
##
##    print nxostest.check_interface_vlan('Ethernet2/1', '3600')
##
##    nxostest.set_interface_ip('Vlan3600', '36.36.36.36/255.255.255.0')
##
##    nxostest.show_interface('Vlan3600')
##
##    nxostest.set_interface_hsrp('Vlan3600', '36', '36.36.36.254')
##
##    nxostest.show_interface('Ethernet2/1')
##
##    nxostest.show_interface('Vlan3600')
##
##    nxostest.show_interfaces_list()
##
##    nxostest.show_vlans_list()
##
##    nxostest.show_current_vdc()
##
##    nxostest.set_interface('Ethernet2/4-5', switchport='access')
##
    try:
        nxostest.set_portchannel('3000', 'Ethernet2/4-5', podescription="My favorite port channel")
    except:
        print nxostest._send_xml_cli_show('show port-channel compatibility-parameters')




    #nxostest.save_config()


from collections import namedtuple
import functools
import logging
import sys
import traceback
from lxml import etree
from netconf import NxosConnect
from nxosXmlFunctions import parse_get_nsmap, find_element, parse_xml_heirarchy, buildshowintcommand, INTSCHEMA
from vdcnetconf import VDCNxosConnect, VDCError


__author__ = 'rragan'


__version__ = '2015.7.20.1'

from lxml import etree
from netconf import NxosConnect


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
        self.logger.debug('vdchandler: instance {} of class {} is now decorated whee!'.format(self, self.__class__))
        self.logger.debug('vdchhandler: args {}, kwargs {}'.format(args, kwargs))
        self.logger.debug("vdchandler: VDC checks for {}".format(self.host))
        if 'vdc' not in kwargs:
            vpar = self.current_vdc
            vdc = [self.current_vdc]
        elif kwargs['vdc'].lower() == 'all':
            vpar = 'all'
            vdc = self.vdcs.keys()
        else:
            vpar = kwargs['vdc']
            vdc = [kwargs['vdc']]
        self.logger.debug('vdchandler: vdc list is {}'.format(str(vdc)))
        if 'vlan' in func.func_name and 'get_vlans_detail' not in func.func_name:
            for v in vdc:
                if self.vdcs[v].vlans is None:
                    self.logger.debug('vdchander: Running get_vlans_detail on host {}'.format(self.host))
                    self.get_vlans_detail([v])
        if 'interface' in func.func_name and func.func_name != 'get_interfaces':
            for v in vdc:
                if self.vdcs[v].interfaces is None:
                    self.logger.debug('vdchandler: Running get_interfaces on host {}'.format(self.host))
                    self.get_interfaces([v])
        try:
            kwargs['vdc'] = vdc
            self.logger.debug('vdchandler: Running {} on host {}'.format(func.func_name, self.host))
            vdcmessage = func(self, *args, **kwargs)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("vdchandler: Error with the decorated function {} on host {}".format(func.func_name, self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        return vdcmessage

    return decorator

class Nexus7kXML(VDCNxosConnect):
    """
    Wrapper to handle XML specific tasks
    """
    def __init__(self, host, prompt):
        super(Nexus7kXML, self).__init__(host, prompt)
        self.connected = self._ncconnected
        self.logger = logging.getLogger('nexus7k_model.Nexus7kXML')
        self.logger.debug("Instantiating Nexus7k XML object for {}".format(self.host))

    def connect(self, username, password, *args, **kwargs):
        self.nc_sshconnect(username=username, password=password, *args, **kwargs)
        self.connected = self._ncconnected

    @xmlbuilder
    def get_version(self):
        verparsed, sysmgrclischema = self._send_xml_cli_show('show version')
        self.logger.debug("NSMAP: {}".format(sysmgrclischema))
        showversion = find_element(['sys_ver_str', 'chassis_id', 'host_name', 'loader_ver_str'], sysmgrclischema,
                                   verparsed)
        return showversion

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
            self.nxoscli(commands)
        except:
            raise

    @xmlbuilder
    def _send_xml_cli_show(self, command):
        """
        Method for sending a show command to the device
        @param command: single show command, nx-os does not allow more than one
        @return: string dictionary of show version parameters
        """
        assert isinstance(command, str)
        self.logger.debug("Sending show command {} to {}".format(str(command), self.host))
        xml_result = self.nxoscli(command)
        self.logger.debug("On {} received output: {}".format(self.host, xml_result))
        xml_parsed = _begin_parse(xml_result)
        return (xml_parsed, parse_get_nsmap(xml_parsed))

    def get_vdcs(self):
        """
        On a 7k, gets the list of vdcs currently configured. Runs automatically when the object is instantiated

        @return: dictionary of vdcs

        """
        vdcparsed, vdcschema = self._send_xml_cli_show('show vdc')
        showvdc = parse_xml_heirarchy('ROW_vdc', ['vdc_id', 'vdc_name', 'state'], vdcschema,
                                          vdcparsed)
        return showvdc

    def get_current_vdc(self):
        """
        Is run to update the current_vdc attribute

        """
        vdcparsed, vdcschema = self._send_xml_cli_show('show vdc current-vdc')
        showvdc = find_element(['name'], vdcschema,
                            vdcparsed)
        return showvdc

    def disconnect(self):
        self.logger.debug("Logging out of {}".format(self.host))
        if self.connected:
            if self.in_xml:
                self.logger.debug("XML Session still running. Closing on {}".format(self.host))
                self._closesession()
                self.in_xml = False
        self.logger.debug("Closing shell on {}".format(self.host))
        self._closesession()
        self.send('\n')
        self.look_for_prompt()
        self.send('exit\n')
        self.look_for_prompt()
        self.connected = False

    def get_modules(self):
        """
        Returns list of modules

        @return: list of modules
        """

        self.logger.debug("Getting module info from host {}".format(self.host))
        modparsed, modschema = self._send_xml_cli_show('show mod')
        self.logger.debug("Received module info from {} {}".format(self.host, modparsed))
        rowlist = [r.find(".//{}modinf".format(modschema)).text for r in modparsed]
        modlist = [r.find(".//{}model".format(modschema)).text for r in modparsed]
        return zip(rowlist, modlist)

    @xmlbuilder
    def _interfaces_xml_builder(self):
        showcommands = {'deviceintstatusxml': [buildshowintcommand, ('status',), INTSCHEMA]}

        xmlresponse = {}
        self.interfaces = {}
        self.logger.debug("Getting interface information from {}".format(self.host))
        for s in showcommands.keys():
            key = s
            self.logger.debug(
                "Building {} {} command and sending to host {}".format(s, showcommands[key][1], self.host))
            xmlresponse[key] = self.nxosget(showcommands[key][0](*showcommands[key][1]),
                                                 schema=showcommands[key][2], getfilter="subtree")
            self.logger.debug(
                "Received XML for show {} {} command from server {}".format(s, showcommands[key][1], self.host))
            self.logger.debug(xmlresponse[key])
        self.logger.debug("XML Response: {}".format(xmlresponse))
        return xmlresponse

    def get_interfaces(self, vdc, mod=None):
        """
        Method to get result of show int status from device
        Calls _interfaces_xml_builder() method to get XML from server
        Calls Interface._parseallinterface class method to parse the xml, returns a dictionary
        This method iterates through the dictionary and creates a dictionary of Interface objects

        """

        self.logger.debug("XML Model: Getting interfaces in vdc {} on {}".format(vdc, self.host))
        intdict = Interface._parseallinterface(**self._interfaces_xml_builder())
        return intdict

    def get_interface_statistics(self, vdc, mod=None, statistics=None):
        """
        Method to get result of show int from device
        Calls _send_xml_cli_show method to get XML from server
        Calls parse_xml_heirarchy function to parse the xml, returns a list of dictionaries
        This method iterates through the dictionary and creates a dictionary of Interface objects

        @rtype : list of dictionaries
        """

        self.logger.debug("XML Model: Getting interface statistics in vdc {} on {}".format(vdc, self.host))
        intstatparsed, intstatschema = self._send_xml_cli_show('show interface')
        showintstat = parse_xml_heirarchy('ROW_interface', ['interface',]+statistics, intstatschema,
                                          intstatparsed)
        return showintstat

    def disconnect(self):
        if self.connected:
            self._ncc.disconnect()
            self.connected = False


def _begin_parse(message):
    if message is not None:
        parser = etree.XMLParser(remove_blank_text=True)
        return etree.fromstring(message, parser=parser)


class Nexus7k(object):
    """
    Class to connect to Nexus 7k and run commands
    """
    def __init__(self, host, prompt=None, conn='XML'):
        """
        Connect via SSH

        *host* is the hostname or IP address to connect to the Nexus
        *conn* is the connection type, XML or SSH
                currently only XML is supported
        *prompt* regular expression - necessary if connection type is SSH or if the 7k has multiple VDCs
        """


        assert conn == 'XML', "Currently only a connection type of XML is supported"
        self.conn = conn
        self.host = host
        self.hostname = None
        self.system_version = None
        self.chassis_id = None
        self.logger = logging.getLogger('nexus7k_model.Nexus7k')
        self.logger.debug("Instantiating NX-OS 7k object for {}".format(self.host))

        if self.conn == 'XML':
            self._ncc = Nexus7kXML(host, prompt)
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
            self._ncc.connect(username=username, password=password, *args, **kwargs)
            self.connected = True
            self.logger.debug("Opening Connection to " + self.host)
            self.get_version()
        #Check if device is a 7k, if it is change to an object type that can handle switching between vdcs
        if self._check_for_7k():
            self.logger.debug("{} is a 7k".format(self.host))
            self.get_vdcs()
            self.get_current_vdc()
            self.logger.debug("Switching to ssh shell object")
            self.connected = True
            #Fill in vdc dictionary
            self.get_vdcs()
            self.get_current_vdc()
        else:
            self.vdcs = {'default': VDC('1', 'default')}


    def _check_for_7k(self):
        return '7000' in self.chassis_id or '7700' in self.chassis_id

    def disconnect(self):
        if self.connected:
            self._ncc.closesession()
            self.connected = False

    def get_version(self):
        """
        Gets the show version of the device

        """
        showversion = self._ncc.get_version()
        self.logger.debug(showversion)
        self.hostname = showversion['host_name']
        self.chassis_id = showversion['chassis_id']
        self.system_version = showversion['sys_ver_str']

    def get_modules(self):
        """

        @return:
        """
        showmod = self._ncc.get_modules()
        self.logger.debug("Nexus 7k host {}: results of show mod is {}".format(self.host, showmod))
        mods = {}
        for slot, card_type in showmod:
            self.logger.debug("Host {}: Slot {}: {}".format(self.host, slot, card_type))
            mods[slot] = Card(slot, card_type)
        self.mods = mods
        self.logger.debug("mods dictionary on host {}: {}".format(self.host, mods))


    def show_hostname(self):
        """
        returns the hostname of the device

        """
        if self.hostname is None:
            self.get_version()
        print(self.hostname)

    def show_system_version(self):
        if self.system_version is None:
            self.get_version()
        print(self.system_version)

    def show_chassis_id(self):
        if self.chassis_id is None:
            self.get_version()
        print(self.chassis_id)

    def show_modules(self):
        if self.mods is None:
            self.get_modules()
        for mod in self.mods.itervalues():
            print(mod)

    def get_vdcs(self):
        """
        On a 7k, gets the list of vdcs currently configured. Runs automatically when the object is instantiated

        Populates self.vdcs

        """
        if self._check_for_7k():
            self.logger.debug('Getting VDC information from {}'.format(self.host))
            showvdc = self._ncc.get_vdcs()
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
            print(v)

    def show_vdcs_detail(self):
        """

        Prints the details of the vdcs currently configured on the device

        """
        for v in self.vdcs:
            print(self.vdcs[v])

    def get_current_vdc(self):
        """
        Is run to update the current_vdc attribute

        """
        if self._check_for_7k():
            showvdc = self._ncc.get_current_vdc()
            self.logger.debug("get_current_vdc: {}".format(str(showvdc)))
            self.current_vdc = showvdc['name']
            self._ncc.current_vdc = showvdc['name']

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
    def get_interfaces(self, mod=None, vdc=None):
        """
        Method to get result of show int status from device
        Calls _interfaces_xml_builder() method to get XML from server
        Calls Interface._parseallinterface class method to parse the xml, returns a dictionary
        This method iterates through the dictionary and creates a dictionary of Interface objects

        """

        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            self.logger.debug("Getting interfaces in vdc {} on {}".format(self.current_vdc, self.host))
            intdict = self._ncc.get_interfaces(vdcname)
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
    def get_interface_statistics(self, vdc, mod=None, statistics=["eth_indiscard", "eth_outdiscard"]):
        """


        @param statistics: a list or tuple or set of the desired statistics
        @type mod: string
        @param vdc: string indicating the vdc you wish to check, 'all' means check all vdcs
        @param mod: currently unused

        """

        for vdcname in vdc:
            self.switchto_vdc(vdcname)
            self.logger.debug("Getting interface statistics in vdc {} on {}".format(self.current_vdc, self.host))

            #intstatdict is a list of dictionaries
            intstatdict = self._ncc.get_interface_statistics(vdc=vdcname, statistics=statistics)
            self.logger.debug('intstatdict: {}'.format(str(intstatdict)))
            if self.vdcs[vdcname].interfaces is None:
                self.get_interfaces()
            for interfacedict in intstatdict:
                interface = interfacedict['interface']
                del interfacedict['interface']
                interface = interface.title()
                self.logger.debug(
                    "Updating interface object: {} for vdc {} with statistics {}".format(interface, self.current_vdc, statistics))
                if interface in self.vdcs[self.current_vdc].interfaces:
                    self.vdcs[self.current_vdc].interfaces[interface].update(**interfacedict)
                else:
                    self.vdcs[self.current_vdc].interfaces[interface] = Interface(interface, **interfacedict)

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
            print("VDC: {}".format(vdcname))
            if interface is not None and interface in self.vdcs[vdcname].interfaces:
                print(self.vdcs[vdcname].interfaces[interface])
            else:
                for i in self.vdcs[vdcname].interfaces:
                    print(self.vdcs[vdcname].interfaces[i])

    @vdchandler
    def get_interfaces_list(self, vdc=None):
        intlist = []
        for vdcname in vdc:
            intlist.append(self.vdcs[vdcname].interfaces.keys())
        return intlist

    @vdchandler
    def show_interfaces_list(self, vdc=None):
        for vdcname in vdc:
            print("VDC: {}".format(vdcname))
            self.vdcs[vdcname].show_interfaces_list()


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

    def get_interfaces_list(self):
        return self.interfaces.keys()

    def show_interfaces_list(self):
        print self.get_interfaces_list()


class Card(object):
    def __init__(self, slot, card_type):
        self.slot = slot
        self.module = card_type

    def __str__(self):
        return "Slot {}: {}".format(self.slot, self.module)

class Interface(object):
    """
    Class to encapsulate interface information

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
        self.logger = logging.getLogger('nexus7k_model.Interface')
        self.logger.debug("Instantiating Interface object {}".format(interface))

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
        self.unset_attributes = set([])
        if kwargs is not None:
            for value in kwargs:
                self.logger.debug("Interface: adding {} attribue".format(value))
                exec('self.{} = kwargs["{}"]'.format(value, value))
                self.unset_attributes.add(value)

    def __str__(self):
        strobject = str(self.interface) + '\n'
        strobject += 'description: ' + str(self.name) + '\n'
        strobject += 'state: ' + str(self.state) + '\n'
        strobject += 'switchport type: ' + str(self.switchport) + '\n'
        if self.switchport == 'access':
            strobject += 'vlan: ' + str(self.vlan) + '\n'
        strobject += 'type: ' + str(self.type) + '\n'
        # if self.switchport == 'routed':
        #     strobject += 'IP address: ' + str(self.ip_address) + '\n'
        #     strobject += 'IP subnet: ' + str(self.ip_subnet) + '\n'
        #     strobject += 'IP mask length: ' + str(self.ip_mask_len) + '\n'
        #     strobject += 'IP disabled: ' + str(self.ip_disabled) + '\n'
        # if self.portchannel is not None:
        #     strobject += 'member of port channel: ' + str(self.portchannel) + '\n'
        #     strobject += 'member status: ' + str(self.po_status) + '\n'
        # if self.po_group is not None:
        #     strobject += 'port-channel group: ' + str(self.po_group) + '\n'
        #     strobject += 'port-channel protocol: ' + str(self.po_protocol) + '\n'
        #     strobject += 'port-channel status: ' + str(self.po_status) + '\n'
        #     strobject += 'port-channel layer: ' + str(self.po_layer) + '\n'
        #     strobject += 'port-channel interfaces: ' + str(self.port_channel_members) + '\n'
        # if self.switchport == 'trunk':
        #     strobject += 'native vlan: ' + str(self.native_vlan) + '\n'
        #     strobject += 'allowed vlans: ' + str(self.allowed_vlans) + '\n'
        #     strobject += 'stp forwarding vlans: ' + str(self.stp_fwd_vlans) + '\n'
        #     strobject += 'errored vlans: ' + str(self.errored_vlans) + '\n'
        # if self.hsrp_groups is not None:
        #     for group in self.hsrp_groups:
        #         strobject += 'HSRP group: ' + str(group) + '\n'
        #         strobject += 'HSRP vip: ' + self.hsrp_groups[group].hsrp_group_vip + '\n'
        #         strobject += 'HSRP pri: ' + self.hsrp_groups[group].hsrp_group_pri + '\n'
        #         strobject += 'HSRP preempt: ' + self.hsrp_groups[group].hsrp_group_preempt + '\n'
        #         strobject += 'HSRP group state: ' + self.hsrp_groups[group].hsrp_group_state + '\n'
        #         strobject += 'HSRP group active: ' + self.hsrp_groups[group].hsrp_group_active + '\n'
        #         strobject += 'HSRP group standby: ' + self.hsrp_groups[group].hsrp_group_standby + '\n'
        #         strobject += 'HSRP group name: ' + self.hsrp_groups[group].hsrp_group_name + '\n'
        for attr, item in self.__dict__.items():
            if attr in self.unset_attributes and item is not None:
                strobject += attr + ': ' + str(item) + '\n'
        return strobject

    def update(self, name=None, state='connected', switchport='routed', vlan=None, type=None,
                 native=None, allowedvlans=None, erroredvlans=None, stpfwd_vlans=None,
                 portchannel=None, pogroup=None, polayer=None, postatus=None, poprotocol=None, ports=None,
                 ipprefix=None, ipsubnet=None, masklen=None, ipdisabled=None, hsrp=None, neighbor=None, **kwargs):

        self.logger.debug("Interface: Updating Interface object {}".format(self.interface))
        self.logger.debug("Interface: kwargs {}".format(kwargs))

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
        if hsrp is not None:
            self.hsrp_groups = hsrp
        if neighbor is not None:
            self.neighbor = neighbor
        if kwargs is not None:
            for value in kwargs:
                self.logger.debug("Interface: adding {} attribue".format(value))
                exec('self.{} = kwargs["{}"]'.format(value, value))
                self.unset_attributes.add(value)

    def compare_statistics(self, **kwargs):
        """



        @type kwargs: object
        """

        curr_values = self.unset_attributes.intersection(set(kwargs.keys()))
        changed_value = namedtuple('changed_value', 'previous, current')
        Ps = namedtuple('Ps', curr_values)
        self.logger.debug("Interface: moving {} attributes to previous".format(str(curr_values)))
        self.previous_statistics = Ps(**{eval("'{}'".format(value)):eval("self.{}".format(value)) for value in curr_values})
        self.logger.debug("Interface: updating values {}".format(kwargs))
        self.update(**kwargs)

        changed_values = {}

        for value in curr_values:
            if int(kwargs[value]) != int(eval('self.previous_statistics.{}'.format(value))):
                changed_values[value] = changed_value(int(eval('self.previous_statistics.{}'.format(value))), int(kwargs[value]))
                self.logger.debug("Interface: {} has changed from {} to {}".format(value, changed_values[value].previous,changed_values[value].current ))

        self.logger.debug("Interface: changed_values is {}".format(changed_values))
        return changed_values


    @classmethod
    def _parseallinterface(cls, deviceintstatusxml=None):
        """



            @param deviceintstatusxml:XML output for show int status
        """
        elementlist = {}
        trunklist = {}
        posummlist = {}
        ipintlist = {}
        hsrplist = {}
        intstatusparsed = _begin_parse(deviceintstatusxml)

        intschema = parse_get_nsmap(intstatusparsed)

        intstatuslist = cls._parseshowintstatuscommand(intstatusparsed, intschema)
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

if __name__ == "__main__":
    LOGFILE = "netconflog.log"
    SCREENLOGLEVEL = logging.DEBUG
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

    nxostest = Nexus7k(host="192.168.10.10", prompt="switch")
    nxostest.connect(username='admin', password='cisco')
    nxostest.show_hostname()
    nxostest.show_chassis_id()
    nxostest.show_system_version()
    nxostest.show_vdcs()
    nxostest.get_modules()
    nxostest.show_modules()
    nxostest.get_interfaces(vdc='all')
    nxostest.show_interfaces_list()
    print(nxostest.vdcs['switch'].interfaces)
    nxostest.show_interface(vdc='all')
    nxostest.get_interface_statistics(vdc='all')
    for value in nxostest.vdcs['switch'].interfaces.values():
        print(value.__dict__.keys())
    nxostest.show_interface(vdc='all')

import functools
import logging
import sys
import traceback
from lxml import etree
from netconf import NxosConnect
from nxosXmlFunctions import parse_get_nsmap, find_element, parse_xml_heirarchy
from vdcnetconf import VDCNxosConnect


__author__ = 'rragan'


__version__ = '2015.6.23.1'

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

class Nexus7kXML(VDCNxosConnect):
    """
    Wrapper to handle XML specific tasks
    """
    def __init__(self, host, prompt):
        super(NxosConnect, self).__init__(host, prompt)

    def get_version(self):
        verxml = self._ncc.nxoscli('show version')
        self.logger.debug(verxml)
        verparsed = _begin_parse(verxml)
        sysmgrclischema = parse_get_nsmap(verparsed)
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
            self._ncc.nxoscli(commands)
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
        return self._ncc.nxoscli(command)

    def get_vdcs(self):
        """
        On a 7k, gets the list of vdcs currently configured. Runs automatically when the object is instantiated

        @return: dictionary of vdcs

        """
        vdcxml = self._ncc.nxoscli('show vdc')
        vdcparsed = _begin_parse(vdcxml)
        vdcschema = parse_get_nsmap(vdcparsed)
        showvdc = parse_xml_heirarchy('ROW_vdc', ['vdc_id', 'vdc_name', 'state'], vdcschema,
                                          vdcparsed)
        return showvdc

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
            return showvdc


def _begin_parse(message):
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
        self.logger = logging.getLogger('nexusswitch.NxosSwitch')
        self.logger.debug("Instantiating NxosSwitch object for {}".format(self.host))

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
            self.logger.debug("Opening Connection to " + self.host)
        #Check if device is a 7k, if it is change to an object type that can handle switching between vdcs
        if self._check_for_7k():
            self.logger.debug("{} is a 7k".format(self.host))
            self.get_vdcs()
            self.get_current_vdc()
            self.logger.debug("Switching to ssh shell object")
            self._ncc.nc_sshconnect(username=username, password=password, *args, **kwargs)
            self.connected = True
            #Fill in vdc dictionary
            self.get_vdcs()
            self.get_current_vdc()
        else:
            self.vdcs = {'default': VDC('1', 'default')}
        self.get_version()

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
            print v

    def show_vdcs_detail(self):
        """

        Prints the details of the vdcs currently configured on the device

        """
        for v in self.vdcs:
            print self.vdcs[v]

    def get_current_vdc(self):
        """
        Is run to update the current_vdc attribute

        """
        if self._check_for_7k():
            showvdc = self._ncc.get_current_vdc()
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

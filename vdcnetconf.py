import logging
import socket
import traceback
import sys

from lxml import etree

from netconf import NxosConnect, MSG_DELIM, _stripdelim
from nxos_XML_errors import XMLError, NetConfRPCError, TimeoutExpiredError, ServerClosedChannelError, NotConnectedError
import nxos_XML_errors
from xmlFunctions import buildclienthello, rpcparse

__version__ = '2014.3.18.1'

logger = logging.getLogger('vdcnetconf')


class VDCError(ValueError):
    """A Value Error related to being in an expected vdc."""


class VDCNxosConnect(NxosConnect):
    """
    A subclass of NxosConnect that adds the ability to switch between VDCs

    This is only possible by ssh'ing to the cli, running the switchto vdc command and then dropping into the xml subsystem
    """
    def __init__(self, host, prompt):
        """

         A subclass of NxosConnect that adds the ability to switch between VDCs

        This is only possible by ssh'ing to the cli, running the switchto vdc command and then dropping into the xml subsystem

        @param host: str
        @param prompt: str, need a prompt so we can detect when a cli command has finished running

        """
        NxosConnect.__init__(self, host)
        self.sent_xml = ''
        self.in_xml = False
        self.prompt = r'{}.*#'.format(prompt)
        self.logger = logging.getLogger('vdcnetconf.VDCNXOSConnect')
        self.logger.debug("Instantiating Nexus7k XML VDC extension object for {}".format(self.host))

    #SSH object requires that the subclass define the object
    def setup_channel(self):
        """
        Activating an interactive shell for 7k
        """
        self.ssh_shell()
        self.look_for_prompt()
        self.goto_xml_subsystem()

    def goto_xml_subsystem(self):
        """
        Run the xmlagent command from the shell

        """
        self.logger.debug("Switching to xml subsystem")
        response = self.send('xmlagent\n')
        self.logger.debug("goto_xml_subsystem response {}".format(response))
        self.in_xml = True

    def initiate_xml_subsystem(self):
        self.goto_xml_subsystem()
        self._netconf_hello()

    def goto_ssh_prompt(self):
        """

        Drop out of the xmlagent subsystem back to the cli

        """
        self.logger.debug("Switching back to ssh shell prompt")
        self._closesession()
        self.send('\n')
        self.look_for_prompt()

    def look_for_prompt(self):
        """
        Look for prompt from interactive shell
        @return:
        """
        try:
            self.logger.debug("Waiting for ssh shell prompt {}".format(self.prompt))
            s = self.rpexpect(self.prompt)
            self.logger.debug("Received from server {}".format(s))
        except:
            self.logger.error("Unexpected string from device {}".format(self.host))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise
        self.in_xml = False

    def switchto_vdc(self, vdc='default', vdcnotdefault=False):
        """

        @param vdc: str, vdc to switch to

        """
        command = []
        if vdcnotdefault:
            command.append('switchback\n')
        command.append('switchto vdc {}\n'.format(vdc))
        self.logger.debug("vdcnetconf: Switching to vdc {} on {}".format(vdc, self.host))
        self.goto_ssh_prompt()
        for c in command:
            self.send(c)
            self.look_for_prompt()
        self.initiate_xml_subsystem()

    #Now I expect to see a hello from the server
    def _netconf_hello(self):
        """
        Looking for hello from server
        Replies with client hello

        @type self: NxosConnect

        Once a connection is opened to the nx-os xmlagent subsystem, thye server should immediately return a
        hello message. This method waits for the hello and parses it for errors.

        If we did not receive a hello, raise XMLError
        If a hello was received, parse and log the capabilities
        If no capabilities in the message, raise XMLError
        Check the message for a session id, if not present raise XMLError

        Construct the client hello, by calling the xmlFunctions.buildclienthello function
        Send client hello to server
        nx-os does not reply to the client hello unless there is an error. This is annoying but compliant
        with the RFC. To account for this, the command_timeout used by ncssh.rpexpect is reset to 5 seconds

        In this case, no response from the server is good so timeouts are not raised to higher level
        handlers

        If there is a response, it is almost certainly an error. Parse to check
        If error, raise NetConfRPCError


        """
        self.logger.debug("NC Hello: Getting Server Hello from " + self.host)
        namespace = "{urn:ietf:params:xml:ns:netconf:base:1.0}"

        try:
            server_hello = self.rpexpect(MSG_DELIM)
            self.logger.info(server_hello)
            server_hello = _stripdelim(server_hello)
            #added to compensate for interactive shell
            server_hello = server_hello[server_hello.find('<'):]
            server_hello = server_hello.lstrip()
        except (socket.timeout, TimeoutExpiredError):
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Timed Out Waiting for Hello from " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise

        self.logger.debug(server_hello)
        self.logger.debug("NC Hello: Parsing the XML")
        try:
            root = etree.fromstring(server_hello)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Failure parsing what should be the Hello from " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise

        if 'hello' not in root.tag:
            self.logger.critical("NC Hello: Did not get hello from " + self.host)
            raise XMLError("Did not receive hello from " + self.host)
        capele = [i.text for i in root.iter() if 'capability' in i.tag]
        if len(capele):
            self.server_capabilities = capele
            self.logger.debug("NC Hello: Server Capabilities: {}".format(str(self.server_capabilities)))
        else:
            self.logger.critical("NC Hello: No capabilities in hello message from " + self.host)
            raise XMLError("Did not receive capabilities in the hello message from " + self.host)
        sessele = root.findall(".//" + namespace + "session-id")
        if len(sessele):
            self.sessionid = sessele[0].text
            self.logger.debug("NC Hello: Session ID {} from {}".format(str(self.sessionid), self.host))
        else:
            self.logger.critical("NC Hello: No session-id in the hello message from " + self.host)
            raise XMLError("Did not receive session-id in the hello message from " + self.host)

        self.logger.debug("NC Hello: Construct client hello for " + self.host)

        try:
            client_hello = buildclienthello()
            self.logger.debug("NC Hello: Constructed client hello message " + client_hello)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Unable to construct client hello to send to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

        self.logger.debug("NC Hello: Sending client hello to " + self.host)

        response = None
        savetimeout = self.command_timeout

        #nx-os does not reply to the client hello unless there is an error. This is annoying but compliant
        #with the RFC. To account for this, the command_timeout used by ncssh.rpexpect is reset to 5 seconds
        #this five seconds should probably be a global variable or it should be an instance variable made into a
        #property

        try:
            self.send(client_hello + MSG_DELIM)
            #should not see anything from server unless there is an error
            self.logger.debug("NC Hello: Current timeout is configured as " + str(self.command_timeout))
            self.logger.debug("NC Hello: Resetting Paramiko socket timeout to 5 seconds")
            self.command_timeout = 5
            response = self.rpexpect(MSG_DELIM, code=5)
            #Added to compensate for interfactive shell
            response = response.replace(client_hello + MSG_DELIM, '')
        #A successful client hello should trigger no output from server, so look for socket timeout, which
        # is desirable in this case
        except (socket.timeout, nxos_XML_errors.TimeoutExpiredError):
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.info("NC Hello: Timeout sending client hello to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("NC Hello: Unexpected error sending client hello to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        else:
            #if rpexpect returns successfully, we received a message from the server
            #it is probably an error message, so parse to check
            try:
                rpcparse(_stripdelim(response))
            except NetConfRPCError:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.error("Error received from server after sending client hello to " + self.host)
                self.logger.debug(response)
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
        finally:
            self.logger.debug("Resetting Paramiko socket timeout to " + str(savetimeout))
            self.command_timeout = savetimeout
            self.logger.debug("Current timeout is configured as " + str(self.command_timeout))

    def _send(self, nxosmessage, rpcmessageid=None):

        """
        Send constructed client rpc message to server

        This method wraps the ncssh.send method and then waits for a response from the server using the
         ncssh.rpexpect method, which may return one of the following exceptions if there was a problem
        socket.timeout
        nxos_XML_errors.TimeoutExpiredError
        nxos_XML_errors.ServerClosedChannelError

        Any exceptions returned by ncssh.rpexpect are reraised

        Once the response is received, it is parsed to check for RPC error, NetConfRPCError, if detected,
        it is logged but not reraised.

        """

        #send message to server
        self.logger.debug("NC: Sending message to server {}: {}".format(self.host, nxosmessage  + MSG_DELIM))
        self.send(nxosmessage + MSG_DELIM + '\n')

        #wait for response from server
        self.logger.debug("Waiting for response from server {} ".format(self.host))
        response = None
        try:
            response = self.rpexpect(r'rpc-reply>[\n\r]*{}'.format(MSG_DELIM))
            self.logger.debug("NC Send: message from server {}: {}".format(str(response), self.host))
        except socket.timeout:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Socket timeout waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        except TimeoutExpiredError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Loop timeout waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        except ServerClosedChannelError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Server closed channel while waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.closesession()
            #do not propagate exception, closesession will raise one
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Unexpected error while waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

        #parse response and check for errors
        self.logger.debug("NC Send: Received respone {}".format(response))
        self.logger.debug("NC Send: Parsing response from {}".format(self.host))
        try:
            #added to compensate for interactive shell
            response = response[response.find(MSG_DELIM) + len(MSG_DELIM) + 1 :]
            self.logger.debug("NC Send strip one: {}".format(response))
            response = response.lstrip()
            response = _stripdelim(response)
            self.logger.debug("NC Send strip two: {}".format(response))
            rpcparse(response, rpcmessageid=rpcmessageid)
        except NetConfRPCError as E:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Error received from server after sending client message to " + self.host)
            self.logger.error(response)
            self.logger.error(sys.exc_info())
            self.logger.error(stacktrace)
            raise
        except NotConnectedError as E:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Server {} indicates that session has timed out".format(self.host))
            self.logger.error(response)
            self.logger.error(sys.exc_info())
            self.logger.error(stacktrace)
            self.closesession()
            #do not propagate exception, closesession will raise one
        self.logger.info("Received response from " + self.host + ": " + response)
        return response



"""
     module: ciscorouter_acl_connector.py
     short_description: This Phantom app connects to Cisco IOS
     devices adds or removes a deny entry from an extended ACL
     or a static route.
     author: Adam Puleo, Charles Schwab, Inc.

     Copyright (c) 2020 Charles Schwab, Inc.
"""
#
#  system imports
#
import json
import time
import ipaddress
import socket

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from ciscorouterblocks_consts import *
import paramiko


def make_acl_entry(ip_net_str):
    """
    Format the IP address and possibly the mask so it's suitable for
    an ACL entry on the router.

    Paramters:
        ip_net_str: String: IP address to format.

    Returns:
        string: A string suitable for input into the router ACL.
    """

    ip_net = ipaddress.IPv4Network(ip_net_str)

    if ip_net == ipaddress.IPv4Network(u'0.0.0.0/0'):
        result = 'any'
    elif ip_net.prefixlen == 32:
        result = 'host {}'.format(ip_net.network_address)
    else:
        result = '{} {}'.format(ip_net.network_address, ip_net.hostmask)

    return result


def make_route(ip_net_str):
    """
    Format the IP network for the route in the static route command.

    Paramters:
        ip_net_str: String: IP address to format.

    Returns:
        string: A string suitable for the route portion of the static route
                command.
    """

    ip_net = ipaddress.IPv4Network(ip_net_str)

    return '{} {}'.format(ip_net.network_address, ip_net.netmask)


def make_next_hop(ip_net_str):
    """
    Format the IP network for the next hop address in the static route command.

    Paramters:
        ip_net_str: String: IP address to format.

    Returns:
        string: A string suitable for the next hop protion of the satic route
                command.
    """

    ip_net = ipaddress.IPv4Network(ip_net_str)

    if ip_net == ipaddress.ip_network(u'255.255.255.255/32'):
        result = 'null0'
    elif ip_net.prefixlen == 32:
        result = '{}'.format(ip_net.network_address)
    else:
        # Should throw an error here.
        result = ''

    return result


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CiscoRouterBlocksConnector(BaseConnector):
    """
    Python connector class for Cisco Router Blocks.
    """

    _BANNER = "Cisco Router Blocks"

    # These are used by the state variable in __init__.
    _INIT_STATE = 'init'
    _USER_MODE_STATE = 'user'
    _PRIV_MODE_STATE = 'priv'
    _GLOBAL_CONFIG_STATE = 'global config'
    _ACL_CONFIG_STATE = 'acl config'

    def __init__(self):
        """
        Create and initialize all instance variables.
        """

        # Call the BaseConnectors init first
        super(CiscoRouterBlocksConnector, self).__init__()

        self._debug = None
        self._username = None
        self._password = None
        self._device = None
        self._ssh = None
        self._csr_conn = None
        self._timeout = None
        self._entry_idx = None
        self._acl_name = None
        self._block = None

        # The current state variable keeps track of which state the router
        # is in so that the ACL reindex happens only once and when finalize
        # is called it knows if it has to exit config mode and save the
        # configuration.
        self._router_state = self._INIT_STATE

        # Not implemented
        self.print_progress_message = False

    def _wait_for_prompt(self):
        """
        Gather all of the router's output and look for a prompt to see if
        there was an error.

        Returns:
            Tuple
            Boolean: If the boolean is true, the router returned a known error string.
            String: The string is the router's output.
        """

        error = False
        output = ''
        while True:
            try:
                chunk = self._csr_conn.recv(1024)
            except socket.timeout as socket_exception:
                self.save_progress("Timeout waiting for prompt from: {}". format(self._device))
                self.save_progress("Error: {}".format(socket_exception))
                return (True, output)
            output += chunk.decode('utf-8')
            if not self._csr_conn.recv_ready():
                if 'Incomplete command' in output or \
                   'Invalid input detected' in output or \
                   'Unknown command or computer name' in output or \
                   'Error in authentication' in output:
                    error = True
                    # Try and slurp the rest of the output before returning.

                if output.endswith('>') or \
                   output.endswith('#'):
                    break

                elif output.endswith('Password:') or \
                     output.endswith('Destination filename [startup-config]?'):
                    break

        return (error, output)

    def _send_command(self, command):
        """
        Sends a command to the router, waits for the result, and logs
        the result.

        Paramters:
            command: String: String to send to the router.

        Returns:
            Tuple
            Boolean: True if _wait_for_prompt detected an error; false
                     otherwise.
            String: Router's output.
        """

        self._csr_conn.send(command + '\n')
        (error, output) = self._wait_for_prompt()

        if error:
            if command == self._password:
                self.debug_print(CiscoRouterBlocksConnector._BANNER,
                                 "detected an error while sending password _ resp: {}".format(output))
            else:
                self.debug_print(CiscoRouterBlocksConnector._BANNER,
                                 "detected an error with command {} _ resp: {}".format(command,
                                                                                       output))

        elif self._debug:
            if command == self._password:
                self.debug_print(CiscoRouterBlocksConnector._BANNER,
                                 "sent password _ resp: {0}".format(output))
            else:
                self.debug_print(CiscoRouterBlocksConnector._BANNER,
                                 "{} _ resp: {}".format(command, output))

        return (error, output)

    def _go_to_priv_mode(self):
        """
        This function executes the enable command on the router to put
        the user in privileged mode. The user is required to be in
        privileged mode before configuring the router.

        Parameters:
            None

         Returns:
            Tuple
            Boolean: True if the user could not enter enable mode.
            String: Router's output.
        """

        if self._router_state == self._PRIV_MODE_STATE:
            self.debug_print(CiscoRouterBlocksConnector._BANNER, "Alread in privileged mode.")
            error = False
            output = ''

        elif self._router_state == self._USER_MODE_STATE:
            (error, output) = self._send_command('enable')
            if error:
                return (error, 'Could not enter enable mode: ' + output)

            (error, output) = self._send_command(self._password)
            if error:
                return (error, 'Invalid password for enable mode: ' + output)

            self._router_state = self._PRIV_MODE_STATE

        else:
            self.debug_print(CiscoRouterBlocksConnector._BANNER,
                             "Did not try to go into privileged mode; not in user mode state.")
            error = True
            output = ''

        return (error, output)

    def _go_to_config_mode(self, action_result):
        """
        This function executes the commands to put the router into global configuration mode.

        Parameters:
            action_result: Phantom ActionResult: Used to return status.

        Returns:
            RetVal
        """

        if self._router_state == self._GLOBAL_CONFIG_STATE:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Already in config mode."))

        if self._router_state == self._USER_MODE_STATE:
            # Have to be enabled to enter configure mode.
            (error, output) = self._go_to_priv_mode()
            if error:
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                       'Could not enter privileged mode: ' + output))

        if self._router_state != self._PRIV_MODE_STATE:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Should be in priv mode, but not.'))

        # Go into config mode
        (error, output) = self._send_command('configure terminal')
        if error:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not enter config mode: ' + output))
        self._router_state = self._GLOBAL_CONFIG_STATE

        return RetVal(action_result.set_status(phantom.APP_SUCCESS, output))

    def _handle_test_connectivity(self, param):
        """
        Called when the user depresses the test connectivity
        button on the Phantom UI.
        """

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("{} TEST_CONNECTIVITY".format(CiscoRouterBlocksConnector._BANNER))

        action_result.add_data({'router': self._device})
        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            return action_result.set_status(phantom.APP_ERROR, 'Could not login to the router.')

        (error, _) = self._send_command('show version')
        if error:
            self.save_progress("Unable to connect to device: {0}".format(self._device))
            return action_result.set_status(phantom.APP_ERROR,
                                            "FAILURE! Unable to connect to device")

        if self._router_state == self._USER_MODE_STATE:
            (error, _) = self._go_to_priv_mode()
            if error:
                self.save_progress("Could not enter privileged mode.")
                return action_result.set_status(phantom.APP_ERROR,
                                                "FAILURE! Could not enter privileged mode.")

        self.save_progress("Successfully connected to device: {0}".format(self._device))
        return action_result.set_status(phantom.APP_SUCCESS, "SUCCESS Connected to device")

    def _modify_acl(self, source_net, destination_net, add, action_result):
        """
        Adds or removes deny entries from an ACL. If adding entries, adds at top of ACL by
        reindexing.

        Parameters:
            source_net: String: Source IP
            destination_net: String: Destination IP
            add: Boolean: True to create an entry, False to remove an entry.
            action_result: Phantom ActionResult: Used to return status.

        Returns:
            RetVal
        """

        src_str = make_acl_entry(source_net)
        dst_str = make_acl_entry(destination_net)
        entry = 'deny ip {} {}'.format(src_str, dst_str)
        if not add:
            entry = 'no ' + entry

        ret_val = self._go_to_config_mode(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not enter config mode.'))

        if add:
            # Make room at the top of the ACL for the new entries.
            (error, output) = self._send_command('ip access-list resequence {} 10000 10'.format(self._acl_name))
            if error:
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                       'Could not resequence ACL: ' + output))

        # Switch to ACL
        (error, output) = self._send_command('ip access-list extended {}'.format(self._acl_name))
        if error:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not configure ACL: ' + output))
        self._router_state = self._ACL_CONFIG_STATE

        # Add or remove entry
        if add:
            (error, output) = self._send_command('{} {}'.format(self._entry_idx, entry))
            if error:
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                       'Could not add an entry to the ACL: ' + output))
        else:
            (error, output) = self._send_command(entry)
            if error:
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                       'Could not remove an entry from the ACL: ' + output))

        self._entry_idx += 1

        return RetVal(action_result.set_status(phantom.APP_SUCCESS,
                                               "Successfully executed '{}' on {}.".format(entry,
                                                                                          self._device)))

    def _add_static_route(self, route, next_hop, tag, name, action_result):
        """
        This function creates a static route.
        """

        route_str = make_route(route)
        next_hop_str = make_next_hop(next_hop)
        if tag:
            static_route = 'ip route {} {} tag {} name {}'.format(route_str, next_hop_str, tag, name)
        else:
            static_route = 'ip route {} {} name {}'.format(route_str, next_hop_str, name)

        ret_val = self._go_to_config_mode(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not enter config mode.'))

        # Add new entry
        (error, output) = self._send_command(static_route)
        if error:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not create static route: ' + output))

        self._entry_idx += 1

        return RetVal(action_result.set_status(phantom.APP_SUCCESS,
                                               "Successfully executed '{}' on {}.".format(static_route,
                                                                                          self._device)))

    def _remove_static_route(self, route, action_result):
        """
        This function removes a static route.
        """

        route_str = make_route(route)

        static_route = 'no ip route {}'.format(route_str)

        ret_val = self._go_to_config_mode(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not enter config mode.'))

        # Remove static route
        (error, output) = self._send_command(static_route)
        if error:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                   'Could not remove static route: ' + output))

        self._entry_idx += 1

        return RetVal(action_result.set_status(phantom.APP_SUCCESS,
                                               "Successfully executed '{}' on {}.".format(static_route,
                                                                                          self._device)))

    def _handle_block_ip(self, param):
        """
        This function executes the block IP action.
        """

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(CiscoRouterBlocksConnector._BANNER,
                         "In action handler for: {}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result.add_data({'router': self._device})
        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            return action_result.set_status(phantom.APP_ERROR, 'Could not login to the router.')

        # Required values can be accessed directly
        block_type = param['block_type']
        source_network = param['source_network']
        destination_network = param['destination_network']

        if block_type == 'static_route':
            # Optional values should use the .get() function
            tag = param.get('tag', '')

            ret_val, _ = self._add_static_route(source_network,
                                                destination_network,
                                                tag,
                                                param['name'],
                                                action_result)

            if not phantom.is_fail(ret_val):
                summary = action_result.update_summary({})
                summary['total_objects_successful'] = self._entry_idx - 1

            return action_result.get_status()

        elif block_type == 'acl':
            self._acl_name = param['name']

            ret_val, _ = self._modify_acl(source_network,
                                          destination_network,
                                          True,
                                          action_result)

            if not phantom.is_fail(ret_val):
                summary = action_result.update_summary({})
                summary['total_objects_successful'] = self._entry_idx - 1

            return action_result.get_status()

        return action_result.set_status(phantom.APP_ERROR,
                                        "Unknown block_type value '{}'. Must either be 'static_route' or 'acl'.".format(block_type))

    def _handle_unblock_ip(self, param):
        """
        This function executes the unblock IP action.
        """

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(CiscoRouterBlocksConnector._BANNER,
                         "In action handler for: {}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result.add_data({'router': self._device})
        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            return action_result.set_status(phantom.APP_ERROR, 'Could not login to the router.')

        # Required values can be accessed directly
        block_type = param['block_type']
        source_network = param['source_network']

        if block_type == 'static_route':
            ret_val, _ = self._remove_static_route(source_network, action_result)

            if not phantom.is_fail(ret_val):
                summary = action_result.update_summary({})
                summary['total_objects_successful'] = self._entry_idx - 1

            return action_result.get_status()

        elif block_type == 'acl':
            destination_network = param['destination_network']
            self._acl_name = param['name']

            ret_val, _ = self._modify_acl(source_network,
                                          destination_network,
                                          False,
                                          action_result)

            if not phantom.is_fail(ret_val):
                summary = action_result.update_summary({})
                summary['total_objects_successful'] = self._entry_idx - 1

            return action_result.get_status()

        return action_result.set_status(phantom.APP_ERROR,
                                        "Unknown block_type value '{}'. Must either be 'static_route' or 'acl'.".format(block_type))

    def _handle_enumerate_acl(self, param):
        """
        Lists all of the entries in an ACL.
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(CiscoRouterBlocksConnector._BANNER,
                         "In action handler for: {}".format(self.get_action_identifier()))

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result.add_data({'router': self._device})
        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            return action_result.set_status(phantom.APP_ERROR, 'Could not login to the router.')

        acl_name = param['acl_name']

        # Get the ACL.
        (error, acl) = self._send_command('show access-list ' + acl_name)

        self.debug_print(CiscoRouterBlocksConnector._BANNER,
                         "_get_acl_entries RAW: {0}".format(acl))

        # Even if the query was successfull the data might not be available
        if error or not acl:
            return action_result.set_status(phantom.APP_ERROR, 'Query returned with no data')

        acl_list = acl.split('\n')
        for entry in acl_list:
            action_result.add_data({'acl_entry': entry})
        summary = "Query returned {0} entries".format(len(acl_list))
        action_result.update_summary({'message': summary})
        action_result.add_data({'total_objects_successful': len(acl_list)})

        return action_result.set_status(phantom.APP_SUCCESS, summary)

    def _handle_list_networks(self, param):
        """
        Lists all of the static routes on a router.
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.debug_print(CiscoRouterBlocksConnector._BANNER,
                         "In action handler for: {}".format(self.get_action_identifier()))

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result.add_data({'router': self._device})
        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            return action_result.set_status(phantom.APP_ERROR, 'Could not login to the router.')

        # Get the routes.
        (error, routes) = self._send_command('show ip route static')

        self.debug_print(CiscoRouterBlocksConnector._BANNER, "_raw_output RAW: {0}".format(routes))

        # Even if the query was successfull the data might not be available
        if error or not routes:
            return action_result.set_status(phantom.APP_ERROR, 'Query returned with no data')

        routes_list = routes.split('\n')
        for route in routes_list:
            action_result.add_data({'route': route})
        summary = "Query returned {0} routes".format(len(routes_list))
        action_result.update_summary({'message': summary})
        action_result.add_data({'total_objects_successful': len(routes_list)})

        return action_result.set_status(phantom.APP_SUCCESS, summary)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'block_ip':
            self._block = True
            ret_val = self._handle_block_ip(param)

        elif action_id == 'unblock_ip':
            self._block = False
            ret_val = self._handle_unblock_ip(param)

        elif action_id == 'enumerate_acl':
            ret_val = self._handle_enumerate_acl(param)

        elif action_id == 'list_networks':
            ret_val = self._handle_list_networks(param)

        return ret_val

    def initialize(self):
        """
        This function is called once per action. Connection to the router
        is established here and all configuration variables are read and
        initialized.

        Always return APP_SUCCESS. If APP_ERROR is returned Phantom seems
        to have a bad day. In handle_action return the error.
        """

        self.save_progress("{0} INITIALIZE {1}".format(CiscoRouterBlocksConnector._BANNER,
                                                       time.asctime()))
        self.debug_print(CiscoRouterBlocksConnector._BANNER,
                         "INITIALIZE {}".format(time.asctime()))

        config = self.get_config()

        try:
            self._debug = config["debug"]
            self._username = config["username"]
            self._password = config["password"]
            self._device = config["router"]
            self._timeout = config["timeout"]
        except KeyError:
            self.save_progress("KeyError attempting to parse app parameters")
            self.save_progress("Error: {0}".format(KeyError))
            return phantom.APP_SUCCESS

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.save_progress("Starting SSH session to {}.".format(self._device))

        try:
            self._ssh.connect(self._device, username=self._username,
                              password=self._password, allow_agent=False,
                              look_for_keys=False, timeout=self._timeout)
        except (socket.error, socket.gaierror) as socket_exception:
            self.save_progress("Socket error trying to connect to: {}". format(self._device))
            self.save_progress("Error: {}".format(socket_exception))
            return phantom.APP_SUCCESS
        except socket.timeout as socket_exception:
            self.save_progress("Socket timeout waiting for: {}". format(self._device))
            self.save_progress("Error: {}".format(socket_exception))
            return phantom.APP_SUCCESS
        except paramiko.AuthenticationException as auth_exception:
            self.save_progress("Invalid username or password for: {}". format(self._device))
            self.save_progress("Error: {}".format(auth_exception))
            return phantom.APP_SUCCESS
        except Exception as unknown_exception:
            self.save_progress("Unknown error while connecting to: {}". format(self._device))
            self.save_progress("Error: {}".format(unknown_exception))
            return phantom.APP_SUCCESS

        self._csr_conn = self._ssh.invoke_shell()
        self._csr_conn.settimeout(self._timeout)

        # Absorb banner.
        self._wait_for_prompt()

        # Set the terminal length so that we do not have to worry about
        # pagination.
        (error, output) = self._send_command('terminal length 0')
        if error:
            self.save_progress("Could not disable pagination: {}". format(output))
            result = phantom.APP_SUCCESS
        else:
            result = phantom.APP_SUCCESS

            if output.endswith('#'):
                self._router_state = self._PRIV_MODE_STATE
            else:
                self._router_state = self._USER_MODE_STATE

            self._entry_idx = 1  # Router ACL indexes start at 1.

        return result

    def finalize(self):
        """
        This function gets called once all the param dictionary
        elements are looped over and no more handle_action calls are
        left to be made.

        If the router was in a configuration state, it saves the
        configuration. Then logs off of the router and closes the SSH
        connection.
        """

        self.save_progress("{0} FINALIZE".format(CiscoRouterBlocksConnector._BANNER))
        self.debug_print(CiscoRouterBlocksConnector._BANNER, "FINALIZE")

        if self._router_state == self._ACL_CONFIG_STATE:
            if self._block:
                # Make room at the top of the ACL for other people's (DDoS') entries.
                self._send_command('ip access-list resequence {} 10000 10'.format(self._acl_name))
                # The resequence command puts the router back in global config state.
            else:
                self._send_command('exit')
                # Exit back to global config state.
            self._router_state = self._GLOBAL_CONFIG_STATE

        if self._router_state == self._GLOBAL_CONFIG_STATE:
            # Exit config and save.
            self._send_command('\x1a')
            self._router_state = self._PRIV_MODE_STATE
            self._send_command('copy running-config startup-config')
            self._send_command('')  # Send an empty line to accept the default destination filename.

        if self._router_state == self._USER_MODE_STATE \
           or self._router_state == self._PRIV_MODE_STATE:
            self._csr_conn.send('logout\n')

        if self._csr_conn:
            self._csr_conn.close()

        if self._ssh:
            self._ssh.close()

        return phantom.APP_SUCCESS

    def handle_exception(self, exception_object):
        """
        All the code within BaseConnector::_handle_action is within
        a 'try: except:' clause.  Thus if an exception occurs during
        the execution of this code it is caught at a single place. The
        resulting exception object is passed to the
        AppConnector::handle_exception() to do any cleanup of it's own
        if required. This exception is then added to the connector run
        result and passed back to spawn, which gets displayed in the
        Phantom UI.

        Perhaps this function should try and gracefully logout of the
        router.
        """

        self.save_progress("{} HANDLE_EXCEPTION {}".format(CiscoRouterBlocksConnector._BANNER,
                                                           exception_object))
        self.debug_prog(CiscoRouterBlocksConnector._BANNER,
                        "HANDLE_EXCEPTION {}".format(exception_object))

        # Just close the connection down since we do not know where we were
        # at in the configuration.
        if self._csr_conn:
            self._csr_conn.close()

        if self._ssh:
            self._ssh.close()

        return


def main():
    import pudb
    import argparse
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CiscoRouterBlocksConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            phantom_request = requests.get(login_url, verify=False)
            csrftoken = phantom_request.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            phantom_request = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = phantom_request.cookies['sessionid']
        except Exception as some_exception:
            print("Unable to get session id from the platform. Error: " + str(some_exception))
            exit(1)

    with open(args.input_test_json) as input_json_file:
        in_json = input_json_file.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CiscoRouterBlocksConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()

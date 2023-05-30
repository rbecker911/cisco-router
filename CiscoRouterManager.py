import paramiko
import socket

class CiscoRouterManager:
    # These are used by the state variable in __init__.
    _INIT_STATE = 'init'
    _USER_MODE_STATE = 'user'
    _PRIV_MODE_STATE = 'priv'
    _GLOBAL_CONFIG_STATE = 'global config'
    _ACL_CONFIG_STATE = 'acl config'

    def __init__(self, config):
        """
        This method is called once when the instance of the class is created.
        Connection to the router is established here and all configuration 
        variables are read and initialized.

        :param config: configuration parameters
        """
        
        try:
            self._debug = config["debug"]
            self._username = config["username"]
            self._password = config["password"]
            self._device = config["router"]
            self._timeout = config["timeout"]
        except KeyError as e:
            raise Exception(f"KeyError attempting to parse app parameters: {str(e)}")

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._ssh.connect(self._device, username=self._username,
                              password=self._password, allow_agent=False,
                              look_for_keys=False, timeout=self._timeout)
        except (socket.error, socket.gaierror) as socket_exception:
            raise Exception(f"Socket error trying to connect to: {self._device}. Error: {str(socket_exception)}")
        except socket.timeout as socket_exception:
            raise Exception(f"Socket timeout waiting for: {self._device}. Error: {str(socket_exception)}")
        except paramiko.AuthenticationException as auth_exception:
            raise Exception(f"Invalid username or password for: {self._device}. Error: {str(auth_exception)}")
        except Exception as unknown_exception:
            raise Exception(f"Unknown error while connecting to: {self._device}. Error: {str(unknown_exception)}")

        self._csr_conn = self._ssh.invoke_shell()
        self._csr_conn.settimeout(self._timeout)

        # Absorb banner.
        self._wait_for_prompt()

        # Set the terminal length so that we do not have to worry about
        # pagination.
        (error, output) = self._send_command('terminal length 0')
        if error:
            raise Exception(f"Could not disable pagination: {output}")

        if output.endswith('#'):
            self._router_state = self._PRIV_MODE_STATE
        else:
            self._router_state = self._USER_MODE_STATE

        self._entry_idx = 1  # Router ACL indexes start at 1.

    def make_acl_entry(self, ip_net_str):
        ip_net = ipaddress.IPv4Network(ip_net_str)
        if ip_net == ipaddress.IPv4Network(u'0.0.0.0/0'):
            result = 'any'
        elif ip_net.prefixlen == 32:
            result = 'host {}'.format(ip_net.network_address)
        else:
            result = '{} {}'.format(ip_net.network_address, ip_net.hostmask)
        return result

    def make_route(self, ip_net_str):
        ip_net = ipaddress.IPv4Network(ip_net_str)
        return '{} {}'.format(ip_net.network_address, ip_net.netmask)

    def make_next_hop(self, ip_net_str):
        ip_net = ipaddress.IPv4Network(ip_net_str)
        if ip_net == ipaddress.ip_network(u'255.255.255.255/32'):
            result = 'null0'
        elif ip_net.prefixlen == 32:
            result = '{}'.format(ip_net.network_address)
        else:
            result = ''
        return result


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
                raise Exception(f"Timeout waiting for prompt from: {self._device}. Error: {str(socket_exception)}")

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

    def ping(self):
        """
        Called to test connectivity to the device.
        """

        print("{} TEST_CONNECTIVITY".format(self._BANNER))

        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            raise Exception('Could not login to the router.')

        (error, _) = self._send_command('show version')
        if error:
            print("Unable to connect to device: {0}".format(self._device))
            raise Exception("FAILURE! Unable to connect to device")

        if self._router_state == self._USER_MODE_STATE:
            (error, _) = self._go_to_priv_mode()
            if error:
                print("Could not enter privileged mode.")
                raise Exception("FAILURE! Could not enter privileged mode.")

        print("Successfully connected to device: {0}".format(self._device))
        return "SUCCESS Connected to device"
        
    def _send_command(self, command):
        """
        Sends a command to the router, waits for the result, and logs
        the result.

        Parameters:
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
                raise Exception(f"Detected an error while sending password. Response: {output}")
            else:
                raise Exception(f"Detected an error with command {command}. Response: {output}")

        elif self._debug:
            if command == self._password:
                print(f"Sent password. Response: {output}")
            else:
                print(f"{command} _ resp: {output}")

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
            print("Already in privileged mode.")
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
            print("Did not try to go into privileged mode; not in user mode state.")
            error = True
            output = ''
            
        return (error, output)

    def _go_to_config_mode(self):
        """ 
        This function executes the commands to put the router into global configuration mode.
        
        Parameters:                                    
            None

        Returns:
            Tuple
            Boolean: True if there was an error.
            String: Router's output.
        """ 
                                                   
        if self._router_state == self._GLOBAL_CONFIG_STATE:
            return (False, "Already in config mode.")
        
        if self._router_state == self._USER_MODE_STATE:
            # Have to be enabled to enter configure mode.
            (error, output) = self._go_to_priv_mode()
            if error:
                return (error, 'Could not enter privileged mode: ' + output)
        
        if self._router_state != self._PRIV_MODE_STATE:
            return (True, 'Should be in priv mode, but not.')
                                    
        # Go into config mode
        (error, output) = self._send_command('configure terminal')
        if error:
            return (error, 'Could not enter config mode: ' + output)
        
        self._router_state = self._GLOBAL_CONFIG_STATE
    
        return (False, output)
        
    def modify_acl(self, source_net, destination_net, add):
        """
        Adds or removes deny entries from an ACL. If adding entries, adds at top of ACL by
        reindexing.

        Parameters:
            source_net: String: Source IP
            destination_net: String: Destination IP
            add: Boolean: True to create an entry, False to remove an entry.

        Returns:
            String: Status message
        """

        src_str = self.make_acl_entry(source_net)
        dst_str = self.make_acl_entry(destination_net)
        entry = 'deny ip {} {}'.format(src_str, dst_str)
        if not add:
            entry = 'no ' + entry

        try:
            self.go_to_config_mode()
        except Exception as e:
            raise Exception('Could not enter config mode: {}'.format(str(e)))

        if add:
            # Make room at the top of the ACL for the new entries.
            (error, output) = self._send_command('ip access-list resequence {} 10000 10'.format(self._acl_name))
            if error:
                raise Exception('Could not resequence ACL: {}'.format(output))

        # Switch to ACL
        (error, output) = self._send_command('ip access-list extended {}'.format(self._acl_name))
        if error:
            raise Exception('Could not configure ACL: {}'.format(output))
        self._router_state = self._ACL_CONFIG_STATE

        # Add or remove entry
        if add:
            (error, output) = self._send_command('{} {}'.format(self._entry_idx, entry))
            if error:
                raise Exception('Could not add an entry to the ACL: {}'.format(output))
        else:
            (error, output) = self._send_command(entry)
            if error:
                raise Exception('Could not remove an entry from the ACL: {}'.format(output))

        self._entry_idx += 1

        return "Successfully executed '{}' on {}.".format(entry, self._device)


    def add_static_route(self, route, next_hop, tag, name):
        """
        This function creates a static route.
        """

        route_str = self.make_route(route)
        next_hop_str = self.make_next_hop(next_hop)
        if tag:
            static_route = 'ip route {} {} tag {} name {}'.format(route_str, next_hop_str, tag, name)
        else:
            static_route = 'ip route {} {} name {}'.format(route_str, next_hop_str, name)

        try:
            self.go_to_config_mode()
        except Exception as e:
            raise Exception('Could not enter config mode: {}'.format(str(e)))

        # Add new entry
        (error, output) = self._send_command(static_route)
        if error:
            raise Exception('Could not create static route: {}'.format(output))

        self._entry_idx += 1

        return "Successfully executed '{}' on {}.".format(static_route, self._device)

    def remove_static_route(self, route):
        """
        This function removes a static route.
        """

        route_str = self.make_route(route)

        static_route = 'no ip route {}'.format(route_str)

        try:
            self.go_to_config_mode()
        except Exception as e:
            raise Exception('Could not enter config mode: {}'.format(str(e)))

        # Remove static route
        (error, output) = self._send_command(static_route)
        if error:
            raise Exception('Could not remove static route: {}'.format(output))

        self._entry_idx += 1

        return "Successfully executed '{}' on {}.".format(static_route, self._device)
    
    def block_ip(self, param):
        """
        This function executes the block IP action.
        """

        if self._router_state == self._INIT_STATE:
            # initialize failed, return an error here.
            raise Exception('Could not login to the router.')

        # Required values can be accessed directly
        block_type = param['block_type']
        source_network = param['source_network']
        destination_network = param['destination_network']

        if block_type == 'static_route':
            # Optional values should use the .get() function
            tag = param.get('tag', '')

            try:
                self.add_static_route(source_network, destination_network, tag, param['name'])
                return {'total_objects_successful': self._entry_idx - 1}
            except Exception as e:
                raise Exception('Error while adding static route: {}'.format(str(e)))

        elif block_type == 'acl':
            self._acl_name = param['name']

            try:
                self.modify_acl(source_network, destination_network, True)
                return {'total_objects_successful': self._entry_idx - 1}
            except Exception as e:
                raise Exception('Error while modifying ACL: {}'.format(str(e)))

        raise Exception("Unknown block_type value '{}'. Must either be 'static_route' or 'acl'.".format(block_type))

    def unblock_ip(self, param):
        """
        This function executes the unblock IP action.
        """

        if self._router_state == self._INIT_STATE:
            # initialize failed, raise an error here.
            raise Exception('Could not login to the router.')

        # Required values can be accessed directly
        block_type = param['block_type']
        source_network = param['source_network']

        if block_type == 'static_route':
            try:
                self.remove_static_route(source_network)
                return {'total_objects_successful': self._entry_idx - 1}
            except Exception as e:
                raise Exception('Error while removing static route: {}'.format(str(e)))

        elif block_type == 'acl':
            destination_network = param['destination_network']
            self._acl_name = param['name']

            try:
                self.modify_acl(source_network, destination_network, False)
                return {'total_objects_successful': self._entry_idx - 1}
            except Exception as e:
                raise Exception('Error while modifying ACL: {}'.format(str(e)))

        raise Exception("Unknown block_type value '{}'. Must either be 'static_route' or 'acl'.".format(block_type))


    def enumerate_acl(self, acl_name):
        """
        Lists all of the entries in an ACL.
        """
        if self._router_state == self._INIT_STATE:
            # initialize failed, raise an error here.
            raise Exception('Could not login to the router.')

        # Get the ACL.
        error, acl = self._send_command('show access-list ' + acl_name)

        # Even if the query was successful the data might not be available
        if error or not acl:
            raise Exception('Query returned with no data')

        acl_list = acl.split('\n')
        summary = "Query returned {0} entries".format(len(acl_list))
        result = [{'acl_entry': entry} for entry in acl_list]
        result.append({'total_objects_successful': len(acl_list)})

        return result, summary

    def list_networks(self):
        """
        Lists all of the static routes on a router.
        """
        if self._router_state == self._INIT_STATE:
            # initialize failed, raise an error here.
            raise Exception('Could not login to the router.')

        # Get the routes.
        error, routes = self._send_command('show ip route static')

        # Even if the query was successful the data might not be available
        if error or not routes:
            raise Exception('Query returned with no data')

        routes_list = routes.split('\n')
        summary = "Query returned {0} routes".format(len(routes_list))
        result = [{'route': route} for route in routes_list]
        result.append({'total_objects_successful': len(routes_list)})

        return result, summary



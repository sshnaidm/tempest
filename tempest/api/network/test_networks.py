# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import itertools
import netaddr
import random

from tempest.api.network import base
from tempest.common import custom_matchers
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class NetworksTestJSON(base.BaseNetworkTest):
    _interface = 'json'
    _subnet_special = {}

    """
    Tests the following operations in the Neutron API using the REST
    client for Neutron:

        create a network for a tenant
        list tenant's networks
        show a tenant network details
        create a subnet for a tenant
        list tenant's subnets
        show a tenant subnet details
        network update
        subnet update
        delete a network also deletes its subnets
        list external networks

        All subnet tests are run once with ipv4, once with ipv6,
        once with each of IPv6 attributes.

    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        tenant_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant ipv4 subnets

        tenant_network_mask_bits with the mask bits to be used to partition
        the block defined by tenant_network_cidr

        each tenant_network_cidr and tenant_network_mask_bits are defined
        according to class IP version
    """

    @classmethod
    def resource_setup(cls):
        super(NetworksTestJSON, cls).resource_setup()
        cls.network = cls.create_network()
        cls.name = cls.network['name']
        cls.subnet = cls.create_subnet(cls.network)
        cls.cidr = cls.subnet['cidr']
        cls._subnet_data = {'gateway':
                            str(cls._get_gateway_from_tempest_conf()),
                            'allocation_pools':
                            cls._get_allocation_pools_from_gateway(),
                            'dns_nameservers': ['8.8.4.4', '8.8.8.8'],
                            'host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': '10.100.1.1'}],
                            'new_host_routes': [{'destination':
                                                 '10.20.0.0/32',
                                                 'nexthop':
                                                 '10.100.1.2'}],
                            'new_dns_nameservers': ['7.8.8.8', '7.8.4.4']}

    @classmethod
    def _get_gateway_from_tempest_conf(cls):
        """Return first subnet gateway for configured CIDR """
        cidr = netaddr.IPNetwork(cls.tenant_network_cidr)
        if cls.tenant_network_mask_bits >= cidr.prefixlen:
            return netaddr.IPAddress(cidr) + 1
        else:
            for subnet in cidr.subnet(cls.tenant_network_mask_bits):
                return netaddr.IPAddress(subnet) + 1

    @classmethod
    def _get_allocation_pools_from_gateway(cls):
        """Return allocation range for subnet of given gateway"""
        gateway = cls._get_gateway_from_tempest_conf()
        return [{'start': str(gateway + 2), 'end': str(gateway + 3)}]

    def subnet_dict(self, include_keys):
        """Return a subnet dict which has include_keys and their corresponding
           value from self._subnet_data
        """
        return dict((key, self._subnet_data[key])
                    for key in include_keys)

    def _compare_resource_attrs(self, actual, expected):
        exclude_keys = set(actual).symmetric_difference(expected)
        self.assertThat(actual, custom_matchers.MatchesDictExceptForKeys(
                        expected, exclude_keys))

    def random_cidr(self):
        net = netaddr.IPNetwork(self.tenant_network_cidr)
        nets = net.subnet(self.tenant_network_mask_bits)
        for i in xrange(random.randint(100, 1000)):
            next(nets)
        return str(next(nets))

    def _create_verify_delete_subnet(self, cidr=None, mask_bits=None,
                                     specify_gateway=True, **kwargs):
        network = self.create_network()
        net_id = network['id']
        gateway = kwargs.pop('gateway', None)
        kwargs.update(self._subnet_special)
        if specify_gateway:
            subnet = self.create_subnet(network, gateway, cidr, mask_bits,
                                        **kwargs)
        else:
            _, body = self.client.create_subnet(network_id=net_id,
                                                cidr=self.random_cidr(),
                                                ip_version=self._ip_version,
                                                **kwargs)
            subnet = body['subnet']
            self.subnets.append(subnet)
        compare_args_full = dict(gateway_ip=gateway, cidr=cidr,
                                 mask_bits=mask_bits, **kwargs)
        compare_args = dict((k, v) for k, v in compare_args_full.iteritems()
                            if v is not None)

        if 'dns_nameservers' in set(subnet).intersection(compare_args):
            self.assertEqual(sorted(compare_args['dns_nameservers']),
                             sorted(subnet['dns_nameservers']))
            del subnet['dns_nameservers'], compare_args['dns_nameservers']

        self._compare_resource_attrs(subnet, compare_args)
        self.client.delete_network(net_id)
        self.networks.pop()
        self.subnets.pop()

    @test.attr(type='smoke')
    def test_create_update_delete_network_subnet(self):
        """Test update of network and subnet
        """
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        net_id = network['id']
        self.assertEqual('ACTIVE', network['status'])
        # Verify network update
        new_name = "New_network"
        _, body = self.client.update_network(net_id, name=new_name)
        updated_net = body['network']
        self.assertEqual(updated_net['name'], new_name)
        # Find a cidr that is not in use yet and create a subnet with it
        subnet = self.create_subnet(network)
        subnet_id = subnet['id']
        # Verify subnet update
        new_name = "New_subnet"
        _, body = self.client.update_subnet(subnet_id, name=new_name)
        updated_subnet = body['subnet']
        self.assertEqual(updated_subnet['name'], new_name)

    @test.attr(type='smoke')
    def test_show_network(self):
        """Verify the details of a network """
        _, body = self.client.show_network(self.network['id'])
        network = body['network']
        for key in ['id', 'name']:
            self.assertEqual(network[key], self.network[key])

    @test.attr(type='smoke')
    def test_show_network_fields(self):
        """Verify specific fields in a network query """
        fields = ['id', 'name']
        _, body = self.client.show_network(self.network['id'],
                                           fields=fields)
        network = body['network']
        self.assertEqual(sorted(network.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(network[field_name], self.network[field_name])

    @test.attr(type='smoke')
    def test_list_networks(self):
        """Verify the network exists in the list of all networks """
        _, body = self.client.list_networks()
        networks = [network['id'] for network in body['networks']
                    if network['id'] == self.network['id']]
        self.assertNotEmpty(networks, "Created network not found in the list")

    @test.attr(type='smoke')
    def test_list_networks_fields(self):
        """Verify specific fields in a networks list query """
        fields = ['id', 'name']
        _, body = self.client.list_networks(fields=fields)
        networks = body['networks']
        self.assertNotEmpty(networks, "Network list returned is empty")
        for network in networks:
            self.assertEqual(sorted(network.keys()), sorted(fields))

    @test.attr(type='smoke')
    def test_show_subnet(self):
        """Verify the details of a subnet """
        _, body = self.client.show_subnet(self.subnet['id'])
        subnet = body['subnet']
        self.assertNotEmpty(subnet, "Subnet has no fields")
        for key in ['id', 'cidr']:
            self.assertIn(key, subnet)
            self.assertEqual(subnet[key], self.subnet[key])

    @test.attr(type='smoke')
    def test_show_subnet_fields(self):
        """Verify specific fields of a subnet query """
        fields = ['id', 'network_id']
        _, body = self.client.show_subnet(self.subnet['id'],
                                          fields=fields)
        subnet = body['subnet']
        self.assertEqual(sorted(subnet.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(subnet[field_name], self.subnet[field_name])

    @test.attr(type='smoke')
    def test_list_subnets(self):
        """Verify specific fields in a subnets list query """
        _, body = self.client.list_subnets()
        subnets = [subnet['id'] for subnet in body['subnets']
                   if subnet['id'] == self.subnet['id']]
        self.assertNotEmpty(subnets, "Created subnet not found in the list")

    @test.attr(type='smoke')
    def test_list_subnets_fields(self):
        """Verify specific fields in a subnets list query """
        fields = ['id', 'network_id']
        _, body = self.client.list_subnets(fields=fields)
        subnets = body['subnets']
        self.assertNotEmpty(subnets, "Subnet list returned is empty")
        for subnet in subnets:
            self.assertEqual(sorted(subnet.keys()), sorted(fields))

    def _try_delete_network(self, net_id):
        # delete network, if it exists
        try:
            self.client.delete_network(net_id)
        # if network is not found, this means it was deleted in the test
        except exceptions.NotFound:
            pass

    @test.attr(type='smoke')
    def test_delete_network_with_subnet(self):
        # Create a network
        name = data_utils.rand_name('network-')
        _, body = self.client.create_network(name=name)
        network = body['network']
        net_id = network['id']
        self.addCleanup(self._try_delete_network, net_id)
        # Create a subnet
        subnet = self.create_subnet(network)
        subnet_id = subnet['id']

        # Delete network while the subnet still exists
        _, body = self.client.delete_network(net_id)

        # Verify that the subnet got automatically deleted.
        self.assertRaises(exceptions.NotFound, self.client.show_subnet,
                          subnet_id)

        # Since create_subnet adds the subnet to the delete list, and it is
        # is actually deleted here - this will create and issue, hence remove
        # it from the list.
        self.subnets.pop()

    @test.attr(type='smoke')
    def test_create_delete_subnet_without_gateway(self):
        """Test network and subnet without gateway """
        self._create_verify_delete_subnet()

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_gw(self):
        """Test network and subnet with specific gateway """
        self._create_verify_delete_subnet(
            **self.subnet_dict(['gateway']))

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_default_gw(self):
        """Test network and subnet with specific gateway """
        self._create_verify_delete_subnet(
            specify_gateway=False)

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_allocation_pools(self):
        """Test network and subnet with allocation pools """
        self._create_verify_delete_subnet(
            **self.subnet_dict(['allocation_pools']))

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_gw_and_allocation_pools(self):
        """Test network and subnet with specific gateway
        and allocation pools
        """
        self._create_verify_delete_subnet(**self.subnet_dict(
            ['gateway', 'allocation_pools']))

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_host_routes_and_dns_nameservers(self):
        """Test network and subnet without gateway, with host routes
        and dns nameservers
        """
        self._create_verify_delete_subnet(
            **self.subnet_dict(['host_routes', 'dns_nameservers']))

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_dhcp_disabled(self):
        """Test network and subnet with disabled DHCP """
        self._create_verify_delete_subnet(enable_dhcp=False)

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_dhcp_enabled(self):
        """Test network and subnet with enabled DHCP """
        self._create_verify_delete_subnet(enable_dhcp=True)

    @test.attr(type='smoke')
    def test_update_subnet_gw_dns_host_routes_dhcp(self):
        network = self.create_network()

        subnet = self.create_subnet(
            network, **self.subnet_dict(['gateway', 'host_routes',
                                        'dns_nameservers',
                                         'allocation_pools']))
        subnet_id = subnet['id']
        new_gateway = str(netaddr.IPAddress(
                          self._subnet_data['gateway']) + 1)
        # Verify subnet update
        new_host_routes = self._subnet_data['new_host_routes']

        new_dns_nameservers = self._subnet_data['new_dns_nameservers']
        kwargs = {'host_routes': new_host_routes,
                  'dns_nameservers': new_dns_nameservers,
                  'gateway_ip': new_gateway, 'enable_dhcp': True}

        new_name = "New_subnet"
        _, body = self.client.update_subnet(subnet_id, name=new_name,
                                            **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name
        self.assertEqual(sorted(updated_subnet['dns_nameservers']),
                         sorted(kwargs['dns_nameservers']))
        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)

    @test.attr(type='smoke')
    def test_create_delete_subnet_all_attributes(self):
        self._create_verify_delete_subnet(
            enable_dhcp=True,
            **self.subnet_dict(['gateway', 'host_routes', 'dns_nameservers']))

    @test.attr(type='smoke')
    def test_external_network_visibility(self):
        """Verifies user can see external networks but not subnets."""
        _, body = self.client.list_networks(**{'router:external': True})
        networks = [network['id'] for network in body['networks']]
        self.assertNotEmpty(networks, "No external networks found")

        nonexternal = [net for net in body['networks'] if
                       not net['router:external']]
        self.assertEmpty(nonexternal, "Found non-external networks"
                                      " in filtered list (%s)." % nonexternal)
        self.assertIn(CONF.network.public_network_id, networks)

        subnets_iter = (network['subnets'] for network in body['networks'])
        # subnets_iter is a list (iterator) of lists. This flattens it to a
        # list of UUIDs
        public_subnets_iter = itertools.chain(*subnets_iter)
        _, body = self.client.list_subnets()
        subnets = [sub['id'] for sub in body['subnets']
                   if sub['id'] in public_subnets_iter]
        self.assertEmpty(subnets, "Public subnets visible")


class BulkNetworkOpsTestJSON(base.BaseNetworkTest):
    _interface = 'json'

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        bulk network creation
        bulk subnet creation
        bulk port creation
        list tenant's networks

    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        tenant_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant networks

        tenant_network_mask_bits with the mask bits to be used to partition the
        block defined by tenant-network_cidr
    """

    def _delete_networks(self, created_networks):
        for n in created_networks:
            self.client.delete_network(n['id'])
        # Asserting that the networks are not found in the list after deletion
        resp, body = self.client.list_networks()
        networks_list = [network['id'] for network in body['networks']]
        for n in created_networks:
            self.assertNotIn(n['id'], networks_list)

    def _delete_subnets(self, created_subnets):
        for n in created_subnets:
            self.client.delete_subnet(n['id'])
        # Asserting that the subnets are not found in the list after deletion
        resp, body = self.client.list_subnets()
        subnets_list = [subnet['id'] for subnet in body['subnets']]
        for n in created_subnets:
            self.assertNotIn(n['id'], subnets_list)

    def _delete_ports(self, created_ports):
        for n in created_ports:
            self.client.delete_port(n['id'])
        # Asserting that the ports are not found in the list after deletion
        resp, body = self.client.list_ports()
        ports_list = [port['id'] for port in body['ports']]
        for n in created_ports:
            self.assertNotIn(n['id'], ports_list)

    @test.attr(type='smoke')
    def test_bulk_create_delete_network(self):
        """Bulk create networks """
        # Creates 2 networks in one request
        network_names = [data_utils.rand_name('network-'),
                         data_utils.rand_name('network-')]
        _, body = self.client.create_bulk_network(network_names)
        created_networks = body['networks']
        self.addCleanup(self._delete_networks, created_networks)
        # Asserting that the networks are found in the list after creation
        resp, body = self.client.list_networks()
        networks_list = [network['id'] for network in body['networks']]
        for n in created_networks:
            self.assertIsNotNone(n['id'])
            self.assertIn(n['id'], networks_list)

    @test.attr(type='smoke')
    def test_bulk_create_delete_subnet(self):
        """Bulk create subnets """
        networks = [self.create_network(), self.create_network()]
        # Creates 2 subnets in one request
        cidr = netaddr.IPNetwork(self.tenant_network_cidr)
        mask_bits = self.tenant_network_mask_bits
        cidrs = [subnet_cidr for subnet_cidr in cidr.subnet(mask_bits)]
        names = [data_utils.rand_name('subnet-') for _ in range(len(networks))]
        subnets_list = []
        # TODO(sergsh): for dual-stack, version list [4, 6] will be used.
        ip_version = [self._ip_version] * len(names)
        for i in range(len(names)):
            p1 = {
                'network_id': networks[i]['id'],
                'cidr': str(cidrs[(i)]),
                'name': names[i],
                'ip_version': ip_version[i]
            }
            subnets_list.append(p1)
        del subnets_list[1]['name']
        _, body = self.client.create_bulk_subnet(subnets_list)
        created_subnets = body['subnets']
        self.addCleanup(self._delete_subnets, created_subnets)
        # Asserting that the subnets are found in the list after creation
        resp, body = self.client.list_subnets()
        subnets_list = [subnet['id'] for subnet in body['subnets']]
        for n in created_subnets:
            self.assertIsNotNone(n['id'])
            self.assertIn(n['id'], subnets_list)

    @test.attr(type='smoke')
    def test_bulk_create_delete_port(self):
        """Bulk create ports """
        networks = [self.create_network(), self.create_network()]
        # Creates 2 ports in one request
        names = [data_utils.rand_name('port-') for _ in range(len(networks))]
        port_list = []
        state = [True, False]
        for i in range(len(names)):
            p1 = {
                'network_id': networks[i]['id'],
                'name': names[i],
                'admin_state_up': state[i],
            }
            port_list.append(p1)
        del port_list[1]['name']
        _, body = self.client.create_bulk_port(port_list)
        created_ports = body['ports']
        self.addCleanup(self._delete_ports, created_ports)
        # Asserting that the ports are found in the list after creation
        resp, body = self.client.list_ports()
        ports_list = [port['id'] for port in body['ports']]
        for n in created_ports:
            self.assertIsNotNone(n['id'])
            self.assertIn(n['id'], ports_list)


class BulkNetworkOpsIpV6TestJSON(BulkNetworkOpsTestJSON):
    _ip_version = 6


class NetworksIpV6TestJSON(NetworksTestJSON):
    _ip_version = 6

    @classmethod
    def resource_setup(cls):
        super(NetworksIpV6TestJSON, cls).resource_setup()
        cls._subnet_data = {'gateway':
                            str(cls._get_gateway_from_tempest_conf()),
                            'allocation_pools':
                            cls._get_allocation_pools_from_gateway(),
                            'dns_nameservers': ['2001:c01d:c0ca::c01a',
                                                '2001:ac01:5a::baba'],
                            'host_routes': [{'destination': '2001::/64',
                                             'nexthop': '2003::1'}],
                            'new_host_routes': [{'destination':
                                                 '2001::/64',
                                                 'nexthop': '2005::1'}],
                            'new_dns_nameservers':
                                ['2001:1:fee1:beaf::f00d',
                                 '2001:c001:babe::b00b']}

    @test.attr(type='smoke')
    def test_create_list_subnet_with_no_gw64_one_network(self):
        """Test creating subnets with IPv4 and IPv6 together
        in the same network
        """
        name = data_utils.rand_name('network-')
        network = self.create_network(name)
        ipv6_gateway = self.subnet_dict(['gateway'])['gateway']
        subnet1 = self.create_subnet(network,
                                     ip_version=6,
                                     gateway=ipv6_gateway)
        self.assertEqual(netaddr.IPNetwork(subnet1['cidr']).version, 6,
                         'The created subnet is not IPv6')
        subnet2 = self.create_subnet(network,
                                     gateway=None,
                                     ip_version=4)
        self.assertEqual(netaddr.IPNetwork(subnet2['cidr']).version, 4,
                         'The created subnet is not IPv4')
        # Verifies Subnet GW is set in IPv6
        self.assertEqual(subnet1['gateway_ip'], ipv6_gateway)
        # Verifies Subnet GW is None in IPv4
        self.assertEqual(subnet2['gateway_ip'], None)
        # Verifies all 2 subnets in the same network
        _, body = self.client.list_subnets()
        subnets = [sub['id'] for sub in body['subnets']
                   if sub['network_id'] == network['id']]
        test_subnet_ids = [sub['id'] for sub in (subnet1, subnet2)]
        self.assertItemsEqual(subnets,
                              test_subnet_ids,
                              'Subnet are not in the same network')


class NetworksIpV6TestAttrsStateless(NetworksIpV6TestJSON):
    _subnet_special = {'ipv6_ra_mode': 'dhcpv6-stateless',
                       'ipv6_address_mode': 'dhcpv6-stateless'}

    @classmethod
    def resource_setup(cls):
        if not CONF.network_feature_enabled.ipv6_subnet_attributes:
            raise cls.skipException("IPv6 extended attributes for "
                                    "subnets not available")
        super(NetworksIpV6TestAttrsStateless, cls).resource_setup()

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_dhcp_disabled(self):
        """Test network and subnet with disabled DHCP and IPv6 attributes """
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            "ipv6_ra_mode or ipv6_address_mode cannot be set when "
            "enable_dhcp is set to False",
            self._create_verify_delete_subnet,
            enable_dhcp=False)


class NetworksIpV6TestAttrsSLAAC(NetworksIpV6TestAttrsStateless):
    _subnet_special = {'ipv6_ra_mode': 'slaac',
                       'ipv6_address_mode': 'slaac'}


class NetworksIpV6TestAttrsStateful(NetworksIpV6TestAttrsStateless):
    _subnet_special = {'ipv6_ra_mode': 'dhcpv6-stateful',
                       'ipv6_address_mode': 'dhcpv6-stateful'}

#
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Ross Davies <davies.ross@gmail.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
    name: prism_inventory
    plugin_type: inventory
    author:
        - Ross Davies <davies.ross@gmail.com>

    short_description: Inventory plugin to dynamically generate an inventory from provided Prism Element/Central endpoints.

    version_added: "0.0.1"

    description:
        - Fetch hosts and VMs for one or more clusters
        - Groups by prism central (if applicable), category (if applicable), project (if applicable), cluster.
        - Also creates groups of all CVMs, Hypervisor and IPMIs present
        - Uses YAML configuration file to set parameter values.

    options:
        plugin:
             description: token that ensures this is a source file for the 'nutanix' plugin.
             required: True
             choices: ['nutanix']
        connections:
            description:
                - Mandatory list of cluster connection settings.
            required: true
            suboptions:
                ip_address:
                    description: IP address of the Nutanix endpoint
                    required: true
                port:
                    description: TCP port to connect with the Nutanix endpoint
                    default: 9440
                username:
                    description: Username to log into the Nutanix endpoint
                    required: true
                    default: 'admin'
                password:
                    description: Password to log into the Nutanix endpoint
                    required: true
                    default: 'nutanix/4u'
                validate_certs:
                    description: Whether or not to verify the Nutanix API's SSL certificates.
                    type: str('yes', 'no')
                    required: false
                    default: 'no'
                include_vms:
                    description: Include VMs in hierarchy
                    type: str('yes', 'no')
                    required: false
                    default: 'yes'

    requirements:
    - "python >= 2.7"
    - "ntnx-api >= 1.1.30"
'''

EXAMPLES = r'''
    # File must be named nutanix.yaml or nutanix.yml

    # Authenticate to Nutanix clusters and return inventory for one cluster
    plugin: community.nutanix.prism_inventory
    connections:
      - ip_address: '192.168.1.100'
        password: 'xxxxxxxxxxxxxxxx'

    # Authenticate to Nutanix clusters and return inventory for one cluster and include virtual machines
    plugin: community.nutanix.prism_inventory
    connections:
      - ip_address: '192.168.1.100'
        password: 'xxxxxxxxxxxxxxxx'
        include_vms: 'yes'

    # Authenticate to Nutanix clusters and return inventory for one cluster with certificate validation
    plugin: community.nutanix.prism_inventory
    connections:
      - ip_address: '192.168.1.100'
        password: 'xxxxxxxxxxxxxxxx'
        validate_certs: 'yes'

    # Authenticate to Nutanix clusters and return inventory for multiple clusters
    plugin: community.nutanix.prism_inventory
    connections:
        - ip_address: '192.168.1.100'
          password: 'xxxxxxxxxxxxxxxx'
        - ip_address: '192.168.2.100'
          password: 'xxxxxxxxxxxxxxxx'
        - ip_address: '192.168.3.100'
          password: 'xxxxxxxxxxxxxxxx'

    # Authenticate to Nutanix clusters and return inventory for multiple clusters including a prism central
    plugin: community.nutanix.prism_inventory
    connections:
      - name: 'test-pc1'
        ip_address: 192.168.1.10
        password: xxxxxxxxxxxxxxxx
      - name: 'test-cluster14'
        ip_address: 192.168.3.100
        password: xxxxxxxxxxxxxxxx
'''

import re
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode
from ansible.errors import AnsibleError, AnsibleParserError
import logging
import logging.config
import os

try:
    from ntnx_api.client import PrismApi
    from ntnx_api import prism
    HAS_NTNX_API = True
except ImportError:
    HAS_NTNX_API = False

# Setup logging
logger = logging.getLogger('community.nutanix.prism_inventory')
logging_level = os.environ.get('NTNX_API_LOG_LEVEL', 'WARNING').upper()
logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,  # this fixes the problem
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'community.nutanix.prism_inventory': {
            'level': logging_level,
            'class': 'logging.StreamHandler',
            "formatter": "standard",
            "stream": "ext://sys.stdout"
        },
    },
    'loggers': {
        '': {
            'handlers': ['community.nutanix.prism_inventory'],
            'level': 'INFO',
            'propagate': True
        }
    }
})


# Function to replace unwanted characters in a given string
def _fixstring(txtString):
    """
    Replace unwanted characters in string
    """
    logger = logging.getLogger('community.nutanix.prism_inventory._fixstring')
    full_pattern = re.compile('[^a-zA-Z0-9]|_')
    logger.info('original string "{0}"'.format(txtString))
    new_string = re.sub(full_pattern, '_', txtString).lower()
    logger.info('new string "{0}"'.format(new_string))
    return new_string


class NutanixPrismInventoryException(Exception):
    pass


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = 'community.nutanix.prism_inventory'

    def verify_file(self, path):
        """
        Verify plugin configuration file and mark this plugin active
        Args:
            path: Path of configuration YAML file
        Returns: True if everything is correct, else False
        """
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.verify_file')
        valid = False
        logger.info(path)
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('nutanix.yaml', 'nutanix.yml', 'ntnx.yaml', 'ntnx.yml')):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.parse')
        super(InventoryModule, self).parse(inventory, loader, path)
        cache_key = self.get_cache_key(path)
        config_data = self._read_config_data(path)
        self.setup(config_data, cache, cache_key)

    def setup(self, config_data, cache, cache_key):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.setup')
        connections = config_data.get('connections')

        if not HAS_NTNX_API:
            raise AnsibleParserError(
                "This module requires the Nutanix API SDK. Try `pip install ntnx_api`."
            )

        source_data = None
        if cache and cache_key in self._cache:
            try:
                source_data = self._cache[cache_key]
            except KeyError:
                pass

        if not source_data:
            self.fetch_objects(connections)

    def fetch_objects(self, connections):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.fetch_objects')
        if connections:
            if not isinstance(connections, list):
                raise NutanixPrismInventoryException("Expecting connections to be a list.")

            # create root groups
            self.inventory.add_group('prism')
            # top_level_groups = ['clusters', 'cvms', 'hypervisors', 'ipmi', 'vms', ]
            top_level_groups = ['clusters', 'projects', 'categories', 'protection_rules', ]
            for top_level_group in top_level_groups:
                self.inventory.add_group(top_level_group)
                self.inventory.add_child('prism', top_level_group)

            for connection in connections:
                if not isinstance(connection, dict):
                    raise NutanixPrismInventoryException("Expecting connection to be a dictionary.")

                if not connection.get('password'):
                    raise NutanixPrismInventoryException('Mandatory parameter password needs to be set.')
                else:
                    password = connection.get('password')
                    if isinstance(password, AnsibleVaultEncryptedUnicode):
                        password = password.data

                if not connection.get('ip_address'):
                    raise NutanixPrismInventoryException('Mandatory parameter ip_address needs to be set.')
                else:
                    ip_address = connection.get('ip_address')

                if not connection.get('port'):
                    port = '9440'
                else:
                    port = connection.get('port')

                if not connection.get('username'):
                    username = 'admin'
                else:
                    username = connection.get('username')

                if not connection.get('validate_certs'):
                    validate_certs = False
                else:
                    if connection.get('validate_certs').lower() == 'yes':
                        validate_certs = True
                    else:
                        validate_certs = False

                if not connection.get('include_vms'):
                    include_vms = True
                else:
                    if connection.get('include_vms').lower() == 'yes':
                        include_vms = True
                    else:
                        include_vms = False

                nutanix_api = PrismApi(ip_address=ip_address, username=username, password=password, port=port, validate_certs=validate_certs)
                if not nutanix_api.test():
                    NutanixPrismInventoryException('Unable to connect to the Nutanix API for connection {}.'.format(ip_address))

                self.get_prism(nutanix_api=nutanix_api)
                if nutanix_api.connection_type == 'pc':
                    self.get_pc_projects(nutanix_api=nutanix_api)
                    self.get_pc_categories(nutanix_api=nutanix_api)
                    self.get_pc_protection_rules(nutanix_api=nutanix_api)
                self.get_clusters(nutanix_api=nutanix_api)
                self.get_hosts(nutanix_api=nutanix_api)
                if include_vms:
                    self.get_vms(nutanix_api=nutanix_api)

        else:
            raise NutanixPrismInventoryException("Expecting at least one defined connection.")

    def get_prism(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_prism')
        logger.info('starting function')
        self.inventory.add_group('prism')

        # Top level groups
        top_level_groups = ['all_cvms', 'all_hypervisors', 'all_ipmis', 'all_vms', 'all_pe_vips', 'all_pc_vips', ]
        for top_level_group in top_level_groups:
            self.inventory.add_group(top_level_group)
            self.inventory.add_child('prism', top_level_group)

        if nutanix_api.connection_type == 'pc':
            self.inventory.add_host(host='pc_{0}'.format(nutanix_api.ip_address), group='all_pc_vips')
            self.inventory.set_variable('pc_{0}'.format(nutanix_api.ip_address), 'ansible_host', nutanix_api.ip_address)

        # Retrieve service status from PC
        # if nutanix_api.connection_type == 'pe':
        #     service_status = {}
        #
        # else:
        #     service_status = {}
        #     services = ['xfit', 'microseg', 'disaster_recovery', 'oss', 'nucalm']
        #     for service in services:
        #         service_state = nutanix_api.get_service_status(service)
        #         service_status.setdefault(service, service_state['service_enablement_status'])
        # self.inventory.set_variable('prism_vip', 'service_status', service_status)

        logger.info('ending function')

    def get_pc_projects(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_pc_projects')
        logger.info('starting function')
        self.inventory.add_group('default')
        self.inventory.add_child('projects', 'default')

        projects = prism.Config(api_client=nutanix_api).get_projects()
        logger.debug('projects {0}'.format(projects))
        if projects:
            for project in projects:
                project_name = _fixstring(project['spec']['name'])
                logger.info('processing project "{0}"'.format(project_name))
                self.inventory.add_group(project_name)
                self.inventory.add_child('projects', project_name)
        logger.info('ending function')

    def get_pc_categories(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_pc_categories')
        logger.info('starting function')
        categories = prism.Config(api_client=nutanix_api).get_categories()
        logger.debug('categories {0}'.format(categories))

        if categories:
            for category in categories:
                category_name = _fixstring(category.get('name'))
                self.inventory.add_group(category_name)
                self.inventory.add_child('categories', category_name)

                category_keys = prism.Config(api_client=nutanix_api).get_category_keys(category=category.get('name'))
                logger.info('got category keys "{0}"'.format(category_keys))
                for category_key in category_keys:
                    category_key = _fixstring('{0}_{1}'.format(category.get('name'), category_key.get('value')))
                    logger.info('processing category key "{0}" for category "{1}"'.format(category_key, category_name))
                    self.inventory.add_group(category_key)
                    self.inventory.add_child(category_name, category_key)
        logger.info('ending function')

    def get_pc_protection_rules(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_pc_categories')
        logger.info('starting function')
        protection_rules = prism.Config(api_client=nutanix_api).get_protection_rules()

        if protection_rules:
            for protection_rule in protection_rules:
                protection_rule_name = _fixstring('protectionrule_' + protection_rule.get('spec').get('name'))
                self.inventory.add_group(protection_rule_name)
                self.inventory.add_child('protection_rules', protection_rule_name)
        logger.info('ending function')
        pass

    def get_clusters(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_clusters')
        logger.info('starting function')
        clusters = []
        self.inventory.add_group('clusters')
        self.inventory.add_child('prism', 'clusters')

        cluster_obj = prism.Cluster(api_client=nutanix_api)
        clusters = cluster_obj.get_all_uuids()
        logger.info("cluster list '{0}'".format(clusters))
        for each_uuid in clusters:
            logger.info("processing cluster '{0}'".format(each_uuid))
            cluster = cluster_obj.get(clusteruuid=each_uuid)
            logger.debug("found cluster data '{0}'".format(cluster))
            cluster_name = _fixstring(cluster.get('name'))
            logger.info("found cluster_name '{0}'".format(cluster_name))
            cluster_external_ipaddress = cluster.get('cluster_external_ipaddress')
            logger.info("found cluster_external_ipaddress '{0}'".format(cluster_external_ipaddress))
            cluster_ncc_version = cluster.get('ncc_version')
            logger.info("found cluster_ncc_version '{0}'".format(cluster_ncc_version))
            cluster_version = cluster.get('version')
            logger.info("found cluster_version '{0}'".format(cluster_version))
            services = {}

            if cluster_name:
                # clusters.append(cluster_name)
                self.inventory.add_group(cluster_name)
                self.inventory.add_child('clusters', cluster_name)

                self.inventory.set_variable(cluster_name, 'cluster_external_ipaddress', cluster_external_ipaddress)
                self.inventory.set_variable(cluster_name, 'ncc_version', cluster_ncc_version)
                self.inventory.set_variable(cluster_name, 'version', cluster_version)

                cluster_groups = ['cvm', 'ipmi', 'hypervisor', 'blocks', 'vms', 'vip']
                for cluster_group in cluster_groups:
                    group_name = '{0}_{1}'.format(cluster_name, cluster_group)
                    self.inventory.add_group(group_name)
                    self.inventory.add_child(cluster_name, group_name)

                cluster_vip_name = '{0}'.format(cluster_name)
                self.inventory.add_host(cluster_vip_name, group='all_pe_vips')
                self.inventory.add_host(cluster_vip_name, group='{0}_vip'.format(cluster_name))
                logger.info("adding cluster to inventory '{0}'".format(cluster_name))
                self.inventory.set_variable(cluster_vip_name, 'ansible_host', cluster_external_ipaddress)
                logger.info("set cluster '{0}' variable ansible_host to '{1}'".format(cluster_name, cluster_external_ipaddress))
                self.inventory.set_variable(cluster_vip_name, 'cluster_name', cluster_name)
                logger.info("set cluster '{0}' variable cluster_name to '{1}'".format(cluster_name, cluster_name))

            logger.info('ending loop "for each_uuid in clusters"')

        logger.info('ending function')

    def get_hosts(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_hosts')
        logger.info('starting function')
        cluster_obj = prism.Cluster(api_client=nutanix_api)
        host_obj = prism.Hosts(api_client=nutanix_api)
        clusters = cluster_obj.get_all_uuids()
        logger.info("cluster list '{0}'".format(clusters))
        for cluster_uuid in clusters:
            blocks = []
            cluster = cluster_obj.get(clusteruuid=cluster_uuid)
            cluster_name = _fixstring(cluster.get('name'))
            hosts = host_obj.get(clusteruuid=cluster_uuid)
            logger.info("host list '{0}'".format(hosts))
            for each_host in hosts:
                logger.debug("processing host '{0}'".format(each_host))
                block_serial = _fixstring(each_host.get('block_serial'))
                logger.info("host block_serial '{0}'".format(block_serial))
                block_model = each_host.get('block_model_name')
                logger.info("host block_model '{0}'".format(block_model))
                node_name = _fixstring(each_host.get('name'))
                logger.info("host node_name '{0}'".format(node_name))
                node_cvm_ip = each_host.get('service_vmexternal_ip')
                logger.info("host node_cvm_ip '{0}'".format(node_cvm_ip))
                node_hypervisor_ip = each_host.get('hypervisor_address')
                logger.info("host node_hypervisor_ip '{0}'".format(node_hypervisor_ip))
                node_hypervisor_type = each_host.get('hypervisor_type')
                logger.info("host node_hypervisor_type '{0}'".format(node_hypervisor_type))
                node_ipmi_ip = each_host.get('ipmi_address')
                logger.info("host node_ipmi_ip '{0}'".format(node_ipmi_ip))
                node_uuid = each_host.get('uuid')
                logger.info("host node_uuid '{0}'".format(node_uuid))
                node_v3_spec = None

                if block_model != 'null':
                    # Nutanix does not provide a way to uniquely identify a host by its name
                    # i.e. there can be two host with same name in different clusters
                    # Appending "_" and UUID to make it unique
                    node_hypervisor_name = '{0}_{1}'.format(node_name, node_uuid)
                    logger.info("host node_hypervisor_name '{0}'".format(node_hypervisor_name))
                    node_cvm_name = '{0}_cvm_{1}'.format(node_name, node_uuid)
                    logger.info("host node_cvm_name '{0}'".format(node_cvm_name))
                    node_ipmi_name = '{0}_ipmi_{1}'.format(node_name, node_uuid)
                    logger.info("host node_ipmi_name '{0}'".format(node_ipmi_name))

                    block_group = 'block_{0}'.format(block_serial)
                    if block_serial not in blocks:
                        blocks.append(block_serial)
                        self.inventory.add_group(block_group)
                        self.inventory.add_child('{0}_blocks'.format(cluster_name), block_group)
                        self.inventory.set_variable(block_group, 'block_model', block_model)

                    group_list = []
                    group_list.append('all_hypervisors'.format(cluster_name))
                    group_list.append('{0}_hypervisor'.format(cluster_name))
                    group_list.append(block_group)

                    logger.info("getting host '{0}' projects".format(node_name))
                    project = host_obj.get_project(uuid=node_uuid)
                    logger.info("host project list '{0}'".format(project))
                    if project:
                        group_list.append(_fixstring(project))

                    logger.info("getting host '{0}' categories".format(node_name))
                    categories = host_obj.get_categories(uuid=node_uuid)
                    logger.info("host category list '{0}'".format(categories))
                    if categories:
                        for key, value in categories.items():
                            category = _fixstring('{0}_{1}'.format(key, value))
                            group_list.append(category)

                    # Add hypervisor host
                    for group in group_list:
                        logger.info('adding host "{0} to group {1}'.format(node_hypervisor_name, group))
                        self.inventory.add_host(host=node_hypervisor_name, group=group)

                    self.inventory.set_variable(node_hypervisor_name, 'ansible_host', node_hypervisor_ip)
                    self.inventory.set_variable(node_hypervisor_name, 'node_v3_spec', node_v3_spec)
                    self.inventory.set_variable(node_hypervisor_name, 'hypervisor_type', node_hypervisor_type)

                    # Add cvm host
                    # cvm_name = '{0}_cvm'.format(name)
                    self.inventory.add_host(host=node_cvm_name, group='all_cvms')
                    self.inventory.add_host(host=node_cvm_name, group=block_group)
                    self.inventory.add_host(host=node_cvm_name, group='{0}_cvm'.format(cluster_name))
                    self.inventory.set_variable(node_cvm_name, 'ansible_host', node_cvm_ip)

                    # Add ipmi host
                    self.inventory.add_host(host=node_ipmi_name, group='all_ipmis')
                    self.inventory.add_host(host=node_ipmi_name, group=block_group)
                    self.inventory.add_host(host=node_ipmi_name, group='{0}_ipmi'.format(cluster_name))
                    self.inventory.set_variable(node_ipmi_name, 'ansible_host', node_ipmi_ip)
        logger.info('ending function')

    def get_vms(self, nutanix_api):
        logger = logging.getLogger('community.nutanix.prism_inventory.InventoryModule.get_vms')
        logger.info('starting function')
        cluster_obj = prism.Cluster(api_client=nutanix_api)
        vms_obj = prism.Vms(api_client=nutanix_api)
        clusters = cluster_obj.get_all_uuids()
        logger.info("cluster list '{0}'".format(clusters))
        for cluster_uuid in clusters:
            vms = vms_obj.get(clusteruuid=cluster_uuid)
            logger.info("vm list '{0}'".format(vms))
            for vm in vms:
                cluster = cluster_obj.get(clusteruuid=cluster_uuid)
                cluster_name = _fixstring(cluster.get('name'))
                vm_name = _fixstring(vm.get('name'))
                vm_num_cores_per_vcpu = vm.get('num_cores_per_vcpu')
                vm_num_vcpus = vm.get('num_vcpus')
                vm_power_state = vm.get('power_state')
                vm_uuid = vm.get('uuid')
                vm_nics = vm.get('vm_nics')
                vm_disks = vm.get('vm_disk_info')
                vm_ip_address = None

                # Get the first ip address for this vm
                for vm_nic in vm.get('vm_nics'):
                    if vm_nic.get('is_connected') and 'ip_address' in vm_nic:
                        if vm_nic.get('ip_address'):
                            vm_ip_address = vm_nic.get('ip_address')
                            break

                # Nutanix does not provide a way to uniquely identify a vm by its name
                # i.e. there can be two virtual machines with same name
                # Appending "_" and UUID to make it unique
                name = '{0}_{1}'.format(vm_name, vm_uuid)

                group_list = []
                group_list.append('all_vms')
                group_list.append('{0}_vms'.format(cluster_name))

                project = vms_obj.get_project(uuid=vm_uuid)
                if project:
                    group_list.append(_fixstring(project))

                categories = vms_obj.get_categories(uuid=vm_uuid)
                if categories:
                    for key, value in categories.items():
                        category = _fixstring('{0}_{1}'.format(key, value))
                        group_list.append(category)

                protection_rules = vms_obj.get_protection_rules(uuid=vm_uuid)
                if protection_rules:
                    for key, value in protection_rules.items():
                        protection_rule = _fixstring('{0}_{1}'.format(key, value))
                        group_list.append(protection_rule)

                for group in group_list:
                    logger.info('adding vm "{0} to group {1}'.format(name, group))
                    self.inventory.add_host(host=name, group=group)

                self.inventory.set_variable(name, 'num_cores_per_vcpu', vm_num_cores_per_vcpu)
                self.inventory.set_variable(name, 'num_vcpus', vm_num_vcpus)
                self.inventory.set_variable(name, 'power_state', vm_power_state)
                self.inventory.set_variable(name, 'uuid', vm_uuid)
                self.inventory.set_variable(name, 'nics', vm_nics)
                self.inventory.set_variable(name, 'disks', vm_disks)

                if vm_ip_address:
                    self.inventory.set_variable(name, 'ansible_host', vm_ip_address)
        logger.info('ending function')

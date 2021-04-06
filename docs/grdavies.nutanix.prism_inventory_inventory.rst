.. _grdavies.nutanix.prism_inventory_inventory:


********************************
grdavies.nutanix.prism_inventory
********************************

**Inventory plugin to dynamically generate an inventory from provided Prism Element/Central endpoints.**


Version added: 0.0.1

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Fetch hosts and VMs for one or more clusters
- Groups by prism central (if applicable), category (if applicable), project (if applicable), cluster.
- Also creates groups of all CVMs, Hypervisor and IPMIs present
- Uses YAML configuration file to set parameter values.



Requirements
------------
The below requirements are needed on the local Ansible controller node that executes this inventory.

- python >= 2.7
- ntnx-api >= 1.1.30


Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="2">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
                <th>Configuration</th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>connections</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">-</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                </td>
                    <td>
                    </td>
                <td>
                        <div>Mandatory list of cluster connection settings.</div>
                </td>
            </tr>
                                <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>include_vms</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">str('yes', 'no')</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"yes"</div>
                </td>
                    <td>
                    </td>
                <td>
                        <div>Include VMs in hierarchy</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>ip_address</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">-</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                </td>
                    <td>
                    </td>
                <td>
                        <div>IP address of the Nutanix endpoint</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>password</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">-</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"nutanix/4u"</div>
                </td>
                    <td>
                    </td>
                <td>
                        <div>Password to log into the Nutanix endpoint</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>port</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">-</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">9440</div>
                </td>
                    <td>
                    </td>
                <td>
                        <div>TCP port to connect with the Nutanix endpoint</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>username</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">-</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"admin"</div>
                </td>
                    <td>
                    </td>
                <td>
                        <div>Username to log into the Nutanix endpoint</div>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder"></td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>validate_certs</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">str('yes', 'no')</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"no"</div>
                </td>
                    <td>
                    </td>
                <td>
                        <div>Whether or not to verify the Nutanix API&#x27;s SSL certificates.</div>
                </td>
            </tr>

            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>plugin</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">-</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>nutanix</li>
                        </ul>
                </td>
                    <td>
                    </td>
                <td>
                        <div>token that ensures this is a source file for the &#x27;nutanix&#x27; plugin.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

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




Status
------


Authors
~~~~~~~

- Ross Davies <davies.ross@gmail.com>


.. hint::
    Configuration entries for each entry type have a low to high priority order. For example, a variable that is lower in the list will override a variable that is higher up.

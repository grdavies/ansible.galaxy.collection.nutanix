# Ansible Collection - grdavies.nutanix

This repo hosts the `grdavies.nutanix` Ansible collection.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.9.10,<2.11**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the Nutanix community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install grdavies.nutanix

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: grdavies.nutanix
```

### Required Python libraries

Nutanix community collection depends upon following third party libraries:

* [`ntnx-api`](https://gitlab.com/nutanix-se/python/nutanix-api-library) >= 1.1.30

### Installing required SDK

Installing the collection does not install any required third party Python libraries or SDKs. You need to install the required Python libraries using following command:

    pip install -r ~/.ansible/collections/ansible_collections/grdavies/nutanix/requirements.txt


## Included content

<!--start collection content-->
### Inventory plugins
Name | Description
--- | ---
[grdavies.nutanix.prism_inventory](https://gitlab.com/nutanix-se/ansible/community.nutanix/blob/main/docs/grdavies.nutanix.prism_inventory_inventory.rst)|Inventory plugin to dynamically generate an inventory from provided Prism Element/Central endpoints.

<!--end collection content-->

## Testing and Development

If you want to develop new content for this collection or improve what is already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

- [Guidelines for Nutanix module development](https://[add_docs_url])

### Testing with `ansible-test`

Refer [testing](testing.md) for more information.

## Publishing New Version

Prepare the release:
- Refresh the README.md: `tox -e add_docs`
- Refresh the changelog: `tox -e antsibull-changelog -- release`
- Clean up the changelog fragments.
- Commit everything and push a PR for review

Push the release:
- Tag the release: `git tag -s 1.0.0`
- Push the tag: `git push origin 1.0.`

## Communication

TBD

## License

GNU General Public License v3.0 or later

See [LICENSE](LICENSE) to see the full text.

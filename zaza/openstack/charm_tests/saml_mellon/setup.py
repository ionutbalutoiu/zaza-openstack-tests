# Copyright 2019 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Code for setting up keystone federation."""

import json
import tempfile

import keystoneauth1

import zaza.model
from zaza.openstack.utilities import (
    cert as cert_utils,
    cli as cli_utils,
    openstack as openstack_utils,
)

MEMBER = "Member"
PROTOCOL_NAME = "mapped"
IDP_REMOTE_ID = "http://{}/simplesaml/saml2/idp/metadata.php"
MAP_TEMPLATE = '''
    [{{
            "local": [
                {{
                    "user": {{
                        "name": "{{0}}"
                    }},
                    "group": {{
                        "name": "{group_id}",
                        "domain": {{
                            "id": "{domain_id}"
                        }}
                    }},
                    "projects": [
                    {{
                        "name": "{{0}}_project",
                        "roles": [
                                     {{
                                         "name": "{role_name}"
                                     }}
                                 ]
                    }}
                    ]
               }}
            ],
            "remote": [
                {{
                    "type": "MELLON_NAME_ID"
                }}
            ]
    }}]
'''

SP_SIGNING_KEY_INFO_XML_TEMPLATE = '''
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data>
        <ds:X509Certificate>
            {}
        </ds:X509Certificate>
    </ds:X509Data>
</ds:KeyInfo>
'''


def _keystone_federation_setup(federated_domain=None, federated_group=None,
                               idp_name=None, idp_remote_id=None):
    """Configure Keystone Federation."""
    cli_utils.setup_logging()
    keystone_session = openstack_utils.get_overcloud_keystone_session()
    keystone_client = openstack_utils.get_keystone_session_client(
        keystone_session)

    try:
        domain = keystone_client.domains.find(name=federated_domain)
    except keystoneauth1.exceptions.http.NotFound:
        domain = keystone_client.domains.create(
            federated_domain,
            description="Federated Domain",
            enabled=True)

    try:
        group = keystone_client.groups.find(
            name=federated_group, domain=domain)
    except keystoneauth1.exceptions.http.NotFound:
        group = keystone_client.groups.create(
            federated_group,
            domain=domain,
            enabled=True)

    role = keystone_client.roles.find(name=MEMBER)
    keystone_client.roles.grant(role, group=group, domain=domain)

    try:
        idp = keystone_client.federation.identity_providers.get(idp_name)
    except keystoneauth1.exceptions.http.NotFound:
        idp = keystone_client.federation.identity_providers.create(
            idp_name,
            remote_ids=[idp_remote_id],
            domain_id=domain.id,
            enabled=True)

    JSON_RULES = json.loads(MAP_TEMPLATE.format(
        domain_id=domain.id, group_id=group.id, role_name=MEMBER))

    map_name = "{}_mapping".format(idp_name)
    try:
        keystone_client.federation.mappings.get(map_name)
    except keystoneauth1.exceptions.http.NotFound:
        keystone_client.federation.mappings.create(
            map_name, rules=JSON_RULES)

    try:
        keystone_client.federation.protocols.get(idp_name, PROTOCOL_NAME)
    except keystoneauth1.exceptions.http.NotFound:
        keystone_client.federation.protocols.create(
            PROTOCOL_NAME, mapping=map_name, identity_provider=idp)


def _attach_saml_resources(keystone_saml_mellon_app_name=None,
                           test_saml_idp_app_name=None):
    """Attach resources to the Keystone SAML Mellon and the local IdP."""
    idp_metadata_name = "idp-metadata"
    sp_metadata_name = "sp-metadata"
    sp_private_key_name = "sp-private-key"
    sp_signing_keyinfo_name = "sp-signing-keyinfo"

    test_saml_idp_unit = zaza.model.get_units(
        test_saml_idp_app_name).pop()
    action_result = zaza.model.run_action(
        test_saml_idp_unit.name, 'get-idp-metadata')
    idp_metadata = action_result.data['results']['output']

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml') as fp:
        fp.write(idp_metadata)
        fp.flush()
        zaza.model.attach_resource(
            keystone_saml_mellon_app_name, idp_metadata_name, fp.name)

    (key, cert) = cert_utils.generate_cert('SP Signing Key')

    cert = cert.decode().strip("-----BEGIN CERTIFICATE-----")
    cert = cert.strip("-----END CERTIFICATE-----")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem') as fp:
        fp.write(key.decode())
        fp.flush()
        zaza.model.attach_resource(
            keystone_saml_mellon_app_name, sp_private_key_name, fp.name)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml') as fp:
        fp.write(SP_SIGNING_KEY_INFO_XML_TEMPLATE.format(cert))
        fp.flush()
        zaza.model.attach_resource(
            keystone_saml_mellon_app_name, sp_signing_keyinfo_name, fp.name)

    keystone_saml_mellon_unit = zaza.model.get_units(
        keystone_saml_mellon_app_name).pop()
    action_result = zaza.model.run_action(
        keystone_saml_mellon_unit.name, 'get-sp-metadata')
    sp_metadata = action_result.data['results']['output']

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml') as fp:
        fp.write(sp_metadata)
        fp.flush()
        zaza.model.attach_resource(
            test_saml_idp_app_name, sp_metadata_name, fp.name)


def attach_saml_resources_idp1():
    """Attach the SAML resources for the local IdP #1."""
    _attach_saml_resources(
        keystone_saml_mellon_app_name="keystone-saml-mellon1",
        test_saml_idp_app_name="test-saml-idp1")


def attach_saml_resources_idp2():
    """Attach the SAML resources for the local IdP #2."""
    _attach_saml_resources(
        keystone_saml_mellon_app_name="keystone-saml-mellon2",
        test_saml_idp_app_name="test-saml-idp2")


def keystone_federation_setup_idp1():
    """Configure Keystone Federation for the local IdP #1."""
    test_saml_idp_unit = zaza.model.get_units("test-saml-idp1").pop()
    idp_remote_id = IDP_REMOTE_ID.format(
        test_saml_idp_unit.data['public-address'])

    _keystone_federation_setup(
        federated_domain="federated_domain_idp1",
        federated_group="federated_users_idp1",
        idp_name="test-saml-idp1",
        idp_remote_id=idp_remote_id)


def keystone_federation_setup_idp2():
    """Configure Keystone Federation for the local IdP #2."""
    test_saml_idp_unit = zaza.model.get_units("test-saml-idp2").pop()
    idp_remote_id = IDP_REMOTE_ID.format(
        test_saml_idp_unit.data['public-address'])

    _keystone_federation_setup(
        federated_domain="federated_domain_idp2",
        federated_group="federated_users_idp2",
        idp_name="test-saml-idp2",
        idp_remote_id=idp_remote_id)

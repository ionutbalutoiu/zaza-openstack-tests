# Copyright 2018 Canonical Ltd.
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

"""Keystone SAML Mellon Testing."""

import logging
from lxml import etree
import requests

import zaza.model
from zaza.openstack.charm_tests.keystone import BaseKeystoneTest
import zaza.openstack.utilities.openstack as openstack_utils


class FailedToReachIDP(Exception):
    """Custom Exception for failing to reach the IDP."""


class BaseCharmKeystoneSAMLMellonTest(BaseKeystoneTest):
    """Charm Keystone SAML Mellon tests."""

    @classmethod
    def setUpClass(cls,
                   application_name="keystone-saml-mellon",
                   test_saml_idp_app_name="test-saml-idp",
                   horizon_idp_option_name="myidp_mapped",
                   horizon_idp_display_name="myidp via mapped"):
        """Run class setup for running Keystone SAML Mellon charm tests."""
        super(BaseCharmKeystoneSAMLMellonTest, cls).setUpClass()
        cls.application_name = application_name
        cls.test_saml_idp_app_name = test_saml_idp_app_name
        cls.horizon_idp_option_name = horizon_idp_option_name
        cls.horizon_idp_display_name = horizon_idp_display_name
        cls.action = "get-sp-metadata"
        cls.current_release = openstack_utils.get_os_release()
        cls.FOCAL_USSURI = openstack_utils.get_os_release("focal_ussuri")

    def test_run_get_sp_metadata_action(self):
        """Validate the get-sp-metadata action."""
        unit = zaza.model.get_units(self.application_name)[0]
        if self.vip:
            ip = self.vip
        else:
            ip = unit.public_address

        action = zaza.model.run_action(unit.entity_id, self.action)
        if "failed" in action.data["status"]:
            raise Exception(
                "The action failed: {}".format(action.data["message"]))

        output = action.data["results"]["output"]
        root = etree.fromstring(output)
        for item in root.items():
            if "entityID" in item[0]:
                assert ip in item[1]

        for appt in root.getchildren():
            for elem in appt.getchildren():
                for item in elem.items():
                    if "Location" in item[0]:
                        assert ip in item[1]

        logging.info("Successul get-sp-metadata action")

    def test_saml_mellon_redirects(self):
        """Validate the horizon -> keystone -> IDP redirects."""
        if self.vip:
            keystone_ip = self.vip
        else:
            unit = zaza.model.get_units(self.application_name)[0]
            keystone_ip = unit.public_address

        horizon = "openstack-dashboard"
        horizon_config = zaza.model.get_application_config(horizon)
        horizon_vip = horizon_config.get("vip").get("value")
        if horizon_vip:
            horizon_ip = horizon_vip
        else:
            unit = zaza.model.get_units("openstack-dashboard")[0]
            horizon_ip = unit.public_address

        if self.tls_rid:
            proto = "https"
        else:
            proto = "http"

        # Use Keystone URL for < Focal
        if self.current_release < self.FOCAL_USSURI:
            region = "{}://{}:5000/v3".format(proto, keystone_ip)
        else:
            region = "default"

        idp_address = zaza.model.get_units(
            self.test_saml_idp_app_name).pop().data['public-address']

        url = "{}://{}/horizon/auth/login/".format(proto, horizon_ip)
        horizon_expect = '<option value="{0}">{1}</option>'.format(
            self.horizon_idp_option_name, self.horizon_idp_display_name)

        # This is the message the local test-saml-idp displays after you are
        # redirected. It shows we have been directed to:
        # horizon -> keystone -> test-saml-idp
        idp_expect = (
            "A service has requested you to authenticate yourself. Please "
            "enter your username and password in the form below.")

        def _do_redirect_check(url, region, idp_expect,
                               horizon_expect, idp_address):

            # start session, get csrftoken
            client = requests.session()
            # Verify=False see note below
            login_page = client.get(url, verify=False)

            # Validate SAML method is available
            assert horizon_expect in login_page.text

            # Get cookie
            if "csrftoken" in client.cookies:
                csrftoken = client.cookies["csrftoken"]
            else:
                raise Exception("Missing csrftoken")

            # Build and send post request
            form_data = {
                "auth_type": self.horizon_idp_option_name,
                "csrfmiddlewaretoken": csrftoken,
                "next": "/horizon/project/api_access",
                "region": region,
            }

            # Verify=False due to CA certificate bundles.
            # If we don't set it validation fails for keystone/horizon
            # We would have to install the keystone CA onto the system
            # to validate end to end.
            response = client.post(
                url, data=form_data,
                headers={"Referer": url},
                allow_redirects=True,
                verify=False)

            if idp_expect not in response.text:
                msg = "FAILURE code={} text={}".format(response, response.text)
                # Raise a custom exception.
                raise FailedToReachIDP(msg)

            idp_url = ("http://{0}/simplesaml/"
                       "module.php/core/loginuserpass.php").format(idp_address)

            # Validate that we were redirected to the proper IdP
            assert response.url.startswith(idp_url)
            assert idp_url in response.text

        # Execute the check
        # We may need to try/except to allow horizon to build its pages
        _do_redirect_check(url, region, idp_expect,
                           horizon_expect, idp_address)
        logging.info("SUCCESS")


class CharmKeystoneSAMLMellonIDP1Test(BaseCharmKeystoneSAMLMellonTest):
    """Charm Keystone SAML Mellon tests class for the local IDP #1."""

    @classmethod
    def setUpClass(cls):
        """Run class setup for running Keystone SAML Mellon charm tests.

        It does the necessary setup for the local IDP #1.
        """
        super(CharmKeystoneSAMLMellonIDP1Test, cls).setUpClass(
            application_name="keystone-saml-mellon1",
            test_saml_idp_app_name="test-saml-idp1",
            horizon_idp_option_name="test-saml-idp1_mapped",
            horizon_idp_display_name="Test SAML IDP #1")


class CharmKeystoneSAMLMellonIDP2Test(BaseCharmKeystoneSAMLMellonTest):
    """Charm Keystone SAML Mellon tests class for the local IDP #2."""

    @classmethod
    def setUpClass(cls):
        """Run class setup for running Keystone SAML Mellon charm tests.

        It does the necessary setup for the local IDP #2.
        """
        super(CharmKeystoneSAMLMellonIDP2Test, cls).setUpClass(
            application_name="keystone-saml-mellon2",
            test_saml_idp_app_name="test-saml-idp2",
            horizon_idp_option_name="test-saml-idp2_mapped",
            horizon_idp_display_name="Test SAML IDP #2")

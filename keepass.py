# Copyright: (c) 2020, jasle <jasle at riseup dot net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# python 3 headers, required if submitting to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
                name: keepass
                short_description: get data from keepass file
                description:
                  - This lookup returns the contents from a keepass file on the ansible controller.
                version_added: '0.1'
                author: jasle (@jasle)
                options:
                  _terms:
                    description: path of KeePass entry
                    required: True
                    type: str
                  include_password:
                    description: include password
                    type: bool
                    default: False
                  kdbx_file:
                    description: path of KeePass file
                    type: str
                    default: ~/Passwords.kdbx
                    env:
                      - name: KEEPASS_FILE
                  kdbx_password:
                    description: password for KeePass file
                    type: str
                    no_log: True
                    env:
                      - name: KEEPASS_PASSWORD
                requirements:
                  - pykeepass
                '''

RETURN = '''
         _raw:
           description:
             - requested data
           type: list
           elements: dictionary
         '''

from ansible.errors import AnsiblePluginError, AnsibleAuthenticationFailure, AnsibleConnectionFailure
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

try:
    from pykeepass import PyKeePass
except ImportError:
    raise AnsiblePluginError('pykeepass is missing, please install it')

display = Display()

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        # load options
        self.set_options(var_options=variables, direct=kwargs)
        # get searching properties
        regex = self.get_option('regex')
        include_password = self.get_option('include_password')
        # get keepass file properties
        kdbx_file = self.get_option('kdbx_file')
        kdbx_password = self.get_option('kdbx_password')

        # load keepass file
        try:
            self._keepass = PyKeePass(kdbx_file, password=kdbx_password)
        except CredentialsError:
            raise AnsibleAuthenticationFailure('Wrong pass for KeePass file')
        except (HeaderChecksumError, PayloadChecksumError) as e:
            raise AnsibleConnectionFailure('Could not open KeePass file: %s' % to_native(e))

        ret = []

        # search entries in keepass and add them to ret as dict
        for term in terms:
            entry = self._keepass.find_entries(path=term)
            if entry == None:
                raise AnsibleLookupError('Could not find any matching entry')
            ret.append(self._entry_to_dict(entry, include_password))

        return ret

    def _entry_to_dict(self, entry, include_password):
        # get a list of "real" attributes for the entry
        attributes = [a for a in dir(entry) if not callable(getattr(entry, a)) and not a.startswith('_')]
        # remove password if not explicitly requested
        if include_password==False:
            attributes.remove('password')
        ret = {}
        # some attributes need special handling for conversations
        ret['attachments'] = [n.filename for n in entry.attachments]
        attributes.remove('attachments')
        ret['group'] = entry.group.path
        attributes.remove('group')
        ret['parentgroup'] = entry.parentgroup.path
        attributes.remove('parentgroup')
        ret['history'] = [self._entry_to_dict(e, include_password) for e in entry.history]
        attributes.remove('history')

        # converte all remaining attributes
        for attr in attributes:
            ret[attr] = str(getattr(entry, attr))
        return ret
#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
module: certificate_authority
author: "Sacha Trémoureux <sacha@tremoureux.fr>"
version_added: "0.1"
short_description: Manage certificate authority
requirements: [ openssl ]
description:
  - Manage certificate authority.
options:
'''

EXAMPLES = '''
- name: Create a certificate authority 'myca'
  certificate_authority:
    common_name: myca
    config: '/opt/myca/openssl.cnf'
    countryname: FR
    state: 'Loire-Atlantique'
    locality: Nantes
    organization: 'The World Company'
    organization_unit: TechUnit
    email: user@theworldcompany.com
    state: present

- name: Create an intermediate certificate authority 'mysubca'
  certificate_authority:
    common_name: mysubca
    authority: myca
    config: '/opt/myca/mysubca/openssl.cnf'
    informations:
      countryname: FR
      state: 'Loire-Atlantique'
      locality: Nantes
      organization: 'The World Company'
      organization_unit: TechUnit
      email: user@theworldcompany.com
    state: present
'''
from ansible.module_utils.basic import AnsibleModule
import OpenSSL
import ConfigParser
import os

class CertificateAuthority:
    def __init__(self, module):
        self.module = module
        self.config = dict()

        self.state             = module.params['state']
        self.name              = module.params['name']
        self.configfile        = module.params['config']
        self.country_name      = module.params['country_name']
        self.state_name        = module.params['state_name']
        self.organization      = module.params['organization']
        self.organization_unit = module.params['organization_unit']
        self.email             = module.params['email']
        if 'authority' in module.params:
            self.authority         = module.params['authority']

    def present(self):
        if self.config_exists():
            self.parse_config()

            if not self.directories_exists():
                self.create_missing_directories()

            if not self.database_exists():
                self.create_missing_database()

            if not self.serial_exists():
                self.create_missing_serial()

            if not self.private_key_exists():
                self.create_private_key()

            if not self.authority_exists():
                self.create_authority()
            else:
                if self.authority_expired():
                    self.delete_authority()
                    self.create_authority()

        else:
            self.module.exit_json(failed=True, msg='Configuration file not accessible')

    def absent(self):
        if self.authority_exists():
            self.delete_authority()
 
    def config_exists(self):
        return os.path.exists(self.configfile) and os.access(self.configfile, os.R_OK)

    def parse_config(self):
        cfg = ConfigParser.ConfigParser()
        cfg.read(self.configfile)
        for section in cfg.sections():
            self.config[section.strip()] = dict()
            for item in cfg.items(section):
                self.config[section.strip()][item[0].strip()] = item[1]

    def directories_exists(self):
        self.default_ca = self.config['ca']['default_ca']
        self.dir = self.config[self.default_ca]['dir']
        for subdir in ('certs', 'crl_dir', 'new_certs_dir'):
            config_dir = self.config[self.default_ca][subdir].replace('$dir', self.dir)
            if not os.path.exists(config_dir):
                return False
        private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)
        private_dir = os.path.dirname(private_key)
        if not os.path.exists(private_dir):
            return False
        return True
        
    def create_missing_directories(self):
        for subdir in ('certs', 'crl_dir', 'new_certs_dir'):
            config_dir = self.config[self.default_ca][subdir].replace('$dir', self.dir)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)

        private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)
        private_dir = os.path.dirname(private_key)
        if not os.path.exists(private_dir):
            os.makedirs(private_dir)

    def database_exists(self):
        db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
        return os.path.exists(db) and os.access(db, os.W_OK)
        
    def create_missing_database(self):
        db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
        os.mknod(db)

    def serial_exists(self):
        serial = self.config[self.default_ca]['serial'].replace('$dir', self.dir)
        return os.path.exists(serial) and os.access(serial, os.W_OK)
        
    def create_missing_serial(self):
        serial = self.config[self.default_ca]['serial'].replace('$dir', self.dir)
        with open(serial, 'a') as serial_f:
            serial_f.write('1000')

    def private_key_exists(self):
        private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)
        return os.path.exists(private_key) and os.access(db, os.R_OK)

    def create_private_key(self):
        pass

    def authority_exists(self):
        pass

    def create_authority(self):
        if hasattr(self, 'authority'):
            self.create_intermediate_authority(self)
        else:
            pass

    def create_intermediate_authority(self):
        pass

    def delete_authority(self):
        if hasattr(self, 'authority'):
            self.delete_intermediate_authority(self)
        else:
            pass

    def delete_intermediate_authority(self):
        pass

    def authority_expired(self):
        pass


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state             = dict(default='present', choices=['present', 'absent']),
            name              = dict(required=True, aliases=['common_name']),
            config            = dict(required=True),
            country_name      = dict(required=True),
            state_name        = dict(required=True),
            organization      = dict(required=True),
            organization_unit = dict(required=True),
            email             = dict(required=True)))
    ca = CertificateAuthority(module)

    if ca.state == 'absent':
        ca.absent()
    elif ca.state == 'present':
        ca.present()
    module.exit_json(changed=False)

if __name__ == '__main__':
    main()


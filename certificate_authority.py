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
from datetime import datetime, timedelta
import ssl
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
        self.locality          = module.params['locality']
        self.state_name        = module.params['state_name']
        self.organization      = module.params['organization']
        self.organization_unit = module.params['organization_unit']
        self.email             = module.params['email']
        if 'authority_file' in module.params:
            self.authority_file     = module.params['authority_file']

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
                    self.create_authority(renew=True)
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
        self.default_ca  = self.config['ca']['default_ca']
        self.dir         = self.config[self.default_ca]['dir']
        self.private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)
        self.private_dir = os.path.dirname(self.private_key)
        self.csr_dir = self.dir + '/csr'

        for subdir in ('certs', 'crl_dir', 'new_certs_dir'):
            config_dir= self.config[self.default_ca][subdir].replace('$dir', self.dir)
            if not os.path.exists(config_dir):
                return False
        if not os.path.exists(self.private_dir) or not os.path.exists(self.csr_dir):
            return False
        return True
        
    def create_missing_directories(self):
        for subdir in ('certs', 'crl_dir', 'new_certs_dir'):
            config_dir = self.config[self.default_ca][subdir].replace('$dir', self.dir)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
        if not os.path.exists(self.private_dir):
            os.makedirs(self.private_dir)
        if not os.path.exists(self.csr_dir):
            os.makedirs(self.csr_dir)

    def database_exists(self):
        db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
        return os.path.exists(db) and os.access(db, os.W_OK)
        
    def create_missing_database(self):
        db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
        os.mknod(db)

    def serial_exists(self):
        self.serial = self.config[self.default_ca]['serial'].replace('$dir', self.dir)
        return os.path.exists(self.serial) and os.access(self.serial, os.W_OK)
        
    def create_missing_serial(self):
        with open(self.serial, 'a') as serial_f:
            serial_f.write('1000')

    def private_key_exists(self):
        return os.path.exists(self.private_key) and os.access(self.private_key, os.R_OK)

    def create_private_key(self):
        (rc, uname_os, stderr) = self.module.run_command("openssl genrsa -out "+self.private_key+" 4096")
        return rc

    def authority_exists(self):
        self.certificate = self.config[self.default_ca]['certificate'].replace('$dir', self.dir)
        return os.path.exists(self.certificate) and os.access(self.certificate, os.R_OK)

    def create_authority(self, renew=False):
        self.extensions = self.config['req']['x509_extensions']
        self.infos = "/C={}/ST={}/L={}/O={}/OU={}/CN={}/emailAddress={}".format(
            self.country_name,
            self.state_name,
            self.locality,
            self.organization,
            self.organization_unit,
            self.name,
            self.email)

        if self.authority_file != 'False':
            self.create_intermediate_authority(renew)
        else:
            if renew:
                print("Yeah")
            else:
                command_line = ("openssl req -config {} "\
                                "-key {} "\
                                "-new "\
                                "-x509 "\
                                "-days 7300 "\
                                "-sha256 "\
                                "-extensions {} "\
                                "-out {} "\
                                "-subj '{}'"
                                ).format(self.configfile,
                                             self.private_key,
                                             self.extensions,
                                             self.certificate,
                                             self.infos)
                (rc, uname_os, stderr) = self.module.run_command(command_line)

    def create_intermediate_authority(self, renew=False):
        if renew:
            print("Yeah (inter)")
        else:
            if not self.certificate_signed():
                self.create_request_and_sign()

    def certificate_signed(self):
        return False

    def create_request_and_sign(self):
        command_line = ("openssl req -config {} "\
                            "-new "\
                            "-sha256 "\
                            "-key {} " \
                            "-out {}/{}.pem "\
                            "-subj '{}'"
                            ).format(self.configfile,
                                         self.private_key,
                                         self.csr_dir,
                                         self.name,
                                         self.infos)
        (rc, uname_os, stderr) = self.module.run_command(command_line)

        if rc == 0:
            print(":)")
            command_line = ("openssl ca "\
                                "-config {} "\
                                "-extensions {} "\
                                "-days 3650 "\
                                "-notext "\
                                "-md sha256 "\
                                "-in {}/{}.pem "\
                                "-out {}").format(self.authority_file,
                                                      self.extensions,
                                                      self.csr_dir,
                                                      self.name,
                                                      self.certificate)
            print(command_line)
            (rc_signed, output_signed, stderr_signed) = self.module.run_command(command_line)
            if rc_signed == 0:
                print(":)")
                 
        
    def delete_authority(self):
        if self.attribute_file:
            self.delete_intermediate_authority(self)
        else:
            pass

    def delete_intermediate_authority(self):
        pass

    def authority_expired(self):
        (rc, not_after, stderr) = self.module.run_command(
            "openssl x509 -in {} -enddate -noout".format(self.certificate))
        not_after_str = not_after.split('=')[1].strip()
        timestamp = ssl.cert_time_to_seconds(not_after_str)

        delta = datetime.fromtimestamp(timestamp)-datetime.now()
        limit = timedelta(days=7200)
        return limit > delta


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state             = dict(default='present', choices=['present', 'absent']),
            name              = dict(required=True, aliases=['common_name']),
            authority_file    = dict(default=False),
            config            = dict(required=True),
            country_name      = dict(required=True),
            locality          = dict(required=True),
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


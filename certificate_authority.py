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
import ConfigParser as configparser
import os

class CertificateAuthority:
    def __init__(self, module, renew=False):
        self.module = module

        self.state             = module.params['state']
        self.name              = module.params['name']
        self.config_file       = module.params['config_file']
        if 'authority_file' in module.params:
            self.authority_file    = module.params['authority_file']
        if 'country_name' in module.params:
            self.country_name      = module.params['country_name']            
        if 'locality' in module.params:
            self.locality          = module.params['locality']            
        if 'state_name' in module.params:
            self.state_name        = module.params['state_name']
        if 'organization' in module.params:
            self.organization      = module.params['organization']            
        if 'organization_unit' in module.params:
            self.organization_unit = module.params['organization_unit']
        if 'days' in module.params:
            self.days              = int(module.params['days'])            
        if 'email' in module.params:
            self.email             = module.params['email']            
        if(renew):
            self.present()

    def present(self):
        if self.config_exists():
            self.timestamp = datetime.now().strftime("-%Y%m%d-%H%M%S")
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
                if self.certificate_expired(self.certificate):
                    self.create_authority(renew=True)
        else:
            self.module.exit_json(failed=True, msg='Configuration file not accessible')

    def absent(self):
        if self.config_exists():
            self.parse_config()

        if self.authority_exists(delete=True):
            self.delete_authority()
 
    def config_exists(self):
        return os.path.exists(self.config_file) and os.access(self.config_file, os.R_OK)

    def parse_config(self, authority=False):
        cfg = configparser.ConfigParser()
        if not authority:
            self.config = dict()
            cfg.read(self.config_file)
            for section in cfg.sections():
                self.config[section.strip()] = dict()
                for item in cfg.items(section):
                    self.config[section.strip()][item[0].strip()] = item[1]
        else:
            self.authority_config = dict()
            cfg.read(self.authority_file)
            for section in cfg.sections():
                self.authority_config[section.strip()] = dict()
                for item in cfg.items(section):
                    self.authority_config[section.strip()][item[0].strip()] = item[1]

        self.default_ca  = self.config['ca']['default_ca']
        self.dir         = self.config[self.default_ca]['dir']
        self.private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)
        self.private_dir = os.path.dirname(self.private_key)
        self.csr_dir = self.dir + '/csr'

    def directories_exists(self):
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

    def delete_directories(self):
        for subdir in ('certs', 'crl_dir', 'new_certs_dir'):
            config_dir = self.config[self.default_ca][subdir].replace('$dir', self.dir)
            print(config_dir)
        print(self.private_dir)
        print(self.csr_dir)            
        pass

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
        print("openssl genrsa -out "+self.private_key+" 4096")
        return rc

    def authority_exists(self, delete=False):
        if delete:
            self.certificate = self.config[self.default_ca]['certificate'].replace('$dir', self.dir)
        else:
            self.certificate = self.config[self.default_ca]['certificate'].replace('$dir', self.dir)+self.timestamp
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
                self.module.params['authority_file'] = self.module.params['config']
                CertificateAuthority(self.module, renew=True)
            else:
                command_line = ("openssl req -config {} "\
                                "-key {} "\
                                "-new "\
                                "-x509 "\
                                "-days {} "\
                                "-sha256 "\
                                "-extensions {} "\
                                "-out {} "\
                                "-subj '{}'"
                                ).format(self.config_file,
                                             self.private_key,
                                             self.days,
                                             self.extensions,
                                             self.certificate,
                                             self.infos)
                (rc, uname_os, stderr) = self.module.run_command(command_line)
                cert_symlink = self.certificate.replace(self.timestamp, '')
                if os.path.exists(cert_symlink) and os.access(cert_symlink, os.W_OK):
                    os.remove(cert_symlink)
                os.symlink(self.certificate, cert_symlink)

    def create_intermediate_authority(self, renew=False):
        self.create_request()
        self.sign_certificate()

    def certificate_signed(self):
        self.parse_config(authority=True)
        self.authority_dir = self.authority_config[self.default_ca]['dir']
        self.authority_certificate = self.authority_config[self.default_ca]['certificate'].replace('$dir', self.authority_dir)
        command_line = ("openssl verify -CAfile {} {}"
                        ).format(self.authority_certificate,
                                 self.certificate)
        print(command_line)
        (rc, uname_os, stderr) = self.module.run_command(command_line)
        if rc == 0:
            return True
        else:
            return False

    def create_request(self):
        self.request = self.csr_dir+"/"+self.name+self.timestamp
        command_line = ("openssl req -config {} "\
                            "-new "\
                            "-sha256 "\
                            "-key {} " \
                            "-out {} "\
                            "-subj '{}'"
                            ).format(self.config_file,
                                         self.private_key,
                                         self.request,
                                         self.infos)
        (rc, uname_os, stderr) = self.module.run_command(command_line)
        request_symlink = self.request.replace(self.timestamp, '')
        if os.path.exists(request_symlink) and os.access(request_symlink, os.W_OK):
            os.remove(request_symlink)         
        os.symlink(self.request, request_symlink)

    def sign_certificate(self):
        command_line = ("openssl ca "\
                        "-batch "\
                        "-config {} "\
                        "-extensions {} "\
                        "-days {} "\
                        "-notext "\
                        "-md sha256 "\
                        "-in {} "\
                        "-out {}").format(self.authority_file,
                                          self.extensions,
                                          self.days,
                                          self.request,
                                          self.certificate)
        (rc_signed, output_signed, stderr_signed) = self.module.run_command(command_line)
        cert_symlink = self.certificate.replace(self.timestamp, '')
        if os.path.exists(cert_symlink) and os.access(cert_symlink, os.W_OK):
            os.remove(cert_symlink)
        os.symlink(self.certificate, cert_symlink)

    def delete_authority(self):
        if self.authority_file != 'False':
            self.delete_intermediate_authority()
        else:
            self.delete_directories()

    def delete_intermediate_authority(self):
        dir_certs = os.path.dirname(self.certificate)
        for root, dirname, filenames in os.walk(dir_certs):
            for filename in filenames:
                certificate = root+'/'+filename
                if not os.path.islink(certificate):
                    if not self.certificate_expired(certificate):
                        command_line = ("openssl ca "\
                                            "-batch "\
                                            "-config {} "\
                                            "-revoke {}").format(
                                                self.authority_file,
                                                certificate)
                        (rc_revoked, output_revoked, stderr_revoked) = self.module.run_command(command_line)
        self.delete_directories()

    def certificate_expired(self, certificate):
        (rc, not_after, stderr) = self.module.run_command(
            "openssl x509 -in {} -enddate -noout".format(certificate))
        not_after_str = not_after.split('=')[1].strip()
        timestamp = ssl.cert_time_to_seconds(not_after_str)

        delta = datetime.fromtimestamp(timestamp)-datetime.now()
        limit = timedelta(days=(self.days/10))
        return limit > delta


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state             = dict(default='present', choices=['present', 'absent']),
            name              = dict(required=True, aliases=['common_name']),
            authority_file    = dict(default=False),
            days              = dict(default=365),
            config_file       = dict(required=True),
            country_name      = dict(required=False),
            locality          = dict(required=False),
            state_name        = dict(required=False),
            organization      = dict(required=False),
            organization_unit = dict(required=False),
            email             = dict(required=False)))
    ca = CertificateAuthority(module)

    if ca.state == 'absent':
        ca.absent()
    elif ca.state == 'present':
        ca.present()
    module.exit_json(changed=False)

if __name__ == '__main__':
    main()


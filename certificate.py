#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
module: certificate
author: "Sacha Trémoureux <sacha@tremoureux.fr>"
version_added: "0.1"
short_description: Manage certificate authority
requirements: [ openssl ]
description:
  - Manage certificate authority.
options:
'''

EXAMPLES = '''
- name: create master ca
  certificate:
    name: master-ca
    state: present
    config_file: '/opt/masterca.cnf'
    country_name: '{{ countryname }}'
    state_name: '{{ state }}'
    locality: '{{ locality }}'
    organization: '{{ organization }}'
    organization_unit: '{{ organization_unit }}'
    email: '{{ email }}'

- name: create inter ca
  certificate:
    name: inter-ca
    state: present
    authority_file: '/opt/masterca.cnf'
    config_file: '/opt/interca.cnf'

- name: create vhosts
  certificate:
    name: '{{ item }}'
    is_certificate: true
    state: present
    config_file: '/opt/interca.cnf'
    extension: server_cert
  with_items:
    - "{{ vhosts.keys() }}"

- name: list current vhosts
  certificate:
    name: master-ca
    state: list
    config_file: '/opt/masterca.cnf'
'''
from ansible.module_utils.basic import AnsibleModule
from datetime import datetime, timedelta
import ssl
try:
    import ConfigParser as configparser
except:
    import configparser as configparser
import os

class Certificate:
    def __init__(self, module, renew=False):
        self.changed = False
        self.module = module

        self.state                 = module.params['state']
        self.name                  = module.params['name'].replace(' ', '_')
        self.config_file           = module.params['config_file']
        if 'authority_file' in module.params:
            self.authority_file    = module.params['authority_file']
        if 'is_certificate' in module.params and module.params['is_certificate'] is not None:
            self.is_certificate    = True
        else:
            self.is_certificate    = False
        if 'extension' in module.params:
            self.extension          = module.params['extension']
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

    def listing(self):
        if self.config_exists():
            self.parse_config(is_certificate=self.is_certificate)
            if self.database_exists():
                db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
                cn = []
                with open(db) as dbfile:
                    for line in dbfile:
                       if(line.startswith('V')):
                           cn.append(line.split('/')[6].replace('CN=',''))
                self.module.exit_json(changed=False,certs=cn)
            else:
                self.module.exit_json(changed=False,certs=[])
        else:
            self.module.exit_json(failed=True, msg='Configuration file not accessible')

    def present(self):
        if self.config_exists():
            self.timestamp = datetime.now().strftime("-%Y%m%d-%H%M%S")
            self.parse_config(is_certificate=self.is_certificate)
            if not self.is_certificate:
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
                    if self.certificate_expired():
                        self.create_authority(renew=True)
            else:
                if not self.private_key_exists():
                    self.create_private_key()
                if (not self.certificate_signed(is_certificate=self.is_certificate) or self.certificate_expired()):
                    self.create_request()
                    self.sign_certificate()
        else:
            self.module.exit_json(failed=True, msg='Configuration file not accessible')

    def absent(self):
        if self.config_exists():
            self.parse_config()

        if self.authority_exists():
            if not self.is_certificate:
                self.delete_authority()
            else:
                self.revoke_certificate()
 
    def config_exists(self):
        return os.path.exists(self.config_file) and os.access(self.config_file, os.R_OK)

    def parse_config(self, authority=False, is_certificate=False):
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
            self.authority_dir = self.authority_config[self.default_ca]['dir']
            self.authority_chain = self.authority_config[self.default_ca]['certs'].replace('$dir', self.authority_dir) + '/chain.pem'

        self.default_ca  = self.config['ca']['default_ca']
        self.dir         = self.config[self.default_ca]['dir']
        self.csr_dir     = self.dir + '/csr'

        if self.country_name is None:
            self.country_name      = self.config['req_distinguished_name']['countryname_default']
        if self.locality is None:
            self.locality          = self.config['req_distinguished_name']['localityname_default']
        if self.state_name is None:
            self.state_name        = self.config['req_distinguished_name']['stateorprovincename_default']
        if self.organization is None:
            self.organization      = self.config['req_distinguished_name']['0.organizationname_default']
        if self.organization_unit is None:
            self.organization_unit = self.config['req_distinguished_name']['organizationalunitname_default']
        if self.email is None:
            self.email             = self.config['req_distinguished_name']['emailaddress_default']

        self.infos = "/C={}/ST={}/L={}/O={}/OU={}/CN={}/emailAddress={}/subjectAltName=DNS.1={}".format(
            self.country_name,
            self.state_name,
            self.locality,
            self.organization,
            self.organization_unit,
            self.name,
            self.email,
            self.name
        )
        self.chain = self.config[self.default_ca]['certs'].replace('$dir', self.dir) + '/chain.pem'
        self.certs_dir = self.config[self.default_ca]['certs'].replace('$dir', self.dir)

        if is_certificate:
            self.authority_file = self.config_file
            self.certificate = self.certs_dir+'/'+self.name + '.crt.pem'
            self.ca_private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)            
            self.private_dir = os.path.dirname(self.ca_private_key)            
            self.private_key = self.private_dir + '/' + self.name + '.key.pem'
        else:
            self.private_key = self.config[self.default_ca]['private_key'].replace('$dir', self.dir)
            self.private_dir = os.path.dirname(self.private_key)
            self.certificate = self.config[self.default_ca]['certificate'].replace('$dir', self.dir)            

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
                self.add_change('Create directory {}'.format(config_dir))
                os.makedirs(config_dir)
        if not os.path.exists(self.private_dir):
            self.add_change('Create directory {}'.format(self.private_dir))
            os.makedirs(self.private_dir)
        if not os.path.exists(self.csr_dir):
            self.add_change('Create directory {}'.format(self.csr_dir))
            os.makedirs(self.csr_dir)

    def delete_directories(self):
        # Purge directories specified in configuration file
        for subdir in ('certs', 'crl_dir', 'new_certs_dir'):
            config_dir = self.config[self.default_ca][subdir].replace('$dir', self.dir)
            for root, dirnames, filenames in os.walk(config_dir):
                for filename in filenames:
                    self.add_change('Remove file {}/{}'.format(root,filename))
                    os.remove(root+'/'+filename)

        # Purge module-specific directories
        dirs = [self.private_dir, self.csr_dir, self.dir]
        for delete_dir in dirs:
            for root, dirnames, filenames in os.walk(delete_dir):
                for filename in filenames:
                    self.add_change('Remove file {}/{}'.format(root,filename))
                    os.remove(root+'/'+filename)
                self.add_change('Remove directory {}'.format(root))
                os.rmdir(root)                

    def database_exists(self):
        db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
        return os.path.exists(db) and os.access(db, os.W_OK)
        
    def create_missing_database(self):
        db = self.config[self.default_ca]['database'].replace('$dir', self.dir)
        self.add_change('Add empty directory {}'.format(db))
        os.mknod(db)

    def serial_exists(self):
        self.serial = self.config[self.default_ca]['serial'].replace('$dir', self.dir)
        return os.path.exists(self.serial) and os.access(self.serial, os.W_OK)
        
    def create_missing_serial(self):
        with open(self.serial, 'a') as serial_f:
            self.add_change('Initialize serial ({}) at 1000'.format(self.serial))
            serial_f.write('1000')

    def private_key_exists(self):
        return os.path.exists(self.private_key) and os.access(self.private_key, os.R_OK)

    def create_private_key(self):
        command_line = "openssl genrsa -out "+self.private_key+" 4096"
        self.module.debug(command_line)
        self.add_change('Generating new private key ({})'.format(self.private_key))
        (rc, uname_os, stderr) = self.module.run_command(command_line)
        if(rc != 0):
            self.module.exit_json(failed=True, msg='Error while generating {}, rc={}, uname_os={}, stderr={}'.format(
                self.private_key, rc, uname_os, stderr))
        return rc

    def authority_exists(self):
        return os.path.exists(self.certificate) and os.access(self.certificate, os.R_OK)

    def create_authority(self, renew=False):
        self.certificate_ts = self.certificate+self.timestamp
        self.extension = self.config['req']['x509_extensions']

        if self.authority_file != 'False':
            self.create_intermediate_authority(renew)
        else:
            if renew:
                self.module.params['authority_file'] = self.module.params['config_file']
                Certificate(self.module, renew=True)
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
                                             self.extension,
                                             self.certificate_ts,
                                             self.infos)
                self.module.debug(command_line)
                self.add_change('Create new authority {}'.format(self.certificate_ts))
                (rc, uname_os, stderr) = self.module.run_command(command_line)

                if rc != 0:
                    self.module.exit_json(failed=True, msg='Error while generating {}, rc={}, uname_os={}, stderr={}'.format(
                        self.config_file, rc, uname_os, stderr))
                if os.path.exists(self.certificate) and os.access(cert_symlink, os.W_OK):
                    self.add_change('Remove old authority symlink {}'.format(self.certificate))
                    os.remove(self.certificate)
                os.symlink(self.certificate_ts, self.certificate)
                with open(self.chain, 'w') as outfile:
                    with open(self.certificate) as infile:
                        self.add_change('Generating new chain {}'.format(outfile))
                        outfile.write(infile.read())

    def create_intermediate_authority(self, renew=False):
        self.parse_config(authority=True)        
        self.create_request()
        self.sign_certificate()

    def certificate_signed(self, is_certificate=False):
        command_line = ("openssl verify -CAfile {} {}").format(self.chain, self.certificate)
        self.module.debug(command_line)
        (rc, uname_os, stderr) = self.module.run_command(command_line)
        if rc == 0:
            return True
        else:
            return False

    def create_request(self):
        self.request = self.csr_dir+"/"+self.name+'.pem'+self.timestamp
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
        self.module.debug(command_line)
        self.add_change('Creating new request {}'.format(self.request))
        (rc, uname_os, stderr) = self.module.run_command(command_line)
        request_symlink = self.request.replace(self.timestamp, '')
        if os.path.exists(request_symlink) and os.access(request_symlink, os.W_OK):
            self.add_change('Remove old request symlink {}'.format(request_symlink))
            os.remove(request_symlink)         
        os.symlink(self.request, request_symlink)

    def sign_certificate(self):
        self.certificate_ts = self.certificate+self.timestamp
        command_line = ("openssl ca "\
                        "-batch "\
                        "-config {} "\
                        "-extensions {} "\
                        "-days {} "\
                        "-notext "\
                        "-md sha256 "\
                        "-in {} "\
                        "-out {}").format(self.authority_file,
                                          self.extension,
                                          self.days,
                                          self.request,
                                          self.certificate_ts)
        self.module.debug(command_line)
        self.add_change('Sign request {} and generate certificate {}'.format(self.request, self.certificate_ts))
        (rc_signed, output_signed, stderr_signed) = self.module.run_command(command_line)
        if(rc_signed != 0):
            self.module.exit_json(failed=True, msg='Error while signing {}, rc={}, uname_os={}, stderr={}'.format(
                self.certificate_ts, rc_signed, output_signed, stderr_signed))
        if os.path.exists(self.certificate) and os.access(self.certificate, os.W_OK):
            self.add_change('Remove old certificate symlink {}'.format(self.certificate))
            os.remove(self.certificate)

        os.symlink(self.certificate_ts, self.certificate)

        if not self.is_certificate:
            chains = [ self.certificate, self.authority_chain ]
            with open(self.chain, 'w') as outfile:
                for chain in chains:
                    with open(chain) as infile:
                        self.add_change('Add {} to {} chain file'.format(infile, outfile))
                        outfile.write(infile.read())

    def delete_authority(self):
        if self.authority_file != 'False':
            self.delete_intermediate_authority()
        else:
            self.delete_directories()

    def revoke_certificate(self):
        dirs = [self.certs_dir, self.csr_dir, self.private_dir]
        for delete_dir in dirs:
            for root, dirnames, filenames in os.walk(delete_dir):
                for filename in filenames:
                    certificate = root+'/'+filename
                    if filename.startswith(self.name):
                        if not os.path.islink(certificate) and delete_dir == self.certs_dir:
                            command_line = ("openssl ca "\
                                                "-batch "\
                                                "-config {} "\
                                                "-revoke {}").format(
                                                    self.config_file,
                                                    certificate)
                            self.module.debug(command_line)
                            self.add_change('Revoke certificate {}'.format(self.config_file))
                            (rc_revoked, output_revoked, stderr_revoked) = self.module.run_command(command_line)
                        self.add_change('Remove certificate {}'.format(certificate))
                        os.remove(certificate)
                        
    def delete_intermediate_authority(self):
        for root, dirnames, filenames in os.walk(self.certs_dir):
            for filename in filenames:
                certificate = root+'/'+filename
                if not os.path.islink(certificate):
                    command_line = ("openssl ca "\
                                        "-batch "\
                                        "-config {} "\
                                        "-revoke {}").format(
                                            self.authority_file,
                                            certificate)
                    self.module.debug(command_line)
                    self.add_change("Revoke authority {}".format(self.authority_file))
                    (rc_revoked, output_revoked, stderr_revoked) = self.module.run_command(command_line)
        self.delete_directories()

    def certificate_expired(self):
        command_line = "openssl x509 -in {} -enddate -noout".format(self.certificate)
        (rc, not_after, stderr) = self.module.run_command(command_line)
        not_after_str = not_after.split('=')[1].strip()
        timestamp = ssl.cert_time_to_seconds(not_after_str)

        delta = datetime.fromtimestamp(timestamp)-datetime.now()
        limit = timedelta(days=(self.days/10))
        return limit > delta

    def add_change(self, msg):
        if not self.changed:
            self.msg = msg
        else:
            self.msg += msg + '\n'
        self.changed = True

def main():
    module = AnsibleModule(
        argument_spec = dict(
            state             = dict(default='present', choices=['present', 'absent', 'list']),
            name              = dict(required=True, aliases=['common_name']),
            authority_file    = dict(default=False),
            days              = dict(default=365),
            config_file       = dict(required=True),
            is_certificate    = dict(required=False),
            extension         = dict(required=False),
            country_name      = dict(required=False),
            locality          = dict(required=False),
            state_name        = dict(required=False),
            organization      = dict(required=False),
            organization_unit = dict(required=False),
            email             = dict(required=False)
        )
    )
    ca = Certificate(module)

    if ca.state == 'absent':
        ca.absent()
    elif ca.state == 'present':
        ca.present()
    elif ca.state == 'list':
        ca.listing()
    module.exit_json(changed=ca.changed)

if __name__ == '__main__':
    main()

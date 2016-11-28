#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
module: certificate
author: "Sacha Trémoureux <sacha@tremoureux.fr>"
version_added: "0.2"
short_description: Manage certificate authority
requirements: [ openssl ]
description:
  - Manage certificate authority.
options:
'''

EXAMPLES = '''
'''
from ansible.module_utils.basic import AnsibleModule
from datetime import datetime
import OpenSSL
import os
import yaml

class Certificate:
    def __init__(self, module, renew=False):
        self.changed = False
        self.module = module

        self.state                 = module.params['state']
        self.config_file           = module.params['config_file']
        if(renew):
            self.present()
        self.timestamp = datetime.now().strftime("-%Y%m%d-%H%M%S")

    def present(self):
        (self
             .parse_config()
             .ensure_dirs()
             .ensure_private_key()
             .ensure_cert()
        )

    def absent(self):
        (self
             .parse_config()
             .delete_cert()
        )

    def listing(self):
        (self
             .parse_config()
             .list_certs()
        )

    def list_certs(self):
        list = []
        self.index_file = self.dir+'/index.yml'
        self.index_exists = os.path.exists(self.index_file) and os.access(self.index_file, os.R_OK)            
        if self.index_exists:
            with open(self.index_file, 'r') as data:
                self.index = yaml.load(data)
        for index in self.index:
            if index != 'current' and self.index[index]['status'] == 'valid':
                list.append(self.index[index]['name'])
        self.module.exit_json(changed=False,certs=list)

    def parse_config(self):
        with open(self.config_file, 'r') as data:
            self.config = yaml.load(data)
        self.is_certificate = 'is_certificate' in self.config and self.config['is_certificate']
        self.has_root_ca = 'root_ca' in self.config

        if self.is_certificate:
            with open(self.config['root_ca'], 'r') as data:
                self.root_config = yaml.load(data)
            self.root_dir = self.root_config['dir']+'/'+self.root_config['name']
            self.dir = self.root_config['dir']+'/'+self.root_config['name']
            self.index_file = self.dir+'/index.yml'
        elif self.has_root_ca:
            with open(self.config['root_ca'], 'r') as data:
                self.root_config = yaml.load(data)
            self.root_dir = self.root_config['dir']+'/'+self.root_config['name']
            self.dir = self.config['dir']+'/'+self.config['name']
            self.index_file = self.root_dir+'/index.yml'
        else:
            self.dir = self.config['dir']+'/'+self.config['name']
            self.index_file = self.dir+'/index.yml'


        self.index_exists = os.path.exists(self.index_file) and os.access(self.index_file, os.R_OK)            
        if self.index_exists:
            with open(self.index_file, 'r') as data:
                self.index = yaml.load(data)
        else:
            self.index = {'current': 1000}
        return self

    def ensure_dirs(self):
        if not self.is_certificate:
            sub_dirs = [ 'certs', 'csr', 'private' ]
            if not os.path.exists(self.dir):
              os.makedirs(self.dir)
              self.changed = True
            for cur_dir in sub_dirs:
              if not os.path.exists(self.dir+'/'+cur_dir):
                  os.makedirs(self.dir+'/'+cur_dir)
                  self.changed = True
            if not self.index_exists:
                with open(self.index_file, 'w+') as outfile:
                    yaml.dump(self.index, outfile, default_flow_style=True)                  
        return self

    def ensure_private_key(self):
        self.pkey_file = self.dir+'/private/'+self.config['name']+'.pem'
        pkey_exists = os.path.exists(self.pkey_file) and os.access(self.pkey_file, os.R_OK)
        if not pkey_exists:
            pkey = OpenSSL.crypto.PKey()
            pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            pkey_dump = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                        pkey)
            with open(self.pkey_file, 'wb') as keyfile:
                keyfile.write(pkey_dump)
            self.changed = True

        with open(self.pkey_file, 'r') as pkey:
            self.pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey.read())
        if self.has_root_ca:
            self.root_pkey_file = self.root_dir+'/private/'+self.root_config['name']+'.pem'
            with open(self.root_pkey_file, 'r') as pkey:
                self.root_pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey.read())
        return self

    def ensure_cert(self):
        self.cert_file = self.dir+'/certs/'+self.config['name']+'.pem'
        if self.is_certificate or self.has_root_ca:
            self.root_cert_file = self.root_dir+'/certs/'+self.root_config['name']+'.pem'
            self.root_chain = self.root_dir+'/certs/chain.pem'
            with open(self.root_cert_file, 'r') as certfile:
                self.root_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                certfile.read())
            if not self.cert_valided() or not self.cert_signed() or self.cert_expired():
                self.create_signed_cert()
        else:
            if not self.cert_valided():
                self.create_ca()
            elif self.cert_expired():
                self.create_signed_cert()
        return self

    def cert_valided(self):
        cert_exists = os.path.exists(self.cert_file) and os.access(self.cert_file, os.R_OK)
        if cert_exists:
            with open(self.cert_file, 'r') as certfile:
                self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                certfile.read())
        return cert_exists

    def cert_signed(self):
        store = OpenSSL.crypto.X509Store()
        certs = []
        i = 0
        with open(self.root_chain, 'r') as chain:
            for line in chain:
                if line == '-----BEGIN CERTIFICATE-----\n':
                    certs.append('')
                certs[i] += line
                if line == '-----END CERTIFICATE-----\n':
                    i = i+1
        for raw_cert in certs:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, raw_cert)
            store.add_cert(cert)

        context = OpenSSL.crypto.X509StoreContext(store, self.cert)
        signed = True
        try:
            context.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError as context_error:
            signed = False
        return signed

    def cert_expired(self):
        return self.cert.has_expired()

    def ca_exists(self):
        ca_exists = os.path.exists(self.ca_file) and os.access(self.ca_file, os.R_OK)
        if ca_exists:
            self.ca = OpenSSL.crypto.X509()
            with open(self.ca_file, 'r') as ca:
                self.ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                              ca.read())
            self.ca_private = OpenSSL.crypto.X509()
            with open(self.ca_private_file, 'r') as ca_private:
                self.ca_private = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                                     ca_private.read())
        return ca_exists

    def create_ca(self):
        self.cert_ts = self.cert_file+self.timestamp
        self.chain = self.dir+'/certs/chain.pem'

        self.ca = OpenSSL.crypto.X509()
        subject = self.ca.get_subject()
        subject.C = self.config['infos']['country']
        subject.ST = self.config['infos']['state']
        subject.L = self.config['infos']['locality']
        subject.O = self.config['infos']['organization']
        subject.OU = self.config['infos']['organization_unit']
        subject.emailAddress = self.config['infos']['email_address']
        subject.CN = self.config['name'] 
        self.ca.set_version(2)
        self.ca.set_serial_number(self.index['current'])
        self.ca.gmtime_adj_notBefore(0)
        self.ca.gmtime_adj_notAfter(self.config['days'] * 24 * 60 * 60)
        self.ca.set_issuer(self.ca.get_subject())
        self.ca.set_pubkey(self.pkey)
        self.ca.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints", True,
                                         b"CA:TRUE"),
            OpenSSL.crypto.X509Extension(b"keyUsage", True,
                                         b"digitalSignature, cRLSign, keyCertSign, nonRepudiation"),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                         subject=self.ca)
        ])
        self.ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False,
                                         b'keyid:always', issuer=self.ca)
        ])

        self.ca.sign(self.pkey, b'sha256')
        ca_dump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  self.ca)
        with open(self.cert_ts, 'wb') as ca_file:
            ca_file.write(ca_dump)

        if os.path.exists(self.cert_file) and os.access(self.cert_file, os.W_OK):
            os.remove(self.cert_file)
        os.symlink(self.cert_ts, self.cert_file)
        with open(self.chain, 'w') as outfile:
            with open(self.cert_file) as infile:
                outfile.write(infile.read())

        self.index[self.index['current']] = { 'status': 'valid', 'name': self.config['name'] }
        self.index['current'] += 1
        with open(self.index_file, 'w') as outfile:
            yaml.dump(self.index, outfile, default_flow_style=True)
        self.changed = True

    def create_signed_cert(self):
        (self
             .create_request()
             .sign_certificate()
        )

    def create_request(self):
        self.csr_file = self.dir+"/csr/"+self.config['name']+'.pem'+self.timestamp
        self.csr = OpenSSL.crypto.X509Req()
        subject = self.csr.get_subject()
        subject.C = self.config['infos']['country']
        subject.ST = self.config['infos']['state']
        subject.L = self.config['infos']['locality']
        subject.O = self.config['infos']['organization']
        subject.OU = self.config['infos']['organization_unit']
        subject.emailAddress = self.config['infos']['email_address']
        subject.CN = self.config['name']

        self.csr.set_pubkey(self.pkey)
        self.csr.sign(self.pkey, b'sha256')
        req_dump = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM,
                                                           self.csr)
        with open(self.csr_file, 'wb') as req_file:
            req_file.write(req_dump)
        
        csr_symlink = self.csr_file.replace(self.timestamp, '')
        if os.path.exists(csr_symlink) and os.access(csr_symlink, os.W_OK):
            self.add_change('Remove old request symlink {}'.format(csr_symlink))
            os.remove(csr_symlink)         
        os.symlink(self.csr_file, csr_symlink)

        self.changed = True
        return self

    def sign_certificate(self):
        self.cert_ts = self.cert_file+self.timestamp
        self.chain = self.dir+'/certs/chain.pem'

        self.cert = OpenSSL.crypto.X509()
        self.cert.set_version(3)
        self.cert.set_subject(self.csr.get_subject())
        self.cert.set_serial_number(self.index['current'])
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(self.config['days'] * 24 * 60 * 60)
        self.cert.set_issuer(self.root_cert.get_subject())        
        self.cert.set_pubkey(self.csr.get_pubkey())

        if self.is_certificate:
            self.cert.add_extensions([
                OpenSSL.crypto.X509Extension(b"keyUsage", True,
                                            b"digitalSignature, keyEncipherment, dataEncipherment, nonRepudiation"),
                OpenSSL.crypto.X509Extension(b'subjectAltName', False, ('DNS:'+self.config['name']).encode()),
                OpenSSL.crypto.X509Extension(b'extendedKeyUsage', False, b"serverAuth, clientAuth")
            ])
        else:
            self.cert.add_extensions([
                OpenSSL.crypto.X509Extension(b"basicConstraints", True,
                                            b"CA:TRUE, pathlen:0"),
                OpenSSL.crypto.X509Extension(b"keyUsage", True,
                                            b"digitalSignature, cRLSign, keyCertSign, nonRepudiation"),
                OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                            subject=self.cert),
                OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False,
                                            b'keyid:always', issuer=self.root_cert)
            ])

        self.cert.sign(self.root_pkey, b'sha256')

        cert_dump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  self.cert)
        with open(self.cert_ts, 'wb') as cert_file:
            cert_file.write(cert_dump)

        if os.path.exists(self.cert_file) and os.access(self.cert_file, os.W_OK):
            os.remove(self.cert_file)

        os.symlink(self.cert_ts, self.cert_file)

        if not self.is_certificate:
            chains = [ self.cert_file, self.root_chain ]
            with open(self.chain, 'w') as outfile:
                for chain in chains:
                    with open(chain) as infile:
                        outfile.write(infile.read())

        self.index[self.index['current']] = { 'status': 'valid', 'name': self.config['name'] }
        self.index['current'] += 1
        with open(self.index_file, 'w') as outfile:
            yaml.dump(self.index, outfile, default_flow_style=True)
        self.changed = True

        return self

    def delete_cert(self):
        pass

def main():
    module = AnsibleModule(
        argument_spec = dict(
            state             = dict(default='present', choices=['present', 'absent', 'list']),
            config_file       = dict(required=True),
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

#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
module: certificate
author: "Sacha Trémoureux <sacha@tremoureux.fr>"
version_added: "0.3"
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
        )
        for conf_cert in self.config:
            certname = conf_cert['name']
            (self
             .ensure_private_key(certname)
             .ensure_cert(certname)
            )

    def absent(self):
        self.parse_config()
        for conf_cert in self.config:
            certname = conf_cert['name']
            self.delete_cert(certname)

    def listing(self):
        (self
             .parse_config()
             .list_certs()
        )

    def list_certs(self):
        pass
#         list = []
#         self.index_file = self.dir+'/index.yml'
#         self.index_exists = os.path.exists(self.index_file) and os.access(self.index_file, os.R_OK)
#         if self.index_exists:
#             with open(self.index_file, 'r') as data:
#                 self.index = yaml.load(data)
#         for index in self.index:
#             if index != 'current' and self.index[index]['status'] == 'valid':
#                 list.append(self.index[index]['name'])
#         self.module.exit_json(changed=False,certs=list)

    def parse_config(self):
        self.is_certificate = {}
        self.has_root_ca = {}
        self.dir = {}
        self.index = {}
        self.infos = {}
        self.index_file = {}
        self.config = {}
        self.root_dir = {}
        self.pkey_file = {}
        self.pkey = {}
        self.root_certname = {}
        self.root_chain = {}
        self.root_cert = {}
        self.root_cert_file = {}
        self.root_pkey_file = {}
        self.root_pkey = {}
        self.cert_file = {}
        self.cert_ts = {}
        self.csr_file = {}
        self.chain = {}
        self.csr = {}
        self.ca = {}
        self.cert = {}


        with open(self.config_file, 'r') as data:
            self.config = yaml.load(data)
        for conf_cert in self.config:
            certname = conf_cert['name']
            self.is_certificate[certname] = 'is_certificate' in conf_cert and conf_cert['is_certificate']
            self.has_root_ca[certname] = 'root_ca' in conf_cert

            if self.is_certificate[certname]:
                self.root_certname[certname] = conf_cert['root_ca']
                self.root_dir[certname] = self.dir[self.root_certname[certname]]
                self.dir[certname] = self.dir[self.root_certname[certname]]
                self.index_file[certname] = self.dir[certname]+'/index.yml'
            elif self.has_root_ca[certname]:
                self.root_certname[certname] = conf_cert['root_ca']
                self.root_dir[certname] = self.dir[self.root_certname[certname]]
                self.dir[certname] = conf_cert['dir']+'/'+conf_cert['name']
                self.index_file[certname] = self.dir[self.root_certname[certname]]+'/index.yml'
            else:
                self.dir[certname] = conf_cert['dir']+'/'+conf_cert['name']
                self.index_file[certname] = self.dir[certname]+'/index.yml'

            self.infos[certname] = {}
            self.infos[certname]['country'] = conf_cert['infos']['country']
            self.infos[certname]['state'] = conf_cert['infos']['state']
            self.infos[certname]['locality'] = conf_cert['infos']['locality']
            self.infos[certname]['organization'] = conf_cert['infos']['organization']
            self.infos[certname]['organization_unit'] = conf_cert['infos']['organization_unit']
            self.infos[certname]['email_address'] = conf_cert['infos']['email_address']
            self.infos[certname]['days'] = conf_cert['days']
            self.chain[certname] = self.dir[certname]+'/certs/chain.pem'

            self.index_exists = os.path.exists(self.index_file[certname]) and os.access(self.index_file[certname], os.R_OK)
            if self.index_exists:
                with open(self.index_file[certname], 'r') as data:
                    self.index[certname] = yaml.load(data)
            else:
                self.index[certname] = {'current': 1000}
        return self

    def ensure_dirs(self):
        for conf_cert in self.config:
            certname = conf_cert['name']
            if not self.is_certificate[certname]:
                sub_dirs = [ 'certs', 'csr', 'private' ]
                if not os.path.exists(self.dir[certname]):
                  os.makedirs(self.dir[certname])
                  self.changed = True
                for cur_dir in sub_dirs:
                  if not os.path.exists(self.dir[certname]+'/'+cur_dir):
                      os.makedirs(self.dir[certname]+'/'+cur_dir)
                      self.changed = True
                if not self.index_exists:
                    with open(self.index_file[certname], 'w+') as outfile:
                        yaml.dump(self.index[certname], outfile, default_flow_style=True)
        return self

    def ensure_private_key(self, certname):
        self.pkey_file[certname] = self.dir[certname]+'/private/'+certname+'.pem'
        pkey_exists = os.path.exists(self.pkey_file[certname]) and os.access(self.pkey_file[certname], os.R_OK)
        if not pkey_exists:
            pkey = OpenSSL.crypto.PKey()
            pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            pkey_dump = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                        pkey)
            with open(self.pkey_file[certname], 'wb') as keyfile:
                keyfile.write(pkey_dump)
            self.changed = True

        with open(self.pkey_file[certname], 'r') as pkey:
            self.pkey[certname] = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey.read())
        if self.has_root_ca[certname]:
            self.root_pkey_file[certname] = self.root_dir[certname]+'/private/'+self.root_certname[certname]+'.pem'
            with open(self.root_pkey_file[certname], 'r') as pkey:
                self.root_pkey[certname] = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey.read())
        return self

    def ensure_cert(self, certname):
        self.cert_file[certname] = self.dir[certname]+'/certs/'+certname+'.pem'
        if self.is_certificate[certname] or self.has_root_ca[certname]:
            self.root_cert_file[certname] = self.root_dir[certname]+'/certs/'+self.root_certname[certname]+'.pem'
            self.root_chain[certname] = self.root_dir[certname]+'/certs/chain.pem'
            with open(self.root_cert_file[certname], 'r') as certfile:
                self.root_cert[certname] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                           certfile.read())
            if not self.cert_valided(certname) or not self.cert_signed(certname) or self.cert_expired(certname):
                self.create_signed_cert(certname)
        else:
            # Create master CA
            if not self.cert_valided(certname):
                self.create_ca(certname)
            # Renew master CA
            elif self.cert_expired(certname):
                self.root_cert[certname] = self.cert[certname]
                self.root_pkey[certname] = self.pkey[certname]
                self.root_chain[certname] = self.chain[certname]
                self.create_signed_cert(certname)
        return self

    def cert_valided(self, certname):
        cert_exists = os.path.exists(self.cert_file[certname]) and os.access(self.cert_file[certname], os.R_OK)
        if cert_exists:
            with open(self.cert_file[certname], 'r') as certfile:
                self.cert[certname] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                      certfile.read())
        return cert_exists

    def cert_signed(self, certname):
        store = OpenSSL.crypto.X509Store()
        certs = []
        i = 0
        with open(self.root_chain[certname], 'r') as chain:
            for line in chain:
                if line == '-----BEGIN CERTIFICATE-----\n':
                    certs.append('')
                certs[i] += line
                if line == '-----END CERTIFICATE-----\n':
                    i = i+1
        for raw_cert in certs:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, raw_cert)
            store.add_cert(cert)

        context = OpenSSL.crypto.X509StoreContext(store, self.cert[certname])
        signed = True
        try:
            context.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError as context_error:
            signed = False
        return signed

    def cert_expired(self, certname):
        return self.cert[certname].has_expired()

    def ca_exists(self, certname):
        ca_exists = os.path.exists(self.ca_file[certname]) and os.access(self.ca_file[certname], os.R_OK)
        if ca_exists:
            self.ca[certname] = OpenSSL.crypto.X509()
            with open(self.ca_file[certname], 'r') as ca:
                self.ca[certname] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                    ca.read())
            self.ca_private[certname] = OpenSSL.crypto.X509()
            with open(self.ca_private_file[certname], 'r') as ca_private:
                self.ca_private = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                                 ca_private.read())
        return ca_exists

    def create_ca(self, certname):
        self.cert_ts[certname] = self.cert_file[certname]+self.timestamp

        self.ca[certname] = OpenSSL.crypto.X509()
        subject = self.ca[certname].get_subject()
        subject.C = self.infos[certname]['country']
        subject.ST = self.infos[certname]['state']
        subject.L = self.infos[certname]['locality']
        subject.O = self.infos[certname]['organization']
        subject.OU = self.infos[certname]['organization_unit']
        subject.emailAddress = self.infos[certname]['email_address']
        subject.CN = certname
        self.ca[certname].set_version(2)
        self.ca[certname].set_serial_number(self.index[certname]['current'])
        self.ca[certname].gmtime_adj_notBefore(0)
        self.ca[certname].gmtime_adj_notAfter(self.infos[certname]['days'] * 24 * 60 * 60)
        self.ca[certname].set_issuer(self.ca[certname].get_subject())
        self.ca[certname].set_pubkey(self.pkey[certname])
        self.ca[certname].add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints", True,
                                         b"CA:TRUE"),
            OpenSSL.crypto.X509Extension(b"keyUsage", True,
                                         b"digitalSignature, cRLSign, keyCertSign, nonRepudiation"),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                         subject=self.ca[certname])
        ])
        self.ca[certname].add_extensions([
            OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False,
                                         b'keyid:always', issuer=self.ca[certname])
        ])

        self.ca[certname].sign(self.pkey[certname], b'sha256')
        ca_dump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  self.ca[certname])
        with open(self.cert_ts[certname], 'wb') as ca_file:
            ca_file.write(ca_dump)

        if os.path.exists(self.cert_file[certname]) and os.access(self.cert_file[certname], os.W_OK):
            os.remove(self.cert_file[certname])
        os.symlink(self.cert_ts[certname], self.cert_file[certname])
        with open(self.chain[certname], 'w') as outfile:
            with open(self.cert_file[certname]) as infile:
                outfile.write(infile.read())

        self.index[certname][self.index[certname]['current']] = { 'status': 'valid', 'name': certname }
        self.index[certname]['current'] += 1
        with open(self.index_file[certname], 'w') as outfile:
            yaml.dump(self.index[certname], outfile, default_flow_style=True)
        self.changed = True

    def create_signed_cert(self, certname):
        (self
             .create_request(certname)
             .sign_certificate(certname)
        )

    def create_request(self, certname):
        self.csr_file[certname] = self.dir[certname]+"/csr/"+certname+'.pem'+self.timestamp
        self.csr[certname] = OpenSSL.crypto.X509Req()
        subject = self.csr[certname].get_subject()
        subject.C = self.infos[certname]['country']
        subject.ST = self.infos[certname]['state']
        subject.L = self.infos[certname]['locality']
        subject.O = self.infos[certname]['organization']
        subject.OU = self.infos[certname]['organization_unit']
        subject.emailAddress = self.infos[certname]['email_address']
        subject.CN = certname

        self.csr[certname].set_pubkey(self.pkey[certname])
        self.csr[certname].sign(self.pkey[certname], b'sha256')
        req_dump = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM,
                                                           self.csr[certname])
        with open(self.csr_file[certname], 'wb') as req_file:
            req_file.write(req_dump)

        csr_symlink = self.csr_file[certname].replace(self.timestamp, '')
        if os.path.exists(csr_symlink) and os.access(csr_symlink, os.W_OK):
            os.remove(csr_symlink)
        os.symlink(self.csr_file[certname], csr_symlink)

        self.changed = True
        return self

    def sign_certificate(self, certname):
        self.cert_ts[certname] = self.cert_file[certname]+self.timestamp
        self.chain[certname] = self.dir[certname]+'/certs/chain.pem'

        self.cert[certname] = OpenSSL.crypto.X509()
        self.cert[certname].set_version(2)
        self.cert[certname].set_subject(self.csr[certname].get_subject())
        self.cert[certname].set_serial_number(self.index[certname]['current'])
        self.cert[certname].gmtime_adj_notBefore(0)
        self.cert[certname].gmtime_adj_notAfter(self.infos[certname]['days'] * 24 * 60 * 60)
        self.cert[certname].set_issuer(self.root_cert[certname].get_subject())
        self.cert[certname].set_pubkey(self.csr[certname].get_pubkey())

        if self.is_certificate[certname]:
            self.cert[certname].add_extensions([
                OpenSSL.crypto.X509Extension(b"keyUsage", True,
                                            b"digitalSignature, keyEncipherment, dataEncipherment, nonRepudiation"),
                OpenSSL.crypto.X509Extension(b'subjectAltName', False, ('DNS:'+certname).encode()),
                OpenSSL.crypto.X509Extension(b'extendedKeyUsage', False, b"serverAuth, clientAuth")
            ])
        else:
            self.cert[certname].add_extensions([
                OpenSSL.crypto.X509Extension(b"basicConstraints", True,
                                            b"CA:TRUE, pathlen:0"),
                OpenSSL.crypto.X509Extension(b"keyUsage", True,
                                            b"digitalSignature, cRLSign, keyCertSign, nonRepudiation"),
                OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                            subject=self.cert[certname]),
                OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False,
                                            b'keyid:always', issuer=self.root_cert[certname])
            ])

        self.cert[certname].sign(self.root_pkey[certname], b'sha256')

        cert_dump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  self.cert[certname])
        with open(self.cert_ts[certname], 'wb') as cert_file:
            cert_file.write(cert_dump)

        if os.path.exists(self.cert_file[certname]) and os.access(self.cert_file[certname], os.W_OK):
            os.remove(self.cert_file[certname])

        os.symlink(self.cert_ts[certname], self.cert_file[certname])

        if not self.is_certificate[certname]:
            chains = [ self.cert_file[certname], self.root_chain[certname] ]
            with open(self.chain[certname], 'w') as outfile:
                for chain in chains:
                    with open(chain) as infile:
                        outfile.write(infile.read())

        self.index[certname][self.index[certname]['current']] = { 'status': 'valid', 'name': certname }
        self.index[certname]['current'] += 1
        with open(self.index_file[certname], 'w') as outfile:
            yaml.dump(self.index[certname], outfile, default_flow_style=True)
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

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

- name: Create a client certificate request
  certificate_client:
    state: present
    common_name: myclient1.tld
    authority: mysubca
    config: '/opt/mysubca/openssl.cnf'
    informations:
      countryname: FR
      state: 'Loire-Atlantique'
      locality: Nantes
      organization: 'The World Company'
      organization_unit: TechUnit
      email: user@theworldcompany.com

- name: Revoke a client request
  certificate_client:
    common_name: myclient2.tld
    authority: myca
    state: absent
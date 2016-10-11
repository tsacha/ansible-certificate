```ansible
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
    country_name: '{{ countryname }}'
    state_name: '{{ state }}'
    locality: '{{ locality }}'
    organization: '{{ organization }}'
    organization_unit: '{{ organization_unit }}'
    email: '{{ email }}'

- name: create vhosts
  certificate:
    name: '{{ item }}'
    is_certificate: true
    state: present
    config_file: '/opt/interca.cnf'
    country_name: '{{ countryname }}'
    state_name: '{{ state }}'
    locality: '{{ locality }}'
    organization: '{{ organization }}'
    organization_unit: '{{ organization_unit }}'
    email: '{{ email }}'
    extension: server_cert
  with_items:
    - "{{ vhosts.keys() }}"
```
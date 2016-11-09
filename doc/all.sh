rm -Rf /opt/my*
python2 /opt/ansible/hacking/test-module -m /opt/ansible-certificate/certificate.py -a "state=present config_file=/opt/ca.yml"
python2 /opt/ansible/hacking/test-module -m /opt/ansible-certificate/certificate.py -a "state=present config_file=/opt/subca.yml"
python2 /opt/ansible/hacking/test-module -m /opt/ansible-certificate/certificate.py -a "state=present config_file=/opt/site1a.yml"
python2 /opt/ansible/hacking/test-module -m /opt/ansible-certificate/certificate.py -a "state=present config_file=/opt/site2a.yml"
python2 /opt/ansible/hacking/test-module -m /opt/ansible-certificate/certificate.py -a "state=present config_file=/opt/subsubca.yml"
python2 /opt/ansible/hacking/test-module -m /opt/ansible-certificate/certificate.py -a "state=present config_file=/opt/site1b.yml"

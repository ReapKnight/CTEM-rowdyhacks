FROM vulhub/httpd:2.4.50

RUN sed -i 's/Require all denied/Require all granted/g' /usr/local/apache2/conf/httpd.conf \
    && sed -i 's|^#Include conf/extra/httpd-autoindex.conf|Include conf/extra/httpd-autoindex.conf|' /usr/local/apache2/conf/httpd.conf \
    && printf 'CTEM-LAB-PROOF-42013\n' > /tmp/ctem-proof-42013.txt

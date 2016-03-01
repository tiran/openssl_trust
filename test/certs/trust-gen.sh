#!/bin/sh
# Written by Christian Heimes for the OpenSSL project.
set -e

export TRUSTOUTDIR=out
export TRUSTTMPDIR=tmp
export TRUSTTMPROOT=tmp/trust-root
export TRUSTTMPINTERMEDIATE=tmp/trust-intermediate

rm -rf $TRUSTTMPDIR

mkdir -p $TRUSTOUTDIR
mkdir -p $TRUSTTMPDIR
mkdir -p $TRUSTTMPROOT
mkdir -p $TRUSTTMPINTERMEDIATE

touch $TRUSTTMPROOT/trust-root.db
touch $TRUSTTMPROOT/trust-root.db.attr
echo '01' > $TRUSTTMPROOT/trust-root.crt.srl
echo '01' > $TRUSTTMPROOT/trust-root.crl.srl

touch $TRUSTTMPINTERMEDIATE/trust-intermediate.db
touch $TRUSTTMPINTERMEDIATE/trust-intermediate.db.attr
echo '01' > $TRUSTTMPINTERMEDIATE/trust-intermediate.crt.srl
echo '01' > $TRUSTTMPINTERMEDIATE/trust-intermediate.crl.srl

cp *.conf $TRUSTOUTDIR
cp trust-gen.sh $TRUSTOUTDIR

# root CA
openssl req -new \
    -config trust-root.conf \
    -out $TRUSTTMPROOT/trust-root.csr \
    -keyout $TRUSTOUTDIR/trust-root.key \
    -batch

openssl ca -selfsign \
    -config trust-root.conf \
    -in $TRUSTTMPROOT/trust-root.csr \
    -out $TRUSTOUTDIR/trust-root.pem \
    -extensions trust_ca_root_ext \
    -batch

# intermediate CA
openssl req -new \
    -config trust-intermediate.conf \
    -out $TRUSTTMPINTERMEDIATE/trust-intermediate.csr \
    -keyout $TRUSTOUTDIR/trust-intermediate.key \
    -batch

openssl ca \
    -config trust-root.conf \
    -in $TRUSTTMPINTERMEDIATE/trust-intermediate.csr \
    -out $TRUSTOUTDIR/trust-intermediate.pem \
    -policy match_pol \
     -extensions trust_ca_intermediate_ext \
    -batch

# server cert signed by intermediate CA
openssl req -new \
    -config trust-server.conf \
    -out $TRUSTTMPDIR/trust-server.csr \
    -keyout $TRUSTOUTDIR/trust-server.key \
    -batch

openssl ca \
    -config trust-intermediate.conf \
    -in $TRUSTTMPDIR/trust-server.csr \
    -out $TRUSTOUTDIR/trust-server.pem \
    -policy match_pol \
    -extensions server_ext \
    -batch

# client cert signed by intermediate CA
openssl req -new \
    -config trust-client.conf \
    -out $TRUSTTMPDIR/trust-client.csr \
    -keyout $TRUSTOUTDIR/trust-client.key \
    -batch

openssl ca \
    -config trust-intermediate.conf \
    -in $TRUSTTMPDIR/trust-client.csr \
    -out $TRUSTOUTDIR/trust-client.pem \
    -policy match_pol \
    -extensions client_ext \
    -batch

# S/MIME cert signed by intermediate CA
openssl req -new \
    -config trust-smime.conf \
    -out $TRUSTTMPDIR/trust-smime.csr \
    -keyout $TRUSTOUTDIR/trust-smime.key \
    -batch

openssl ca \
    -config trust-intermediate.conf \
    -in $TRUSTTMPDIR/trust-smime.csr \
    -out $TRUSTOUTDIR/trust-smime.pem \
    -policy match_pol \
    -extensions smime_ext \
    -batch

# CA trusted certificates
# (-text doesn't write text to -out)
openssl x509 \
    -in $TRUSTOUTDIR/trust-root.pem \
    -addtrust serverAuth \
    -text \
    > $TRUSTOUTDIR/trust-root.trustserverauth.pem

openssl x509 \
    -in $TRUSTOUTDIR/trust-root.pem \
    -addtrust clientAuth \
    -text \
    > $TRUSTOUTDIR/trust-root.trustclientauth.pem

openssl x509 \
    -in $TRUSTOUTDIR/trust-root.pem \
    -addreject serverAuth \
    -text \
    > $TRUSTOUTDIR/trust-root.rejectserverauth.pem

openssl x509 \
    -in $TRUSTOUTDIR/trust-root.pem \
    -addtrust serverAuth -addreject serverAuth \
    -text \
    > $TRUSTOUTDIR/trust-root.conflictserverauth.pem

openssl x509 \
    -in $TRUSTOUTDIR/trust-root.pem \
    -addtrust emailProtection \
    -text \
    > $TRUSTOUTDIR/trust-root.trustemailprotection.pem


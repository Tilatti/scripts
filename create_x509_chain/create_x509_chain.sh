#!/usr/bin/env bash

# Used documentation:
# https://roll.urown.net/ca/ca_root_setup.html
# https://roll.urown.net/ca/ca_intermed_setup.html

OPENSSL=openssl

if [ $# -ne 2 ]; then
	echo -e "Create a chain of X509 certificates."
	echo -e "Usage: ${0} LEAF_COMMON_NAME DIRECTORY"
	echo -e "Example: ${0} foo.bar.com /home/foo/dir"
	exit -1
fi

LEAF_COMMON_NAME=$1
DIR=$2

if [ ! -d ${DIR} ]; then
	echo -e "Directory ${DIR} not found."
	exit -1
fi

# Create the root certificate ...

ROOT_CRT="${DIR}/root.crt"
ROOT_KEY="${DIR}/root.key"

${OPENSSL} genrsa -out ${ROOT_KEY} 2048
${OPENSSL} req -new -x509 -key ${ROOT_KEY} -out ${ROOT_CRT} -subj "/CN=root_certificate"

# ... some stuff needed for the issued certificates ...

ROOT_INDEX="${DIR}/root.index"
ROOT_SERIAL="${DIR}/root.serial"

touch ${ROOT_INDEX}
${OPENSSL} rand -hex 16 > ${ROOT_SERIAL}

# ... and finally the configuration used to sign the intermediate certificate

ROOT_CONF="${DIR}/root.conf"
cat << EOF > ${ROOT_CONF}
[ca]
default_ca = rootca

[rootca]
dir = ./
new_certs_dir = ${DIR}/
certificate = ${ROOT_CRT}
private_key = ${ROOT_KEY}
database = ${ROOT_INDEX}
default_md = sha256
policy = policy
email_in_dn = no
serial = ${ROOT_SERIAL}
default_days = 30

[policy]
commonName = supplied

[v3_intermediate_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

# Create the intermediate certificate

INTER_CRT="${DIR}/inter.crt"
INTER_CSR="${DIR}/inter.csr"
INTER_KEY="${DIR}/inter.pem"

${OPENSSL} genrsa -out ${INTER_KEY} 2048
${OPENSSL} req -new -key ${INTER_KEY} -out ${INTER_CSR} -subj "/CN=intermediate_certificate"
${OPENSSL} ca -batch -config ${ROOT_CONF} -in ${INTER_CSR} -out ${INTER_CRT} -extensions v3_intermediate_ca

# Verify the intermediate certificate

${OPENSSL} verify -verbose -CAfile ${ROOT_CRT} ${INTER_CRT}
if [ $? -ne 0 ]; then
	echo -e "Certificate verification failed."
	exit -1
fi

# Create the leaf certificate

LEAF_KEY="${DIR}/leaf.key"
LEAF_CSR="${DIR}/leaf.csr"
LEAF_CRT="${DIR}/leaf.crt"

${OPENSSL} genrsa -out ${LEAF_KEY} 2048
${OPENSSL} req -new -key ${LEAF_KEY} -out ${LEAF_CSR} -subj "/CN=${LEAF_COMMON_NAME}"
${OPENSSL} x509 -req -days 30 -in ${LEAF_CSR} -CA ${INTER_CRT} -CAkey ${INTER_KEY} -CAcreateserial -out ${LEAF_CRT}

# Verify the certificate chain

cat ${INTER_CRT} ${LEAF_CRT} | ${OPENSSL} verify -verbose -CAfile ${ROOT_CRT}
if [ $? -ne 0 ]; then
	echo -e "Certificate verification failed."
	exit -1
fi

/*
 * 	Tool: VPNPivot crypto implementation
 *	Next version will support libssl instead
 * 	Author: Simo Ghannam
 * 	Contact: <simo.ghannam@gmail.com>
 * 	Coded: 2015
 *
 * 	Description:
 * 	VPN pivoting tool for penetration testing
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 *      02111-1307  USA
 * 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etn.h"

SSL_CTX *cr_ssl_context(void)
{
	const SSL_METHOD *meth;
	SSL_CTX *ssl;
	
	/* loading ssl features */
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init();	

	/* creat a TLSv1 method instance */
	meth = TLSv1_server_method();
	/* meth = SSLv23_server_method(); */
	ssl = SSL_CTX_new(meth);
	if(!ssl) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	return ssl;
}

SSL_CTX *cr_ssl_context_cli(void)
{
	const SSL_METHOD *meth;
	SSL_CTX *ssl;
	
	/* loading ssl features */
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSL_library_init();	
	/* creat a TLSv1 method instance */
	meth = TLSv1_client_method();
	
	ssl = SSL_CTX_new(meth);
	if(!ssl) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	return ssl;
}

int cr_ssl_connect(struct socket *s)
{
	struct socket *sock;

	sock = s;
	SSL_set_fd(sock->sk_ssl,sock->sk_fd);
	SSL_connect(sock->sk_ssl);
	return -1;
}
/* cr_load_certs : loads private key and certificates from files 
 * if cert_file and key_file are NULL , the function will generate
 * a dynamic certificate and private key
 */
void cr_load_certs(SSL_CTX *ssl,u_char *cert_file,u_char *key_file)
{
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	
	if(cert_file == NULL || key_file == NULL) {
		/* generate a public certificate and a private key */
		
		cr_make_cert(&cert,&pkey,2048,0,365);

		SSL_CTX_use_certificate(ssl, cert);
		SSL_CTX_use_PrivateKey(ssl, pkey);

#ifdef CR_MK_CERT	
		RSA_print_fp(stdout,pkey->pkey.rsa,0);
		X509_print_fp(stdout,cert);
		
		PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
		PEM_write_X509(stdout,cert);
#endif
	} else {
		if (SSL_CTX_use_certificate_file(ssl, (const char*)cert_file,
						 SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}
		if (SSL_CTX_use_RSAPrivateKey_file(ssl, (const char*)key_file,
						SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(4);
		}
	}
	if (!SSL_CTX_check_private_key(ssl)) {
		perrx("Private key does not match the certificate public key\n");		exit(5);
	}
}

/* cr_make_cert generates a server public/private keys 
 * cert : X509 instance
 * pkey : private key instance
 * bits : RSA key length
 * serial : serial number
 * days : how many days the certificate is valid
 */
int cr_make_cert(X509 **cert,EVP_PKEY **pkey,int bits,int serial,int days)
{
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name = NULL;

	if((pkey == NULL) || (*pkey == NULL)) {
		pk = EVP_PKEY_new();
		if(pk == NULL) {
			perrx("EVP_PKEY_new() failed\n");
			return -1;
		}
	} else 
		pk = *pkey;
	
	if((cert == NULL) || (*cert == NULL)) {
		x = X509_new();
		if ((x == NULL)) {
			perrx("X509_new() failed\n");
			return -1;
		} 
	}else
		x= *cert;
	
	/* generate RSA key */
	rsa = RSA_generate_key(bits,RSA_F4,NULL,NULL);
	if(!EVP_PKEY_assign_RSA(pk, rsa)) {
			perrx("X509_new() failed\n");
			return -1;
	}
	rsa = NULL;

	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name,"C",
			MBSTRING_ASC, (const unsigned char *)"UK", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name,"CN",
			MBSTRING_ASC, (const unsigned char*)"VPNPivot", -1, -1, 0);
	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	X509_set_issuer_name(x, name);

	if(!X509_sign(x, pk, EVP_md5())) // secured more with sha1? md5/sha1? sha256?
		abort();

	*cert = x;
	*pkey = pk;

	return 1;
}

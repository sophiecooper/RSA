#include <stdio.h>

#include <gmp.h>

/* Represents an RSA private or public key. If the d member is nonzero, then the
 * key is a private key and can be used in rsa_decrypt or rsa_encrypt.
 * Otherwise, the key is a private key and can be used in rsa_encrypt only. */
struct rsa_key {
	mpz_t d;
	mpz_t e;
	mpz_t n;
};

void rsa_key_init(struct rsa_key *key);

void rsa_key_clear(struct rsa_key *key);

int rsa_key_read(FILE *fp, struct rsa_key *key);

int rsa_key_write(FILE *fp, const struct rsa_key *key);

int rsa_key_load_private(const char *filename, struct rsa_key *key);

int rsa_key_load_public(const char *filename, struct rsa_key *key);

void rsa_encrypt(mpz_t c, const mpz_t m, const struct rsa_key *key);

void rsa_decrypt(mpz_t m, const mpz_t c, const struct rsa_key *key);

void rsa_genkey(struct rsa_key *key, unsigned int numbits);

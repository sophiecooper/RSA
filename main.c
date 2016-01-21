#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa.h"

static int usage(FILE *fp)
{
	return fprintf(fp,
"Usage:\n"
"  rsa encrypt <keyfile> <message>\n"
"  rsa decrypt <keyfile> <ciphertext>\n"
"  rsa genkey <numbits>\n"
	);
}

/* Encode the string s into an integer and store it in x. We're assuming that s
 * does not have any leading \x00 bytes (otherwise we would have to encode how
 * many leading zeros there are). */
static void encode(mpz_t x, const char *s)
{
	mpz_import(x, strlen(s), 1, 1, 0, 0, s);
}

/* Decode the integer x into a NUL-terminated string and return the string. The
 * returned string is allocated using malloc and it is the caller's
 * responsibility to free it. If len is not NULL, store the length of the string
 * (not including the NUL terminator) in *len. */
static char *decode(const mpz_t x, size_t *len)
{
	void (*gmp_freefunc)(void *, size_t);
	size_t count;
	char *s, *buf;

	buf = mpz_export(NULL, &count, 1, 1, 0, 0, x);

	s = malloc(count + 1);
	if (s == NULL)
		abort();
	memmove(s, buf, count);
	s[count] = '\0';
	if (len != NULL)
		*len = count;

	/* Ask GMP for the appropriate free function to use. */
	mp_get_memory_functions(NULL, NULL, &gmp_freefunc);
	gmp_freefunc(buf, count);

	return s;
}

/* The "encrypt" subcommand.
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int encrypt_mode(const char *key_filename, const char *message)
{
	
	mpz_t m, encrypted_m;
	int check;
	struct rsa_key new_key = {};
	rsa_key_init(&new_key);
	mpz_init(m); 
	mpz_init(encrypted_m);
	check = rsa_key_load_public(key_filename, &new_key);
	if (check < 0) {
		return 1;
	}
	encode(m, message);
	rsa_encrypt(encrypted_m, m, &new_key); 
	gmp_printf("%Zd", encrypted_m);
	mpz_clear(m);
	mpz_clear(encrypted_m);
	rsa_key_clear(&new_key);
	
	return 0;
}

/* The "decrypt" subcommand. c_str should be the string representation of an
 * integer ciphertext.
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int decrypt_mode(const char *key_filename, const char *c_str)
{
	mpz_t c, m;
	int check;
	char* m_string;
	struct rsa_key private_key = {};
	rsa_key_init(&private_key);
	check = rsa_key_load_private(key_filename, &private_key);
	if (check < 0) {
		return 1;
	}
	mpz_init(c); 
	mpz_init(m);
	mpz_init_set_str(c, c_str, 10);
	rsa_decrypt(m, c, &private_key);
	size_t str_len = NULL;
	m_string = decode(m, &str_len); // dont know what to input for second argument
	printf("%s", m_string);
	free(m_string);
	mpz_clear(m);
	mpz_clear(c);
	rsa_key_clear(&private_key);
	return 0;
}

/* The "genkey" subcommand. numbits_str should be the string representation of
 * an integer number of bits (e.g. "1024").
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int genkey_mode(const char *numbits_str)
{
	/* TODO */
	struct rsa_key private_key = {};
	unsigned int numbits = 0;
	rsa_key_init(&private_key);
	/* read numbits_str to find numbits */
	numbits = atoi(numbits_str);
	rsa_genkey(&private_key, numbits);
	rsa_key_write(stdout, &private_key);
	rsa_key_clear(&private_key);

	return 1;
}

int main(int argc, char *argv[])
{
	const char *command;

	if (argc < 2) {
		usage(stderr);
		return 1;
	}
	command = argv[1];

	if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "help") == 0) {
		usage(stdout);
		return 0;
	} else if (strcmp(command, "encrypt") == 0) {
		const char *key_filename, *message;

		if (argc != 4) {
			fprintf(stderr, "encrypt needs a key filename and a message\n");
			return 1;
		}
		key_filename = argv[2];
		message = argv[3];

		return encrypt_mode(key_filename, message);
	} else if (strcmp(command, "decrypt") == 0) {
		const char *key_filename, *c_str;

		if (argc != 4) {
			fprintf(stderr, "decrypt needs a key filename and a ciphertext\n");
			return 1;
		}
		key_filename = argv[2];
		c_str = argv[3];

		return decrypt_mode(key_filename, c_str);
	} else if (strcmp(command, "genkey") == 0) {
		const char *numbits_str;

		if (argc != 3) {
			fprintf(stderr, "genkey needs a number of bits\n");
			return 1;
		}
		numbits_str = argv[2];

		return genkey_mode(numbits_str);
	}

	usage(stderr);
	return 1;
}

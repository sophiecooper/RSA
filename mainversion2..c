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
	/*  ROUGH OUTLINE
	* Call rsa_key_init to initialize a key structure
	* Call rsa_key_load_public to load the key from a file
	* Convert message to integer m using the encode function
	* Call rsa_encrypt and output result
	* Call rsa_key_clear to free the public key 
	*/

	
	mpz_t m, encrypted_m;
	/*initialize struct/key to pass in as rsa_key*/
	struct rsa_key new_key = {};
	rsa_key_init(&new_key);
	rsa_key_load_public(key_filename, &new_key);
	mpz_init(m); 
	mpz_init(encrypted_m);
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
	/* ROUGH OUTLINE
	* Call rsa_key_init to initialize a key structure
	* Call rsa_key_load_public to load the key from a file
	* Parse the ciphertext string into an integer c
	* Call rsa_decrypt and store the result in m
	* Convert m to a string and output it (from array to string)
	* Cal rsa_key_clear to free private key 
	*/

	mpz_t m, c;  /* m holds message, c holds ciphertext */
	struct rsa_key new_key = {};
	rsa_key_init(&new_key);
	rsa_key_load_public(key_filename, &new_key);
	mpz_init(m); /*m is message, c is ciphertext*/
	mpz_init(c);


	/*parse the ciphertext from char array */
	encode(c, c_str);
	rsa_decrypt(m, c, &new_key); /* decodes m, stores it in c */
	/* convert m from int to string */
	char *decoded_m;
	size_t str_len = NULL;
	decoded_m = decode(m, &str_len);
	printf("%s\n", decoded_m);

	/* also must free the memory from the decryption fucntion*/
	free(decoded_m);
	mpz_clear(m);
	mpz_clear(c);
	rsa_key_clear(&new_key);


	return 0;
}

/* The "genkey" subcommand. numbits_str should be the string representation of
 * an integer number of bits (e.g. "1024").
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int genkey_mode(const char *numbits_str)
{
	/* ROUGH OUTLINE
	* call rsa_key_init to initialize a key
	* call rsa_genkey
	* call rsa_write(stdout, &key) to output key
	

	struct rsa_key new_key = {};
	rsa_key_init(&new_key);
	rsa_genkey(&new_key, numbits_str);

	rsa_write(stdout, &new_key);
	*/
	return 0;
}

int main(int argc, char *argv[])
{
	/* TEST CODE
	mpz_t a, b, c;

	mpz_init(a);
	mpz_init(b);
	mpz_init(c);

	mpz_set_str(a, "112233445566778899", 10);
	mpz_set_str(b, "998877665544332211", 10);
	
	mpz_mul(c, a, b);
	gmp_printf("%Zd = %Zd * %Zd\n", c, a, b);

	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(c);
	*/


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

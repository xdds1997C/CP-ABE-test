/*
	Include glib.h and pbc.h before including this file.

	This contains data structures and procedures common throughout the
	tools.
*/

/*
	TODO if ssl sha1 not available, use built in one (sha1.c)
*/

char*       suck_file_str( char* file );
char*       suck_stdin();
GByteArray* suck_file( char* file );

void        spit_file( char* file, GByteArray* b, int free );

void read_cpabe_file( char* file,    GByteArray** cph_buf,
											int* file_len, GByteArray** aes_buf );

void write_cpabe_file( char* file,   GByteArray* cph_buf,
											 int file_len, GByteArray* aes_buf );

void die(char* fmt, ...);

GByteArray* aes_128_cbc_encrypt( GByteArray* pt, element_t k );
GByteArray* aes_128_cbc_decrypt( GByteArray* ct, element_t k );

#define CPABE_VERSION PACKAGE_NAME "%s " PACKAGE_VERSION "\n" \
"\n" \
"Parts Copyright (C) 2006, 2007 John Bethencourt and SRI International.\n" \
"This is free software released under the GPL, see the source for copying\n" \
"conditions. There is NO warranty; not even for MERCHANTABILITY or FITNESS\n" \
"FOR A PARTICULAR PURPOSE.\n" \
"\n" \
"Report bugs to John Bethencourt <bethenco@cs.berkeley.edu>.\n"

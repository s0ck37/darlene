/*
 * DEV NOTES
 * 
 * - phex(size) for priting an array (such as key)
 * - debug_arguments(arguments) for debuging the arguments
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "aes.h"

#define ARGS 6         // -> The ammount of arguments

struct Arguments
{
	int arg_encrypt;                // ->    If encrypt flag is invoked
	int arg_decrypt;                // ->    If decrypt flag is invoked
	char arg_target_filename[30];   // ->    Filename enc/dec is called
	int arg_random;                 // -> If random key flag is invoked
	int arg_keyfile;                // ->    If keyfile flag is invoked
	char arg_key_filename[30];      // ->   Filename containing the key
	int arg_stdin;                  // ->  If the stdin flag in invoked
	int arg_help;                   // ->       If help flag is invoked
};

char *flags[] = {
	"--encrypt",
	"--decrypt",
	"--random",
	"--keyfile",
	"--stdin",
	"--help"
};

struct Arguments empty_arguments()
{
	struct Arguments new_arguments;
	new_arguments.arg_encrypt         =  0;
	new_arguments.arg_decrypt         =  0;
	new_arguments.arg_random          =  0;
	new_arguments.arg_keyfile         =  0;
	new_arguments.arg_stdin           =  0;
	new_arguments.arg_help            =  0;
	strcpy(new_arguments.arg_target_filename,"");
	strcpy(new_arguments.arg_key_filename,"");
	return new_arguments;
}

struct Arguments parse_arguments(int argc, char *argv[])
{
	struct Arguments parsed = empty_arguments();
	for(int i = 1; i <= (argc-1); i++)
	{
    int match = -1;
	  for(int t = 0; t < (ARGS); t++)
		{
			int result = strcmp(argv[i],flags[t]);
			if(!result) { match = t; }
		}
		switch(match) // Setting flags if match
		{
			case -1:   printf("Unmatched argument: '%s'\n",argv[i]); break;
			case  0:   parsed.arg_encrypt  = 1; break;     //  Setting the encrypt  flag to true
			case  1:   parsed.arg_decrypt  = 1; break;     //  Setting the decrypt  flag to true
			case  2:   parsed.arg_random   = 1; break;     //  Setting the random   flag to true
			case  3:   parsed.arg_keyfile  = 1; break;     //  Setting the keyfile  flag to true
			case  4:   parsed.arg_stdin    = 1; break;     //  Setting the stdin    flag to true
			case  5:   parsed.arg_help     = 1; break;     //  Setting the help     flag to true
		}
		switch(match) // If ceratin flags are called load the second argument
		{	
			case  0:
			case  1:
				if(i+1 != (argc)) { strcpy(parsed.arg_target_filename,argv[i+1]); i++; }
				break;
			case  3:
				if(i+1 != (argc)) { strcpy(parsed.arg_key_filename,argv[i+1]); i++; }
				break;
		}
	}
	return parsed;
}

int argument_check(struct Arguments arguments)
{
	if(arguments.arg_encrypt  & arguments.arg_decrypt) { return 1; }
	if(arguments.arg_keyfile  & arguments.arg_random ) { return 1; }
	if(arguments.arg_help     & arguments.arg_encrypt) { return 1; }
	if(arguments.arg_help     & arguments.arg_decrypt) { return 1; }
	if(arguments.arg_keyfile  & arguments.arg_stdin)   { return 1; }
	if(arguments.arg_random   & arguments.arg_stdin)   { return 1; }
	if(!((arguments.arg_encrypt || arguments.arg_decrypt) || arguments.arg_help)) { return 1; }
	if(!strcmp(arguments.arg_key_filename,"") & arguments.arg_keyfile)    { return 1; }
	if(!strcmp(arguments.arg_target_filename,"") & arguments.arg_encrypt) { return 1; }
	if(!strcmp(arguments.arg_target_filename,"") & arguments.arg_decrypt) { return 1; }
	return 0;
}

void debug_arguments(struct Arguments arguments)
{
	printf("Encrypt flag:  %d\n",arguments.arg_encrypt);
	printf("Decrypt flag:  %d\n",arguments.arg_decrypt);
	printf("Target file:   '%s'\n",arguments.arg_target_filename);
	printf("Random flag:   %d\n",arguments.arg_random);
	printf("Key file flag: %d\n",arguments.arg_keyfile);
	printf("Key file:      '%s'\n",arguments.arg_key_filename);
	printf("Stding flag:   %d\n",arguments.arg_stdin);
	printf("Help flag:     %d\n",arguments.arg_help);
}

void help()
{
	printf("Give the right instructions to Darlene!\n");
	printf("\n");
	printf("    Basic parameters\n");
	printf("        --encrypt <file>    -> For encrypting a file\n");
	printf("        --decrypt <file>    -> For decrypting a file\n");
	printf("    Key options\n");
	printf("        --random            -> For encrypting with random key\n");
	printf("        --keyfile <file>    -> For loading key from a file\n");
	printf("        --stdin             -> For getting key from stdin\n");
	printf("    Basic usage\n");
	printf("        --help              -> How to give instructions to Darlene\n");
	printf("\n");
}

uint32_t get_file_size(char * filename)
{
	uint32_t size;
	FILE *file_descriptor = fopen(filename,"r");
	if(file_descriptor == NULL) { return -1; }
	fseek(file_descriptor, 0L, SEEK_END);
	size = ftell(file_descriptor);
	fclose(file_descriptor);
	return size;
}

static void phex(uint8_t* str, uint8_t len)
{
	unsigned char i;
	for (i = 0; i < len; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}

int find_offset(int size)
{
	int offset = 16-(size%16);
	if(offset == 16) { return 0; }
  else { return offset; }
}

int main(int argc, char *argv[])
{
  printf("Darlene version: %s\n",VERSION);
	printf("** Darlene is in development phase\n** Do not use it with important files\n");
	
  // -> Checking for the ammount of arguments given
	if(argc < 2) { help(); return 1; }

	// -> Declaring basic variables
	FILE *file_descriptor;
	uint8_t key[32];
	uint8_t iv[16];
	int chr;

	// -> Parsing and checking conflicting arguments
	struct Arguments parsed_arguments = parse_arguments(argc,argv);
	if(argument_check(parsed_arguments)) { printf("Darlene- Wtf dude?\n"); return 1; }
	
	// -> Display help message
	if(parsed_arguments.arg_help) { help(); return 0; }

	// -> Loading key from keyfile
	if(parsed_arguments.arg_keyfile)
	{
		file_descriptor = fopen(parsed_arguments.arg_key_filename, "r");
		if (file_descriptor == NULL)
		{
			printf("Darlene- can't read key file!\n");
			return 1;
		}
		else
		{
			for(int i = 0; i < 32; i++ )
			{
				chr = fgetc(file_descriptor);
				if(chr != EOF) { key[i] = chr; }
				else { i = 32; }
			}
			fclose(file_descriptor);
		}
	}

	// -> Generating random key
	if(parsed_arguments.arg_random)
	{
		srand(time(NULL));
    for(int i = 0; i < 32; i++) { key[i] = (uint8_t)(rand() % 256); }
	}
	
	// -> Getting password from stdin	
	if(parsed_arguments.arg_stdin)
	{
		while(1)
		{
			char *stdin_key = getpass("Encryption key (32 characters limit): ");
      int key_size = strlen(stdin_key);
			if(key_size > 32) { printf("Darlene- c'mon dude... 32 characters!\n"); }
      else
      {
        for(int i = 0; i < key_size%32; i++){ stdin_key[key_size+i] = 0x01; }
        memcpy(key,stdin_key,32);
        break;
      }
		}
	}

	// -> Generating the iv from the key
  for(int i = 0; i < 16; i++) { iv[i] = (uint8_t)((int)key[i]^(int)key[31-i]); }
	
	// -> Getting size of the target file
	uint32_t file_size = get_file_size(parsed_arguments.arg_target_filename);
	if(file_size < 0) { printf("Darlene- can't read target file!\n"); return 1; }
	if(file_size > 0xc800000) { printf("Darlene- can't manage files more than 200 mb!\n"); return 1; }

	// -> Reading file
	int offset = find_offset((int)file_size);
	char data[file_size+offset];
	file_descriptor = fopen(parsed_arguments.arg_target_filename,"r");
	if(file_descriptor == NULL) { printf("Darlene- can't read target file!\n"); return 1; }
	for(int i = 0; i < file_size; i++ )
	{
		chr = (uint8_t)fgetc(file_descriptor);
		if(chr != EOF) { data[i] = chr; }
		else { break; }
	}
	for(int i = 0; i < offset; i++)
		data[i+file_size] = 0x00;
	fclose(file_descriptor);

	// -> Setting up AES
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	// -> Encrypt data
	if(parsed_arguments.arg_encrypt){
		AES_CBC_encrypt_buffer(&ctx, data, file_size+offset);
	}
	// -> Decrypt data
	if(parsed_arguments.arg_decrypt){
		AES_CBC_decrypt_buffer(&ctx, data, file_size+offset);
	}

	// -> Write modified data
	file_descriptor = fopen(parsed_arguments.arg_target_filename,"w");
	if(file_descriptor == NULL)
	{
		printf("Darlene- can't write modified data to file!\n");
		return 1;
	}
	fwrite(data,1,file_size+offset,file_descriptor);
	fclose(file_descriptor);
	printf("Darlene- done!\n");
}

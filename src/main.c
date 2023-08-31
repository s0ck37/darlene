/*
 * DEV NOTES
 *
 * - phex(arrat,size) for priting an array (such as key)
 * - debug_arguments(arguments) for debuging the arguments
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "aes.h"
#include "sha256.h"

#define ARGS 5

struct Arguments {
  int arg_encrypt;
  int arg_decrypt;
  char arg_target_filename[30];
  int arg_random;
  int arg_keyfile;
  char arg_key_filename[30];
  int arg_stdin;
};

char * flags[] = {
  "--encrypt",
  "--decrypt",
  "--random",
  "--keyfile",
  "--stdin"
};

struct Arguments empty_arguments() {
  struct Arguments new_arguments;
  new_arguments.arg_encrypt = 0;
  new_arguments.arg_decrypt = 0;
  new_arguments.arg_random = 0;
  new_arguments.arg_keyfile = 0;
  new_arguments.arg_stdin = 0;
  strcpy(new_arguments.arg_target_filename, "");
  strcpy(new_arguments.arg_key_filename, "");
  return new_arguments;
}

struct Arguments parse_arguments(int argc, char * argv[]) {
  struct Arguments parsed = empty_arguments();
  for (int i = 1; i <= (argc - 1); i++) {
    int match = -1;
    for (int t = 0; t < (ARGS); t++) {
      int result = strcmp(argv[i], flags[t]);
      if (!result) {
        match = t;
      }
    }
    switch (match)
    {
    case -1: printf("Unmatched argument: '%s'\n", argv[i]); break;
    case 0: parsed.arg_encrypt = 1; break;
    case 1: parsed.arg_decrypt = 1; break;
    case 2: parsed.arg_random = 1; break;
    case 3: parsed.arg_keyfile = 1; break;
    case 4: parsed.arg_stdin = 1; break;
    }
    switch (match)
    {
    case 0:
    case 1:
      if (i + 1 != (argc) & strlen(argv[i + 1]) <= 29) {
        strcpy(parsed.arg_target_filename, argv[i + 1]);
        i++;
      }
      break;
    case 3:
      if (i + 1 != (argc) & strlen(argv[i + 1]) <= 29) {
        strcpy(parsed.arg_key_filename, argv[i + 1]);
        i++;
      }
      break;
    }
  }
  return parsed;
}

int argument_check(struct Arguments arguments) {
  if (arguments.arg_encrypt & arguments.arg_decrypt) { return 1; }
  if (arguments.arg_keyfile & arguments.arg_random) { return 1; }
  if (arguments.arg_keyfile & arguments.arg_stdin) { return 1; }
  if (arguments.arg_random & arguments.arg_stdin) { return 1; }
  if (!arguments.arg_keyfile & !arguments.arg_stdin & !arguments.arg_random) { return 1; } 
  if (!strcmp(arguments.arg_key_filename, "") & arguments.arg_keyfile) { return 1; }
  if (!strcmp(arguments.arg_target_filename, "") & arguments.arg_encrypt) { return 1; }
  if (!strcmp(arguments.arg_target_filename, "") & arguments.arg_decrypt) { return 1; }
  return 0;
}

void debug_arguments(struct Arguments arguments) {
  printf("Encrypt flag:  %d\n", arguments.arg_encrypt);
  printf("Decrypt flag:  %d\n", arguments.arg_decrypt);
  printf("Target file:   '%s'\n", arguments.arg_target_filename);
  printf("Random flag:   %d\n", arguments.arg_random);
  printf("Key file flag: %d\n", arguments.arg_keyfile);
  printf("Key file:      '%s'\n", arguments.arg_key_filename);
  printf("Stding flag:   %d\n", arguments.arg_stdin);
}

void help() {
  printf("Give the right instructions to Darlene!\n");
  printf("\n");
  printf("Basic parameters\n");
  printf("  --encrypt <file>    For encrypting a file\n");
  printf("  --decrypt <file>    For decrypting a file\n");
  printf("Key options\n");
  printf("  --random            For encrypting with random key\n");
  printf("  --keyfile <file>    For loading key from a file\n");
  printf("  --stdin             For reading passphrase from stdin\n");
  printf("\n");
}

uint32_t get_file_size(char * filename) {
  uint32_t size;
  FILE * file_descriptor = fopen(filename, "r");
  if (file_descriptor == NULL) {
    return -1;
  }
  fseek(file_descriptor, 0L, SEEK_END);
  size = ftell(file_descriptor);
  fclose(file_descriptor);
  return size;
}

static void phex(uint8_t * str, uint8_t len) {
  unsigned char i;
  for (i = 0; i < len; ++i)
    printf("%.2x", str[i]);
  printf("\n");
}

int find_offset(int size) {
  int offset = 16 - (size % 16);
  if (offset == 16) {
    return 0;
  } else {
    return offset;
  }
}

int main(int argc, char * argv[]) {
  printf("Darlene version: %s\n", VERSION);
  printf("** Darlene is in development phase\n** Do not use it with important files\n");

  // -> Checking for the ammount of arguments given
  if (argc < 2) {
    help();
    return 1;
  }

  // -> Declaring basic variables
  FILE * file_descriptor;
  uint8_t key[32];
  uint8_t iv[16];
  int chr;

  // -> Parsing and checking conflicting arguments
  struct Arguments parsed_arguments = parse_arguments(argc, argv);
  if (argument_check(parsed_arguments)) {
    printf("Bad instructions\n");
    return 1;
  }

  // -> Loading key from keyfile
  if (parsed_arguments.arg_keyfile) {
    file_descriptor = fopen(parsed_arguments.arg_key_filename, "r");
    if (file_descriptor == NULL) {
      printf("Error reading key file\n");
      return 1;
    } else {
      printf("Hashing keyfile\n");
      int n;
      uint8_t cache[8];
      sha256_context sha256_ctx;
      sha256_starts( & sha256_ctx);
      while ((n = fread(cache, 1, sizeof(cache), file_descriptor)) > 0) {
        sha256_update( & sha256_ctx, cache, n);
      }
      sha256_finish( & sha256_ctx, key);
      fclose(file_descriptor);
    }
  }

  // -> Generating random key
  if (parsed_arguments.arg_random) {
    srand(time(NULL));
    printf("Random passphrase option selected (Dangerous)\n");
    printf("Type Y to proceed: ");
    scanf("%c", &chr);
    if(chr != 'Y') { return 1; }
    for (int i = 0; i < 32; i++) {
      key[i] = (uint8_t)(rand() % 256);
    }
  }

  // -> Getting password from stdin	
  if (parsed_arguments.arg_stdin) {
    char * stdin_passphrase = getpass("Encryption passphrase # ");
    int size_passphrase = strlen(stdin_passphrase);
    sha256_context sha256_ctx;
    sha256_starts( & sha256_ctx);
    sha256_update( & sha256_ctx, stdin_passphrase, size_passphrase);
    sha256_finish( & sha256_ctx, key);
  }

  // -> Generating the iv from the key
  for (int i = 0; i < 16; i++) {
    iv[i] = (uint8_t)((int) key[i] ^ (int) key[31 - i]);
  }

  // -> Getting size of the target file
  uint32_t file_size = get_file_size(parsed_arguments.arg_target_filename);
  if (file_size < 0) {
    printf("Target file is not readable\n");
    return 1;
  }
  if (file_size > 0xc800000) {
    printf("Target file is too large\n");
    return 1;
  }

  // -> Reading file
  int offset = find_offset((int) file_size);
  char * data;
  data = (char * ) malloc((file_size + offset) * sizeof(char));
  file_descriptor = fopen(parsed_arguments.arg_target_filename, "r");
  if (file_descriptor == NULL) {
    printf("Target file is not readable\n");
    return 1;
  }
  for (int i = 0; i < file_size; i++) {
    chr = (uint8_t) fgetc(file_descriptor);
    if (chr != EOF) {
      data[i] = chr;
    } else {
      break;
    }
  }
  for (int i = 0; i < offset; i++)
    data[i + file_size] = 0x00;
  fclose(file_descriptor);

  // -> Setting up AES
  struct AES_ctx aes_ctx;
  AES_init_ctx_iv( & aes_ctx, key, iv);

  // -> Encrypt data
  if (parsed_arguments.arg_encrypt) {
    AES_CBC_encrypt_buffer( & aes_ctx, data, file_size + offset);
  }
  // -> Decrypt data
  if (parsed_arguments.arg_decrypt) {
    AES_CBC_decrypt_buffer( & aes_ctx, data, file_size + offset);
  }

  // -> Write modified data
  file_descriptor = fopen(parsed_arguments.arg_target_filename, "w");
  if (file_descriptor == NULL) {
    printf("Error writing modified data\n");
    return 1;
  }
  fwrite(data, 1, file_size + offset, file_descriptor);
  fclose(file_descriptor);

  // -> Free data array
  free(data);
  printf("Job done without errors\n");
}

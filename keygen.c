#include<stdio.h>
#include <cpuid.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>

unsigned char md5digest[16];
unsigned char psn[17];
unsigned char md5decode[33];

enum {
	PATCH = 0,
	DEPATCH = 1,
	GENKEY = 2,
};


void calc_md5(void *data, int len) {
	MD5_CTX mdContext;
	MD5_Init (&mdContext);
	MD5_Update (&mdContext, data, len);
	MD5_Final (md5digest, &mdContext);
}

void patch_app(unsigned char *path) {
	setxattr(path, "user.license", md5decode, 0x21, 0);
}

void genkey_from_psn(unsigned char *psn) {
	calc_md5(psn, 0x10);
	for (int i = 0; i < 16; i++) {
		sprintf(md5decode + i * 2,"%02x", md5digest[15 - i]);
	}
}

void get_psn(unsigned char *psn) {
	unsigned int eax, ebx, ecx, edx, val1, val2;
	__get_cpuid(1, &eax, &ebx, &ecx, &edx);
	val1 = eax << 0x18 | eax >> 0x18 | (eax & 0xff00) << 8 | eax >> 8 & 0xff00;
	val2 = edx << 0x18 | edx >> 0x18 | (edx & 0xff00) << 8 | edx >> 8 & 0xff00;
	snprintf(psn, 17, "%08X%08X", val1, val2);
}

void depatch_app(unsigned char *path) {
	removexattr(path, "user.license");
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s COMMAND -f <patchfile> -i <hardware_id>\n", argv[0]);
		printf("COMMAND:\n");
		printf("\tpatch\tPatch application, -f <patchfile> is required\n");
		printf("\tdepatch\tDepatch application, -f <patchfile> is required\n");
		printf("\tgenkey\tGenerate key\n");
		printf("FLAGS:\n");
		printf("\t-f\tFile to patch\n");
		printf("\t-i\tHardware ID, if not specified, will use current CPU ID\n");
		return 1;
	}

	// Parse arguments
	unsigned char *path = NULL;
	unsigned char *passed_psn = NULL;
	int command = -1;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "patch") == 0 && command == -1) {
			command = PATCH;
		} else if (strcmp(argv[i], "depatch") == 0 && command == -1) {
			command = DEPATCH;
		} else if (strcmp(argv[i], "genkey") == 0 && command == -1) {
			command = GENKEY;
		} else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
			path = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			passed_psn = argv[i + 1];
			i++;
		}
	}

	if (command == -1) {
		printf("No command specified\n");
		return 1;
	}

	if (command == PATCH || command == DEPATCH) {
		if (path == NULL) {
			printf("No file specified\n");
			return 1;
		}
	}

	if (command == PATCH || command == GENKEY) {
		if (passed_psn == NULL) {
			get_psn(psn);
		} else {
			strncpy(psn, passed_psn, 17);
		}
	}

	if (command == PATCH) {
		genkey_from_psn(psn);
		patch_app(path);
		printf("Patched %s with key %s and hardware id %s successfully\n", path, md5decode, psn);
	} else if (command == DEPATCH) {
		depatch_app(path);
		printf("Depatched %s successfully\n", path);
	} else if (command == GENKEY) {
		genkey_from_psn(psn);
		printf("Generated key %s and hardware id %s successfully\n", md5decode, psn);
	}
	

	return 0;
}

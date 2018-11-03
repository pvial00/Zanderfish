#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dyefamily.c"

int rounds = 16;
int keylen = 16;
int j = 0;
int temp[16] = {0};
uint32_t last[2] = {0};
uint32_t next[2] = {0};
int S[4][256];
uint32_t K[16] = {0};

void gen_subkeys(unsigned char * key, int keylen, unsigned char * iv, int ivlen, int rounds) {
    int a = 0;
    int b = 1;
    int c = 2;
    int d = 3;
    int i;
    uint32_t keytemp[(keylen /4)];
    uint32_t temp = 0x00000001;
    for (i = 0; i < (keylen / 4); i++) {
        keytemp[i] = (key[a] << 24) + (key[b] << 16) + (key[c] << 8) + key[d];
	a += 4;
	b += 4;
	c += 4;
	d += 4;
    }
    a = 0;
    b = 1;
    c = 2;
    d = 3;
    for (i = 0; i < (ivlen / 4); i++) {
        keytemp[i] = keytemp[i] ^ ((iv[a] << 24) + (iv[b] << 16) + (iv[c] << 8) + iv[d]);
	a += 4;
	b += 4;
	c += 4;
	d += 4;
    }
    temp = (keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    for (i = 0; i < rounds; i++) {
        temp = (keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
	K[i] = temp;
    }
    temp = (K[0] + keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    last[0] = temp;
    temp = (K[1] + keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    last[1] = temp;

}

void gen_sbox(unsigned char * key, int keylen) {
    int i;
    int s;
    int j;
    int temp;
    for (s = 0; s < 4; s++) {
        for (i = 0; i < 256; i++) {
            S[s][i] = i;
        }
    }
    for (s = 0; s < 4; s++) {
        for (i = 0; i < 256; i++) {
	    j = (j + key[i % keylen]) & 0xFF;
            key[i % keylen] = (key[i % keylen] + key[(i + 1) % keylen] + j) & 0xFF;
	    temp = S[s][i];
            S[s][i] = S[s][j];
	    S[s][j] = temp;
        }
    }
}

uint32_t F(uint32_t xr) {
    int v, x, y, z, a;
    v = (xr & 0xFF000000) >> 24;
    x = (xr & 0x00FF0000) >> 16;
    y = (xr & 0x0000FF00) >> 8;
    z = (xr & 0x000000FF);

    v = v ^ S[0][v];
    x = x ^ S[1][x];
    y = y ^ S[2][y];
    z = z ^ S[3][z];

    v = v ^ S[1][z] + S[2][v];
    x = x ^ S[2][y];
    y = y ^ S[3][x];
    z = z ^ S[0][v];
    xr = (v << 24) + (x << 16) + (y << 8) + z;
    return xr;
}

uint32_t block_encrypt(uint32_t *xl, uint32_t *xr) {
    int i;
    uint32_t temp;
    uint32_t Xl;
    uint32_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = 0; i < rounds; i++) {
        Xr = Xr ^ K[i];
        Xl = Xl ^ F(Xr);

        temp = Xl;
        Xl = Xr;
        Xr = temp;

    }
    temp = Xl;
    Xl = Xr;
    Xr = temp;

    *xl = Xl;
    *xr = Xr;
}

uint32_t block_decrypt(uint32_t *xl, uint32_t *xr) {
    int i;
    uint32_t temp;
    uint32_t Xl;
    uint32_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = (rounds - 1); i != -1; i--) {
        Xl = Xl ^ F(Xr);
        Xr = Xr ^ K[i];

        temp = Xl;
        Xl = Xr;
        Xr = temp;

    }
    temp = Xl;
    Xl = Xr;
    Xr = temp;
    
    *xl = Xl;
    *xr = Xr;
}
    
void usage() {
    printf("zanderfish <encrypt/decrypt> <input file> <output file> <password>\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    FILE *infile, *outfile, *randfile;
    char *in, *out, *mode;
    unsigned char *data = NULL;
    unsigned char *buf = NULL;
    int x = 0;
    int ch;
    int buflen = 8;
    int bsize = 8;
    int iterations = 10000;
    unsigned char *key[keylen];
    unsigned char *password;
    int iv_length = 16;
    unsigned char iv[iv_length];
    unsigned char block[buflen];
    uint32_t xl;
    uint32_t xr;
    if (argc != 5) {
        usage();
    }
    mode = argv[1];
    in = argv[2];
    out = argv[3];
    password = argv[4];
    infile = fopen(in, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(out, "wb");
    int c = 0;
    int b = 0;
    int m = 0;
    if (strcmp(mode, "encrypt") == 0) {
        long blocks = fsize / buflen;
        long extra = fsize % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        randfile = fopen("/dev/urandom", "rb");
        fread(&iv, iv_length, 1, randfile);
        fclose(randfile);
        fwrite(iv, 1, iv_length, outfile);
	unsigned char salt[] = "BlackDyeCipher";
	reddye_kdf(password, key, salt, iterations, keylen);
	gen_subkeys(key, keylen, iv, iv_length, rounds);
	gen_sbox(key, keylen);
	for (int b = 0; b < blocks; b++) {

            fread(block, 1, bsize, infile);
            if (b == (blocks - 1)) {
                for (int p = (bsize - extra) ; p < bsize; p++) {
                    block[p] = extra;
                }
            }

	    xl = (block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3];
	    xr = (block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7];
            xl = xl ^ last[0];
            xr = xr ^ last[1];
	    block_encrypt(&xl, &xr);
            last[0] = xl;
            last[1] = xr;

	    block[0] = (xl & 0xFF000000) >> 24;
	    block[1] = (xl & 0x00FF0000) >> 16;
	    block[2] = (xl & 0x0000FF00) >> 8;
	    block[3] = (xl & 0x000000FF);
	    block[4] = (xr & 0xFF000000) >> 24;
	    block[5] = (xr & 0x00FF0000) >> 16;
	    block[6] = (xr & 0x0000FF00) >> 8;
	    block[7] = (xr & 0x000000FF);
                    
            fwrite(block, 1, bsize, outfile);
	}
    }
    else if (strcmp(mode, "decrypt") == 0) {
        long blocks = (fsize - iv_length) / buflen;
        long extra = (fsize - iv_length) % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        fread(iv, 1, iv_length, infile);
	unsigned char salt[] = "BlackDyeCipher";
	reddye_kdf(password, key, salt, iterations, keylen);
	gen_subkeys(key, keylen, iv, iv_length, rounds);
	gen_sbox(key, keylen);
        for (int d = 0; d < blocks; d++) {
            fread(block, buflen, 1, infile);
	    xl = (block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3];
	    xr = (block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7];
            next[0] = xl;
            next[1] = xr;
	    block_decrypt(&xl, &xr);
            xl = xl ^ last[0];
            xr = xr ^ last[1];
            last[0] = next[0];
            last[1] = next[1];
	    block[0] = (xl & 0xFF000000) >> 24;
	    block[1] = (xl & 0x00FF0000) >> 16;
	    block[2] = (xl & 0x0000FF00) >> 8;
	    block[3] = (xl & 0x000000FF);
	    block[4] = (xr & 0xFF000000) >> 24;
	    block[5] = (xr & 0x00FF0000) >> 16;
	    block[6] = (xr & 0x0000FF00) >> 8;
	    block[7] = (xr & 0x000000FF);
            if (d == (blocks-1)) {
		int count = 0;
		int padcheck = block[7];
		int g = 7;
		for (m = 0; m < padcheck; m++) {
		    if ((int)block[g] == padcheck) {
		        count += 1;
		    }
		    g = (g - 1);
		}
		if (count == padcheck) {
		    bsize = (bsize - count);
		}
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}

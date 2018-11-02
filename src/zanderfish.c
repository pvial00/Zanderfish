#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int rounds = 16;
int keylen = 16;
int j = 0;
int temp[16] = {0};
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

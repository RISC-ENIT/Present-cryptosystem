#include <stdint.h>
#include <stdlib.h>
#include <opencv/cv.h>
#include <opencv/highgui.h>

const uint8_t invsBox4[] = {0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};
const uint8_t sBox4[16] = {0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2};

/* input rotated left (4x) */
#define rotate4l_64(r4lin) ( high4_64(r4lin) | ( r4lin << 4 ) )

/* 4 msb as lsb */
#define high4_64(h4in) ( (uint64_t)h4in >> 60 )
#define BLOCK_SIZE 8

#define KEY_SIZE 10
#define ROUND_KEYS_SIZE 256

#define NUMBER_OF_ROUNDS 31
void RunEncryptionKeySchedule(uint8_t *key, uint64_t *roundKeys)
{
	
	uint64_t keylow = *(uint64_t *)key;
	uint16_t highBytes = *(uint16_t *)(key + 8);
	uint64_t keyhigh = ((uint64_t)(highBytes) << 48) | (keylow >> 16);

	uint64_t temp;
	uint8_t round;
	

	for (round = 0; round < 32; round++)
	{
		/* 61-bit left shift */
		((uint64_t*)roundKeys)[round] = keyhigh;
		temp = keyhigh;
		keyhigh <<= 61;
		keyhigh |= (keylow << 45);
		keyhigh |= (temp >> 19);
		keylow = (temp >> 3) & 0xFFFF;

		/* S-Box application */
		temp = keyhigh >> 60;
		keyhigh &= 0x0FFFFFFFFFFFFFFF;
		temp = sBox4[temp];
		keyhigh |= temp << 60;

		/* round counter addition */
		keylow ^= (((uint64_t)(round + 1) & 0x01) << 15);
		keyhigh ^= ((uint64_t)(round + 1) >> 1);
	}
}



void Encrypt(uint8_t *block, uint64_t *roundKeys)
{
	uint64_t state = *(uint64_t*)block;
	uint64_t temp;
	uint8_t round, k;

	
	for (round = 0; round < 31; round++)
	{
		/* addRoundkey */
		uint32_t subkey_lo = ((uint32_t*)roundKeys)[2 * round];
		uint32_t subkey_hi = ((uint32_t*)roundKeys)[2 * round + 1];
		
		state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

		
		/* sBoxLayer */
		for (k = 0; k < 16; k++)
		{
			/* get lowest nibble */
			uint16_t sBoxValue = state & 0xF;

			/* kill lowest nibble */
			state &= 0xFFFFFFFFFFFFFFF0; 

			/* put new value to lowest nibble (sBox) */
			state |= sBox4[sBoxValue];

			/* next(rotate by one nibble) */
			state = rotate4l_64(state); 
		}
		

		/* pLayer */
		temp = 0;
		for (k = 0; k < 64; k++)
		{
			/* arithmentic calculation of the p-Layer */
			uint16_t position = (16 * k) % 63;

			/* exception for bit 63 */
			if (k == 63)
			{
				position = 63;
			}

			/* result writing */
			temp |= ((state >> k) & 0x1) << position; 
		}
		state = temp;
	}


	/* addRoundkey (Round 31) */
	uint32_t subkey_lo = ((uint32_t*)roundKeys)[62];
	uint32_t subkey_hi = ((uint32_t*)roundKeys)[63];
	
	state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

	
	*(uint64_t*)block = state;
}


void Encrypt_Image(IplImage* img, uint64_t *roundKeys){

CvScalar Pixel;
	int nbrC = img->width;
	int nbrL = img->height;
uint8_t bloc[8];
for (int i = 0; i < nbrL; i++) {
		int j = 0;
		while (j < nbrC){

for(int k=0; k<8;k++){
uint8_t p= (uint8_t)cvGet2D(img,i, j+k).val[0];
bloc[k]=p;
}

Encrypt(bloc,roundKeys);
 
for(int k=0; k<8;k++){
	Pixel.val[0] = bloc[k];

cvSet2D(img, i, j+k, Pixel);

}

j=j+8;
}
}

}

void Decrypt(uint8_t *block, uint64_t *roundKeys)
{
	uint64_t state = *(uint64_t*)block;
	uint64_t temp;
	uint32_t subkey_lo, subkey_hi;
	uint8_t keyindex = 31;
	uint8_t i, k;
	
	
	for (i = 0; i < 31; i++)
	{
		/* addRoundkey */
		subkey_lo = ((uint32_t*)roundKeys)[2 * keyindex];
		subkey_hi = ((uint32_t*)roundKeys)[2 * keyindex + 1];

		state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

		keyindex--;


		/* pLayer */
		temp = 0;
		for (k = 0; k < 64; k++)
		{
			/* arithmetic calculation of the p-Layer */
			uint16_t position = (4 * k) % 63;

			/* exception for bit 63 */
			if (k == 63)
			{										
				position = 63;
			}

			/* result writing */
			temp |= ((state >> k) & 0x1) << position;
		}
		state = temp;


		/* sBoxLayer */
		for (k = 0; k < 16; k++)
		{
			/* get lowest nibble */
			uint16_t sBoxValue = state & 0xF;

			/* kill lowest nibble */			
			state &= 0xFFFFFFFFFFFFFFF0;

			/* put new value to lowest nibble (sbox) */				
			state |= invsBox4[sBoxValue];

			/* next(rotate by one nibble) */				
			state = rotate4l_64(state);						
		}
	}

	
	/* addRoundkey (Round 31) */
	subkey_lo = ((uint32_t*)roundKeys)[2 * keyindex];
	subkey_hi = ((uint32_t*)roundKeys)[2 * keyindex + 1];

	state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

	
	*(uint64_t*)block = state;
}


void Decrypt_Image(IplImage* img, uint64_t *roundKeys){

CvScalar Pixel;
	int nbrC = img->width;
	int nbrL = img->height;
uint8_t bloc[8];
for (int i = 0; i < nbrL; i++) {
		int j = 0;
		while (j < nbrC){

for(int k=0; k<8;k++){
uint8_t p= (uint8_t)cvGet2D(img,i, j+k).val[0];
bloc[k]=p;
}

Decrypt(bloc,roundKeys);
 
for(int k=0; k<8;k++){
	Pixel.val[0] = bloc[k];

cvSet2D(img, i, j+k, Pixel);

}

j=j+8;
}
}

}

static inline uint64_t __cpucycles(){

    uint64_t result;
    //__asm__ __volatile__ ("cpuid" : "=A" (result));
    asm volatile(".byte 15;.byte 49" : "=A" (result));
 // __asm__ __volatile__ ("mfc0 %0,$9; nop" : "=r" (result));
    return result;
}

int main(){
static uint8_t expectedPlaintext[BLOCK_SIZE] = {0xab, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t expectedKey[KEY_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t expectedCiphertext[BLOCK_SIZE] = {0xd2, 0x10, 0x32, 0x21, 0xd3, 0xdc, 0x33, 0x33};
static IplImage* img = cvLoadImage("lena.png", 0);

static uint64_t roundKeys[32];

uint64_t r1=__cpucycles();

RunEncryptionKeySchedule(expectedKey, roundKeys);
Encrypt_Image(img, roundKeys);

uint64_t r2=__cpucycles();
printf("%d \n", r2-r1);

cvSaveImage("resultat.png", img,0);

Decrypt_Image(img, roundKeys);
cvSaveImage("resultat2.png", img,0);

return 0;
}

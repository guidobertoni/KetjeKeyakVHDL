/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

// this test vector generator has been compiled under MS Visual Studio using the keccak code package available https://github.com/gvanas/KeccakCodePackage

//#include "test_crypto_aead.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Ketjev2.h"

int main()
{
	unsigned long long clen, dclen, mlen, adlen,i;
	unsigned char ciphert[200];
	unsigned char deciphert[200];
	unsigned char plaintext[16], AD[16], nonce[16], key[16];

	//test gmu
	/*
	//55565758595A5B5C5D5E5F6061626364
	//unsigned char key[16] = {0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64};
	//unsigned char key[12] = {0xD3, 0x28, 0x4C, 0x67, 0xC9, 0x0A, 0x82, 0x08, 0xE6, 0x0E, 0x0D, 0xB3};
	//unsigned char key[12] = {0x28,0x25,0xC2,0x93,0xD4,0xCF,0x1F,0x9E,0xEB,0x18,0x3B,0x97};
	//unsigned char key[12] = {0x2C,0xCC,0x2A,0x91,0x78,0xA8,0xEB,0x96,0x0A,0x4C,0x23,0xE7};
	//unsigned char key[12] = {0x13,0xB5,0x70,0x1E,0x42,0xF2,0xD8,0x7B,0x03,0xE7,0x0D,0x24};
	unsigned char key[12] = {0xD6,0xFD,0xA0,0xCE,0x41,0xC6,0x0E,0xBE,0x22,0x2E,0x7C,0x54};
	//unsigned char plaintext[16] = {0x14, 0x5e, 0xa8, 0xf2, 0x3d, 0x87, 0xd1, 0x1c ,0x66, 0xb0, 0xfa, 0x45, 0x8f, 0xd9, 0x24, 0x6e};
	//unsigned char plaintext[16] = {0xd0};
	//unsigned char plaintext[16] = {0xde};
	//unsigned char plaintext[32]={	0xBF,0xD9,0x03,0xB7,0x5C,0x46,0xCA,0x49,0x09,0x22,0x62,0xF9,0x0B,0x18,0x27,0x87,0x7E,0x9B,0x19,0x47,0xD1,0x31,0xE3,0x3A,0xE1,0x00,0x00,0x00};
	unsigned char plaintext[100]={0xFE,0x3D,0xDD,0xC2,0xFA,0x14,0xC0,0x9B,0x53,0x8D,
0x57,0x85,0x5E,0xBB,0xAE,0x14,0xF7,0xA4,0x4A,0xCC,
0x9C,0x19,0x5F,0x4F,0xE9,0xFC,0xBA,0x7A,0x68,0xBD,
0x71,0x51,0xCC,0x1F,0xA9,0x26,0x8D,0xB7,0x76,0xE4,
0xA3,0x3A,0xAA,0xDC,0x91,0x14,0xCA,0x5A,0xB7,0x30,
0x2B,0xE7,0xDF,0xF2,0x12,0x33,0x7A,0x4E,0x80,0x46,
0xC6,0x4D,0xF6,0x51,0x2E,0x3B,0xE5,0xAA,0x36,0x5F,
0x87,0x53,0xFE,0x41,0xD5,0xAF,0x2B,0x8C,0x4C,0x38,
0x0D,0x39,0x49,0x38,0x25,0x13,0xCA,0x15,0x7E,0xFF,
0xE7,0xF8,0x6C,0x62,0x13,0xC4,0x1C,0xE8,0x11,0x7E};
	//unsigned char AD[16] = {0x14, 0x5e, 0xa8, 0xf2, 0x3d, 0x87, 0xd1, 0x1c ,0x66, 0xb0, 0xfa, 0x45, 0x8f, 0xd9, 0x24, 0x6e};
	//unsigned char AD[1]={0x3c};
	//unsigned char 	AD[1]={0xbf};
	//unsigned char AD[32]={	0xBF,0xD9,0x03,0xB7,0x5C,0x46,0xCA,0x49,0x09,0x22,0x62,0xF9,0x0B,0x18,0x27,0x87,0x7E,0x9B,0x19,0x47,0xD1,0x31,0xE3,0x3A,0xE1,0x00,0x00,0x00};
	unsigned char AD[100]={0xFE,0x3D,0xDD,0xC2,0xFA,0x14,0xC0,0x9B,0x53,0x8D,
0x57,0x85,0x5E,0xBB,0xAE,0x14,0xF7,0xA4,0x4A,0xCC,
0x9C,0x19,0x5F,0x4F,0xE9,0xFC,0xBA,0x7A,0x68,0xBD,
0x71,0x51,0xCC,0x1F,0xA9,0x26,0x8D,0xB7,0x76,0xE4,
0xA3,0x3A,0xAA,0xDC,0x91,0x14,0xCA,0x5A,0xB7,0x30,
0x2B,0xE7,0xDF,0xF2,0x12,0x33,0x7A,0x4E,0x80,0x46,
0xC6,0x4D,0xF6,0x51,0x2E,0x3B,0xE5,0xAA,0x36,0x5F,
0x87,0x53,0xFE,0x41,0xD5,0xAF,0x2B,0x8C,0x4C,0x38,
0x0D,0x39,0x49,0x38,0x25,0x13,0xCA,0x15,0x7E,0xFF,
0xE7,0xF8,0x6C,0x62,0x13,0xC4,0x1C,0xE8,0x11,0x7E};
	//B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF
	//unsigned char nonce[16] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};
	//unsigned char nonce[64]={0xD0, 0xAA, 0xBE, 0xE0, 0x24, 0xBD, 0x1E, 0x19};
	//unsigned char nonce[64]={0x59,0xB6,0xCA,0x47,0x79,0x6B,0xC9,0xC5};
	//unsigned char nonce[64]={0xE7,0x46,0xD7,0x09,0x70,0x43,0x6B,0xB1};
	unsigned char nonce[64]={0xBC,0xF1,0x18,0x6D,0x16,0x5B,0xA8,0x03};
	*/
			
	FILE* f_datain_ksr,* f_datain_kjr,* f_datain_kmj, * f_datain_kmn;
	FILE* f_dataout_ksr,* f_dataout_kjr,* f_dataout_kmj, * f_dataout_kmn;

	FILE* f_dataindec_ksr,* f_dataindec_kjr,* f_dataindec_kmj, * f_dataindec_kmn;
	FILE* f_dataoutdec_ksr,* f_dataoutdec_kjr,* f_dataoutdec_kmj, * f_dataoutdec_kmn;

	KetjeSr_Instance instance_ksr;
	KetjeJr_Instance instance_kjr;
	KetjeMj_Instance instance_kmj;
	KetjeMn_Instance instance_kmn;

	
	/*
			//test for gmu
	adlen=100;
	mlen=100;
	KetjeJr_Initialize(&instance_kjr, key, 96, nonce, 64);
	
	KetjeJr_FeedAssociatedData(&instance_kjr, AD, adlen);
	KetjeJr_WrapPlaintext(&instance_kjr, plaintext, ciphert, mlen);
	
	clen = mlen;
	KetjeJr_GetTag(&instance_kjr, ciphert+mlen, 8);
	
	mlen=0;
	/*adlen=0;
	mlen=0;
	KetjeMn_Initialize(&instance_kmn, key, 128, nonce, 128);
	
	KetjeMn_FeedAssociatedData(&instance_kmn, AD, adlen);
	KetjeMn_WrapPlaintext(&instance_kmn, plaintext, ciphert, mlen);
	
	clen = mlen;
	KetjeMn_GetTag(&instance_kmn, ciphert+mlen, 16);
	
	*/

	f_datain_ksr=fopen("dataksr.in","w");
	if (f_datain_ksr==NULL){
		printf("Error opening dataksr.in file.\nExiting..");
		return -1;
	}

	f_dataout_ksr=fopen("dataksr.out","w");
	if (f_dataout_ksr==NULL){
		printf("Error opening dataksr.out file.\nExiting..");
		return -1;
	}

	f_datain_kjr=fopen("datakjr.in","w");
	if (f_datain_kjr==NULL){
		printf("Error opening datakjr.in file.\nExiting..");
		return -1;
	}

	f_dataout_kjr=fopen("datakjr.out","w");
	if (f_dataout_kjr==NULL){
		printf("Error opening datakjr.out file.\nExiting..");
		return -1;
	}

	f_datain_kmj=fopen("datakmj.in","w");
	if (f_datain_kmj==NULL){
		printf("Error opening datakmj.in file.\nExiting..");
		return -1;
	}

	f_dataout_kmj=fopen("datakmj.out","w");
	if (f_dataout_kmj==NULL){
		printf("Error opening datakmj.out file.\nExiting..");
		return -1;
	}

	f_datain_kmn=fopen("datakmn.in","w");
	if (f_datain_kmn==NULL){
		printf("Error opening datakmn.in file.\nExiting..");
		return -1;
	}

	f_dataout_kmn=fopen("datakmn.out","w");
	if (f_dataout_kmn==NULL){
		printf("Error opening datakmn.out file.\nExiting..");
		return -1;
	}


	f_dataindec_ksr=fopen("datadecksr.in","w");
	if (f_dataindec_ksr==NULL){
		printf("Error opening datadecksr.in file.\nExiting..");
		return -1;
	}

	f_dataoutdec_ksr=fopen("datadecksr.out","w");
	if (f_dataoutdec_ksr==NULL){
		printf("Error opening datadecksr.out file.\nExiting..");
		return -1;
	}

	f_dataindec_kjr=fopen("datadeckjr.in","w");
	if (f_dataindec_kjr==NULL){
		printf("Error opening datadeckjr.in file.\nExiting..");
		return -1;
	}

	f_dataoutdec_kjr=fopen("datadeckjr.out","w");
	if (f_dataoutdec_kjr==NULL){
		printf("Error opening datadeckjr.out file.\nExiting..");
		return -1;
	}

	f_dataindec_kmj=fopen("datadeckmj.in","w");
	if (f_dataindec_kmj==NULL){
		printf("Error opening datadeckmj.in file.\nExiting..");
		return -1;
	}

	f_dataoutdec_kmj=fopen("datadeckmj.out","w");
	if (f_dataoutdec_kmj==NULL){
		printf("Error opening datadeckmj.out file.\nExiting..");
		return -1;
	}

	f_dataindec_kmn=fopen("datadeckmn.in","w");
	if (f_dataindec_kmn==NULL){
		printf("Error opening datadeckmn.in file.\nExiting..");
		return -1;
	}

	f_dataoutdec_kmn=fopen("datadeckmn.out","w");
	if (f_dataoutdec_kmn==NULL){
		printf("Error opening datadeckmn.out file.\nExiting..");
		return -1;
	}



	for(i=0;i<16;i++)
	{
		plaintext[i]=i;
		AD[i]=i+32;
		nonce[i]=i+64;
		key[i]=i+128;
	}

	for(mlen=1;mlen<17;mlen++){
		for(adlen=1;adlen<17;adlen++){
			fprintf(f_datain_ksr,"#SUV\n");
			fprintf(f_dataindec_ksr,"#SUV\n");
			fprintf(f_datain_ksr,"12\n");
			fprintf(f_dataindec_ksr,"12\n");

			for(i=0;i<16;i++){
				fprintf(f_datain_ksr,"%02X\n",key[i]);
				fprintf(f_dataindec_ksr,"%02X\n",key[i]);
			}
			fprintf(f_datain_ksr,"01\n");
			fprintf(f_dataindec_ksr,"01\n");
			for(i=0;i<16;i++){
				fprintf(f_datain_ksr,"%02X\n",nonce[i]);
				fprintf(f_dataindec_ksr,"%02X\n",nonce[i]);
			}
			fprintf(f_datain_ksr,"01\n");
			fprintf(f_dataindec_ksr,"01\n");
			for(i=0;i<14;i++){
				fprintf(f_datain_ksr,"00\n");
				fprintf(f_dataindec_ksr,"00\n");
			}
			fprintf(f_datain_ksr,"80\n");
			fprintf(f_dataindec_ksr,"80\n");

			fprintf(f_datain_ksr,"#size A\n");
			fprintf(f_dataindec_ksr,"#size A\n");
	

			fprintf(f_datain_ksr,"%d\n",adlen);
			fprintf(f_dataindec_ksr,"%d\n",adlen);
			for(i=0;i<adlen;i++){
				fprintf(f_datain_ksr,"%02X\n",AD[i]);
				fprintf(f_dataindec_ksr,"%02X\n",AD[i]);
			}
			fprintf(f_datain_ksr,"#size B\n");
			fprintf(f_dataoutdec_ksr,"#P\n");
			fprintf(f_datain_ksr,"%d\n",mlen);
			
			for(i=0;i<mlen;i++){
				fprintf(f_datain_ksr,"%02X\n",plaintext[i]);
				fprintf(f_dataoutdec_ksr,"%02X\n",plaintext[i]);
			}			
			    
			KetjeSr_Initialize(&instance_ksr, key, 128, nonce, 128);
			KetjeSr_FeedAssociatedData(&instance_ksr, AD, adlen);
			KetjeSr_WrapPlaintext(&instance_ksr, plaintext, ciphert, mlen);
			clen = mlen;
			KetjeSr_GetTag(&instance_ksr, ciphert+mlen, 16);
			clen += 16;			

			fprintf(f_dataout_ksr,"#C\n");
			fprintf(f_dataindec_ksr,"#C\n");
			fprintf(f_dataindec_ksr,"%d\n",mlen);
			for(i=0;i<clen-16;i++){
			    fprintf(f_dataout_ksr,"%02X\n",ciphert[i]);
				fprintf(f_dataindec_ksr,"%02X\n",ciphert[i]);
			}
	
			fprintf(f_dataout_ksr,"#T\n");
			fprintf(f_dataoutdec_ksr,"#T\n");
			for(i=0;i<16;i++){
				fprintf(f_dataout_ksr,"%02X\n",ciphert[clen-16+i]);
				fprintf(f_dataoutdec_ksr,"%02X\n",ciphert[clen-16+i]);
			}
		}
	}


	for(mlen=1;mlen<17;mlen++){
		for(adlen=1;adlen<17;adlen++){
			fprintf(f_datain_kjr,"#SUV\n");
			fprintf(f_dataindec_kjr,"#SUV\n");
			fprintf(f_datain_kjr,"0E\n");
			fprintf(f_dataindec_kjr,"0E\n");

			for(i=0;i<12;i++){
				fprintf(f_datain_kjr,"%02X\n",key[i]);
				fprintf(f_dataindec_kjr,"%02X\n",key[i]);
			}
			fprintf(f_datain_kjr,"01\n");
			fprintf(f_dataindec_kjr,"01\n");
			for(i=0;i<8;i++){
				fprintf(f_datain_kjr,"%02X\n",nonce[i]);
				fprintf(f_dataindec_kjr,"%02X\n",nonce[i]);
			}
			fprintf(f_datain_kjr,"01\n");
			fprintf(f_dataindec_kjr,"01\n");
			for(i=0;i<1;i++){
				fprintf(f_datain_kjr,"00\n");
				fprintf(f_dataindec_kjr,"00\n");
			}
			fprintf(f_datain_kjr,"80\n");
			fprintf(f_dataindec_kjr,"80\n");

			fprintf(f_datain_kjr,"#size A\n");
			fprintf(f_dataindec_kjr,"#size A\n");
	

			fprintf(f_datain_kjr,"%d\n",adlen);
			fprintf(f_dataindec_kjr,"%d\n",adlen);
			for(i=0;i<adlen;i++){
				fprintf(f_datain_kjr,"%02X\n",AD[i]);
				fprintf(f_dataindec_kjr,"%02X\n",AD[i]);
			}

			fprintf(f_datain_kjr,"#size B\n");
			fprintf(f_dataoutdec_kjr,"#P\n");
			fprintf(f_datain_kjr,"%d\n",mlen);
			for(i=0;i<mlen;i++){
				fprintf(f_datain_kjr,"%02X\n",plaintext[i]);
				fprintf(f_dataoutdec_kjr,"%02X\n",plaintext[i]);
			}			
			    
			KetjeJr_Initialize(&instance_kjr, key, 96, nonce, 64);
			KetjeJr_FeedAssociatedData(&instance_kjr, AD, adlen);
			KetjeJr_WrapPlaintext(&instance_kjr, plaintext, ciphert, mlen);
			clen = mlen;
			KetjeJr_GetTag(&instance_kjr, ciphert+mlen, 8);
			clen += 8;			

			fprintf(f_dataout_kjr,"#C\n");
			fprintf(f_dataindec_kjr,"#C\n");
			fprintf(f_dataindec_kjr,"%d\n",mlen);
			for(i=0;i<clen-8;i++){
			    fprintf(f_dataout_kjr,"%02X\n",ciphert[i]);
				fprintf(f_dataindec_kjr,"%02X\n",ciphert[i]);
			}
	
			fprintf(f_dataout_kjr,"#T\n");
			fprintf(f_dataoutdec_kjr,"#T\n");
			for(i=0;i<8;i++){
				fprintf(f_dataout_kjr,"%02X\n",ciphert[clen-8+i]);
				fprintf(f_dataoutdec_kjr,"%02X\n",ciphert[clen-8+i]);
			}
		}
	}

for(mlen=1;mlen<17;mlen++){
		for(adlen=1;adlen<17;adlen++){
			fprintf(f_datain_kmj,"#SUV\n");
			fprintf(f_dataindec_kmj,"#SUV\n");
			fprintf(f_datain_kmj,"12\n");
			fprintf(f_dataindec_kmj,"12\n");

			for(i=0;i<16;i++){
				fprintf(f_datain_kmj,"%02X\n",key[i]);
				fprintf(f_dataindec_kmj,"%02X\n",key[i]);
			}
			fprintf(f_datain_kmj,"01\n");
			fprintf(f_dataindec_kmj,"01\n");
			for(i=0;i<16;i++){
				fprintf(f_datain_kmj,"%02X\n",nonce[i]);
				fprintf(f_dataindec_kmj,"%02X\n",nonce[i]);
			}
			fprintf(f_datain_kmj,"01\n");
			fprintf(f_dataindec_kmj,"01\n");
			for(i=0;i<(25*8-16-16-4);i++){
				fprintf(f_datain_kmj,"00\n");
				fprintf(f_dataindec_kmj,"00\n");
			}
			fprintf(f_datain_kmj,"80\n");
			fprintf(f_dataindec_kmj,"80\n");

			fprintf(f_datain_kmj,"#size A\n");
			fprintf(f_dataindec_kmj,"#size A\n");
	

			fprintf(f_datain_kmj,"%d\n",adlen);
			fprintf(f_dataindec_kmj,"%d\n",adlen);
			for(i=0;i<adlen;i++){
				fprintf(f_datain_kmj,"%02X\n",AD[i]);
				fprintf(f_dataindec_kmj,"%02X\n",AD[i]);
			}

			fprintf(f_datain_kmj,"#size B\n");
			fprintf(f_dataoutdec_kmj,"#P\n");
			fprintf(f_datain_kmj,"%d\n",mlen);
			for(i=0;i<mlen;i++){
				fprintf(f_datain_kmj,"%02X\n",plaintext[i]);
				fprintf(f_dataoutdec_kmj,"%02X\n",plaintext[i]);
			}			
			    
			KetjeMj_Initialize(&instance_kmj, key, 128, nonce, 128);
			KetjeMj_FeedAssociatedData(&instance_kmj, AD, adlen);
			KetjeMj_WrapPlaintext(&instance_kmj, plaintext, ciphert, mlen);
			clen = mlen;
			KetjeMj_GetTag(&instance_kmj, ciphert+mlen, 16);
			clen += 16;			

			fprintf(f_dataout_kmj,"#C\n");
			fprintf(f_dataindec_kmj,"#C\n");
			fprintf(f_dataindec_kmj,"%d\n",mlen);
			for(i=0;i<clen-16;i++){
			    fprintf(f_dataout_kmj,"%02X\n",ciphert[i]);
				fprintf(f_dataindec_kmj,"%02X\n",ciphert[i]);
			}
	
			fprintf(f_dataout_kmj,"#T\n");
			fprintf(f_dataoutdec_kmj,"#T\n");
			for(i=0;i<16;i++){
				fprintf(f_dataout_kmj,"%02X\n",ciphert[clen-16+i]);
				fprintf(f_dataoutdec_kmj,"%02X\n",ciphert[clen-16+i]);
			}
		}
	}

for(mlen=1;mlen<17;mlen++){
		for(adlen=1;adlen<17;adlen++){
			fprintf(f_datain_kmn,"#SUV\n");
			fprintf(f_dataindec_kmn,"#SUV\n");
			fprintf(f_datain_kmn,"12\n");
			fprintf(f_dataindec_kmn,"12\n");

			for(i=0;i<16;i++){
				fprintf(f_datain_kmn,"%02X\n",key[i]);
				fprintf(f_dataindec_kmn,"%02X\n",key[i]);
			}
			fprintf(f_datain_kmn,"01\n");
			fprintf(f_dataindec_kmn,"01\n");
			for(i=0;i<16;i++){
				fprintf(f_datain_kmn,"%02X\n",nonce[i]);
				fprintf(f_dataindec_kmn,"%02X\n",nonce[i]);
			}
			fprintf(f_datain_kmn,"01\n");
			fprintf(f_dataindec_kmn,"01\n");
			for(i=0;i<(25*4-16-16-4);i++){
				fprintf(f_datain_kmn,"00\n");
				fprintf(f_dataindec_kmn,"00\n");
			}
			fprintf(f_datain_kmn,"80\n");
			fprintf(f_dataindec_kmn,"80\n");

			fprintf(f_datain_kmn,"#size A\n");
			fprintf(f_dataindec_kmn,"#size A\n");
	
			fprintf(f_datain_kmn,"%d\n",adlen);
			fprintf(f_dataindec_kmn,"%d\n",adlen);
			for(i=0;i<adlen;i++){
				fprintf(f_datain_kmn,"%02X\n",AD[i]);
				fprintf(f_dataindec_kmn,"%02X\n",AD[i]);
			}

			fprintf(f_datain_kmn,"#size B\n");
			fprintf(f_dataoutdec_kmn,"#P\n");
			fprintf(f_datain_kmn,"%d\n",mlen);
			for(i=0;i<mlen;i++){
				fprintf(f_datain_kmn,"%02X\n",plaintext[i]);
				fprintf(f_dataoutdec_kmn,"%02X\n",plaintext[i]);
			}			
			    
			KetjeMn_Initialize(&instance_kmn, key, 128, nonce, 128);
			KetjeMn_FeedAssociatedData(&instance_kmn, AD, adlen);
			KetjeMn_WrapPlaintext(&instance_kmn, plaintext, ciphert, mlen);
			clen = mlen;
			KetjeMn_GetTag(&instance_kmn, ciphert+mlen, 16);
			clen += 16;			

			fprintf(f_dataout_kmn,"#C\n");
			fprintf(f_dataindec_kmn,"#C\n");
			fprintf(f_dataindec_kmn,"%d\n",mlen);
			for(i=0;i<clen-16;i++){
			    fprintf(f_dataout_kmn,"%02X\n",ciphert[i]);
				fprintf(f_dataindec_kmn,"%02X\n",ciphert[i]);
			}
	
			fprintf(f_dataout_kmn,"#T\n");
			fprintf(f_dataoutdec_kmn,"#T\n");
			for(i=0;i<16;i++){
				fprintf(f_dataout_kmn,"%02X\n",ciphert[clen-16+i]);
				fprintf(f_dataoutdec_kmn,"%02X\n",ciphert[clen-16+i]);
			}
		}
	}

    fclose(f_dataout_kjr);
	fclose(f_datain_kjr);
	fclose(f_datain_ksr);
	fclose(f_dataout_ksr);

	fclose(f_datain_kmn);
	fclose(f_dataout_kmn);

	fclose(f_datain_kmj);
	fclose(f_dataout_kmj);

	fclose(f_dataoutdec_kjr);
	fclose(f_dataindec_kjr);
	fclose(f_dataindec_ksr);
	fclose(f_dataoutdec_ksr);

	fclose(f_dataindec_kmn);
	fclose(f_dataoutdec_kmn);

	fclose(f_dataindec_kmj);
	fclose(f_dataoutdec_kmj);

	return 0;
}

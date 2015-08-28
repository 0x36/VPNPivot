/*
 * 	Tool: VPNPivot crypto (VERY BUGGY) dummy implementation
 *	Next version will support libssl instead
 * 	Author: Simo Ghannam
 * 	Contact: <simo.ghannam@gmail.com>
 * 	Coded: 2015
 *
 * 	Description:
 * 	VPN pivoting tool for penetration testing
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 *      02111-1307  USA
 * 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etn.h"

void rc4_key_sched(unsigned char *key_data,unsigned int key_len,struct rc4_context *ctx)
{
	int i;
	unsigned char idx1,idx2;
	unsigned char *state;
	
	state = &ctx->state[0];
	
	for(i=0;i<256;i++) 
		state[i] = i;
	ctx->x = ctx->y = idx1 = idx2 = 0;
	
	for(i=0;i<256;i++) {
		idx2 = (key_data[idx1] +state[i] + idx2) %256;
		SWAP_BYTES(&state[i],&state[idx2]);
		idx1 = (idx1 + 1) % key_len;
	}
}

void rc4_cipher(unsigned char *buf,unsigned int buflen,struct rc4_context *ctx)
{
	
	unsigned char x,y,xoridx;
	unsigned char *state;
	int i;
	
	x = ctx->x;
	y = ctx->y;
	
	state = &ctx->state[0];
	for(i=0;i<buflen;i++) {
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		SWAP_BYTES(&state[x],&state[y]);
		xoridx = ( state[x] + state[y]) % 256;
		buf[i] ^= state[xoridx];
	}
	ctx->x = x;
	ctx->y = y;
}

void rc4_prepare_shared_key(struct rc4_context *ctx,unsigned char *shr_key)
{
	unsigned char seed[256];
	unsigned char *skey;
	unsigned int keylen,hex;
	unsigned char digit[5];
	int i;

	memset(seed,0,256);
	memset(digit,0,5);

	keylen = strlen((const char*)shr_key);
	skey = (unsigned char *)malloc(keylen +1);
	if(!skey)
		return;

	memset(skey,0,keylen+1);
	memcpy(skey,shr_key,keylen);
	if(keylen & 1) {
		strcat((char*)skey,"A");
		keylen++;
	}
	keylen /= 2;
	memcpy(digit,"AA",2);
	digit[4]='\0';
	
	for(i=0;i<keylen;i++) {
		digit[2] = skey[i*2];
		digit[3] = skey[i*2+1];
		sscanf((const char*)digit,"%x",&hex);
		seed[i] = hex;
	}
	rc4_key_sched(seed,keylen,ctx);
}

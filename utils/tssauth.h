/********************************************************************************/
/*										*/
/*			     TSS Authorization 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: tssauth.h 1124 2018-01-05 21:32:55Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* This is not a public header.  It should not be used by applications. */

#ifndef TSS_AUTH_H
#define TSS_AUTH_H

#include <tss2/tss.h>
#include "Commands_fp.h"
#include <tssccattributes.h>

typedef struct TSS_AUTH_CONTEXT TSS_AUTH_CONTEXT;

TPM_RC TSS_AuthCreate(TSS_AUTH_CONTEXT **tssAuthContext);

void TSS_InitAuthContext(TSS_AUTH_CONTEXT *tssAuthContext);

TPM_RC TSS_AuthDelete(TSS_AUTH_CONTEXT *tssAuthContext);

TPM_RC TSS_Marshal(TSS_AUTH_CONTEXT *tssAuthContext,
		   COMMAND_PARAMETERS *in,
		   TPM_CC commandCode);

TPM_RC TSS_Unmarshal(TSS_AUTH_CONTEXT *tssAuthContext,
		     RESPONSE_PARAMETERS *out);

TPM_RC TSS_SetCmdAuths(TSS_AUTH_CONTEXT *tssAuthContext, ...);

TPM_RC TSS_GetRspAuths(TSS_AUTH_CONTEXT *tssAuthContext, ...);

TPM_CC TSS_GetCommandCode(TSS_AUTH_CONTEXT *tssAuthContext);

TPM_RC TSS_GetCpBuffer(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint32_t *cpBufferSize,
		       uint8_t **cpBuffer);

TPM_RC TSS_GetCommandDecryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				  uint32_t *decryptParamSize,
				  uint8_t **decryptParamBuffer);

TPM_RC TSS_SetCommandDecryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				  uint32_t encryptParamSize,
				  uint8_t *encryptParamBuffer);

TPM_RC TSS_GetCommandHandleCount(TSS_AUTH_CONTEXT *tssAuthContext,
				 size_t *commandHandleCount);

AUTH_ROLE TSS_GetAuthRole(TSS_AUTH_CONTEXT *tssAuthContext,
			  size_t handleIndex);

TPM_RC TSS_GetCommandHandle(TSS_AUTH_CONTEXT *tssAuthContext,
			    TPM_HANDLE *commandHandle,
			    size_t index);

TPM_RC TSS_GetRpBuffer(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint32_t *rpBufferSize,
		       uint8_t **rpBuffer);

TPM_RC TSS_GetResponseEncryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				   uint32_t *encryptParamSize,
				   uint8_t **encryptParamBuffer);

TPM_RC TSS_SetResponseDecryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				   uint32_t decryptParamSize,
				   uint8_t *decryptParamBuffer);

TPM_RC TSS_AuthExecute(TSS_CONTEXT *tssContext);

#endif

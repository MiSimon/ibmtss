/********************************************************************************/
/*										*/
/*			   ECC_Decrypt						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2022						*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    ECC_Decrypt_In 		in;
    ECC_Decrypt_Out 		out;
    TPMI_DH_OBJECT		keyHandle = 0;
    const char			*keyPassword = NULL;
    const char			*keyPasswordFilename = NULL;
    uint8_t			*keyPasswordBuffer = NULL;
    size_t 			keyPasswordBufferLength = 0;
    const char			*keyPasswordPtr = NULL;
    const char			*decryptFilename = NULL;
    const char			*c1Filename = NULL;
    const char			*c2Filename = NULL;
    const char			*c3Filename = NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    /* command line argument defaults */
    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA256;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPasswordFilename = argv[i];
	    }
	    else {
		printf("-ipwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-od") == 0) {
	    i++;
	    if (i < argc) {
		decryptFilename = argv[i];
	    }
	    else {
		printf("-od option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -halg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ic1") == 0) {
	    i++;
	    if (i < argc) {
		c1Filename = argv[i];
	    }
	    else {
		printf("-ic1 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ic2") == 0) {
	    i++;
	    if (i < argc) {
		c2Filename = argv[i];
	    }
	    else {
		printf("-ic2 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ic3") == 0) {
	    i++;
	    if (i < argc) {
		c3Filename = argv[i];
	    }
	    else {
		printf("-ic3 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if ((c1Filename == NULL) ||
	(c2Filename == NULL) ||
	(c3Filename  == NULL)) {
	printf("Missing input -ic1 -ic2 -ic3\n");
	printUsage();
    }
    if ((keyPassword != NULL) && (keyPasswordFilename != NULL)) {
	printf("Only one of -pwdk and -ipwdk can be specified\n");
	printUsage();
    }
    if (rc == 0) {
	/* use passsword from command line */
	if (keyPassword != NULL) {
	    keyPasswordPtr = keyPassword;
	}
	/* use password from file */
	else if (keyPasswordFilename != NULL) {
	    rc = TSS_File_ReadBinaryFile(&keyPasswordBuffer,     /* freed @2 */
					 &keyPasswordBufferLength,
					 keyPasswordFilename);
	    if ((keyPasswordBufferLength == 0) ||
		(keyPasswordBuffer[keyPasswordBufferLength -1] != '\0')) {
		printf("-ipwdk file must be nul terminated\n");
		printUsage();
	    }
	    keyPasswordPtr = (const char *)keyPasswordBuffer;
	}
	/* empty password */
	else {
	    keyPasswordPtr = NULL;
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    if ((rc == 0) && (c1Filename != NULL)) {
	rc = TSS_File_ReadStructure(&in.C1,
				    (UnmarshalFunction_t)TSS_TPM2B_ECC_POINT_Unmarshalu,
				    c1Filename);
    }
    if ((rc == 0) && (c2Filename != NULL)) {
	rc = TSS_File_ReadStructure(&in.C2,
				    (UnmarshalFunction_t)TSS_TPM2B_MAX_BUFFER_Unmarshalu,
				    c2Filename);
    }
    if ((rc == 0) && (c3Filename != NULL)) {
 	rc = TSS_File_ReadStructure(&in.C3,
				    (UnmarshalFunction_t)TSS_TPM2B_DIGEST_Unmarshalu,
				    c3Filename);
    }
    if (rc == 0) {
	/* Handle of key that will perform eccdecrypting */
	in.keyHandle = keyHandle;
	/* the only scheme that the TPM supports */
	in.inScheme.scheme = TPM_ALG_KDF2;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
        printf("password is %s\n", keyPasswordPtr);
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ECC_Decrypt,
			 sessionHandle0, keyPasswordPtr, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(out.plainText.t.buffer,
				      out.plainText.t.size,
				      decryptFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("eccdecrypt: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("eccdecrypt: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("eccdecrypt\n");
    printf("\n");
    printf("Runs TPM2_ECC_Decrypt\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t[-pwdk\tpassword for key (default empty)[\n");
    printf("\t[-ipwdk\tpassword file for key, nul terminated (default empty)]\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t-od\tdecrypt file name\n");
    printf("\t-ic1\tC1 ECC point file name\n");
    printf("\t-ic2\tC2 data buffer file name\n");
    printf("\t-ic3\tc3 integrity digest file name\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);
}
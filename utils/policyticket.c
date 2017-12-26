/********************************************************************************/
/*										*/
/*			    PolicyTicket	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: policyticket.c 1072 2017-09-11 19:55:31Z kgoldman $		*/
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

/* 

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    PolicyTicket_In 		in;
    TPMI_SH_POLICY		policySession = 0;
    const char 			*timeoutFilename = NULL;
    const char 			*cpHashAFilename = NULL;
    const char			*policyRefFilename = NULL;
    const char 			*authNameFilename = NULL;
    char 			hierarchyChar = 0;
    TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_NULL;
    const char			*ticketFilename = NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    in.cpHashA.b.size = 0;
    in.policyRef.b.size = 0;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &policySession);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-to") == 0) {
	    i++;
	    if (i < argc) {
		timeoutFilename = argv[i];
	    }
	    else {
		printf("-to option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-cp") == 0) {
	    i++;
	    if (i < argc) {
		cpHashAFilename = argv[i];
	    }
	    else {
		printf("-cp option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pref") == 0) {
	    i++;
	    if (i < argc) {
		policyRefFilename = argv[i];
	    }
	    else {
		printf("-pref option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-na") == 0) {
	    i++;
	    if (i < argc) {
		authNameFilename = argv[i];
	    }
	    else {
		printf("-na option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hi") == 0) {
	    i++;
	    if (i < argc) {
		hierarchyChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hi\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-tk") == 0) {
	    i++;
	    if (i < argc) {
		ticketFilename = argv[i];
	    }
	    else {
		printf("-tk option needs a value\n");
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
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (policySession == 0) {
	printf("Missing handle parameter -ha\n");
	printUsage();
    }
    if (timeoutFilename == NULL) {
	printf("Missing timeout file name parameter -to\n");
	printUsage();
    }
    if (ticketFilename == NULL) {
	printf("Missing ticket file name parameter -tk\n");
	printUsage();
    }
    if ((authNameFilename == NULL) && (hierarchyChar == 0)) {
	printf("Missing parameter -na or -hi\n");
	printUsage();
    }
    if ((authNameFilename != NULL) && (hierarchyChar != 0)) {
	printf("Cannot specify both -na and -hi\n");
	printUsage();
    }
    if (rc == 0) {
	in.policySession = policySession;
    }
    if (rc == 0) {
	rc = TSS_File_Read2B(&in.timeout.b,
			     sizeof(TPMU_HA),
			     timeoutFilename);
    }
    if ((rc == 0) && (cpHashAFilename != NULL)) {
	rc = TSS_File_Read2B(&in.cpHashA.b,
			     sizeof(TPMU_HA),
			     cpHashAFilename);
    }
    if ((rc == 0) && (policyRefFilename != NULL)) {
	rc = TSS_File_Read2B(&in.policyRef.b,
			     sizeof(TPMU_HA),
			     policyRefFilename);
    }
    /* if the authorizing entity was an object */
    if ((rc == 0) && (authNameFilename != NULL)) {
	rc = TSS_File_Read2B(&in.authName.b,
			     sizeof(TPMU_NAME),
			     authNameFilename);
    }
    /* if the authorizing object was a hierarchy */
    if ((rc == 0) && (hierarchyChar != 0)) {
	if (hierarchyChar == 'e') {
	    primaryHandle = TPM_RH_ENDORSEMENT;
	}
	else if (hierarchyChar == 'o') {
	    primaryHandle = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    primaryHandle = TPM_RH_PLATFORM;
	}
	else {
	    printf("Bad parameter %c for -hi\n", hierarchyChar);
	    printUsage();
	}
	rc = TSS_TPM2B_CreateUint32(&in.authName.b, primaryHandle, sizeof(TPMU_NAME));
    }
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&in.ticket,
				    (UnmarshalFunction_t)TPMT_TK_AUTH_Unmarshal,
				    ticketFilename);
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyTicket,
			 sessionHandle0, NULL, sessionAttributes0,
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
	if (verbose) printf("policyticket: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("policyticket: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("policyticket\n");
    printf("\n");
    printf("Runs TPM2_PolicyTicket\n");
    printf("\n");
    printf("\t-ha policy session handle\n");
    printf("\t-to timeout file name\n");
    printf("\t-cp cpHash file (default none)\n");
    printf("\t-pref policyRef file (default none)\n");
    printf("\t-na authName file (not hierarchy)\n");
    printf("\t-hi hierarchy (e, o, p)(authName is hierarchy)\n");
    printf("\t\te endorsement, o owner, p platform\n");
    printf("\t-tk ticket file name\n");
    exit(1);	
}

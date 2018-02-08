/********************************************************************************/
/*										*/
/*			   Time a TPM Command					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: timepacket.c 1140 2018-01-22 15:13:31Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2017.						*/
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
#include <time.h>

#include <unistd.h>

#include <openssl/rand.h>

#include <tss2/tss.h>
#include <tss2/tsstransmit.h>
#include <tss2/tssfile.h>
#include <tss2/tssresponsecode.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    	/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    const char			*commandFilename = NULL;
    unsigned char 		*commandBufferString = NULL;
    unsigned char 		*commandBuffer = NULL;
    size_t 			commandStringLength;
    size_t 			commandLength;
    unsigned int 		loops = 1;
    unsigned int 		count;
    uint8_t 			responseBuffer[MAX_RESPONSE_SIZE];;
    uint32_t 			responseLength;
    time_t 			startTime;
    time_t			endTime;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		commandFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-l") == 0) {
	    i++;
	    if (i < argc) {
		loops = atoi(argv[i]);
	    }
	    else {
		printf("-l option needs a value\n");
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
    if (commandFilename == NULL) {
	printf("Missing parameter -if\n");
	printUsage();
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&commandBufferString, &commandStringLength, commandFilename);
    }
    if (rc == 0) {
	if (commandBufferString[commandStringLength-1] != ' ') {
	    printf("packet string does not end in a space\n");
	}
	else {
	    /* nul terminate the string */
	    commandBufferString[commandStringLength-1] = '\0';
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Scan(&commandBuffer,		/* freed @1 */
			    &commandLength, (char *)commandBufferString);
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    double timeDiff = 0;
    for (count = 0 ; (rc == 0) && (count < loops) ; count++) {
	uint32_t usec;
	RAND_bytes((unsigned char *)&usec, sizeof(uint32_t));
	usec %= 1000000;
	usleep(usec);
	startTime = time(NULL);
	rc = TSS_Transmit(tssContext,
			  responseBuffer, &responseLength,
			  commandBuffer, commandLength,
			  NULL);
	endTime = time(NULL);
	printf("End Pass %u\n", count +1);
 	timeDiff += difftime(endTime, startTime);
   }
    if (rc == 0) {
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printf("Loops %u time %f time per pass %f\n", loops, timeDiff, timeDiff/loops);
    }
    if (rc == 0) {
	if (verbose) printf("timepacket: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("timepacket: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(commandBufferString);
    free(commandBuffer);		/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("timepacket\n");
    printf("\n");
    printf("Times the supplied packet\n");
    printf("\n");
    printf("\t-if packet in hexascii (requires one space at end of packet)\n");
    printf("\t[-l number of loops to time (default 1)]\n");
    exit(1);	
}

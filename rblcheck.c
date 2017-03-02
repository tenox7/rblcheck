/*
 * RBLCHECK - Realtime Blacklist Checker for MAILsweeper
 * Version 2.0 FINAL; For MAILsweeper 4.3;  June 05 2003
 * Copyright (c) 2003 by Antoni Sawicki <tenox@tenox.tc>
 *
 */

#define RBLV "RBLCHECK: v2.0 FINAL by Antoni Sawicki <tenox@tenox.tc>; " __DATE__ " " __TIME__ ";\n"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windns.h>
#include "regex.h"

#pragma comment(lib, "dnsapi.lib" )
#pragma comment(lib, "regex.lib" )
#pragma comment(lib, "ws2_32.lib" )
#pragma comment(exestr, RBLV)

//exit codes
#define NONE		0
#define DETECTED	1
#define	NOT_CHECKED	2

//line parsing and regex settings
#define MAXLINE 1024
#define SEPARATORS " ,;:<>[]{}()/\\|!@#$%^&*_=+\"'`\t\n\r"
#define REGEX_SIZE 256
#define IPADDR_PAT "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"

struct RBLSERVER {
	char name[256];
	struct RBLSERVER *next;
};



int main(int argc, char* argv[]){
	
	char line[MAXLINE], logbuff[MAXLINE], query_str[256], revip_str[64];
	char *rblservers, *filename, *logfile, *token;
	int n=0,positive=0, negative=0, minmatches=0, ip_n=0, token_n=0, line_n=0, in_header=0;
	int DEBUG=0, LAST=0, HEADER=0, CACHE=0, DNS_OPTS;

	regex_t re_ipaddr;

	FILE *inputf, *logf;
	IN_ADDR revip;
	DNS_STATUS query_status;
	PDNS_RECORD dns_reply;

	struct RBLSERVER *rblserver_root;
	struct RBLSERVER *rblserver;


	//parse args

	if(argc<5) {
		fprintf(stderr, "%s\nUsage:\nrblcheck.exe [-d] [-l] [-h] [-c] <#_matches> <rblservers> <message> <logfile>\n", RBLV);
		exit(NOT_CHECKED);
	} 

	for(n=1;n<=argc;n++) {
		if(strcmp(argv[n], "-d")==0) {
			DEBUG=1;
		} 
		else if(strcmp(argv[n], "-l")==0) {
			LAST=1;
		} 
		else if(strcmp(argv[n], "-c")==0) {
			CACHE=1;
		}
		else if(strcmp(argv[n], "-h")==0) {
			HEADER=1;
		}
		else {
			minmatches=atoi(argv[n++]);
			rblservers=argv[n++];
			filename=argv[n++];
			logfile=argv[n++];
			break;
		}
	}

	logf=fopen(logfile, "w");
	if(logf==NULL) {
		fprintf(stderr, "ERROR: Unable to open/create logfile!\n");
		exit(NOT_CHECKED);
	}

	if(minmatches<1) {
		fprintf(logf, "ERROR: Number of matches must be more than 0\n");
		exit(NOT_CHECKED);
	}

	if(LAST && HEADER) {
		fprintf(logf, "ERROR: Options -l and -h are mutually exclusive.\n");
		exit(NOT_CHECKED);
	}

	if(CACHE) 
		DNS_OPTS=DNS_QUERY_TREAT_AS_FQDN;
	else
		DNS_OPTS=DNS_QUERY_BYPASS_CACHE | DNS_QUERY_TREAT_AS_FQDN;		

	for(n=0;n<=MAXLINE;n++)
		logbuff[n]=0;

	//initialize regex

	re_set_syntax(RE_SYNTAX_POSIX_EXTENDED);

	re_ipaddr.allocated=REGEX_SIZE;
	re_ipaddr.buffer=malloc(re_ipaddr.allocated);
	re_ipaddr.fastmap=NULL;
	re_ipaddr.translate=NULL;

	if(re_compile_pattern(IPADDR_PAT, strlen(IPADDR_PAT), &re_ipaddr)) {
		fprintf(logf, "ERROR: RE Compilation failed!\n");
		exit(NOT_CHECKED);
	}
	
	if(DEBUG) {
		printf("%s", RBLV);
		printf("RE-Pattern size: %d bytes allocated, %d used, %d free\n", re_ipaddr.allocated, re_ipaddr.used, re_ipaddr.allocated-re_ipaddr.used);
		printf("IP Address RE-Pattern string: %s\n", IPADDR_PAT);
		printf("Buffer size: %d bytes; Token separators: %s", MAXLINE, SEPARATORS);
	}

	//parse dns server list file

	rblserver=malloc(sizeof(struct RBLSERVER));
	rblserver->next=NULL;
	rblserver_root=rblserver;

	n=0;
	inputf=fopen(rblservers, "r");
	if(inputf != NULL) {
		if(DEBUG) printf("Reading RBL server list from file: %s\n", rblservers);
		while(fgets(line, MAXLINE, inputf) != NULL) {

			if(strlen(line) >= 6) {
				_snprintf(rblserver->name, sizeof(rblserver->name), "%s", strtok(line, SEPARATORS));

				if(DEBUG) printf("==> %s\n", rblserver->name);

				rblserver->next=malloc(sizeof(struct RBLSERVER));
				rblserver=rblserver->next;
				rblserver->next=NULL;
				n++;
			}
		}
		fclose(inputf);
	} else {
		fprintf(logf, "ERROR: Cannot open %s file!\n", rblservers);
		exit(NOT_CHECKED);
	}

	if(n==0) {
		fprintf(logf, "ERROR: no valid nameservers found!\n");
		exit(NOT_CHECKED);
	}

	if(DEBUG) { 
						printf("\nWill check on %d rblservers...\n", n);
		if(CACHE)		printf("Will use local resolver DNS cache.\n"); 
		else			printf("Will bypass Local Resolver DNS Cache.\n");
		if(LAST)		printf("Will check only IP of the connecting host.\n");
		else if(HEADER)	printf("Will scan only SMTP header.\n");
		else			printf("Will scan whole message.\n");
						printf("\n");
	}

	
	
	// parse the message file
	
	ip_n=0;
	inputf=fopen(filename, "r");
	if(inputf != NULL) {
		if(DEBUG) printf("Reading SMTP message from file: %s\n", filename);
		while (fgets(line, MAXLINE, inputf) != NULL) {
			line_n++;
		
			if(LAST && line_n>1) goto end;
			if((LAST || HEADER) && strcmp(line, "\n")==0) goto end;
			
			token_n=0;
			token=strtok(line, SEPARATORS);

			if((LAST||HEADER) && (token!=NULL) && (strcmp(token, "Received")==0))
				in_header=1;
			else
				in_header=0;

			while(token!=NULL && (!HEADER || (HEADER && in_header))) {
				token_n++;
				if((re_match(&re_ipaddr,token,strlen(token),0,0)>0) && (!LAST || (LAST && in_header && token_n>3))) {
					
					ip_n++;
					revip.S_un.S_addr = ntohl(inet_addr(token));
					_snprintf(revip_str, sizeof(revip_str), "%s", inet_ntoa(revip));
					if(DEBUG) printf("==> %s:\n", token);

					for(rblserver=rblserver_root;rblserver->next;rblserver=rblserver->next) {
						_snprintf(query_str, sizeof(query_str), "%s.%s.", revip_str, rblserver->name);

						if(DEBUG) printf("    %-35s", rblserver->name);

						query_status=DnsQuery_A(query_str, DNS_TYPE_A, DNS_OPTS, NULL, &dns_reply, NULL);
						
						if((query_status==0) && (dns_reply->Flags.S.Section == DNSREC_ANSWER) && (dns_reply->wType == DNS_TYPE_A)) {
	
							if(DEBUG) printf("+ POSITIVE\n");
							positive++;
							_snprintf(logbuff, sizeof(logbuff), "%s %s@%s,", logbuff, token, rblserver->name);

							if(positive>=minmatches) goto end;
							
						} 
						else {

							switch(query_status) {
								// valid negative answers:
								case 9003L:  if(DEBUG) printf("  Negative\n"); negative++; break; // direct
								case 9501L:  if(DEBUG) printf("  Negative\n"); negative++; break; // cached

								// errors:
								case 9852L:  if(DEBUG) printf("! ERROR: no dns servers defined\n"); break;
								case 1460L:  if(DEBUG) printf("! ERROR: connection timeout\n"); break;
								case 10065L: if(DEBUG) printf("! ERROR: server unreachable\n"); break;
								default :    if(DEBUG) printf("! ERROR: %ld\n", query_status);
							}
						}
					}

					if(DEBUG) printf("\n");

					//if -l specified we scan only single ip adddress
					if(LAST) goto end;
				}
				token=strtok(NULL, SEPARATORS);
			}
		}
end:
		if(DEBUG) printf("\n");
		fclose(inputf);
	} 
	else {
		fprintf(logf, "ERROR: message file %s not found!\n", filename);
		exit(NOT_CHECKED);
	}
	
	if(DEBUG) printf("\nIP Addresses Checked: %d\nNumber of Positive Matches: %d\nNumber of Negative Matches: %d\nMinimum Required for Detected: %d\n\n", ip_n, positive, negative, minmatches);

	_snprintf(logbuff, sizeof(logbuff), "%s [IP Scanned:%d, Positives:%d, Negatives:%d, Required:%d]\n", logbuff, ip_n, positive, negative, minmatches);

	// exit procedure

	if(positive>=minmatches) {
		if(DEBUG) printf("Classified as POSITIVE (DETECTED - Exit code = %d)\n", DETECTED);
		fprintf(logf, "POSITIVE;%s", logbuff);
		exit(DETECTED);
	} 
/* Removed on requests from users. To be implemented as configurable parameter.
   This allows to decrease DNS Query Timeout and not worry about Undetermined.
	else if (positive==0 && negative==0 && ip_n>0) {
		if(DEBUG) printf("Classified as ERROR (NOT_CHECKED - Exit code = %d) [DNS ERRORS]\n", NOT_CHECKED);
		fprintf(logf, "ERROR: DNS Errors!;%s", logbuff);
		exit(NOT_CHECKED);
	} 
*/
	else {
		if(DEBUG) printf("Classified as NEGATIVE (NONE - Exit code = %d)\n", NONE);
		fprintf(logf, "CLEAN;%s", logbuff);
		exit(NONE);
	}
}


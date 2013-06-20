/*
Copyright 2013 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* gcc -O3 -o onesniff -lpcap */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

/* default snap length (maximum bytes per packet to capture) */
#define DEFAULT_SNAP_LEN 256 //1518
#define DEFAULT_CAPTURE_DEVICE "eth0"
#define MAX_FNAME_LEN 2048

/* 5 min = ~1GB files compressed */

#define PERIOD_MINS 5 // has to be between 1 and 60 - how often to rotate the files

char *gfname, *gfname_sample, *gfname_link, *gfname_link_sample, *gfname_stats, *gfname_stats_sample;
#define MAX_DIR_LEN 1024
char dir_prefix[MAX_DIR_LEN];

#define MAX_CAPTURE_NAME 256

#define FLUSH_COUNT 1024

u_int gdumper_sample_count = 0;
u_int gdumper_count = 0;
/* stats */
u_int last_ps_recv;
u_int last_ps_drop;

time_t next_rotation_time;
u_int sample_rate = 0;
u_int min_snap_len = 0;
int flag_only_sample = 0;
pcap_t *handle;                         /* packet capture handle */
char *capture_name;
//[MAX_CAPTURE_NAME] = "\0";
pcap_dumper_t *gpdumper, *gpdumper_sample;
unsigned int packets_seen = 0;
//pcap_t *pd;

void close_and_finalize(pcap_dumper_t *pdumper, char *fname, char *fname_completed) {
	syslog(LOG_NOTICE, "Closing %s / %s (%p)", fname, fname_completed, pdumper);
	pcap_dump_close(pdumper);
	syslog(LOG_NOTICE, "Finished close");
	symlink(fname, fname_completed);
}

void check_mkdir(char *dirname) {
  struct stat sb;
  if (stat(dirname, &sb)==-1) {
    mkdir(dirname, 0755);
  }
}


pcap_dumper_t *open_pcap_file(time_t file_timestamp, pcap_t *handle, char *capture_name_suffix, char *fname, char *fname_completed, char *statsname) {
  char *dirname = malloc(MAX_FNAME_LEN);
  char suffix_str[20] = "\0";
  struct tm *tmv;
  struct stat sb;

  tmv = localtime(&file_timestamp);

  sprintf(dirname,"%s", dir_prefix);
  check_mkdir(dirname);
  sprintf(dirname,"%s/all", dir_prefix);
  check_mkdir(dirname);
  sprintf(dirname,"%s/finished", dir_prefix);
  check_mkdir(dirname);
  sprintf(dirname,"%s/all/%04d", dir_prefix, 1900+tmv->tm_year);
  check_mkdir(dirname);
  sprintf(dirname,"%s/all/%04d/%02d", dir_prefix, 1900+tmv->tm_year, tmv->tm_mon+1);
  check_mkdir(dirname);
  sprintf(dirname,"%s/all/%04d/%02d/%02d", dir_prefix, 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday);
  check_mkdir(dirname);
  sprintf(dirname,"%s/all/%04d/%02d/%02d/%s%s", dir_prefix, 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday,capture_name, capture_name_suffix);
  check_mkdir(dirname);

  snprintf(fname, MAX_FNAME_LEN, "%s/%s%s-%04d%02d%02d-%02d%02d.pcap", dirname,
	   capture_name, capture_name_suffix, 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday, tmv->tm_hour, tmv->tm_min);
  if (stat(fname, &sb)!=-1) {
   int suffix;
   for (suffix=1;suffix<100;suffix++) {
     snprintf(fname, MAX_FNAME_LEN, "%s/%s%s-%04d%02d%02d-%02d%02d.pcap.%d", dirname,
	   capture_name, capture_name_suffix, 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday, tmv->tm_hour, tmv->tm_min, suffix);
     if (stat(fname, &sb)==-1) {
	sprintf(suffix_str,".%d", suffix);
	break;
     }
   }
  }

  snprintf(fname_completed, MAX_FNAME_LEN, "%s/finished/%s%s-%04d%02d%02d-%02d%02d.pcap%s", dir_prefix,
	   capture_name, capture_name_suffix, 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday, tmv->tm_hour, tmv->tm_min,suffix_str);

  sprintf(dirname,"/sdb2/stats.pcap");
  check_mkdir(dirname);
  sprintf(dirname,"/sdb2/stats.pcap/%04d%02d%02d", 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday);
  check_mkdir(dirname);
  snprintf(statsname, MAX_FNAME_LEN, "%s/%s%s-%04d%02d%02d-%02d%02d.pcap%s", dirname,
	   capture_name, capture_name_suffix, 1900+tmv->tm_year, tmv->tm_mon+1, tmv->tm_mday, tmv->tm_hour, tmv->tm_min,suffix_str);

  syslog(LOG_NOTICE, "Capturing to %s / %s", fname, fname_completed);
  free(dirname);
  return pcap_dump_open(handle, fname);

}

time_t get_next_rotation_time(int offset) {
  time_t next_time;
  struct tm *tmv;
  next_time = time(NULL) + (1+offset)*PERIOD_MINS*60;
  tmv = localtime(&next_time);
  tmv->tm_min = tmv->tm_min - (tmv->tm_min%PERIOD_MINS); // truncate the remainder
  tmv->tm_sec = 0;
  return mktime(tmv);
}

void
termination_handler (int signum) {
 // do nothing, loop should exit...
 syslog(LOG_NOTICE,"Terminating...");
 pcap_breakloop(handle);
}

void print_rotate_stats(char *stats_fname) {
	struct pcap_stat stat;
        char stats_str[257];
        int fd;
	u_int delta_ps_recv=0;
	u_int delta_ps_drop=0;
	if (pcap_stats(handle, &stat) >= 0) {
		delta_ps_recv = stat.ps_recv - last_ps_recv;
		delta_ps_drop = stat.ps_drop - last_ps_drop;
		last_ps_recv=stat.ps_recv;
		last_ps_drop=stat.ps_drop;
	}
	syslog(LOG_NOTICE, "Packets saved: %u / Packets received by filter: %u / Packets dropped by kernel: %u", 
               packets_seen, delta_ps_recv, delta_ps_drop);
	fd=open(stats_fname, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	snprintf(stats_str, 200, "%u %u %u\n",
                 packets_seen, delta_ps_recv, delta_ps_drop);
        write(fd, stats_str, strlen(stats_str));
	close(fd);

	packets_seen = 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data) {
 	 //pkt_data = pcap_next(handle, &pkt_hdr);
         if ((pkt_data==NULL) || (pkt_hdr == NULL)) {
	  return;
	 }
	 if (next_rotation_time <= pkt_hdr->ts.tv_sec) {
           print_rotate_stats(gfname_stats_sample);
	   close_and_finalize(gpdumper_sample, gfname_sample, gfname_link_sample);
	   gpdumper_sample = open_pcap_file(next_rotation_time, handle, "sample", gfname_sample, gfname_link_sample, gfname_stats_sample);
	   if (!flag_only_sample) {
	   	close_and_finalize(gpdumper, gfname, gfname_link);
	   	gpdumper = open_pcap_file(next_rotation_time, handle, "", gfname, gfname_link, gfname_stats);
	   }
	   next_rotation_time += PERIOD_MINS*60;
	 }
	 packets_seen += 1;
	if (!flag_only_sample) {
	   // only write out to the file if we want to sample it
  	   pcap_dump((u_char *)gpdumper, pkt_hdr, pkt_data);
	}
        if ((sample_rate > 0) && (random()%sample_rate == 0)) {
	   // only write out to the file if we want to sample it
  	   pcap_dump((u_char *)gpdumper_sample, pkt_hdr, pkt_data);
	}
}

void abort_usage() {
  printf("Syntax: onesniff -n {/24 network} -s {snaplen} -S {sample rate, omit for all packets} -d {directory} -p {/prefix} -m {min snaplen} -N {myname}\n");
  exit(1);
}

int main(int argc, char **argv)
{

        char *dev = DEFAULT_CAPTURE_DEVICE;    /* capture device name */
        char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */

        char filter_exp[1024];
	char prog_id[1024];
        struct bpf_program fp;                  /* compiled filter program (expression) */
        bpf_u_int32 mask;                       /* subnet mask */
        bpf_u_int32 net;                        /* ip */
	int fd;
	int c;
	int snap_len = DEFAULT_SNAP_LEN;
	char *dst_net = NULL;
	char pid_fn[256];
	char pid_str[256];
	int prefix_len = 24;
	char *override_capture_name = NULL;

	srand(getpid());
	while ((c = getopt (argc, argv, "s:S:p:d:n:m:N:O")) != -1) {
		switch (c) {
			case 's': snap_len=atoi(optarg); break;
			case 'p': prefix_len=atoi(optarg); break;
			case 'S': sample_rate = atoi(optarg); break;
			case 'd': strncpy(dir_prefix, optarg, sizeof(dir_prefix)-1); break;
			case 'm': min_snap_len=atoi(optarg); break;
			case 'n': dst_net = optarg; break;
			case 'N': override_capture_name = optarg; break;
			case 'O': flag_only_sample = 1-flag_only_sample; break;
		default: abort_usage();
		}
	}
	gfname = malloc(MAX_FNAME_LEN);
	gfname_sample = malloc(MAX_FNAME_LEN);
	gfname_stats = malloc(MAX_FNAME_LEN);
	gfname_stats_sample = malloc(MAX_FNAME_LEN);
	gfname_link = malloc(MAX_FNAME_LEN);
	gfname_link_sample = malloc(MAX_FNAME_LEN);
	capture_name = malloc(MAX_CAPTURE_NAME);

	if (!dst_net || !dir_prefix[0] || !snap_len) {
		printf("Must provide the network (/24) to capture and the dir prefix to put the output\n");
		abort_usage();
	}
	if ((strchr(dst_net, ' ') != NULL) || (strchr(dst_net, '/') != NULL)) {
		printf("Illegal chars in destination network (no spaces or /s)\n");
		exit(1);
	}
	if (override_capture_name && ((strchr(override_capture_name, ' ') != NULL) || (strchr(override_capture_name, '/') != NULL))) {
		printf("Illegal chars in capture name (no spaces or /s)\n");
		exit(1);
	}
        if (!override_capture_name) {
 	  snprintf(capture_name, MAX_CAPTURE_NAME, "%s", dst_net);
	} else {
 	  snprintf(capture_name, MAX_CAPTURE_NAME, "%s", override_capture_name);
	}
	if (min_snap_len) {
		snprintf(filter_exp, 1024, "dst net %s/%d and greater %d", dst_net, prefix_len, min_snap_len);
	} else {
		snprintf(filter_exp, 1024, "dst net %s/%d", dst_net, prefix_len);
	}
	dev = DEFAULT_CAPTURE_DEVICE;

        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
                net = 0;
                mask = 0;
        }
       /* print capture info */
        printf("Device: %s\n", dev);
        printf("Filter expression: %s\n", filter_exp);


        /* open capture device */
        handle = pcap_open_live(dev, snap_len, 1, 1000, errbuf);

        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(EXIT_FAILURE);
        }

        /* compile the filter expression */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

#if 1
	/* daemonize */
	if(fork() != 0) {
	  printf("running as a daemon...\n");
	  exit(0);
	}
	snprintf(prog_id, 50, "onesniff-%s", capture_name);
	openlog(prog_id, LOG_PID, LOG_LOCAL6);

	setsid();
	chdir("/tmp");
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "r", stdout);
	freopen("/dev/null", "r", stderr);
#endif

	snprintf(pid_fn, 100, "/var/run/%s.pid", prog_id);
	fd=open(pid_fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	snprintf(pid_str, 100, "%d\n", getpid());
        write(fd, pid_str, strlen(pid_str));
	close(fd);

	if (signal (SIGINT, termination_handler) == SIG_IGN)
	   signal (SIGINT, SIG_IGN);
	if (signal (SIGHUP, termination_handler) == SIG_IGN)
	   signal (SIGHUP, SIG_IGN);
	if (signal (SIGTERM, termination_handler) == SIG_IGN)
	   signal (SIGTERM, SIG_IGN);

        /* now we can set our callback function */
	next_rotation_time = get_next_rotation_time(-1);
	if (!flag_only_sample)
		gpdumper = open_pcap_file(next_rotation_time, handle,"", gfname, gfname_link, gfname_stats);
	gpdumper_sample = open_pcap_file(next_rotation_time, handle,"sample", gfname_sample, gfname_link_sample, gfname_stats_sample);
	next_rotation_time = get_next_rotation_time(0);


	pcap_loop(handle, -1, got_packet, NULL);

        /* cleanup */
        pcap_freecode(&fp);
	close_and_finalize(gpdumper_sample, gfname_sample, gfname_link_sample);
	if (!flag_only_sample)
		close_and_finalize(gpdumper, gfname, gfname_link);

	print_rotate_stats(gfname_stats_sample);
        pcap_close(handle);
	unlink(pid_fn);

        syslog(LOG_NOTICE, "Capture complete.");

return 0;
}

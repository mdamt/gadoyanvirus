/*

gadoyanvirus - a virus stopper for qmail.
Mohammad DAMT [mdamt at bisnisweb dot com] 
(c) 2004, PT Cakram Datalingga Duaribu
   
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <syslog.h>

#include <clamav.h>

/*
 * You may modify these settings
 */
#define QMAIL_QUEUE "/var/qmail/bin/qmail-queue"
#define QUARANTINE_DIR "/opt/gadoyanvirus/quarantine"
#define VIRUSMASTER "postmaster@"
/* end of settings */

#define VERSION "0.1"
#define BUFFER_SIZE 1024

void write_log (char *message)
{
	openlog ("gadoyanvirus", LOG_PID | LOG_NDELAY, LOG_MAIL); 
	syslog (LOG_INFO,"%s", message); 
	closelog (); 
}

void die_status (int code, char *message)
{
	write_log (message); 
	exit (code);
}

void die_temp_cl (int ret)
{
	die_status (81, cl_strerror (ret));
}

char *save_maildir (char *path, char *message, long message_len)
{
	time_t now = time (NULL);
	char hostname [512];
	pid_t pid = getpid ();
	char *filename, *new;
	int filename_len;
	struct stat st;
	int fd;
	int ret;

	bzero (hostname, 512);
	if (gethostname (hostname, 512) != 0)
		strcpy (hostname, "localhost");

	if (chdir (path) != 0)
		die_status (81, "couldnt chdir() to maildir path");

	mkdir ("tmp", 0700);
	mkdir ("new", 0700);
	mkdir ("cur", 0700);

	for (;;sleep (2)) {
		filename_len =	4 + /* tmp/ */
						strlen (hostname) +
						20 + /* now */
						10 + /* pid */
						4; /* \0 */

		filename = malloc (filename_len);
		bzero (filename, filename_len);
		snprintf (filename, filename_len, "tmp/%d.%d.%s", (unsigned int) now, (int) pid, hostname);

		if (stat (filename, &st) == 0)
			continue;

		if ((fd = creat (filename, 0600)) == -1)
			die_status (81, "couldn't create quarantine message");
		
		
		if ((ret = write (fd, message, message_len)) < 0) {
			die_status (81, "couldn't write quarantine message");
		}

		fsync (fd);
		close (fd);
		break;
	}
	
	new = strdup (filename);
	if (new == NULL)
		die_status (81, "no memory for new/");

	new [0] = 'n'; new [1] = 'e'; new [2] = 'w';

	link (filename, new);

	unlink (filename);
	free (filename);
	
	return new;
}

void send_notification (	char *virus_name, 
							int message_fd, 
							char *message,
							long message_len,
							int envelope_fd, 
							char *envelope,
							int envelope_len)
{
	char subdir [9];
	char *path, *key;
	int path_len;
	time_t now = time (NULL);
	char hostname [512];

#ifdef VIRUSMASTER
	int i = 0, quot_len, recipient_len;
	char *notification, message_quot [2048];
	char *notification_envelope, *recipient;
#endif

	bzero (hostname, 512);
	if (gethostname (hostname, 512) != 0)
		strcpy (hostname, "localhost");

	strftime (subdir, 9, "%Y%m%d", gmtime (&now));
	subdir [8] = 0;
	path_len = sizeof (QUARANTINE_DIR) + 1 + 9;
	path = malloc (path_len);
	if (path == NULL)
		die_status (51, "out of memory when writing notification");

	sprintf (path, "%s/%s", QUARANTINE_DIR, subdir);
	path [path_len] = 0;
	mkdir (path, 0755);

	key = save_maildir (path, message, message_len);
	free (path);

#ifdef VIRUSMASTER
	recipient_len = envelope_len;
	recipient = envelope;
	while (i < envelope_len) {
		if (recipient [i] == 'T') 
			break;
		i ++;
		recipient_len --;
	}
	recipient += i;
	
	quot_len = 0;
	bzero (message_quot, 2048);
	i = 0;
	while (quot_len < 2047) {
		if (quot_len > message_len)
			break;

		if (message [quot_len] == 10 || message [quot_len] == 13)
			i ++;
		else
			if (i > 0) i --;

		if (i > 2)
			break;

		message_quot [quot_len] = message [quot_len];
		quot_len ++;
	}
	message_quot [quot_len - 1] = 0;

/* man this is very ugly */
#define MSG0 "From: "
#define MSG1 "\nSubject: [VIRUS NOTIFICATION] "
#define MSG2 "\nX-Mailer: gadoyanvirus " VERSION "\n\nHello,\nA mail to you contains virus(es):\n\n * "
#define MSG3 "\n\nWe have quarantined this mail. You may claim this\
 mail by replying and mention this key below: \n\n\t"
#define MSG4 "\n\nThis mail will be kept for 1 week only and after that it will be deleted automatically.\
\n\nThis is the part of the mail:\n\
--------------------------------------------------------------\n"
#define MSG5 "\r\n"

	i = sizeof (MSG0) + sizeof (MSG1) + sizeof (MSG2) + sizeof (MSG3) + 
		sizeof (MSG4) + sizeof (MSG5) + 
		sizeof (VIRUSMASTER) + strlen (hostname) +
		(strlen (key) * 2) +
		strlen (virus_name) + 
		quot_len + /* original message */
		1;

	notification = malloc (i);
	if (notification == NULL)
		die_status (51, "no memory for notification message");

	bzero (notification, i);
	snprintf (notification, i, "%s%s%s%s%s%s%s%s%s%s%s%s",
				MSG0, VIRUSMASTER, hostname,
				MSG1, key,
				MSG2, virus_name, MSG3,
				key, MSG4, message_quot,
				MSG5);
	
	if (write (message_fd, notification, strlen (notification)) < 0)
		die_status (81, "couldn't write notification message");

	free (notification);

	i = 2 + /* F\0 */
		sizeof (VIRUSMASTER) +
		strlen (hostname) +
		recipient_len;

	notification_envelope = malloc (i);
	if (notification_envelope == NULL)
		die_status (51, "out of memory for notification envelope");

	bzero (notification_envelope, i);
	
	sprintf (notification_envelope, "F%s%s", VIRUSMASTER, hostname);
	memcpy (notification_envelope + i - recipient_len - 1, recipient, recipient_len);

	if (write (envelope_fd, notification_envelope, i) < 0)
		die_status (81, "couldn't write notification envelope");
	
	free (notification_envelope);
#endif

	write_log (key);
	write_log (virus_name);
	free (key);
}

int main () 
{
	struct cl_node *root = NULL;
	int ret;
	int r_len = 0;
	int envelope_len = 0;
	unsigned long message_len = 0;
	char buffer [BUFFER_SIZE];
	char *virus_name;
	char *message = NULL;
	char *envelope = NULL;
	int message_pipe [2];
	int envelope_pipe [2];
	int child_status;
	pid_t pid;

	char *temp; 

	if ((ret = cl_loaddbdir (cl_retdbdir (), &root, NULL)) != 0)
		die_temp_cl (ret);

	cl_buildtrie (root);

	if (pipe (envelope_pipe) == -1)
		die_status (51, "couldn't open pipe for envelope");

	if (pipe (message_pipe) == -1) {
		close (envelope_pipe [0]);
		close (envelope_pipe [1]);
		die_status (51, "couldn't open pipe for message");
	}

	pid = fork ();
	switch (pid) {
		case -1:
			close (envelope_pipe [0]);
			close (envelope_pipe [1]);
			close (message_pipe [0]);
			close (message_pipe [1]);
			die_status (51, "fork() failed");
			break;
		case 0:
			close (envelope_pipe [1]);
			close (message_pipe [1]);
			if ((dup2 (message_pipe [0], 0) != 0) || (dup2 (envelope_pipe [0], 1) != 1))
				die_status (51, "dup2() failed");
			
			execl (QMAIL_QUEUE, QMAIL_QUEUE, 0);
			die_status (120, "queue exec failed");
		default:
			close (envelope_pipe [0]);
			close (message_pipe [0]);
			signal (SIGPIPE, SIG_IGN);
	}

	ret = 0;
	while ((r_len = read (0, buffer, BUFFER_SIZE)) != 0) {		
		if (r_len < 0)
			die_status (54, "couldn't read message");

		message_len += r_len;
		message = realloc (message, message_len);
		if (message == NULL)
			die_status (51, "no memory for message");

		memcpy (message + message_len - r_len, buffer, r_len);
	}

	ret = cl_scanbuff (message, message_len, &temp, root);
	if (ret == CL_VIRUS) {
		virus_name = strdup (temp);
	}

	cl_freetrie (root);

	while ((r_len = read (1, buffer, BUFFER_SIZE)) != 0) {
		if (r_len < 0)
			die_status (54, "couldn't read envelope");

		envelope_len += r_len;
		envelope = realloc (envelope, envelope_len);
		if (envelope == NULL)
			die_status (51, "no memory for envelope");

		memcpy (envelope + envelope_len - r_len, buffer, r_len);
	}

	if (ret != CL_VIRUS) {
		if (write (message_pipe [1], message, message_len) < 0)
			die_status (53, "couldn't write message");		
		if (write (envelope_pipe [1], envelope, envelope_len) < 0)
			die_status (53, "couldn't write envelope");
	} else {
		send_notification (	virus_name, 
							message_pipe [1], 
							message, message_len,
							envelope_pipe [1], 
							envelope, envelope_len);
		free (virus_name);
	}

	free (message);
	free (envelope);
	close (message_pipe [1]);
	close (envelope_pipe [1]);
	
	if (waitpid(pid, &child_status, WUNTRACED) == -1)
		die_status (81, "waitpid failed");

    if (!WIFEXITED(child_status)) 
		die_status (81, "qmail-queue crashed");

	if (ret == CL_VIRUS)
		die_status (31, "virus catched");

	if (ret != 0)
		die_temp_cl (ret);

	return 0;
}

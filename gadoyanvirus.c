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
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <syslog.h>
#include <pwd.h>
#include <pthread.h>
#include <clamav.h>

#ifndef QMAIL_QUEUE
#define QMAIL_QUEUE "/var/qmail/bin/qmail-queue"
#endif

#ifndef GADOYANVIRUS_DIR
#define GADOYANVIRUS_DIR "/opt/gadoyanvirus"
#endif

#define QUARANTINE_DIR GADOYANVIRUS_DIR "/quarantine"
#define QUARANTINE_DIR_TMP QUARANTINE_DIR "/tmp"
#define SOCKET_FILE GADOYANVIRUS_DIR "/.socket"

#ifndef SMTP_USER
#define SMTP_USER "qmaild"
#endif

#define SLEEP_TIME 300
#define BUFFER_SIZE 1024

static int server_reloaded = 1;
static struct cl_node *root = NULL;
static struct cl_limits limit;
pthread_mutex_t mt = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mt_server_reloaded = PTHREAD_MUTEX_INITIALIZER;

struct server_rec
{	
	int sock;
};

void write_log (const char *message)
{
	openlog ("gadoyanvirus", LOG_PID | LOG_NDELAY, LOG_MAIL); 
	syslog (LOG_INFO,"%s", message); 
	closelog (); 
}

void die_status (int code, const char *message)
{
	write_log (message); 
	exit (code);
}

void die_temp_cl (int ret)
{
	openlog ("gadoyanvirus", LOG_PID | LOG_NDELAY, LOG_MAIL); 
	syslog (LOG_INFO,"clamav: %s", cl_strerror (ret)); 
	closelog (); 
	exit (81);
}

void save_maildir (char *tmp_path)
{
	time_t now = time (NULL);
	char hostname [512];
	char subdir [9];
	char *path, *new;
	int path_len;

	bzero (hostname, 512);
	if (gethostname (hostname, 512) != 0)
		strcpy (hostname, "localhost");

	strftime (subdir, 9, "%Y%m%d", gmtime (&now));
	subdir [8] = 0;
	path_len = sizeof (QUARANTINE_DIR) + 1 + 9;
	path = malloc (path_len);
	if (path == NULL)
		die_status (51, "out of memory when writing temp message");

	sprintf (path, "%s/%s", QUARANTINE_DIR, subdir);
	path [path_len] = 0;
	mkdir (path, 0755);

	if (chdir (path) != 0)
		die_status (81, "couldnt chdir() to quarantine path");

	mkdir ("tmp", 0700);
	mkdir ("new", 0700);
	mkdir ("cur", 0700);

	new = malloc (4+ strlen (tmp_path) + path_len);
	if (new == NULL)
		die_status (81, "no memory for new/");

	sprintf (new, "%s/new/%s", path, tmp_path);

	free (path);
	path_len = sizeof (QUARANTINE_DIR) + 1 + 3 + strlen (tmp_path);
	path = malloc (path_len);
	if (path == NULL)
		die_status (51, "out of memory when preparing temp message");

	sprintf (path, "%s/tmp/%s", QUARANTINE_DIR, tmp_path);
	path [path_len] = 0;

	link (path, new);
	unlink (path);

	free (new);
	free (path);
}

char *save_temp ()
{
	time_t now = time (NULL);
	char hostname [512];
	pid_t pid = getpid ();
	char *filename;
	int filename_len;
	struct stat st;
	int fd;
	int ret;
	char *path;
	int path_len, r_len;
	char buffer [BUFFER_SIZE];

	bzero (hostname, 512);
	if (gethostname (hostname, 512) != 0)
		strcpy (hostname, "localhost");

	path_len = sizeof (QUARANTINE_DIR) + 1 + 3;
	path = malloc (path_len);
	if (path == NULL)
		die_status (51, "out of memory when preparing temp message");

	sprintf (path, "%s/tmp", QUARANTINE_DIR);
	path [path_len] = 0;
	mkdir (path, 0755);

	if (chdir (path) != 0)
		die_status (81, "couldnt chdir() to quarantine path " QUARANTINE_DIR "/tmp");

	for (;;sleep (2)) {
		filename_len =	strlen (hostname) +
						20 + /* now */
						10 + /* pid */
						4; /* \0 */

		filename = malloc (filename_len);
		bzero (filename, filename_len);
		snprintf (filename, filename_len, "%d.%d.%s", (unsigned int) now, (int) pid, hostname);

		if (stat (filename, &st) == 0)
			continue;

		if ((fd = creat (filename, 0600)) == -1)
			die_status (81, "couldn't create temp message");
				
		while ((r_len = read (0, buffer, BUFFER_SIZE)) != 0) {		
			if (r_len < 0)
				die_status (54, "couldn't read message");

			if ((ret = write (fd, buffer, r_len)) < 0) {
				die_status (81, "couldn't write temp message");
			}
		}

		fsync (fd);
		close (fd);
		break;
	}
	
	return filename;
}

#ifdef VIRUSMASTER
void send_notification (	char *virus_name, 
							char *key,
							int message_fd, 
							int tmp_fd,
							int envelope_fd, 
							char *envelope,
							int envelope_len)
{
	
	char hostname [512];

	int i = 0, quot_len, recipient_len, tmp, r_len;
	char *notification, message_quot [2048];
	char *notification_envelope, *recipient;
	char buffer [BUFFER_SIZE];
	int stop = 0;

	bzero (hostname, 512);
	if (gethostname (hostname, 512) != 0)
		strcpy (hostname, "localhost");

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
	bzero (message_quot, 2047);
	i = 0;

	tmp = 0;
	while ((r_len = read (tmp_fd, buffer, BUFFER_SIZE)) != 0) {
		if (r_len < 0)
			die_status (54, "couldn't read message");

		while (i < BUFFER_SIZE) {
			if (buffer [i] == '\n')
				tmp ++;
			else 
				tmp = 0;

			if (tmp > 1) {
				stop = 1;
				break;
			}

			message_quot [quot_len] = buffer [i];
			i ++;
			quot_len ++;
			if (quot_len > 2047) {
				stop = 1;
				break;
			}
		}
		i = 0;
		if (stop == 1)
			break;
	}

	message_quot [quot_len] = 0;

/* man this is very ugly */
#define MSG0 "From: "
#define MSG1 "\nSubject: [VIRUS NOTIFICATION] "
#define MSG2 "\nX-Mailer: gadoyanvirus " VERSION "\n\nHello,\nA mail to you contains virus(es):\n\n * "
#define MSG3 "\n\nWe have quarantined this mail. You may claim this\
 mail by replying and mention this key below: \n\n\t"
#define MSG4 "\n\nThis mail will be kept for 1 week only and after that it will be deleted automatically.\
\n\nThis is the part of the mail:\n\
--------------------------------------------------------------\n"
#define MSG5 "\n\r\n"

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

}
#endif

int try_listen (const char *path)
{
	struct sockaddr_un address;
	int i = 0, sock;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf (stderr, "Couldn't create socket: %s\n", strerror (errno));
		return -1;
	}
	 
	bzero ((void *) &address, sizeof (address));
	address.sun_family = AF_UNIX;
	memcpy (address.sun_path, path, strlen (path));
	while (i < 10) {
		if (bind (sock, (struct sockaddr*) &address, sizeof (address)) < 0) {
			fprintf (stderr, "Couldn't bind socket file %s: %s, trying to steal\n", path, strerror (errno));
			unlink (path);
			usleep (500);
		} else break;
		i ++;
	}
	
	if (i > 9) {
		fprintf (stderr, "Couldn't bind socket file %s: %s\n", path, strerror (errno));
		return -1;
	}

	if (i > 0) {
		fprintf (stderr, "socket file %s successfully stolen\n", path);
	}
 
	if (listen (sock, 10) != 0) {
		fprintf (stderr, "Couldn't listen on %s: %s\n", path, strerror (errno));
		return -1;
	}

	chmod (path, 0700);
	return sock;
}

int try_accept (int sock)
{
	int retval;
	struct sockaddr_un address;
	socklen_t len = sizeof (struct sockaddr_un);

	retval = accept (sock, (struct sockaddr*) &address, &len);
	if (retval < 0) 
		fprintf (stderr, "Couldn't accept: %s\n", strerror (errno));

	return retval;
}

int try_connect (const char *path, int probe)
{
	int retval = -1, sock =-1;
	struct sockaddr_un address;

	bzero ((char*) &address, sizeof (address));
	address.sun_family = AF_UNIX;
	strcpy (address.sun_path, path);

	if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		write_log ("Couldn't make socket.\n");
		return -1;
	}

	if ((retval = connect (sock, (struct sockaddr*) &address, sizeof (struct sockaddr_un))) < 0) {
		if (probe == 0)
			write_log ("Couldn't make connection.\n");

		return -1;
	}

	return sock;
}

void reload (int arg)
{
	pthread_mutex_lock (&mt_server_reloaded);
	server_reloaded = 1;
	pthread_mutex_unlock (&mt_server_reloaded);
}

void *reload_timer (void *arg)
{
	while (1) {
		sleep (SLEEP_TIME); 
		pthread_mutex_lock (&mt_server_reloaded);
		server_reloaded = 1;
		pthread_mutex_unlock (&mt_server_reloaded);		
	}
	return NULL;
}

void daemonize () 
{
	int i;

	if (getppid () == 1)
		return;

	i = fork ();
	if (i < 0) {
		fprintf (stderr, "Error: %s\n", strerror (errno));
		exit (1);
	}

	if (i > 0) {
		exit (0);
	}
	
	setsid();
	for (i = 0; i < 3; i++)
		close(i);

	i = open("/dev/null",O_RDWR);
	dup(i); dup(i);
	umask (027);

	signal (SIGCHLD, SIG_IGN);
	signal (SIGTSTP, SIG_IGN);
	signal (SIGTTOU, SIG_IGN);
	signal (SIGTTIN, SIG_IGN);
	signal (SIGHUP, reload);
	signal (SIGUSR1, SIG_IGN);
}

int check_server (const char *path)
{
	struct stat st;
	int sock;

	if (stat (path, &st) == -1)
		return 0;

	if (S_ISSOCK (st.st_mode)) {
		if ((sock = try_connect (path, 1)) == -1)
			return 0;

		close (sock);
		
		return -1;
	} else {
		unlink (path);
	}
	return 0;
}

void *scanner (void *arg)
{
	struct server_rec *rec = (struct server_rec *) arg;
	int ret, length;
	unsigned long int scanned;
	
	char *tmp_path = NULL;
	const char *virus_name;

	ret = read (rec->sock, &length, sizeof (int));
	if (ret <= 0) {
		write_log ("server: premature on read the path length");
		goto scanner_exit;
	}

	if (length == 0) {
		write_log ("server: path length is zero");
		goto scanner_exit;
	}

	tmp_path = malloc (strlen (QUARANTINE_DIR_TMP) + length + 2);
	if (tmp_path == NULL) {
		write_log ("server: not enough memory");
		goto scanner_exit;
	}

	bzero (tmp_path, strlen (QUARANTINE_DIR_TMP) + length + 2);
	strcpy (tmp_path, QUARANTINE_DIR_TMP);
	tmp_path [strlen (QUARANTINE_DIR_TMP)] = '/';
	
	ret = read (rec->sock, tmp_path + strlen (QUARANTINE_DIR_TMP) + 1, length);
	if (ret <= 0) {
		write_log ("server: premature on read the file path");
		goto scanner_exit;
	}
	
	pthread_mutex_lock (&mt);
	ret = cl_scanfile (tmp_path, &virus_name, &scanned, root, &limit, CL_MAIL);
	pthread_mutex_unlock (&mt);
	
	if (ret == CL_VIRUS) {
		length = strlen (virus_name);
		ret = write (rec->sock, &length, sizeof (int));

		if (ret <= 0)
			goto scanner_exit;

		write (rec->sock, virus_name, length);
	} else if (ret == CL_CLEAN) {
		ret = 0;
		write (rec->sock, &ret, sizeof (int));
	} else {
		write_log (cl_strerror (ret));
		ret = -1;
		write (rec->sock, &ret, sizeof (int));			
	}

scanner_exit:
	if (tmp_path != NULL)
		free (tmp_path);

	close (rec->sock);
	free (rec);
	pthread_exit (NULL);
	return NULL;
}

void init_scanner ()
{
	int ret, server_sock, client_sock, first_time = 1;
	struct passwd *pwd = NULL;
	struct cl_stat clamav_stat;
	pthread_attr_t att;
	pthread_t t0;
	const char *db_dir;

	limit.maxfiles = 1000;
	limit.maxfilesize = 10 * 1048576;
	limit.maxreclevel = 5;

	db_dir = cl_retdbdir ();
	bzero (&clamav_stat, sizeof (struct cl_stat));
	cl_statinidir (db_dir, &clamav_stat);

	pwd = getpwnam (SMTP_USER);
	if (pwd == NULL) {
		fprintf (stderr,	"ERROR: No such user %s.\n"
							"- qmail may have not been installed.\n"
							"- Recompile gadoyanvirus with proper username who run qmail-smtpd.\n", 
							SMTP_USER);
		exit (-1);
	}

	mkdir (GADOYANVIRUS_DIR, 0711);
	chown (GADOYANVIRUS_DIR, pwd->pw_uid, pwd->pw_gid);

	if (getuid () == 0) {
		setgid (pwd->pw_gid);
		if (setuid (pwd->pw_uid) == -1) {
			fprintf (stderr, "Couldn't setuid to %s.\n", SMTP_USER);
			exit (-1);
		}
	}

	if (check_server (SOCKET_FILE) == -1) {
		fprintf (stderr, "gadoyanvirus server is already running.\n");
		exit (-1);
	}

	signal (SIGHUP, reload);
	if ((server_sock = try_listen (SOCKET_FILE)) == -1) {
		fprintf (stderr, "gadoyanvirus server is unable to run.\n");
		exit (-1);
	}

	daemonize ();
	pthread_attr_init (&att);
	pthread_attr_setdetachstate (&att, PTHREAD_CREATE_DETACHED);
	if (pthread_create (&t0, &att, reload_timer, NULL) == -1) {
		die_status (81, "server: Unable to start timer");
	}
	while (1) {
		struct server_rec *rec;
		pthread_t t;
		
		if (server_reloaded) {
			if (cl_statchkdir (&clamav_stat) == 1 || first_time) {
				pthread_mutex_lock (&mt);
				if (first_time == 0) {
					write_log ("Re-loading virus database");				
					if (root != NULL)
						cl_freetrie (root);
					root = NULL;
				} else {
					write_log ("Loading virus database ");
				}
				
				if ((ret = cl_loaddbdir (db_dir, &root, NULL)) != 0)
					die_temp_cl (ret);

				if (root == NULL)
					die_status (81, "virus database loading failed.");

				if ((ret = cl_buildtrie (root)) != 0)
					die_temp_cl (ret);

				if (first_time == 0) {
					cl_statfree (&clamav_stat);
					cl_statinidir (db_dir, &clamav_stat);
				}
				pthread_mutex_unlock (&mt);
				pthread_mutex_lock (&mt_server_reloaded);
				server_reloaded = 0;
				pthread_mutex_unlock (&mt_server_reloaded);
			}			
			first_time = 0;
		}

		client_sock = try_accept (server_sock);
		if (client_sock == -1) {
			write_log ("Error on accepting connections.\n");
			write_log (strerror (errno));
			break;
		}

		rec = malloc (sizeof (struct server_rec));
		if (rec == NULL) {
			write_log ("Error on allocating server rec.\n");
			break;
		}

		rec->sock = client_sock;
		if (pthread_create (&t, &att, scanner, (void*) rec) == -1) {
			write_log ("Error on creating threads.\n");
			break;
		}		
	}
}

int main () 
{
	char buffer [BUFFER_SIZE];	
	int r_len = 0, ret, sock;
	int envelope_len = 0;
	char *virus_name = NULL;
	char *tmp_path;
	char *envelope = NULL;
	int message_pipe [2];
	int envelope_pipe [2];
	int child_status;
	int tmp_fd, tmp_len;
	pid_t pid;

	if (getuid () == 0) {
		init_scanner ();
		exit (0);
	}

	signal (SIGHUP, SIG_IGN);
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
			exit (-1);
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
	tmp_path = save_temp ();
	tmp_len = strlen (tmp_path);

	if ((sock = try_connect (SOCKET_FILE, 0)) == -1)
		die_status (81, "couldn't connect to server");

	r_len = write (sock, &tmp_len, sizeof (int));
	if (r_len <= 0) 
		die_status (54, "couldn't write to server");
	
	r_len = write (sock, tmp_path, tmp_len);
	if (r_len <= 0) 
		die_status (54, "couldn't write to server");

	r_len = read (sock, &tmp_len, sizeof (int));
	if (r_len <= 0)
		die_status (54, "couldn't read from server");

	if (tmp_len > 0) {
		virus_name = malloc (tmp_len);
		r_len = read (sock, virus_name, tmp_len);
		if (r_len <= 0) {
			free (virus_name);
			die_status (54, "couldn't read from server");
		}
		ret = CL_VIRUS;
	} else if (tmp_len < 0) {
		die_status (81, "see the clamav error message above");
	}

	close (sock);

	while ((r_len = read (1, buffer, BUFFER_SIZE)) != 0) {
		if (r_len < 0)
			die_status (54, "couldn't read envelope");

		envelope_len += r_len;
		envelope = realloc (envelope, envelope_len);
		if (envelope == NULL)
			die_status (51, "no memory for envelope");

		memcpy (envelope + envelope_len - r_len, buffer, r_len);
	}

#define SIGNATURE "X-AntiVirus: gadoyanvirus " VERSION "\n"
	tmp_fd = open (tmp_path, O_RDONLY);
	if (tmp_fd < 0)
		die_status (81, "couldn't read temp message");

	if (ret != CL_VIRUS) {
		if (write (message_pipe [1], SIGNATURE, strlen (SIGNATURE)) < 0)
			die_status (53, "couldn't write message");		

		while ((r_len = read (tmp_fd, buffer, BUFFER_SIZE)) != 0) {		
			if (r_len < 0)
				die_status (54, "couldn't read message");

			if (write (message_pipe [1], buffer, r_len) < 0) {
				die_status (81, "couldn't write temp message");
			}
		}
		close (tmp_fd);
		if (write (envelope_pipe [1], envelope, envelope_len) < 0)
			die_status (53, "couldn't write envelope");
	} else {
		char *log = malloc (strlen (tmp_path) + strlen (virus_name) + 8);
		bzero (log, strlen (tmp_path) + strlen (virus_name) + 8);
		sprintf (log, "virus: %s %s", tmp_path, virus_name);
		write_log (log);
		free (log);
#ifdef VIRUSMASTER
		send_notification (	virus_name, 
							tmp_path,
							message_pipe [1], 
							tmp_fd,
							envelope_pipe [1], 
							envelope, envelope_len);
#endif

		close (tmp_fd);
		save_maildir (tmp_path);
	}

	if (virus_name != NULL)
		free (virus_name);

	unlink (tmp_path);
	free (tmp_path);
	free (envelope);
	close (message_pipe [1]);
	close (envelope_pipe [1]);
	
	if (waitpid(pid, &child_status, WUNTRACED) == -1)
		die_status (81, "waitpid failed");

    if (!WIFEXITED(child_status)) 
		die_status (81, "qmail-queue crashed");

	if (ret == CL_VIRUS)
		exit (31);

	return 0;
}

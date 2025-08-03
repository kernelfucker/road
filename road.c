/* See LICENSE file for license details */
/* road - execute commands as another user */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <shadow.h>
#include <fcntl.h>
#include <crypt.h>
#include <errno.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/types.h>

#define version "0.3"

#define conf "/etc/road.conf"
#define default_pt "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin"

const int so = STDOUT_FILENO;
const int si = STDIN_FILENO;
const int exfl = EXIT_FAILURE;
const int exsc = EXIT_SUCCESS;

typedef struct{
	int permit;
	char *from_user;
	char *to_user;
	char *command;
} rule;

rule *rules = NULL;
int num_rules = 0;

void secure_wipe(const char *s, size_t l){
	if(!s || l == 0) return;
	volatile char *p = (volatile char *)s;
	while(l--) *p++ = 0;
	__asm__ __volatile__ ("" : : "r"(p) : "memory");
}

void yescrypt_salt(char *salt, size_t size){
	const char *pf = "$y$j9T$";
	char rb[16];
	if(getentropy(rb, sizeof(rb))){
		perror("road: getentropy failed");
		exit(exfl);
	}

	if(crypt_gensalt_r(pf, 0, rb, sizeof(rb), salt, size) == NULL){
		perror("road: crypt_gensalt_r failed");
		exit(exfl);
	}

	secure_wipe(rb, sizeof(rb));
}

char *getpasswd(){
	int tf = open("/dev/tty", O_RDWR|O_NOCTTY);
	if(tf == -1){
		if(!isatty(si)){
			fprintf(stderr, "road: no tty available\n");
			return NULL;
		}

		tf = dup(si);
		if(tf == -1){
			perror("road: dup failed");
			return NULL;
		}
	}

	struct termios t, n;
	if(tcgetattr(tf, &t) == -1){
		perror("road: tcgetattr failed");
		close(tf);
		return NULL;
	}

	n = t;
	n.c_lflag &= ~ECHO;
	if(tcsetattr(tf, TCSANOW, &n) == -1){
		perror("road: failed to disable echo");
		close(tf);
		return NULL;
	}

	FILE *tty = fdopen(tf, "r+");
	if(!tty){
		perror("road: fdopen failed");
		tcsetattr(tf, TCSANOW, &t);
		close(tf);
		return NULL;
	}

	fprintf(tty, "passwd: ");
	fflush(tty);

	char *passwd = NULL;

	size_t len = 0;
	ssize_t read = getline(&passwd, &len, tty);

	tcsetattr(tf, TCSANOW, &t);
	fclose(tty);
	if(read == -1){
		if(passwd){
			secure_wipe(passwd, len);
			free(passwd);
		}

		return NULL;
	}

	if(read > 0 && passwd[read-1] == '\n')
		passwd[read-1] = '\0';

	return passwd;
}

void frules(){
	for(int i = 0; i < num_rules; i++){
		free(rules[i].from_user);
		free(rules[i].to_user);
		free(rules[i].command);
	}

	free(rules);
}

void pconf(){
	FILE *f = fopen(conf, "r");
	if(!f){
		fprintf(stderr, "road: failed to open %s: no such file\n", conf);
		exit(exfl);
	}

	char ln[256];
	while(fgets(ln, sizeof(ln), f)){
		if(ln[0] == '#' || ln[0] == '\n') continue;

		char at[10], from[50], as[10], to[50], command[100] = "*", path[100] = "*";
		int flds = sscanf(ln, "%9s %49s %9s %49s %99s %99s", at, from, as, to, command, path);

		if(flds == 4 && strcmp(as, "as") == 0){
			snprintf(command, sizeof(command), "%s", "*");
		}

		else if(flds >=5 && strcmp(as, "as") == 0 && strcmp(command, "command") == 0){
			if(flds == 6){
				snprintf(command, sizeof(command), "%s", path);
			} else {
				snprintf(command, sizeof(command), "%s", "*");
			}
		}

		else{
			fprintf(stderr, "road: invalid line: %s\n", ln);
			continue;
		}

		rule *new_rules = realloc(rules, (num_rules + 1) * sizeof(rule));
		if(!new_rules){
			perror("road: malloc failed");
			exit(exfl);
		}

		rules = new_rules;
		rules[num_rules] = (rule){
			.permit = (strcmp(at, "permit") == 0),
			.from_user = strdup(from),
			.to_user = strdup(to),
			.command = strdup(command)
		};

		if(!rules[num_rules].from_user || !rules[num_rules].to_user || !rules[num_rules].command){
			perror("road: malloc failed");
			exit(exfl);
		}

		num_rules++;
	}

	fclose(f);
}

unsigned char t_secure_memcmp(const void *a, const void *b, size_t l){
	const unsigned char *pa = a;
	const unsigned char *pb = b;
	unsigned char d = 0;
	for(size_t i = 0; i < l; i++){
		d |= pa[i] ^ pb[i];
	}

	return d;
}

int verify_passwd(const char *user, const char *passwd_last){
	struct spwd *sp = getspnam(user);
	if(!sp){
		fprintf(stderr, "road: user '%s' not found\n", user);
		return 0;
	}

	if(strncmp(sp->sp_pwdp, "$y$", 3) != 0){
		char new_salt[32];
		yescrypt_salt(new_salt, sizeof(new_salt));
		char *new_hash = crypt(passwd_last, new_salt);
		if(!new_hash){
			perror("road: crypt failed");
			return 0;
		}

		return 0;
	}

	char *new_hash = crypt(passwd_last, sp->sp_pwdp);
	return new_hash && (strcmp(new_hash, sp->sp_pwdp) == 0);
}
	
void check_p(const char *from, const char *to, const char *command){
	for(int i = 0; i < num_rules; i++){
		if(strcmp(rules[i].from_user, from) == 0 &&
			strcmp(rules[i].to_user, to) == 0 &&
			(strcmp(rules[i].command, "*") == 0 || strcmp(rules[i].command, command) == 0)){
			if(rules[i].permit){
				return;
			}

			fprintf(stderr, "road: permission denied for '%s'as '%s' to run '%s'\n", from, to, command);
			exit(exfl);
		}
	}

	fprintf(stderr, "road: no matching rule for '%s' as '%s' to run '%s'\n", from, to, command);
	exit(exfl);
}

void e_as_user(const char *user, char **argv){
	if(argv[0] == NULL){
		fprintf(stderr, "road: no command specified\n");
		exit(exfl);
	}

	struct passwd *pw = getpwnam(user);
	if(!pw){
		fprintf(stderr, "road: user '%s' not found\n", user);
		exit(exfl);
	}

	setenv("PATH", default_pt, 1);
	setenv("USER", user, 1);
	setenv("HOME", pw->pw_dir, 1);

	if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0){
		perror("road: failed to switch user");
		exit(exfl);
	}

	execvp(argv[0], argv);
	fprintf(stderr, "road: '%s': command not found\n", argv[0]);
	exit(exfl);
}

int main(int argc, char **argv){
	struct rlimit rl = {0, 0};
	setrlimit(RLIMIT_CORE, &rl);
	if(argc > 1){
		if(strcmp(argv[1], "-v") == 0){
			printf("road-%s\n", version);
			exit(exsc);
		}

		else if(strcmp(argv[1], "-h") == 0){
			printf("usage: %s [command]..\n", argv[0]);
			printf("options:\n");
			printf("  -v	show version information\n");
			printf("  -h	display this\n");
			exit(exsc);
		}
	}

	if(argc < 2){
		fprintf(stderr, "usage: %s [command]..\n", argv[0]);
		fprintf(stderr, "try '%s -h' for more information\n", argv[0]);
		exit(exfl);
	}

	pconf();
	atexit(frules);
	char *from_user = getenv("USER");
	if(!from_user){
		struct passwd *pw = getpwuid(getuid());
		if(pw){
			from_user = pw->pw_name;
		} else {
			fprintf(stderr, "road: couldn not determine current user\n");
			exit(exfl);
		}
	}

	const char *to_user = "root";
	check_p(from_user, to_user, argv[1]);

	char *passwd_read = getpasswd();
	if(!passwd_read){
		fprintf(stderr, "road: failed to read passwd\n");
		exit(exfl);
	}

	size_t passwd_len = strlen(passwd_read);
	if(!verify_passwd(from_user, passwd_read)){
		fprintf(stderr, "road: incorrect passwd for '%s'\n", from_user);
		secure_wipe(passwd_read, strlen(passwd_read));
		free(passwd_read);
		exit(exfl);
	}

	secure_wipe(passwd_read, passwd_len);
	free(passwd_read);

	fprintf(stderr, "\n");

	fflush(stdout);
	fflush(stderr);

	e_as_user(to_user, argv + 1);
	return exsc;
}

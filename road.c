/* See LICENSE file for license details */
/* road - execute commands as another user */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>

#define conf "/etc/road.conf"
#define default_pt "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin"

const int so = STDOUT_FILENO;
const int si = STDIN_FILENO;
const int exfl = EXIT_FAILURE;
const int exsc = EXIT_SUCCESS;
const int tcan = TCSANOW;

typedef struct{
	int permit;
	char *from_user;
	char *to_user;
	char *command;
} rule;

rule *rules = NULL;
int num_rules = 0;

void disable_echo(){
	struct termios tios;
	tcgetattr(si, &tios);
	tios.c_lflag &= ~ECHO;
	tcsetattr(si, tcan, &tios);
}

void enable_echo(){
	struct termios tios;
	tcgetattr(si, &tios);
	tios.c_lflag |= ECHO;
	tcsetattr(si, tcan, &tios);
}

char *getpasswd(){
	printf("passwd: ");
	fflush(stdout);
	disable_echo();
	char *passwd = NULL;
	size_t len = 0;
	ssize_t read = getline(&passwd, &len, stdin);
	enable_echo();
	printf("\n");
	if(read == -1){
		free(passwd);
		return NULL;
	}

	passwd[strcspn(passwd, "\n")] = '\0';
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
		fprintf(stderr, "road: failed to open %s: %s\n", conf, strerror(errno));
		exit(exfl);
	}

	char ln[256];
	while(fgets(ln, sizeof(ln), f)){
		if(ln[0] == '#' || ln[0] == '\n') continue;

		char at[10], from[50], as[10], to[50], command[100] = "*", path[100] = "*";
		int flds = sscanf(ln, "%9s %49s %9s %49s %99s %99s", at, from, as, to, command, path);

		if(flds == 4 && strcmp(as, "as") == 0){
			strcpy(command, "*");
		}

		else if(flds >=5 && strcmp(as, "as") == 0 && strcmp(command, "command") == 0){
			if(flds == 6){
				strcpy(command, path);
			} else {
				strcpy(command, "*");
			}
		}

		else{
			fprintf(stderr, "road: invalid line: %s", ln);
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

int verify_passwd(const char *user, const char *passwd_last){
	struct spwd *sp = NULL;
	struct passwd *pw = getpwnam(user);
	if(!pw){
		fprintf(stderr, "road: user '%s' not found\n", user);
		return 0;
	}

	sp = getspnam(user);
	if(sp){
		char *encrypted = crypt(passwd_last, sp->sp_pwdp);
		if(!encrypted){
			perror("road: crypt failed");
			return 0;
		}

		return strcmp(encrypted, sp->sp_pwdp) == 0;
	}

	if(strcmp(pw->pw_passwd, "x") != 0){
		char *encrypted = crypt(passwd_last, pw->pw_passwd);
		if(!encrypted){
			perror("road: crypt failed");
			return 0;
		}

		return strcmp(encrypted, pw->pw_passwd) == 0;
	}

	fprintf(stderr, "road: could not verify passwd, no access to shadow\n");
	return 0;
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
	fprintf(stderr, "road: failed to execute '%s': %s\n", argv[0], strerror(errno));
	exit(exfl);
}

int main(int argc, char **argv){
	if(argc < 2){
		fprintf(stderr, "usage: %s [command]..\n", argv[0]);
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

	if(!verify_passwd(from_user, passwd_read)){
		fprintf(stderr, "road: incorrect passwd for user '%s'\n", from_user);
		free(passwd_read);
		exit(exfl);
	}

	free(passwd_read);

	e_as_user(to_user, argv + 1);
	return exsc;
}

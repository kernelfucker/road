# road
execute commands as another user

# compile
$ clang road.c -o road -Wall -Werror -Os -s -lcrypt -fstack-protector-all

# usage
$ road emerge -va app-editors/vim

# cp, chown, chmod
\# cp road /usr/bin/road

\# chown -v root:root /usr/bin/road

\# chmod -v 4755 /usr/bin/road

# example road.conf
**note: directory of the road.conf is /etc/road.conf**

permit user as root

permit user as root command emerge

permit user as root command fdisk

permit user as root command *

# is road minimal than doas?
<img width="520" height="160" alt="image" src="https://github.com/user-attachments/assets/3f62f093-2bb4-4de0-aa98-ed69f22d410f" />

# is road secure than doas?
\- yescrypt is using it in the back and thats why

\- no buffer overflow problems

# example
<img width="340" height="160" alt="image" src="https://github.com/user-attachments/assets/224187b7-b475-4588-845b-4c91f1ca02b1" />

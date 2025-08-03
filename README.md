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
![image](https://github.com/user-attachments/assets/e021549e-9ba7-4d23-8a2f-fd2ae2f34c8b)

# is road secure than doas?
\- yescrypt is using it in the back and thats why

\- no buffer overflow problems

# example
![image](https://github.com/user-attachments/assets/0a2608fc-4077-443b-9f19-fec32dde15eb)

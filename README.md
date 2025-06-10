# road
execute commands as another user

# compile
$ clang road.c -o road -lcrypt

# usage
$ road emerge -va app-editors/vim

# cp, chown, chmod
\# cp road /usr/bin/road

\# chown -v root:root /usr/bin/road

\# chmod -v 4755 /usr/bin/road

# example road.conf
**note: directory of the road.conf file is /etc/road.conf**

permit user as root

permit user as root command emerge

permit user as root command fdisk

permit user as root command *

# is the road minimal than doas?
answer: yes

proff:

![image](https://github.com/user-attachments/assets/005ffc91-55d7-47b1-aee2-f724dc81bd12)

# example
![image](https://github.com/user-attachments/assets/abd86fed-0427-4968-801d-46425fdf31e8)

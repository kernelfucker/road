# road
execute commands as another user

# compile
$ clang road.c -o road -lcrypt -fstack-protector-all -D_XOPEN_SOURCE=700

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

# is road minimal than doas?
![image](https://github.com/user-attachments/assets/cb356199-5371-4c3b-ac96-61f6e3619435)

# is road secure than doas?
\- yescrypt is using it in the back and thats why

\- no buffer overflow problems

# example
![image](https://github.com/user-attachments/assets/abd86fed-0427-4968-801d-46425fdf31e8)

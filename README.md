# WrongSSH
## a wrong way of managing your docker containers

https://jpetazzo.github.io/2014/06/23/docker-ssh-considered-evil/

> If you run SSHD in your Docker containers, you're doing it wrong!

## How to use:
- generate some keys (id_rsa, id_ed25519);
- run the server;
- ssh -p 2200 root@docker-container@server

## TODO:
- [ ] Support logging in as a non-root user

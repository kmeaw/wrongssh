# WrongSSH
## a wrong way of managing your docker containers

https://jpetazzo.github.io/2014/06/23/docker-ssh-considered-evil/

> If you run SSHD in your Docker containers, you're doing it wrong!

## How to use:
- generate some keys (id_rsa, id_ed25519);
- run the server;
- ssh -p 2200 root@docker-container@server

You can authenticate with a password (/etc/shadow) or a public key
(/etc/passwd + $HOME/.ssh/authorized_keys).

## TODO:
- [ ] Support logging in as a non-root user
- [ ] Support iptables' REDIRECT target to mimic a running sshd on port 22

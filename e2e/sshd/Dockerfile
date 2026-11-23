# Throwaway git server for the e2e tests: user "git" with git-shell, one bare
# repo at /srv/repo.git, keys from /etc/ssh/authorized_keys/git (mounted).
FROM alpine:3.22
RUN apk add --no-cache openssh-server git \
 && adduser -D -s /usr/bin/git-shell git \
 && sed -i 's/^git:!/git:*/' /etc/shadow \
 && ssh-keygen -A \
 && mkdir -p /srv /etc/ssh/authorized_keys \
 && git init --bare -b main /srv/repo.git \
 && chown -R git:git /srv
COPY sshd_config /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd", "-D", "-e"]

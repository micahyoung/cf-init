# cf-init


## Post-steps

```/etc/hosts
echo 172.18.161.254 api.system.cf.young.io uaa.system.cf.young.io login.system.cf.young.io doppler.system.cf.young.io loggregator.system.cf.young.io hm9000.system.cf.young.io ssh.system.cf.young.io foo.app.cf.young.io >> /etc/hosts
```

```bash
cat cf-init/cf-release/ha-proxy-certs/cert-authority.crt >> /etc/ssl/certs/ca-certificates.crt
```

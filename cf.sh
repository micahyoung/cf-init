#!/bin/bash

proxy_ip="172.18.161.5"
export http_proxy="http://$proxy_ip:8123"
export https_proxy="http://$proxy_ip:8123"
export GOPATH=~/.go
export PATH=`pwd`/bin:$PATH:$GOPATH/bin
cf_version=254
uname=`uname | tr '[A-Z]' '[a-z]'`
case $uname in
darwin*)
  base64="base64"
  ;;
linux*)
  base64="base64 -w0"
  ;;
esac

if ! [ -d bin ]; then
  mkdir bin
fi

if ! go version; then
  case $uname in
  darwin*)
    brew install golang
    ;;
  linux*)
    apt install golang
    ;;
  esac
fi

pushd bin
  if ! [ -f cf ]; then
    case $uname in
    darwin*)
      cli_url="https://cli.run.pivotal.io/stable?release=macosx64-binary&version=6.25.0&source=github-rel"
      ;;
    linux*)
      cli_url="https://cli.run.pivotal.io/stable?release=linux64-binary&version=6.25.0&source=github-rel"
      ;;
    esac

    curl -L $cli_url > cf-cli.tgz
    tar xf cf-cli.tgz cf
    rm cf-cli.tgz
  fi

  if ! [ -f spiff ]; then
    curl -JL "https://github.com/cloudfoundry-incubator/spiff/releases/download/v1.0.8/spiff_$(uname)_amd64.zip" > spiff.zip

    unzip spiff.zip
    rm spiff.zip
  fi
popd

if ! [ -d cf-release ]; then
  git clone https://github.com/cloudfoundry/cf-release.git
fi

if [ "$2" == "generate-certs" ]; then
  pushd cf-release
    git checkout "v$cf_version"
    git clean -fdx
    git submodule update --init src/consul-release
    ./scripts/generate-cf-diego-certs
    ./scripts/generate-blobstore-certs
    ./scripts/generate-loggregator-certs cf-diego-certs/cf-diego-ca.crt cf-diego-certs/cf-diego-ca.key
    ./scripts/generate-statsd-injector-certs loggregator-certs/loggregator-ca.crt loggregator-certs/loggregator-ca.key
    ./scripts/generate-hm9000-certs
    ./scripts/generate-consul-certs
    ./scripts/generate-etcd-certs
    ./scripts/generate-uaa-certs
    ./scripts/generate-certs service-provider-certs uaa.service.cf.internal
    ./scripts/generate-certs ha-proxy-certs '*.cf.young.io'
    cat ha-proxy-certs/server.key ha-proxy-certs/server.crt > ha-proxy-certs/server-combined.pem
    mkdir jwt-keys
    openssl genrsa -out jwt-keys/privkey.pem 2048
    openssl rsa -pubout -in jwt-keys/privkey.pem -out jwt-keys/pubkey.pem
  popd
fi


DIRECTOR_UUID=${1:?'Director UUID required'} #changeme
NET_ID='6db713e0-b17b-4bf8-ae44-80e02992a74d' #changeme
ENVIRONMENT=cf
FLOATING_IP=172.18.161.254
SYSTEM_DOMAIN=system.cf.young.io
SYSTEM_DOMAIN_ORGANIZATION=system
APP_DOMAIN=app.cf.young.io
STAGING_UPLOAD_USER=staging
STAGING_UPLOAD_PASSWORD=password
BULK_API_PASSWORD=password
DB_ENCRYPTION_KEY=secret
CC_MUTUAL_TLS_CA_CERT=$($base64 cf-release/cf-diego-certs/cf-diego-ca.crt)
CC_MUTUAL_TLS_PUBLIC_CERT=$($base64 cf-release/cf-diego-certs/cloud-controller.crt)
CC_MUTUAL_TLS_PRIVATE_KEY=$($base64 cf-release/cf-diego-certs/cloud-controller.key)
BLOBSTORE_USERNAME=blobstore
BLOBSTORE_PASSWORD=password
BLOBSTORE_SECRET=blobstore-secret
BLOBSTORE_TLS_CERT=$($base64 cf-release/blobstore-certs/server.crt)
BLOBSTORE_PRIVATE_KEY=$($base64 cf-release/blobstore-certs/server.key)
BLOBSTORE_CA_CERT=$($base64 cf-release/blobstore-certs/server-ca.crt) 
NATS_USER=nats
NATS_PASSWORD=nats-password
ADMIN_SECRET=admin
ADMIN_PASSWORD=admin
LOGGREGATOR_CA_CERT=$($base64 cf-release/loggregator-certs/loggregator-ca.crt)
LOGGREGATOR_DOPPLER_CERT=$($base64 cf-release/loggregator-certs/doppler.crt)
LOGGREGATOR_DOPPLER_KEY=$($base64 cf-release/loggregator-certs/doppler.key)
LOGGREGATOR_TRAFFICCONTROLLER_CERT=$($base64 cf-release/loggregator-certs/trafficcontroller.crt)
LOGGREGATOR_TRAFFICCONTROLLER_KEY=$($base64 cf-release/loggregator-certs/trafficcontroller.key)
LOGGREGATOR_METRON_CERT=$($base64 cf-release/loggregator-certs/metron.crt)
LOGGREGATOR_METRON_KEY=$($base64 cf-release/loggregator-certs/metron.key)
LOGGREGATOR_SYSLOGDRAINBINDER_CERT=$($base64 cf-release/loggregator-certs/syslogdrainbinder.crt)
LOGGREGATOR_SYSLOGDRAINBINDER_KEY=$($base64 cf-release/loggregator-certs/syslogdrainbinder.key)
LOGGREGATOR_STATSDINJECTOR_CERT=$($base64 cf-release/statsd-injector-certs/statsdinjector.crt)
LOGGREGATOR_STATSDINJECTOR_KEY=$($base64 cf-release/statsd-injector-certs/statsdinjector.key)
LOGGREGATOR_ENDPOINT_SHARED_SECRET=secret
HM9000_SERVER_KEY=$($base64 cf-release/hm9000-certs/hm9000_server.key)
HM9000_SERVER_CERT=$($base64 cf-release/hm9000-certs/hm9000_server.crt)
HM9000_CLIENT_KEY=$($base64 cf-release/hm9000-certs/hm9000_client.key)
HM9000_CLIENT_CERT=$($base64 cf-release/hm9000-certs/hm9000_client.crt)
HM9000_CA_CERT=$($base64 cf-release/hm9000-certs/hm9000_ca.crt)
CONSUL_ENCRYPT_KEY=secret
CONSUL_CA_CERT=$($base64 cf-release/consul-certs/server-ca.crt)
CONSUL_SERVER_CERT=$($base64 cf-release/consul-certs/server.crt)
CONSUL_SERVER_KEY=$($base64 cf-release/consul-certs/server.key)
CONSUL_AGENT_CERT=$($base64 cf-release/consul-certs/agent.crt)
CONSUL_AGENT_KEY=$($base64 cf-release/consul-certs/agent.key)
ETCD_CA_CERT=$($base64 cf-release/etcd-certs/etcd-ca.crt)
ETCD_CLIENT_CERT=$($base64 cf-release/etcd-certs/client.crt)
ETCD_CLIENT_KEY=$($base64 cf-release/etcd-certs/client.key)
ETCD_PEER_CA_CERT=$($base64 cf-release/etcd-certs/peer-ca.crt)
ETCD_PEER_CERT=$($base64 cf-release/etcd-certs/peer.crt)
ETCD_PEER_KEY=$($base64 cf-release/etcd-certs/peer.key)
ETCD_SERVER_CERT=$($base64 cf-release/etcd-certs/server.crt)
ETCD_SERVER_KEY=$($base64 cf-release/etcd-certs/server.key)
DOPPLER_SECRET=secret
CCDB_PASSWORD=password
UAADB_PASSWORD=password
DIEGODB_PASSWORD=password
ROUTER_USER=router
ROUTER_PASSWORD=password
CC_CLIENT_SECRET=secret
CC_ROUTING_SECRET=secret
CLOUD_CONTROLLER_USERNAME_LOOKUP_SECRET=secret
GOROUTER_SECRET=secret
TCP_EMITTER_SECRET=secret
TCP_ROUTER_SECRET=secret
LOGIN_CLIENT_SECRET=secret
NOTIFICATIONS_CLIENT_SECRET=secret
CC_SERVICE_DASHBOARDS_SECRET=secret
UAA_CA_CERT=$($base64 cf-release/uaa-certs/server-ca.crt)
UAA_SERVER_CERT=$($base64 cf-release/uaa-certs/server.crt)
UAA_SERVER_KEY=$($base64 cf-release/uaa-certs/server.key)
SERVICE_PROVIDER_PRIVATE_KEY=$($base64 cf-release/service-provider-certs/server.key)
SERVICE_PROVIDER_PRIVATE_CERT=$($base64 cf-release/service-provider-certs/server.crt)
HA_PROXY_COMBINED_CERT=$($base64 cf-release/ha-proxy-certs/server-combined.pem)
JWT_VERIFICATION_KEY=$($base64 cf-release/jwt-keys/pubkey.pem)
JWT_SIGNING_KEY=$($base64 cf-release/jwt-keys/privkey.pem)

cat > cf-stub.yml <<EOF
---
director_uuid: $DIRECTOR_UUID

releases:
- name: cf
  url: https://bosh.io/d/github.com/cloudfoundry/cf-release?v=$cf_version
  sha1: 2b1b4de54927fb0b92c6ace83df353969b1fa69b
  version: $cf_version

compilation:
  cloud_properties:
    instance_type: m1.small
  workers: 3

meta:
  environment: $ENVIRONMENT

  floating_static_ips:
  - $FLOATING_IP

networks:
  - name: floating
    type: vip
    cloud_properties:
      net_id: $NET_ID
      security_groups: []
  - name: cf1
    type: manual
    subnets:
    - range: 10.0.0.0/24
      gateway: 10.0.0.1
      reserved:
      - 10.0.0.2 - 10.0.0.100
      - 10.0.0.200 - 10.0.0.254
      dns:
      - 172.18.161.1
      static:
      - 10.0.0.125 - 10.0.0.175
      cloud_properties:
        net_id: $NET_ID
        security_groups: [cf]
  - name: cf2
    type: manual
    subnets: (( networks.cf1.subnets )) # cf2 unused by default with the OpenStack template
                                        # but the general upstream templates require this
                                        # to be a semi-valid value, so just copy cf1

properties:
  system_domain: $SYSTEM_DOMAIN
  system_domain_organization: $SYSTEM_DOMAIN_ORGANIZATION
  app_domains:
   - $APP_DOMAIN

  ssl:
    skip_cert_verify: true

  cc:
    staging_upload_user: $STAGING_UPLOAD_USER
    staging_upload_password: $STAGING_UPLOAD_PASSWORD
    bulk_api_password: $BULK_API_PASSWORD
    db_encryption_key: $DB_ENCRYPTION_KEY
    uaa_skip_ssl_validation: true
    mutual_tls:
      ca_cert: !!binary $CC_MUTUAL_TLS_CA_CERT
      public_cert: !!binary $CC_MUTUAL_TLS_PUBLIC_CERT
      private_key: !!binary $CC_MUTUAL_TLS_PRIVATE_KEY

  blobstore:
    admin_users:
      - username: $BLOBSTORE_USERNAME
        password: $BLOBSTORE_PASSWORD
    secure_link:
      secret: $BLOBSTORE_SECRET
    tls:
      cert: !!binary $BLOBSTORE_TLS_CERT
      private_key: !!binary $BLOBSTORE_PRIVATE_KEY
      ca_cert: !!binary $BLOBSTORE_CA_CERT
  consul:
    encrypt_keys:
      - $CONSUL_ENCRYPT_KEY
    ca_cert: !!binary $CONSUL_CA_CERT
    server_cert: !!binary $CONSUL_SERVER_CERT
    server_key: !!binary $CONSUL_SERVER_KEY
    agent_cert: !!binary $CONSUL_AGENT_CERT
    agent_key: !!binary $CONSUL_AGENT_KEY
  dea_next:
    disk_mb: 2048
    memory_mb: 1024
  etcd:
    require_ssl: true
    ca_cert: !!binary $ETCD_CA_CERT
    client_cert: !!binary $ETCD_CLIENT_CERT
    client_key: !!binary $ETCD_CLIENT_KEY
    peer_ca_cert: !!binary $ETCD_PEER_CA_CERT
    peer_cert: !!binary $ETCD_PEER_CERT
    peer_key: !!binary $ETCD_PEER_KEY
    server_cert: !!binary $ETCD_SERVER_CERT
    server_key: !!binary $ETCD_SERVER_KEY
  loggregator:
    tls:
      ca_cert: !!binary $LOGGREGATOR_CA_CERT
      doppler:
        cert: !!binary $LOGGREGATOR_DOPPLER_CERT
        key: !!binary $LOGGREGATOR_DOPPLER_KEY
      trafficcontroller:
        cert: !!binary $LOGGREGATOR_TRAFFICCONTROLLER_CERT
        key: !!binary $LOGGREGATOR_TRAFFICCONTROLLER_KEY
      metron:
        cert: !!binary $LOGGREGATOR_METRON_CERT
        key: !!binary $LOGGREGATOR_METRON_KEY
      syslogdrainbinder:
        cert: !!binary $LOGGREGATOR_SYSLOGDRAINBINDER_CERT
        key: !!binary $LOGGREGATOR_SYSLOGDRAINBINDER_KEY
      statsd_injector:
        cert: !!binary $LOGGREGATOR_STATSDINJECTOR_CERT
        key: !!binary $LOGGREGATOR_STATSDINJECTOR_KEY
  loggregator_endpoint:
    shared_secret: $LOGGREGATOR_ENDPOINT_SHARED_SECRET
  login:
    protocol: http
    saml:
      serviceProviderKey: !!binary $SERVICE_PROVIDER_PRIVATE_KEY
      serviceProviderCertificate: !!binary $SERVICE_PROVIDER_PRIVATE_CERT
  nats:
    user: $NATS_USER
    password: $NATS_PASSWORD
  router:
    status:
      user: $ROUTER_USER
      password: $ROUTER_PASSWORD
  uaa:
    admin:
      client_secret: $ADMIN_SECRET
    ca_cert: !!binary $UAA_CA_CERT
    cc:
      client_secret: $CC_CLIENT_SECRET
    clients:
      cc_routing:
        secret: $CC_ROUTING_SECRET
      cloud_controller_username_lookup:
        secret: $CLOUD_CONTROLLER_USERNAME_LOOKUP_SECRET
      doppler:
        secret: $DOPPLER_SECRET
      gorouter:
        secret: $GOROUTER_SECRET
      tcp_emitter:
        secret: $TCP_EMITTER_SECRET
      tcp_router:
        secret: $TCP_ROUTER_SECRET
      login:
        secret: $LOGIN_CLIENT_SECRET
      notifications:
        secret: $NOTIFICATIONS_CLIENT_SECRET
      cc-service-dashboards:
        secret: $CC_SERVICE_DASHBOARDS_SECRET
    jwt:
      verification_key: !!binary $JWT_VERIFICATION_KEY
      signing_key: !!binary $JWT_SIGNING_KEY
    require_https: false
    scim:
      users:
      - name: admin
        password: $ADMIN_PASSWORD
        groups:
        - scim.write
        - scim.read
        - openid
        - cloud_controller.admin
        - doppler.firehose
    sslCertificate: !!binary $UAA_SERVER_CERT
    sslPrivateKey: !!binary $UAA_SERVER_KEY

  ccdb:
    roles:
    - name: ccadmin
      password: $CCDB_PASSWORD
  uaadb:
    roles:
    - name: uaaadmin
      password: $UAADB_PASSWORD
  databases:
    roles:
    - name: ccadmin
      password: $CCDB_PASSWORD
    - name: uaaadmin
      password: $UAADB_PASSWORD
    - name: diego
      password: $DIEGODB_PASSWORD
  hm9000:
    server_key: !!binary $HM9000_SERVER_KEY
    server_cert: !!binary $HM9000_SERVER_CERT
    client_key: !!binary $HM9000_CLIENT_KEY
    client_cert: !!binary $HM9000_CLIENT_CERT
    ca_cert: !!binary $HM9000_CA_CERT

jobs:
  - name: ha_proxy_z1
    networks:
      - name: cf1
        default:
        - dns
        - gateway
    properties:
      ha_proxy:
        ssl_pem: !!binary $HA_PROXY_COMBINED_CERT
  - name: api_z1
    templates:
      - name: consul_agent
        release: cf
        consumes: {consul: nil}
      - name: java-buildpack
        release: cf
      - name: java-offline-buildpack
        release: cf
      - name: go-buildpack
        release: cf
      - name: binary-buildpack
        release: cf
      - name: nodejs-buildpack
        release: cf
      - name: ruby-buildpack
        release: cf
      - name: php-buildpack
        release: cf
      - name: python-buildpack
        release: cf
      - name: staticfile-buildpack
        release: cf
      - name: dotnet-core-buildpack
        release: cf
      - name: cloud_controller_ng
        release: cf
        consumes: {nats: nil}
      - name: cloud_controller_clock
        release: cf
        consumes: {nats: nil}
      - name: cloud_controller_worker
        release: cf
        consumes: {nats: nil}
      - name: metron_agent
        release: cf
      - name: statsd_injector
        release: cf
      - name: route_registrar
        release: cf
        consumes: {nats: nil}

  - name: api_worker_z1
    instances: 0
  - name: clock_global
    instances: 0
EOF

pushd cf-release
  ./scripts/generate_deployment_manifest openstack ../cf-stub.yml > ../cf-deployment.yml
popd


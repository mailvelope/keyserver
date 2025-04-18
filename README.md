Mailvelope Keyserver
====================

A simple OpenPGP public key server that validates email address ownership of uploaded keys.

## Why not use Web of Trust?

There are already OpenPGP key servers like the [SKS keyserver](https://github.com/SKS-Keyserver/sks-keyserver) that employ the [Web of Trust](https://en.wikipedia.org/wiki/Web_of_trust) to provide a way to authenticate a user's PGP keys. The problem with these servers are discussed [here](https://en.wikipedia.org/wiki/Key_server_(cryptographic)#Problems_with_keyservers).

### Privacy

The web of trust raises some valid privacy concerns. Not only is a user's social network made public, common SKS servers are also not compliant with the [EU Data Protection Directive](https://en.wikipedia.org/wiki/Data_Protection_Directive) due to lack of key deletion. This key server addresses these issues by not employing the web of trust and by allowing key removal.

### Usability

The main issue with the Web of Trust though is that it does not scale in terms of usability. The goal of this key server is to enable a better user experience for OpenPGP user agents by providing a more reliable source of public keys. Similar to messengers like Signal, users verify their email address by clicking on a link of a PGP encrypted message. This prevents user A from uploading a public key for user B. With this property in place, automatic key lookup is more reliable than with standard SKS servers.

This requires more trust to be placed in the service provider that hosts a key server, but we believe that this trade-off is necessary to improve the user experience for average users. Tech-savvy users or users with a threat model that requires stronger security may still choose to verify PGP key fingerprints just as before.

## Standardization and (De)centralization

The idea is that an identity provider such as an email provider can host their own key directory under a common `openpgpkey` subdomain. An OpenPGP supporting user agent should attempt to lookup keys under the user's domain e.g. `https://openpgpkey.example.com` for `user@example.com` first. User agents can host their own fallback key server as well, in case a mail provider does not provide its own key directory.

# Demo

Try out the server here: [https://keys.mailvelope.com](https://keys.mailvelope.com)

# API

The key server provides a modern RESTful API, but is also backwards compatible to the OpenPGP HTTP Keyserver Protocol (HKP). The following properties are enforced by the key server to enable reliable automatic key look in user agents:

* Only public keys with at least one verified email address are served
* There can be only one public key per verified email address at a given time
* A key ID specified in a query must be at least 16 hex characters (64-bit long key ID)
* Key ID collisions are checked upon key upload to prevent collision attacks

## HKP API

The HKP APIs are not documented here. Please refer to the [HKP specification](https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00) to learn more. The server generally implements the full specification, but has some constraints to improve the security for automatic key lookup:

#### Accepted `search` parameters
* Email addresses
* V4 Fingerprints
* Key IDs with 16 digits (64-bit long key ID)

#### Accepted `op` parameters
* get
* index
* vindex

#### Accepted `options` parameters
* mr

#### Usage example with GnuPG

```
gpg --keyserver hkps://keys.mailvelope.com --search  info@mailvelope.com
```

## REST API

### Lookup a key

#### By key ID

```
GET /api/v1/key?keyId=b8e4105cc9dedc77
```

#### By fingerprint

```
GET /api/v1/key?fingerprint=e3317db04d3958fd5f662c37b8e4105cc9dedc77
```

#### By email address

```
GET /api/v1/key?email=user@example.com
```

#### Payload (JSON):

```json
{
  "keyId": "b8e4105cc9dedc77",
  "fingerprint": "e3317db04d3958fd5f662c37b8e4105cc9dedc77",
  "userIds": [
    {
      "name": "Jon Smith",
      "email": "jon@smith.com",
      "verified": "true"
    },
    {
      "name": "Jon Smith",
      "email": "jon@organization.com",
      "verified": "false"
    }
  ],
  "created": "Sat Oct 17 2015 12:17:03 GMT+0200 (CEST)",
  "algorithm": "rsaEncryptSign",
  "keySize": "4096",
  "publicKeyArmored": "-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----"
}
```

* **keyId**: The 16 char key id in hex
* **fingerprint**: The 40 char key fingerprint in hex
* **userIds.name**: The user ID's name
* **userIds.email**: The user ID's email address
* **userIds.verified**: If the user ID's email address has been verified
* **created**: The key creation time as a JavaScript Date
* **algorithm**: The primary key alogrithm
* **keySize**: The key length in bits
* **publicKeyArmored**: The ascii armored public key block

### Upload new key

```
POST /api/v1/key
```

#### Payload (JSON):

```json
{
  "publicKeyArmored": "-----BEGIN PGP PUBLIC KEY BLOCK----- ... -----END PGP PUBLIC KEY BLOCK-----"
}
```

* **publicKeyArmored**: The ascii armored public PGP key to be uploaded

E.g. to upload a key from shell:
```bash
curl https://keys.mailvelope.com/api/v1/key --data "{\"publicKeyArmored\":\"$( \
  gpg --armor --export-options export-minimal --export $GPGKEYID | sed ':a;N;$!ba;s/\n/\\n/g' \
  )\"}" 
```

### Verify uploaded key (via link in email)

```
GET /api/v1/key?op=verify&keyId=b8e4105cc9dedc77&nonce=6a314915c09368224b11df0feedbc53c
```

### Request key removal

```
DELETE /api/v1/key?keyId=b8e4105cc9dedc77 OR ?email=user@example.com
```

### Verify key removal (via link in email)

```
GET /api/v1/key?op=verifyRemove&keyId=b8e4105cc9dedc77&nonce=6a314915c09368224b11df0feedbc53c
```

## Abuse resistant key server

The key server implements mechanisms described in the draft [Abuse-Resistant OpenPGP Keystores](https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-abuse-resistant-keystore-06) to mitigate various attacks related to flooding the key server with bogus keys or certificates. The filtering of keys can be customized with [environment variables](#settings).

In detail the following key components are filtered out:

* user attribute packets
* third-party certificates
* certificates exceeding 8383 bytes
* certificates that cannot be verified with primary key
* unhashed subpackets except: issuer, issuerFingerprint, embeddedSignature
* unhashed subpackets of embedded signatures
* user IDs without email address
* user IDs exceeding 1024 bytes
* user IDs that have no self certificate or revocation signature
* subkeys exceeding 8383 bytes
* above 5 revocation signatures. Hardest, earliest revocations are kept.
* superseded certificates. Newest 5 are kept.

A key is rejected if one of the following is detected:

* primary key packet exceeding 8383 bytes
* primary key packet is not version 4
* key without user ID
* key with more than 20 email addresses
* key with more than 20 subkeys
* key size exceeding 32768 bytes
* new uploaded key is not valid 24h in the future

# Language & DB

The server is written is in JavaScript ES2020 and runs on [Node.js](https://nodejs.org/) v18+.

It uses [MongoDB](https://www.mongodb.com/) v6.0+ or [FerretDB](https://ferretdb.com) 2.0+ (Free Software replacement for MongoDB) as its database.

# Getting started
## Installation

### Node.js (macOS)

This is how to install node on Mac OS using [homebrew](https://brew.sh/). For other operating systems, please refer to the [Node.js download page](https://nodejs.org/en/download/).

```shell
brew update
brew install node
```

### MongoDB (macOS)

This is the installation guide to get a local development installation on macOS using [homebrew](https://brew.sh/). For other operating systems, please refer to the [MongoDB Installation Tutorials](https://www.mongodb.com/docs/v6.0/installation/#mongodb-installation-tutorials).

```shell
brew update
brew install mongodb-community@6.0
mongod --config /opt/homebrew/etc/mongod.conf
```

Now the mongo daemon should be running in the background. To have mongo start automatically as a background service on startup you can also do:

```shell
brew services start mongodb
```

Now you can use the `mongosh` CLI client to create a new test database. The username and password used here match the ones in the `.env` file. **Be sure to change them for production use**:

```shell
mongosh
use keyserver-test
db.createUser({ user:"keyserver-user", pwd:"your_mongo_db_pwd", roles:[{ role:"readWrite", db:"keyserver-test" }] })
```

## FerrerDB

You can find [instructions to install FerretDB on their website](https://docs.ferretdb.io/installation/ferretdb/).

#### Purge unverfied keys with TTL (time to live) indexes

Unverified keys are automatically purged after `PUBLIC_KEY_PURGE_TIME` days. The MongoDB TTLMonitor thread that is used for this purpose, runs by default every 60 seconds. To change this interval to a more appropriate value run the following admin command in the mongo shell:

```
db.adminCommand({setParameter:1, ttlMonitorSleepSecs: 86400}) // 1 day
```

#### Recommended indexes

To improve query performance the following indexes are recommended:

```
db.publickey.createIndex({"userIds.email" : 1, "userIds.verified" : 1}) // query by email
db.publickey.createIndex({"keyId" : 1, "userIds.verified" : 1}) // query by keyID
db.publickey.createIndex({"fingerprint" : 1, "userIds.verified" : 1}) // query by fingerprint
```

### Dependencies

```shell
npm install
```

## Configuration

Configuration settings may be provided as environment variables. The file config/config.js reads the environment variables and defines configuration values for settings with no corresponding environment variable. Warning: Default settings are only provided for a small minority of settings in these files (as most of them are very individual like host/user/password)!

### Development

If you don't use environment variables to configure settings, you can alternatively create a .env file for example with the following content:

```
PORT=3000
CORS_HEADER=true
HTTP_SECURITY_HEADER=true
CSP_HEADER=true
LOG_LEVEL=info
MONGO_URI=127.0.0.1:27017/keyserver-test
MONGO_USER=keyserver-user
MONGO_PASS=your_mongo_db_pwd
SMTP_HOST=sabic.uberspace.de
SMTP_PORT=465
SMTP_TLS=true
SMTP_STARTTLS=false
SMTP_PGP=true
SMTP_USER=info@your-key-server.net
SMTP_PASS=your_smtp_pwd
SENDER_NAME=My Key Server Demo
SENDER_EMAIL=info@your-key-server.net
```

## Unit and integration tests

Create a test database for the integration tests:

```shell
mongosh
use keyserver-test-int
db.createUser({ user:"keyserver-user", pwd:"your_mongo_db_pwd", roles:[{ role:"readWrite", db:"keyserver-test-int" }] })
```

Afterwards start the unit tests with `npm test`.

### Production

For production use, settings configuration with environment variables is recommended as `NODE_ENV=production` is REQUIRED to be set as environment variable to instruct node.js to adapt e.g. logging to production use.

### Settings

Available settings with its environment-variable-names, possible/example values and meaning (if not self-explainable). Defaults **bold**:

* NODE_ENV=development|production (no default, needs to be set as environment variable)
* LOG_LEVEL=debug|**info**|notice|warning|err|crit|alert|emerg
* SERVER_HOST=**localhost**
* PORT=**8888** (application server port)
* CORS_HEADER=true [CORS headers](https://hapi.dev/api#-routeoptionscors)
* HTTP_SECURITY_HEADER=true [security headers](https://hapi.dev/api#-routeoptionssecurity)
* CSP_HEADER=true (add Content-Security-Policy as in src/lib/csp.js)
* MONGO_URI=127.0.0.1:27017/keyserver
* MONGO_USER=keyserver-user
* MONGO_PASS=your_mongo_db_pwd
* SMTP_HOST=smpt.your-email-provider.com
* SMTP_PORT=465
* SMTP_TLS=**true** (if true the connection will use TLS when connecting to server. If false then TLS is used if server supports the STARTTLS extension. In most cases set this value to true if you are connecting to port 465. For port 587 or 25 keep it false.)
* SMTP_STARTTLS=**true** (if this is true and SMTP_TLS is false then Nodemailer tries to use STARTTLS even if the server does not advertise support for it.)
* SMTP_PGP=**true** (encrypt verification message with public key (allows to verify presence + usability of private key at owner of the email address))
* SMTP_USER=smtp_user
* SMTP_PASS=smtp_pass
* SENDER_NAME="OpenPGP Key Server"
* SENDER_EMAIL=noreply@your-key-server.net
* PUBLIC_KEY_PURGE_TIME=**14** (number of days after which uploaded keys are deleted if they have not been verified)
* UPLOAD_RATE_LIMIT=10 (key upload rate limit per email address in the PUBLIC_KEY_PURGE_TIME period)

The following variables are available to customize the filtering behavior as outlined in [Abuse resistant key server](#abuse-resistant-key-server):

* PURIFY_KEY=**true** (main switch to enable filtering of keys)
* MAX_NUM_USER_EMAIL=**20** (max. number of email addresses per key)
* MAX_NUM_SUBKEY=**20** (max. number of subkeys per key)
* MAX_NUM_CERT=**5** (max. number of superseding certificates)
* MAX_SIZE_USERID=**1024**
* MAX_SIZE_PACKET=**8383**
* MAX_SIZE_KEY=**32768**

### Notes on SMTP

The key server uses [nodemailer](https://nodemailer.com) to send out emails upon public key upload to verify email address ownership. To test this feature locally, configure `SMTP_USER` and `SMTP_PASS` settings to your email test account. Make sure that `SMTP_USER` and `SENDER_EMAIL` match.

For production you should use a service like [Amazon SES](https://aws.amazon.com/ses/), [Mailgun](https://www.mailgun.com/) or [Sendgrid](https://sendgrid.com/use-cases/transactional-email/). Nodemailer supports all of these out of the box.

## Run tests

```shell
npm test
```

## Start local server

```shell
npm start
```

# License

AGPL v3.0

See the [LICENSE](https://raw.githubusercontent.com/mailvelope/keyserver/master/LICENSE) file for details

## Libraries

Among others, this project relies on the following open source libraries:

* [OpenPGP.js](https://openpgpjs.org/)
* [Nodemailer](https://nodemailer.com/)
* [hapi](https://hapi.dev/)
* [mongodb](https://mongodb.github.io/node-mongodb-native/)

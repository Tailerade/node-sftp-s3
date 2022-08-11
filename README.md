# node-sftp-s3

[![CircleCI](https://circleci.com/gh/cmrigney/node-sftp-s3.svg?style=svg)](https://circleci.com/gh/cmrigney/node-sftp-s3)

[![Coverage Status](https://coveralls.io/repos/github/cmrigney/node-sftp-s3/badge.svg?branch=master)](https://coveralls.io/github/cmrigney/node-sftp-s3?branch=master)

**This is a fork of [cmrigney/node-sftp-s3](https://github.com/cmrigney/node-sftp-s3) which is no longer maintained.**
It has its dependencies updated as well as support for dynamically loaded authentication data (e.g. from a database),
supporting both ssh public keys and bcrypt password hashes.

Node JS module for creating a SFTP server with user isolation that uses S3 for file storage.

## Install

This fork is not currently available from NPM. Hence you need to install via GIT:

`npm install git+https://github.com/Tailerade/node-sftp-s3.git`

## Usage

```
var SFTPS3Server = require('node-sftp-s3').SFTPS3Server;

var AWS = require('aws-sdk');
var path = require('path');
var fs = require('fs');

//aws.json contains credentials for S3 access
AWS.config.loadFromPath(path.join(__dirname, 'aws.json'));

var s3 = new AWS.S3({ params: { Bucket: 'testing' } });

var server = new SFTPS3Server(s3);

//You can generate a key with ssh-keygen
server.addHostKey(fs.readFileSync(path.join(__dirname, 'server_key_rsa')));

//Add users' public keys.  These can also be added after the server has already started
server.addPublicKey(fs.readFileSync(path.join(__dirname, 'client_key_rsa.pub')), 'baruser' /* , 'myapp' (optional path prefix) */);

server.listen(2222, '127.0.0.1', function(port) {
  console.log('Listening on ' + port);
  //server.stop() will stop the server
});


```

## Events

SFTPServer emits several events. Each event passes a dictionary object with the listed parameters.

The path parameter includes the user's subfolder name.

- **client-error** - `{ client: <Object>, error: <Error> }`
- **login** - `{ username: <string> }`
- **file-uploaded** - `{ path: <string>, username: <string> }`
- **file-downloaded** - `{ path: <string>, username: <string> }`
- **file-deleted** - `{ path: <string>, username: <string> }`
- **directory-deleted** - `{ path: <string>, username: <string> }`
- **directory-created** - `{ path: <string>, username: <string> }`
- **file-renamed** - `{ path: <string>, oldPath: <string>, username: <string> }`

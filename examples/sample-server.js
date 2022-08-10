const sftps3 = require('../index.js');

const AWS = require('aws-sdk');
const path = require('path');
const fs = require('fs');
const ssh2 = require('ssh2');

const defaultRegion = process.env.AWS_DEFAULT_REGION;
const s3Bucket = process.env.AWS_S3_BUCKET;
const sftpPort = process.env.SFTP_PORT;
const loggingEnabled = process.env.LOGGING_ENABLED;

AWS.config.s3 = {
  region: defaultRegion,
};

const s3 = new AWS.S3({ params: { Bucket: s3Bucket } });

const server = new sftps3.SFTPS3Server(s3);
if (loggingEnabled) server.enableLogging();

//When using this module, make sure you generate your own key with openssl!
server.addHostKey(fs.readFileSync(path.join(__dirname, 'keys/server_key_rsa')));

//Add users' keys
server.addPublicKey(fs.readFileSync(path.join(__dirname, 'keys/id_rsa.pub')), 'someuser', 'uploads');

// Dynamically load/provide public keys
server.on('authentication-publickey', ({ username, tryPublicKey }) => {
  if (username !== 'hans') {
    return;
  }

  tryPublicKey(
    new Promise((resolve) =>
      setTimeout(
        () =>
          resolve({
            key: ssh2.utils.parseKey(fs.readFileSync(path.join(__dirname, 'keys/id_rsa.pub'))),
            path: 'hans',
          }),
        500
      )
    )
  );
});

// Catch and log client errors
server.on('client-error', ({ error }) => console.log('got error', error));

server.listen(sftpPort, '127.0.0.1', function (port) {
  console.log('Listening on ' + port);
});

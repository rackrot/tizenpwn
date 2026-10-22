// Node 4 compatibility shims. The target's signed Node is v4.4.3.
(function() {
  var needsFrom = false;
  try { Buffer.from('x', 'ascii'); } catch (error) { needsFrom = true; }
  function from(value, encoding) {
    if (Buffer.isBuffer(value)) {
      var copy = new Buffer(value.length);
      value.copy(copy);
      return copy;
    }
    if (Array.isArray(value)) return new Buffer(value);
    if (value && value.buffer && value.byteLength !== undefined) {
      return new Buffer(value);
    }
    return new Buffer(value, encoding);
  }
  function alloc(size, fill) {
    var buffer = new Buffer(size);
    if (fill !== undefined) buffer.fill(fill);
    return buffer;
  }
  function allocUnsafe(size) { return new Buffer(size); }
  if (needsFrom) {
    Object.defineProperty(Buffer, 'from', { value: from, writable: true, configurable: true });
  }
  if (typeof Buffer.alloc !== 'function') {
    Object.defineProperty(Buffer, 'alloc', { value: alloc, writable: true, configurable: true });
  }
  if (typeof Buffer.allocUnsafe !== 'function') {
    Object.defineProperty(Buffer, 'allocUnsafe', { value: allocUnsafe, writable: true, configurable: true });
  }
})();

var fs = require('fs');
var cp = require('child_process');
var crypto = require('crypto');
var path = require('path');
var ssh2 = require('ssh2');
var utils = ssh2.utils;
var SFTPStream = require('ssh2-streams').SFTPStream;
var STATUS = ssh2.SFTP_STATUS_CODE;
var OPEN_MODE = ssh2.SFTP_OPEN_MODE;

var config = {
  listen: '0.0.0.0:2222',
  hostKey: '/opt/tizenpwn-ssh/etc/ssh_host_rsa_key',
  authorizedKeys: '/opt/tizenpwn-ssh/etc/authorized_keys',
  log: '/opt/tizenpwn-ssh/var/sshd.log',
  pidFile: '/opt/tizenpwn-ssh/var/sshd.pid',
  user: 'root',
  shell: '/bin/bash',
  home: '/root',
  script: '/usr/bin/script',
  logCommands: false
};

function parseArgs(argv) {
  for (var i = 2; i < argv.length; i++) {
    var arg = argv[i];
    if (arg === '--version') { console.log('tizenpwn-sshd-js 0.1.0'); process.exit(0); }
    if (arg === '--log-commands') { config.logCommands = true; continue; }
    var value = argv[++i];
    switch (arg) {
      case '--listen': config.listen = value; break;
      case '--host-key': config.hostKey = value; break;
      case '--authorized-keys': config.authorizedKeys = value; break;
      case '--log': config.log = value; break;
      case '--pid-file': config.pidFile = value; break;
      case '--user': config.user = value; break;
      case '--shell': config.shell = value; break;
      case '--home': config.home = value; break;
      case '--script': config.script = value; break;
      default:
        console.error('unknown argument: ' + arg);
        process.exit(2);
    }
  }
}

parseArgs(process.argv);

function writeLine(line) {
  var text = new Date().toISOString() + ' ' + line + '\n';
  try {
    if (config.log !== '-') {
      var directory = path.dirname(config.log);
      if (!fs.existsSync(directory)) fs.mkdirSync(directory, 0700);
      try {
        if (fs.statSync(config.log).size > 1048576) {
          fs.renameSync(config.log, config.log + '.1');
        }
      } catch (ignore) {}
      fs.appendFileSync(config.log, text);
    } else {
      process.stderr.write(text);
    }
  } catch (error) {
    process.stderr.write('log error: ' + error.message + '\n');
  }
}

function log(message) { writeLine(message); }

function requirePrivateFile(filename) {
  var stat = fs.statSync(filename);
  if (stat.mode & 077) {
    throw new Error(filename + ' must not be group- or world-accessible');
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new Error(filename + ' must be owned by the server user');
  }
}

function loadAuthorizedKeys(filename) {
  requirePrivateFile(filename);
  var text = fs.readFileSync(filename, 'utf8');
  var keys = [];
  var lines = text.split('\n');
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].replace(/^\s+|\s+$/g, '');
    if (!line || line.charAt(0) === '#') continue;
    keys.push(utils.parseKey(line));
  }
  if (!keys.length) throw new Error('authorized_keys contains no keys');
  return keys;
}

function fingerprint(data) {
  return crypto.createHash('sha256').update(data).digest('base64')
    .replace(/=+$/, '');
}

function modeString(mode) {
  var type = '-';
  if ((mode & 0170000) === 0040000) type = 'd';
  else if ((mode & 0170000) === 0120000) type = 'l';
  var text = type;
  var bits = [0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001];
  var chars = ['r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'];
  for (var i = 0; i < bits.length; i++) {
    text += (mode & bits[i]) ? chars[i] : '-';
  }
  return text;
}

function attrsFromStats(stats) {
  return {
    mode: stats.mode,
    uid: stats.uid,
    gid: stats.gid,
    size: stats.size,
    atime: Math.floor(stats.atime.getTime() / 1000),
    mtime: Math.floor(stats.mtime.getTime() / 1000)
  };
}

function longname(name, stats) {
  return modeString(stats.mode) + ' 1 ' + stats.uid + ' ' + stats.gid + ' ' +
    stats.size + ' ' + stats.mtime.toUTCString() + ' ' + name;
}

function openFlags(flags) {
  var converted = SFTPStream.flagsToString(flags);
  if (converted) return converted;
  var read = flags & OPEN_MODE.READ;
  var write = flags & OPEN_MODE.WRITE;
  var append = flags & OPEN_MODE.APPEND;
  var create = flags & OPEN_MODE.CREAT;
  var truncate = flags & OPEN_MODE.TRUNC;
  var exclusive = flags & OPEN_MODE.EXCL;
  if (read && write) {
    if (append) return 'a+';
    if (truncate) return 'w+';
    if (create) return 'a+';
    return 'r+';
  }
  if (write) {
    if (append) return 'a';
    if (exclusive) return 'wx';
    if (truncate || create) return 'w';
    return 'r+';
  }
  return 'r';
}

function statusFor(error) {
  if (!error) return STATUS.FAILURE;
  if (error.code === 'ENOENT') return STATUS.NO_SUCH_FILE;
  if (error.code === 'EACCES' || error.code === 'EPERM') {
    return STATUS.PERMISSION_DENIED;
  }
  return STATUS.FAILURE;
}

function quote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

function startCommand(stream, command, ptyInfo) {
  var environment = {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: config.home,
    USER: config.user,
    LOGNAME: config.user,
    SHELL: config.shell,
    LANG: 'C',
    HISTFILE: '/dev/null'
  };
  if (ptyInfo) {
    environment.TERM = ptyInfo.term || 'xterm';
    environment.COLUMNS = String(ptyInfo.cols || 80);
    environment.LINES = String(ptyInfo.rows || 24);
  }
  var child;
  if (ptyInfo) {
    var inner = quote(config.shell) +
      (command === null ? ' -l' : ' -c ' + quote(command));
    child = cp.spawn(config.script, ['-q', '-c', inner, '/dev/null'], {
      cwd: config.home,
      env: environment
    });
  } else {
    child = cp.spawn(
      config.shell,
      command === null ? ['-l'] : ['-c', command],
      { cwd: config.home, env: environment }
    );
  }
  stream.on('error', function(error) {
    log('channel error: ' + error.message);
  });
  if (child.stdin) {
    child.stdin.on('error', function() {});
    stream.pipe(child.stdin, { end: false });
    stream.on('end', function() {
      try { child.stdin.end(); } catch (ignore) {}
    });
  }
  if (child.stdout) {
    child.stdout.on('error', function() {});
    child.stdout.pipe(stream, { end: false });
  }
  if (child.stderr) {
    child.stderr.on('error', function() {});
    if (stream.stderr) child.stderr.pipe(stream.stderr, { end: false });
  }
  child.on('error', function(error) {
    log('child error: ' + error.message);
    stream.exit(1);
    stream.end();
  });
  child.on('exit', function(code) {
    stream.exit(code === null ? 1 : code);
    setTimeout(function() { stream.end(); }, 50);
  });
}

function handleSFTP(sftp) {
  var handles = {};
  var nextHandle = 1;

  function putHandle(value) {
    var handle = new Buffer(4);
    handle.writeUInt32BE(nextHandle, 0, true);
    handles[nextHandle] = value;
    nextHandle++;
    return handle;
  }

  function getHandle(handle) {
    if (!Buffer.isBuffer(handle) || handle.length !== 4) return null;
    return handles[handle.readUInt32BE(0, true)] || null;
  }

  function closeHandle(handle) {
    var entry = getHandle(handle);
    if (!entry) return;
    if (entry.type === 'file') {
      try { fs.closeSync(entry.fd); } catch (ignore) {}
    }
    delete handles[handle.readUInt32BE(0, true)];
  }

  function replyError(reqid, error) {
    sftp.status(reqid, statusFor(error), error ? error.message : undefined);
  }

  sftp.on('OPEN', function(reqid, filename, flags, attrs) {
    try {
      var flagString = openFlags(flags);
      if (!flagString) {
        log('open unsupported flags=' + flags + ' path=' + filename);
        return sftp.status(reqid, STATUS.FAILURE);
      }
      var mode = attrs && attrs.mode ? (attrs.mode & 0777) : 0666;
      try {
        var fd = fs.openSync(filename, flagString, mode);
        sftp.handle(reqid, putHandle({ type: 'file', fd: fd }));
      } catch (openError) {
        log('open failed path=' + filename + ' flags=' + flags +
            ' mode=' + flagString + ' error=' + openError.message);
        replyError(reqid, openError);
      }
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('READ', function(reqid, handle, offset, length) {
    try {
      var entry = getHandle(handle);
      if (!entry || entry.type !== 'file') {
        return sftp.status(reqid, STATUS.FAILURE);
      }
      var buffer = new Buffer(length);
      var read = fs.readSync(entry.fd, buffer, 0, length, offset);
      if (read <= 0) return sftp.status(reqid, STATUS.EOF);
      sftp.data(reqid, buffer.slice(0, read));
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('WRITE', function(reqid, handle, offset, data) {
    try {
      var entry = getHandle(handle);
      if (!entry || entry.type !== 'file') {
        return sftp.status(reqid, STATUS.FAILURE);
      }
      fs.writeSync(entry.fd, data, 0, data.length, offset);
      sftp.status(reqid, STATUS.OK);
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('FSTAT', function(reqid, handle) {
    try {
      var entry = getHandle(handle);
      if (!entry || entry.type !== 'file') {
        return sftp.status(reqid, STATUS.FAILURE);
      }
      sftp.attrs(reqid, attrsFromStats(fs.fstatSync(entry.fd)));
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('FSETSTAT', function(reqid, handle, attrs) {
    try {
      var entry = getHandle(handle);
      if (!entry || entry.type !== 'file') {
        return sftp.status(reqid, STATUS.FAILURE);
      }
      if (attrs.mode !== undefined) fs.fchmodSync(entry.fd, attrs.mode & 07777);
      if (attrs.uid !== undefined || attrs.gid !== undefined) {
        var stat = fs.fstatSync(entry.fd);
        fs.fchownSync(
          entry.fd,
          attrs.uid !== undefined ? attrs.uid : stat.uid,
          attrs.gid !== undefined ? attrs.gid : stat.gid
        );
      }
      if (attrs.atime !== undefined || attrs.mtime !== undefined) {
        var current = fs.fstatSync(entry.fd);
        fs.futimesSync(
          entry.fd,
          attrs.atime !== undefined ? attrs.atime : current.atime,
          attrs.mtime !== undefined ? attrs.mtime : current.mtime
        );
      }
      sftp.status(reqid, STATUS.OK);
    } catch (error) { log('fsetstat/setstat error: ' + error.message); replyError(reqid, error); }
  });

  sftp.on('CLOSE', function(reqid, handle) {
    try { closeHandle(handle); sftp.status(reqid, STATUS.OK); }
    catch (error) { replyError(reqid, error); }
  });

  sftp.on('OPENDIR', function(reqid, dirname) {
    try {
      var names = ['.', '..'].concat(fs.readdirSync(dirname));
      var entries = [];
      for (var i = 0; i < names.length; i++) {
        var full = path.join(dirname, names[i]);
        try {
          var stats = fs.lstatSync(full);
          entries.push({
            filename: names[i],
            longname: longname(names[i], stats),
            attrs: attrsFromStats(stats)
          });
        } catch (ignore) {}
      }
      sftp.handle(reqid, putHandle({
        type: 'dir', entries: entries, sent: false
      }));
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('READDIR', function(reqid, handle) {
    try {
      var entry = getHandle(handle);
      if (!entry || entry.type !== 'dir') {
        return sftp.status(reqid, STATUS.FAILURE);
      }
      if (entry.sent) return sftp.status(reqid, STATUS.EOF);
      entry.sent = true;
      sftp.name(reqid, entry.entries);
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('LSTAT', function(reqid, filename) {
    try {
      sftp.attrs(reqid, attrsFromStats(fs.lstatSync(filename)));
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('STAT', function(reqid, filename) {
    try {
      sftp.attrs(reqid, attrsFromStats(fs.statSync(filename)));
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('REMOVE', function(reqid, filename) {
    try { fs.unlinkSync(filename); sftp.status(reqid, STATUS.OK); }
    catch (error) { replyError(reqid, error); }
  });

  sftp.on('RMDIR', function(reqid, dirname) {
    try { fs.rmdirSync(dirname); sftp.status(reqid, STATUS.OK); }
    catch (error) { replyError(reqid, error); }
  });

  sftp.on('REALPATH', function(reqid, filename) {
    try {
      var resolved = fs.realpathSync(filename || config.home);
      sftp.name(reqid, [{ filename: resolved, longname: resolved }]);
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('READLINK', function(reqid, filename) {
    try {
      var target = fs.readlinkSync(filename);
      sftp.name(reqid, [{ filename: target, longname: target }]);
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('SETSTAT', function(reqid, filename, attrs) {
    try {
      if (attrs.mode !== undefined) fs.chmodSync(filename, attrs.mode & 07777);
      if (attrs.uid !== undefined || attrs.gid !== undefined) {
        var stat = fs.statSync(filename);
        fs.chownSync(
          filename,
          attrs.uid !== undefined ? attrs.uid : stat.uid,
          attrs.gid !== undefined ? attrs.gid : stat.gid
        );
      }
      if (attrs.atime !== undefined || attrs.mtime !== undefined) {
        var current = fs.statSync(filename);
        fs.utimesSync(
          filename,
          attrs.atime !== undefined ? attrs.atime : current.atime,
          attrs.mtime !== undefined ? attrs.mtime : current.mtime
        );
      }
      sftp.status(reqid, STATUS.OK);
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('MKDIR', function(reqid, dirname, attrs) {
    try {
      fs.mkdirSync(dirname, attrs && attrs.mode ? (attrs.mode & 0777) : 0777);
      sftp.status(reqid, STATUS.OK);
    } catch (error) { replyError(reqid, error); }
  });

  sftp.on('RENAME', function(reqid, oldPath, newPath) {
    try { fs.renameSync(oldPath, newPath); sftp.status(reqid, STATUS.OK); }
    catch (error) { replyError(reqid, error); }
  });

  sftp.on('SYMLINK', function(reqid, linkPath, targetPath) {
    try { fs.symlinkSync(targetPath, linkPath); sftp.status(reqid, STATUS.OK); }
    catch (error) { replyError(reqid, error); }
  });

  sftp.on('error', function(error) { log('sftp error: ' + error.message); });
}

var keys = loadAuthorizedKeys(config.authorizedKeys);
requirePrivateFile(config.hostKey);
var hostKey = fs.readFileSync(config.hostKey);
var hostKeyObject = utils.parseKey(hostKey);
var listenParts = config.listen.split(':');
var listenHost = listenParts.length > 1 ? listenParts.slice(0, -1).join(':') : '0.0.0.0';
var listenPort = parseInt(listenParts[listenParts.length - 1], 10);
if (!listenPort) throw new Error('invalid listen address');

var server = new ssh2.Server({
  hostKeys: [hostKey],
  ident: 'tizenpwn_0.1',
  algorithms: {
    kex: ['diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'],
    cipher: ['aes128-ctr', 'aes256-ctr'],
    hmac: ['hmac-sha2-256', 'hmac-sha1'],
    serverHostKey: ['ssh-rsa'],
    compress: ['none']
  }
}, function(client) {
  client.on('authentication', function(ctx) {
    if (ctx.username !== config.user || ctx.method !== 'publickey') {
      return ctx.reject();
    }
    var data = ctx.key.data;
    var allowed = null;
    for (var i = 0; i < keys.length; i++) {
      if (keys[i].type === ctx.key.algo &&
          keys[i].getPublicSSH().equals(data)) {
        allowed = keys[i];
        break;
      }
    }
    if (!allowed) return ctx.reject();
    if (ctx.signature && allowed.verify(ctx.blob, ctx.signature) !== true) {
      return ctx.reject();
    }
    log('login user=' + ctx.username + ' key=SHA256:' + fingerprint(data) +
        ' from=' + (client._sock ? client._sock.remoteAddress : 'unknown'));
    ctx.accept();
  }).on('ready', function() {
    client.on('session', function(accept, reject) {
      var session = accept();
      session.on('error', function(error) {
        log('session error: ' + error.message);
      });
      var ptyInfo = null;
      session.on('pty', function(acceptPty, rejectPty, info) {
        ptyInfo = info;
        acceptPty();
      });
      session.on('window-change', function(acceptWindow, rejectWindow) {
        if (acceptWindow) acceptWindow();
      });
      session.on('env', function(acceptEnv) {
        if (acceptEnv) acceptEnv();
      });
      session.on('shell', function(acceptShell) {
        var stream = acceptShell();
        startCommand(stream, null, ptyInfo);
      });
      session.on('exec', function(acceptExec, rejectExec, info) {
        var stream = acceptExec();
        if (config.logCommands) log('exec: ' + info.command);
        startCommand(stream, info.command, ptyInfo);
      });
      session.on('sftp', function(acceptSftp) {
        handleSFTP(acceptSftp());
      });
      session.on('x11', function(acceptX11, rejectX11) {
        if (rejectX11) rejectX11();
      });
      session.on('auth-agent', function(acceptAgent, rejectAgent) {
        if (rejectAgent) rejectAgent();
      });
      session.on('signal', function(acceptSignal) {
        if (acceptSignal) acceptSignal();
      });
    });
    client.on('tcpip', function(acceptTcpip, rejectTcpip) {
      if (rejectTcpip) rejectTcpip();
    });
  }).on('error', function(error) {
    log('client error: ' + error.message);
  }).on('end', function() {
    log('client disconnected');
  });
});

server.on('error', function(error) {
  log('server error: ' + error.message);
  process.exit(1);
});

if (config.pidFile) {
  try {
    var pidDir = path.dirname(config.pidFile);
    if (!fs.existsSync(pidDir)) fs.mkdirSync(pidDir, 0700);
    fs.writeFileSync(config.pidFile, String(process.pid) + '\n', { mode: 0644 });
  } catch (error) {
    log('pid file error: ' + error.message);
    process.exit(1);
  }
}

function shutdown() {
  log('shutting down');
  try {
    if (config.pidFile && fs.existsSync(config.pidFile)) {
      fs.unlinkSync(config.pidFile);
    }
  } catch (ignore) {}
  server.close(function() { process.exit(0); });
  setTimeout(function() { process.exit(0); }, 1000);
}

process.on('uncaughtException', function(error) {
  var detail = error && error.stack ? error.stack : String(error);
  log('uncaught exception: ' + detail);
  try {
    fs.writeFileSync(
      '/tmp/tizenpwn-sshd-crash',
      new Date().toISOString() + ' ' + detail + '\n',
      { mode: 0644 }
    );
  } catch (ignore) {}
  process.exit(1);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(listenPort, listenHost, function() {
  log('listening on ' + listenHost + ':' + listenPort + ' as ' + config.user +
      '; host key SHA256:' + fingerprint(hostKeyObject.getPublicSSH()) +
      '; ' + keys.length + ' authorized key(s)');
});

import logging
import copy

class GnuPG(object):
    def __init__(self, homedir, gpg_path):
        self.__gpg = gpg_path
        self.__common_params = ['--homedir', homedir, '--yes']
        self.__password = None
        self.__userid = None

    @property
    def bin(self):
        return self.__gpg

    @property
    def common_params(self):
        import copy
        return copy.copy(self.__common_params)

    @property
    def password(self):
        return self.__password

    @property
    def userid(self):
        return self.__userid

    @userid.setter
    def userid(self, val):
        self.__userid = val

    @password.setter
    def password(self, val):
        self.__password = val

    def _run(self, cmd, batch_input = None):
        import subprocess
        logging.debug((' '.join(cmd)).strip())
        process = subprocess.Popen(cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        output, errout = process.communicate(input = batch_input)
        retcode = process.poll()
        logging.debug(errout.strip())
        logging.debug(output.strip())
        return retcode == 0

    def generte_key_batch(self, batch_input):
        params = ['--gen-key', '--expert', '--batch',
                  '--pinentry-mode', 'loopback'] + self.common_params
        if self.password:
            params += ['--passphrase', self.password]
        return self._run([self.__gpg] + params, batch_input)

    def export_key(self, out_filename, secret=False):
        params = ['--armor']
        if secret:
            params += ['--pinentry-mode', 'loopback', '--export-secret-key']
            params += ['--passphrase', self.password]
        else:
           params = ['--export']

        params = self.common_params + \
            params + ['-o', out_filename, self.userid]
        return self._run([self.__gpg] + params)

    def import_key(self, filename, secret = False):
        params = self.common_params
        if secret:
            params += ['--trust-model', 'always']
            params += ['--batch']
            params += ['--passphrase', self.password]
        params += ['--import', filename]
        return self._run([self.__gpg] + params)

    def sign(self, out, input):
        params = self.common_params
        params += ['--passphrase', self.password]
        params += ['--batch']
        params += ['--pinentry-mode', 'loopback']
        params += ['-o', out]
        params += ['--sign', input]
        return self._run([self.__gpg] + params)

    def verify(self, input):
        params = self.common_params
        params += ['--verify', input]
        return self._run([self.__gpg] + params)

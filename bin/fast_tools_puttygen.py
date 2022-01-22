from django.conf import settings
import tempfile
import shutil
import subprocess
#tempfile.tempdir='/tmp/'


class ERROR_CODES:
	OK = (0x0, '+OK')
	ERR_MKDIR_TMPDIR = (1, 'Unable to handle request.')
	ERR_NEWPASSPHRASE_FILE_WRITE = (2, 'Unable to handle request.')
	ERR_OLDPASSPHRASE_FILE_WRITE = (3, 'Unable to handle request.')
	ERR_NEWFILE_WRITE = (4, 'Unable to handle request.')
	ERR_EXEC_FAILED = (4, 'Unable to handle request.')

	@classmethod
	def new(self, Err_No: int, Err_Msg: str):
		return (Err_No if Err_No is not None else 1, Err_Msg)


class PuttyGen:
	PREFIX = 'puttygen-'

	@classmethod
	def clean_tmp_puttygen_dir(self, folder):
		if folder is None:
			return

		try:
			shutil.rmtree(folder, ignore_errors=True)
		except:
			pass

	@classmethod
	def convert_ppk_2_pem(self, ppk_data: str, old_passphrase: str = None, new_passphrase: str = None):
		tempfile.tempdir = settings.TMP_DIR
		errno, errmsg = ERROR_CODES.OK
		try:
			tmp_puttygen_dir = tempfile.mkdtemp(prefix=self.PREFIX)
		except:
			tmp_puttygen_dir = None
			errno, errmsg = ERROR_CODES.ERR_MKDIR_TMPDIR

		if errno:
			self.clean_tmp_puttygen_dir(tmp_puttygen_dir)
			return {}

		file_ppk = "%s/private.ppk" % (tmp_puttygen_dir, )
		file_out = "%s/private.pem" % (tmp_puttygen_dir, )
		file_old_passphrase = "%s/old_passphrase.txt" % (tmp_puttygen_dir, )
		file_new_passphrase = "%s/new_passphrase.txt" % (tmp_puttygen_dir, )

		errno, errmsg = ERROR_CODES.OK
		if old_passphrase:
			try:
				with open(file_old_passphrase, 'w') as p:
					p.write(old_passphrase)
			except:
				errno, errmsg = ERROR_CODES.ERR_OLDPASSPHRASE_FILE_WRITE
		else:
			file_old_passphrase = None

		if new_passphrase:
			try:
				with open(file_new_passphrase, 'w') as p:
					p.write(new_passphrase)
			except:
				errno, errmsg = ERROR_CODES.ERR_NEWPASSPHRASE_FILE_WRITE
		else:
			file_new_passphrase = None

		if ppk_data:
			ppk_data = ppk_data.strip()
			try:
				with open(file_ppk, 'w') as p:
					p.write(ppk_data)
			except Exception as e:
				errno, errmsg = ERROR_CODES.ERR_NEWPPK_FILE_WRITE

		if errno:
			self.clean_tmp_puttygen_dir(tmp_puttygen_dir)
			response = {}
			response['errno'], response['errmsg'] == errno, errmsg
			return {}

		#exit([file_ppk, file_out, file_old_passphrase, file_new_passphrase])
		cmd = [settings.PUTTYGEN_BIN, file_ppk, '-O', 'private-openssh', '-o', '%s' % (file_out)]
		if file_old_passphrase:
			cmd.extend(["--old-passphrase", file_old_passphrase])

		if file_new_passphrase:
			cmd.extend(["--new-passphrase", file_new_passphrase])

		pem_data = ''
		stderr = b''
		try:
			process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = process.communicate()
			if stderr:
				errno, errmsg = ERROR_CODES.ERR_EXEC_FAILED
				errmsg = stderr.decode()
			else:
				with open(file_out, 'r') as p:
					pem_data = p.read()
		except Exception as e:
			#raise e
			errno, errmsg = ERROR_CODES.ERR_NEWPPK_FILE_WRITE
		#exit([stdout, stderr])
		#self.clean_tmp_puttygen_dir(tmp_puttygen_dir)

		#print(stdout, stderr, file_out, pem_data)
		#exit([file_out, cmd, stdout, stderr, file_out])

		#exit([tmp_puttygen_dir])

		response = {}
		response['errno'], response['errmsg'] = errno, errmsg
		response['pemdata'] = pem_data
		response['oldpp'] = old_passphrase
		response['newpp'] = new_passphrase
		response['buffer'] = ''

		return response

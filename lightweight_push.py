#!/usr/bin/python2

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the GNU Public License, version 2.

import time
import socket
import ssl
import logging
import os
import base64
import random
import json
import hashlib
import tempfile
import optparse
import sys
import re
from Crypto.Cipher import AES
BUFSIZE = 4096


################ GLOBAL CONFIGURATION DATA ################

# Used log level (will be ignored if command line parameter is given).
# valid log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
loglevel = logging.INFO

# Shared secret used to encrypt the message
# (will be ignored if command line parameter is given).
shared_secret = "MySuperSecretSharedSecret"

# Username used to send the message to the server.
# The username is the eMail address you used for your alertr.de account
# (will be ignored if command line parameter is given).
username = "MyEmailAccount@alertr.de"

# The password of your alertr.de account.
# (will be ignored if command line parameter is given).
password = "MyAlertrDePassword"

# Channel used for the message
# (will be ignored if command line parameter is given).
channel = "MyChannel"

# Number of connection retries until sending is given up
# (will be ignored if command line parameter is given).
# A value of -1 means it is retried indefinitely.
max_retries = 16

################ GLOBAL CONFIGURATION DATA ################

# certificate of push.alertr.de
ca_certificate = "-----BEGIN CERTIFICATE-----\n" \
	+ "MIIFuzCCA6OgAwIBAgIJAIt8yGcHzfvzMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" \
	+ "BAYTAkRFMQwwCgYDVQQIDANOUlcxDzANBgNVBAoMBmFsZXJ0UjENMAsGA1UECwwE\n" \
	+ "cHVzaDEXMBUGA1UEAwwOcHVzaC5hbGVydHIuZGUxHjAcBgkqhkiG9w0BCQEWD3Nx\n" \
	+ "YWxsQGg0ZGVzLm9yZzAeFw0xNjA5MjYwOTA2MjJaFw0yNjA5MjQwOTA2MjJaMHQx\n" \
	+ "CzAJBgNVBAYTAkRFMQwwCgYDVQQIDANOUlcxDzANBgNVBAoMBmFsZXJ0UjENMAsG\n" \
	+ "A1UECwwEcHVzaDEXMBUGA1UEAwwOcHVzaC5hbGVydHIuZGUxHjAcBgkqhkiG9w0B\n" \
	+ "CQEWD3NxYWxsQGg0ZGVzLm9yZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC\n" \
	+ "ggIBAMQrvQvAomHgcF8lG4/yaJgcHO3K0HEjyMTuEsy3IBQA5paYgttX+jFloQca\n" \
	+ "rR0RTtLjbT8GNP3XbljwtFbhN3LTKoWiGx2SO6xSHAR4jFQO4KvnTWQhRgeHtqsL\n" \
	+ "NZEV04CzjKftV7qapRpgMGJVh5kDqDKdoDSFb2KNmhF1Pedu98QZw14LyDLA9dV4\n" \
	+ "Dg0dL7l7YotP/IPuaZug6uN4eX2jpXi4eLFF+WmjMiRrdnO5iuz1Bef8mFWL7H6f\n" \
	+ "RVfcERnnMepCm3QzIzPrsWYCyY8FGaP95CWf62q6FmhESVeoP0BjOPFigQUe9M+S\n" \
	+ "6jOvluX2nHNmEhfQ87a4Sfg/IO7neZaDUYObja+1kW4KrO4X13FtRRGlOfhkzoGv\n" \
	+ "hRrBuE+mYUNGajo93Rtrii3blzsRvI7tObMcGW3hxQcRCRBaP33bPXB0VHo6x5hQ\n" \
	+ "/J/+cNvoziyBtVh0Zk4xYct3Qei+ACebLsM59z36QuX08zXRbZtXqgkvQkYOUm7r\n" \
	+ "0CKlTDVHfQ+aZY77OYDkkxRh7XkPhCrovJBXYCcd8DU3/EWcBmjZaQxDFIR2TJfs\n" \
	+ "7bmAC9n9K8y/nFHA7JM0mOnvpBCdpq9YC8DaoBznMIZdSnp+Q+2MOwmt0qI5fUbd\n" \
	+ "ny0CEbP3FiQWgbRCRCKMlef587d9XtyTrAxCvM9LEmjeg6YfAgMBAAGjUDBOMB0G\n" \
	+ "A1UdDgQWBBTsjPl3CmuAEpyKpFPng+sPAmqk2jAfBgNVHSMEGDAWgBTsjPl3CmuA\n" \
	+ "EpyKpFPng+sPAmqk2jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCB\n" \
	+ "nWaqwmP3bY/NlMcoUZ7idLD1l6vTCLKmPuRJolRNnXCcmRWDoRktH6Sia8Zn6eSv\n" \
	+ "wJ207OyiK+KkRC9SSJawk1t7lCcoLmFEuJTtVbBJFtKCCLemWrftGh6nsUkYu4vv\n" \
	+ "wkRXMCt3wkH7OK2eUbcmT6BWdKJPaGqXd3/ByykoVTcYUVYZdFAjS5EH8IYQ2TPL\n" \
	+ "S+9DdQzSGSKgjUi7kvwGwsgvvuWNnjYzoI1vce1MCHm8DZD3eTJSKxiNXe4QLYYp\n" \
	+ "fNTz2Sl5D3DdTGm2X7xGspIapqhYqCOn0FVILywgBCAZ27cDcBVahJwzcuWLMPgw\n" \
	+ "vMiiZE8887bGhgvsC+uQNHSMO0TKd4hUkIgxkCvJanBCT8BevLr1HbhMiDCe9JWq\n" \
	+ "Z/a+9JSYUVKqouISxOr0dLzg65cjC3T7RvLNQDE6T3bFoILDHrwgvydP4W/jbyil\n" \
	+ "TXXHMTnT+HrdAMhLinqWfujLATfGlsrA/JXRH+g+O5nbgP/y2aRzlIWx8nLuhfQa\n" \
	+ "9LLuiTZqtaeA/qqQuqc8YYMKZCcJi9ZC3Ye2LrTRjCoDSEcYjjM9/vFHSDTicK/I\n" \
	+ "EMsfizV4S7K188KtaKP6gh7nE2kvj8BpxczIGL+Mjjnw24JHLfPQ5BI/vuana5cg\n" \
	+ "s5oOGPo2PIqYZZ3olOVP35IDA9iOPNUtf3CXLtIqUQ==\n" \
	+ "-----END CERTIFICATE-----\n"


# Push server error codes.
class ErrorCodes:
    NO_ERROR = 0
    DATABASE_ERROR = 1
    AUTH_ERROR = 2
    ILLEGAL_MSG_ERROR = 3
    GOOGLE_MSG_TOO_LARGE = 4
    GOOGLE_CONNECTION = 5
    GOOGLE_UNKNOWN = 6
    GOOGLE_AUTH = 7
    VERSION_MISSMATCH = 8
    NO_NOTIFICATION_PERMISSION = 9


# simple class of an ssl tcp client
class Client:

	def __init__(self, host, port, serverCAFile):
		self.host = host
		self.port = port
		self.serverCAFile = serverCAFile
		self.socket = None
		self.sslSocket = None


	def connect(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self.sslSocket = ssl.wrap_socket(self.socket,
			ca_certs=self.serverCAFile, cert_reqs=ssl.CERT_REQUIRED,
			ssl_version=ssl.PROTOCOL_TLSv1)

		self.sslSocket.connect((self.host, self.port))


	def send(self, data):
		count = self.sslSocket.send(data)


	def recv(self, buffsize, timeout=3.0):
		data = None
		self.sslSocket.settimeout(timeout)
		data = self.sslSocket.recv(buffsize)
		self.sslSocket.settimeout(None)
		return data


	def close(self):
		# closing SSLSocket will also close the underlying socket
		self.sslSocket.close()


# This function makes a clean exit.
def exit(exit_code, ca_file):

	# remove temporary ca file
	removeCaFile(ca_file)

	sys.exit(exit_code)


# Create the channel name linked to the username.
# NOTE: This function is not collision free but will improve collision
# resistance if multiple parties choose the same channel.
def generatePrefixedChannel(username, channel):
	# Create a encryption key from the secret.
	sha256 = hashlib.sha256()
	sha256.update(username)
	prefix = sha256.hexdigest()[0:8]
	return prefix.lower() + "_" + channel


# Truncates the message and subject to fit in a notification message.
def truncToSize(subject, message):
	len_json_sbj = len(json.dumps(subject))
	len_sbj = len(subject)
	len_json_msg = len(json.dumps(message))
	len_msg = len(message)

	# Consider json encoding (characters like \n need two characters).
	if (len_json_sbj + len_json_msg) > 1400:
		number_to_remove = (len_json_sbj + len_json_msg + 7) - 1400
		if len_msg > number_to_remove:
			message = message[0:(len_msg-number_to_remove)]
			message += "*TRUNC*"
		elif len_sbj > number_to_remove:
			subject = subject[0:(len_sbj-number_to_remove)]
			subject += "*TRUNC*"
		else:
			message = "*TRUNC*"
			number_to_remove = number_to_remove - len_msg + 7
			subject = subject[0:(len_sbj-number_to_remove)]
			subject += "*TRUNC*"

	return subject, message


def checkChannel(channel):
	return bool(re.match(r'^[a-zA-Z0-9-_.~%]+$', channel))


# This function removes the CA file.
def removeCaFile(ca_file):

	if not ca_file:
		return

	# Remove temporary ca file.
	try:
		os.remove(ca_file)
	except Exception as e:
		logging.exception("Could not remove temporary certificate file.")


if __name__ == '__main__':

	# create ca file used to connect to the repository
	# (unfortunately, because of the ssl api this is prone for a
	# race condition => exchange ca file before it is used to send data)
	temp_file_tuple = tempfile.mkstemp()
	ca_file_handle = os.fdopen(temp_file_tuple[0], "w")
	ca_file_handle.write(ca_certificate)
	ca_file_handle.close()
	ca_file = temp_file_tuple[1]

	# parsing command line options
	parser = optparse.OptionParser()

	parser.formatter = optparse.TitledHelpFormatter()

	# Give an example command to send a message
	parser.epilog = "Example command to send a message: " \
		+ "\t\t\t\t\t\t\t\t\t\t" \
		+ "'python %s --sbj \"Test Subject\" --msg \"Long text.\"'" \
		% sys.argv[0] \
		+ "\t\t\t\t\t\t\t\t\t\t" \
		+ "Example command to send a message with stdin: " \
		+ "\t\t\t\t\t\t\t\t\t\t" \
		+ "'echo \"Long text.\" | python %s --sbj \"Test Subject\"'" \
		% sys.argv[0] \
		+ "\t\t\t\t\t\t\t\t\t\t" \
		+ "For more detailed examples please visit: " \
		+ "\t\t\t\t\t\t\t\t\t\t" \
		+ "https://github.com/sqall01/lightweight-push"

	message_group = optparse.OptionGroup(parser,
		"Message arguments.")

	message_group.add_option("--sbj",
		"--subject",
		dest="subject",
		action="store",
		help="Subject of the message. " \
			"(Required)",
		default=None)

	message_group.add_option("--msg",
		"--message",
		dest="message",
		action="store",
		help="Message to send. " \
			"(Required if message is not given via stdin)",
		default=None)

	message_group.add_option("-s",
		"--state",
		dest="state",
		action="store",
		type="int",
		help="State of the sensor alert message " \
			"(if not given, the message is not "\
			"considered to be a sensor alert). " \
			"Valid values: 0 or 1 " \
			"(Optional)",
		default=None)

	message_group.add_option("-t",
		"--time-triggered",
		dest="tt",
		action="store",
		type="int",
		help="UTC timestamp the alarm was triggered " \
			"(if not given, the current UTC time is used). " \
			"(Optional)",
		default=None)

	config_group = optparse.OptionGroup(parser,
		"Configuration arguments.")

	config_group.add_option("-u",
		"--username",
		dest="username",
		action="store",
		help="Username used to send the message to the server. " \
			"The username is the eMail address you used for your " \
			"alertr.de account " \
			"(if not given, the one configured in the script is used). " \
			"(Optional)",
		default=None)

	config_group.add_option("-p",
		"--password",
		dest="password",
		action="store",
		help="The password of your alertr.de account " \
			"(if not given, the one configured in the script is used). " \
			"(Optional)",
		default=None)

	config_group.add_option("-c",
		"--channel",
		dest="channel",
		action="store",
		help="Channel used for the message " \
			"(if not given, the one configured in the script is used). " \
			"(Optional)",
		default=None)

	config_group.add_option("--ss",
		"--shared-secret",
		dest="shared_secret",
		action="store",
		help="Shared secret used to encrypt the message " \
			"(if not given, the one configured in the script is used). " \
			"(Optional)",
		default=None)

	config_group.add_option("-m",
		"--max-retries",
		dest="max_retries",
		action="store",
		type="int",
		help="Number of connection retries until sending is given up " \
			"(if not given, the one configured in the script is used). " \
			"A value of -1 means it is retried indefinitely " \
			"(Optional)",
		default=None)

	config_group.add_option("-l",
		"--loglevel",
		dest="loglevel",
		action="store",
		help="Used log level " \
			"(if not given, the one configured in the script is used). " \
			"Valid log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL " \
			"(Optional)",
		default=None)

	config_group.add_option("",
		"--no-check-ssl-certificate",
		dest="no_check_SSL_certificate",
		action="store_true",
		help="Do not verify the SSL certificate of the server. " \
			"Only use it if you know what you are doing. This option " \
			"will allow Man-In-The-Middle attacks during the sending " \
			"process. " \
			"(Optional)",
		default=False)

	parser.add_option_group(message_group)
	parser.add_option_group(config_group)
	(options, args) = parser.parse_args()

	# Remove CA file for checking SSL connection.
	if options.no_check_SSL_certificate:
		removeCaFile(ca_file)
		ca_file = None

	# Overwrite settings if given as an command line argument.
	if options.username:
		username = options.username

	# Parse username option.
	if options.password:
		password = options.password

	# Parse channel option.
	if options.channel:
		channel = options.channel

	# Parse shared secret option.
	if options.shared_secret:
		shared_secret = options.shared_secret

	# Parse max retries option.
	if options.max_retries:
		max_retries = options.max_retries

	# Parse loglevel option.
	if options.loglevel:
		temp_loglevel = options.loglevel.upper()
		if temp_loglevel == "DEBUG":
			loglevel = logging.DEBUG
		elif temp_loglevel == "INFO":
			loglevel = logging.INFO
		elif temp_loglevel == "WARNING":
			loglevel = logging.WARNING
		elif temp_loglevel == "ERROR":
			loglevel = logging.ERROR
		elif temp_loglevel == "CRITICAL":
			loglevel = logging.CRITICAL
		else:
			print "Given loglevel illegal."
			exit(1, ca_file)

	# Initialize logging
	logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', 
		datefmt='%m/%d/%Y %H:%M:%S', level=loglevel)

	# Parse state option.
	if options.state is not None:
		is_sa = True
		if options.state == 1 or options.state == 0:
			state = options.state
		else:
			logging.critical("State can either be 0 or 1.")
			exit(1, ca_file)
	else:
		is_sa = False
		state = None

	# Parse time triggered option.
	if options.tt:
		tt = options.tt
	else:
		tt = int(time.time())

	# Parse subject option
	if options.subject is None:
		logging.critical("Subject of message is required.")
		exit(1, ca_file)
	else:
		subject = options.subject

	# Check if channel is valid.
	if not checkChannel(channel):
		logging.critical("Channel contains illegal characters.")
		exit(1, ca_file)

	# Check if script is used directly.
	if options.message:
		message = options.message
	elif not sys.stdin.isatty():
		# Parse message from stdin as script is used in a pipe.
		message = ""
		for line in sys.stdin:
			message += line
	else:
		logging.critical("Message is required.")
		exit(1, ca_file)

	# Truncate size to current maximum size.
	subject, message = truncToSize(subject, message)

	# Prepare base of message.
	payload = {
		"sbj": subject,
		"msg": message,
		"tt": tt,
		"is_sa": is_sa,
		}
	if is_sa:
		payload["st"] = state

	# Create a encryption key from the secret.
	sha256 = hashlib.sha256()
	sha256.update(shared_secret)
	key = sha256.digest()

	# Generate random bytes for encryption.
	iv = os.urandom(16)
	internal_iv = os.urandom(4)

	# Prepare channel
	prefixed_channel = generatePrefixedChannel(username, channel)

	# Prepare data to send.
	data_send = {"username": username,
			"password": password,
			"channel": prefixed_channel,
			"version": 0.1}

	max_retries_ctr = max_retries
	times_sleep = 5
	while True:

		ts = int(time.time())
		payload["ts"] = ts

		# Add random bytes in the beginning of the message to increase
		# randomness.
		padded_payload = internal_iv + json.dumps(payload)
		padding = len(padded_payload) % 16
		if padding != 0:
			for i in range(16 - padding):
				# Use whitespaces as padding since they are ignored by json.
				padded_payload += " "

		cipher = AES.new(key, AES.MODE_CBC, iv)
		encrypted_payload = cipher.encrypt(padded_payload)

		temp = iv + encrypted_payload
		data_payload = base64.b64encode(temp)

		data_send["data"] = data_payload

		logging.info("Sending message.")

		try:
			client = Client("push.alertr.de", 14944, ca_file)
			client.connect()
			client.send(json.dumps(data_send))
			data_recv = client.recv(BUFSIZE)
			client.close()
			error_code = json.loads(data_recv)["Code"]
		except:
			logging.exception("Not able to send message.")
			error_code = None

		# Processing error code
		if error_code is None:
			pass
		elif error_code == ErrorCodes.NO_ERROR:
			logging.info("Sending message successful.")
			break
		elif error_code == ErrorCodes.DATABASE_ERROR:
			logging.error("Database error on server side. Trying again.")
		elif error_code == ErrorCodes.AUTH_ERROR:
			logging.error("Authentication failed. "
				+ "Check your credentials.")
			exit(1, ca_file)
		elif error_code == ErrorCodes.ILLEGAL_MSG_ERROR:
			logging.error("Illegal message was sent. "
				+ "Please make sure to use the newest version. "
				+ "If you do, please open an issue on "
				+ "https://github.com/sqall01/lightweight-push")
			exit(1, ca_file)
		elif error_code == ErrorCodes.GOOGLE_MSG_TOO_LARGE:
			logging.error("Transmitted message too large. "
				+ "Please shorten it.")
			exit(1, ca_file)
		elif error_code == ErrorCodes.GOOGLE_CONNECTION:
			logging.error("Connection error on server side. "
				+ "Trying again.")
		elif error_code == ErrorCodes.GOOGLE_AUTH:
			logging.error("Authentication error on server side. "
				+ "Trying again.")
		elif error_code == ErrorCodes.VERSION_MISSMATCH:
			logging.error("Version mismatch. "
				+ "Please update your client.")
			exit(1, ca_file)
		elif error_code == ErrorCodes.NO_NOTIFICATION_PERMISSION:
			logging.error("No permission to use notification channel. "
				+ "Please update channel configuration.")
			exit(1, ca_file)
		else:
			logging.error("The following error code occurred: %d."
				% error_code
				+ "Please make sure to use the newest version. "
				+ "If you do, please open an issue on "
				+ "https://github.com/sqall01/lightweight-push")
			exit(1, ca_file)

		# Process retries.
		if max_retries_ctr == 0:
			logging.error("Tried the maximum of times for sending. Giving up.")
			exit(1, ca_file)
		elif max_retries_ctr < 0:
			pass
		else:
			max_retries_ctr -= 1

		logging.info("Waiting %d seconds before trying again." % times_sleep)
		time.sleep(times_sleep)
		times_sleep *= 2
		if times_sleep > 86400:
			times_sleep = 86400

	exit(0, ca_file)
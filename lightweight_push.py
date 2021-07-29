#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

import time
import logging
import optparse
import sys
from lightweightpush import LightweightPush, ErrorCodes

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

if __name__ == '__main__':

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
            print("Given loglevel illegal.")
            sys.exit(1)

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
            sys.exit(1)
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
        sys.exit(1)
    else:
        subject = options.subject

    push_service = LightweightPush(username,
                                   password,
                                   shared_secret)

    # Check if channel is valid.
    if not push_service._check_channel(channel):
        logging.critical("Channel contains illegal characters.")
        sys.exit(1)

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
        sys.exit(1)

    max_retries_ctr = max_retries
    times_sleep = 5
    while True:

        error_code = push_service.send_msg(subject,
                                           message,
                                           channel,
                                           state=state,
                                           time_triggered=tt,
                                           max_retries=1)

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
            sys.exit(1)
        elif error_code == ErrorCodes.ILLEGAL_MSG_ERROR:
            logging.error("Illegal message was sent. "
                + "Please make sure to use the newest version. "
                + "If you do, please open an issue on "
                + "https://github.com/sqall01/lightweight-push")
            sys.exit(1)
        elif error_code == ErrorCodes.GOOGLE_MSG_TOO_LARGE:
            logging.error("Transmitted message too large. "
                + "Please shorten it.")
            sys.exit(1)
        elif error_code == ErrorCodes.GOOGLE_CONNECTION:
            logging.error("Connection error on server side. "
                + "Trying again.")
        elif error_code == ErrorCodes.GOOGLE_AUTH:
            logging.error("Authentication error on server side. "
                + "Trying again.")
        elif error_code == ErrorCodes.VERSION_MISSMATCH:
            logging.error("Version mismatch. "
                + "Please update your client.")
            sys.exit(1)
        elif error_code == ErrorCodes.NO_NOTIFICATION_PERMISSION:
            logging.error("No permission to use notification channel. "
                + "Please update channel configuration.")
            sys.exit(1)
        elif error_code == ErrorCodes.CLIENT_CONNECTION_ERROR:
            logging.error("Client could not create a connection to the "
                + "server. Please check your Internet connection.")
        elif error_code == ErrorCodes.CLIENT_TIMEOUT_ERROR:
            logging.error("Client connection timed out. "
                + "Please check your Internet connection.")
        elif error_code == ErrorCodes.WEB_BRIDGE_ERROR:
            logging.error("Web bridge error on server side. "
                + "Trying again.")
        else:
            logging.error("The following error code occurred: %d."
                % error_code
                + "Please make sure to use the newest version. "
                + "If you do, please open an issue on "
                + "https://github.com/sqall01/lightweight-push")
            sys.exit(1)

        # Process retries.
        if max_retries_ctr == 0:
            logging.error("Tried the maximum of times for sending. Giving up.")
            sys.exit(1)
        elif max_retries_ctr < 0:
            pass
        else:
            max_retries_ctr -= 1

        logging.info("Waiting %d seconds before trying again." % times_sleep)
        time.sleep(times_sleep)
        times_sleep *= 2
        if times_sleep > 86400:
            times_sleep = 86400

    sys.exit(0)
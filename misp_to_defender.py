#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2024-2025 Jisc Services Limited
# SPDX-FileContributor: Luke Hopkins
# SPDX-License-Identifier: GPL-3.0-only

__author__ = "Luke Hopkins"
__copyright__ = "Copyright 2024-2025, Jisc Services Limited"
__email__ = "Luke.Hopkins@jisc.ac.uk"
__license__ = "GPL-3.0-only"
__maintainer__ = "Luke Hopkins"
__status__ = "Beta"
__version__ = "0.0.1"


from configparser import ConfigParser, NoSectionError, NoOptionError
import requests
import logging
import os

try:
    from pymisp import PyMISP
    from pymisp.exceptions import PyMISPError
except (ImportError, ModuleNotFoundError):
    print("PyMISP is not installed, cannot run. Run: pip install pymisp")
    exit(1)


# Input file name for the script ini file.
CONFIG_FILE = "misp_defender_config.ini"
# Output file name for the script logging.
LOGGING_FILE = "misp_to_defender.log"


def EstablishMISPConn(url, auth_key, verify_tls, logger):
    logger.info(
        f"Attempting to connect to MISP instance at {url} using configured auth key.")
    try:
        return PyMISP(url, auth_key, ssl=verify_tls)
    except PyMISPError as e:
        logger.error(f"Error connecting to MISP Instance: {e}")
        exit(1)


def GetIOCsFromMISP(pymisp_instance, tag, logger):
    # Maps MISP object types into Defender object types.
    defender_map = {
        "domain": "DomainName",
        "hostname": "DomainName",
        "ip-src": "IpAddress",
        "ip-dst": "IpAddress",
        "url": "Url",
        "md5": "FileMd5",
        "sha256": "FileSha256",
    }
    try:
        logger.info(f"Searching MISP events for tags: {tag}")
        # Initiates a search on the pymisp instance for the tag(s). If multiple
        # tags are present, it will get all events that contain any of the
        # indiviudal tags specified (OR operation).
        results = pymisp_instance.search(tags=tag)
        extracted_iocs = []
        for event in results:
            logger.info(
                f"Found MISP Event: {
                    event.get(
                        'Event',
                        {}).get("id")}")
            attributes = event.get("Event", {}).get("Attribute", [])
            for attr in attributes:
                # Checks that the MISP attribute can be mapped to a Defender
                # object type and that the IDS flag is set.
                if (
                    attr.get("type") in defender_map.keys()
                    and attr.get("to_ids")
                ):
                    extracted_iocs.append(
                        {
                            "indicatorType": defender_map[attr.get("type")],
                            "indicatorValue": attr.get("value"),
                            # All indicators are set to block by default.
                            "action": "Block",
                            "title": f"IoC from MISP Event {event.get('Event', {}).get("id")}",
                            "description": f"IoC from MISP Event {event.get('Event', {}).get("id")}",
                        }
                    )
        return extracted_iocs
    except PyMISPError as e:
        logger.error(f"Error fetching IoCs: {e}")
    return []


def GetMSAuthToken(tenant_id, client_id, client_secret, logger):
    # Requests an OAuth token needed for pushing IoCs into the Defender API.
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://api.securitycenter.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    logger.info(f"Attempting to obtain OAuth Token from {url}")
    response = requests.post(url, data=data)
    response.raise_for_status()
    logger.info("Obtained OAuth token successfully.")
    return response.json().get("access_token")


def PushIOCsToDefender(auth_token, iocs, logger):
    # Pushes each individual IoC into the specified Defender instance, and
    # sets to block.
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }

    url = "https://api.securitycenter.microsoft.com/api/indicators"

    for ioc in iocs:
        response = requests.post(url, headers=headers, json=ioc)
        if response.status_code == 200:
            logger.info(
                f"Sent IoC {ioc['indicatorType']} {
                    ioc['indicatorValue']} successfully into Defender")
        else:
            logger.error(
                f"Failed to add IoC {
                    ioc['indicatorValue']}: {
                    response.status_code}, {
                    response.text}")


def ConfigureLogging(log_file="misp_to_defender.log"):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Console Handler Configuration
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # File Handler Configuration
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # Apply Defined Log Format
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(log_format)
    file_handler.setFormatter(log_format)

    # Add Handlers to Logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Suppress External Loggers to Critical notifications only
    logging.getLogger("requests").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    logging.getLogger("pymisp").setLevel(logging.CRITICAL)

    return logger


def Main():
    logger = ConfigureLogging(LOGGING_FILE)

    # Checks if the config file exists before proceeding
    if not os.path.isfile(CONFIG_FILE):
        logger.error(f"The config file '{CONFIG_FILE}' does not exist.")
        exit(1)

    config = ConfigParser()
    config.read(CONFIG_FILE)

    # Obtains config data for MISP.
    try:
        base_url = config.get("MISP", "baseUrl")
        auth_key = config.get("MISP", "authKey")
        verify_tls = config.get("MISP", "VerifyTLS")
        tags = config.get("MISP", "Tags")
    except NoSectionError:
        logger.error(
            "Unable to proceed, missing MISP section of configuration file.")
        exit(1)
    except NoOptionError:
        logger.error(
            "Unable to proceed, missing key variables from MISP section of configuration file")
        exit(1)

    # Splits the tags by comma if multiple tags are present.
    tags = tags.split(", ")

    # Makes sure all variables are set before proceeding.
    if not base_url or not auth_key or not tags:
        logger.error(
            "Unable to proceed, missing MISP information in config file.")
        exit(1)

    # Check to make sure VerifyTLS is either True or False. PyMISP only
    # accepts bool type, so must convert from str input.
    if verify_tls.strip().lower() == "true":
        verify_tls = True
    elif verify_tls.strip().lower() == "false":
        verify_tls = False
    else:
        logger.error(
            "VerifyTLS variable in configuration file should be either True or False.")
        exit(1)

    misp_conn = EstablishMISPConn(
        base_url, auth_key, verify_tls, logger=logger)
    iocs = GetIOCsFromMISP(misp_conn, tags, logger=logger)

    # Checks that there is actually valid IoCs that were extracted before
    # pushing to Defender.
    if not iocs:
        print(
            "Unable to find any compatible IoCs. Try changing the search tag and try again."
        )
        exit(1)

    # Obtains config data for Defender instance.
    try:
        tenant_id = config.get("MSDefender", "Tenant_id")
        client_id = config.get("MSDefender", "Client_id")
        client_secret = config.get("MSDefender", "Client_secret")
    except NoSectionError:
        logger.error(
            "Unable to proceed, missing Defender section of configuration file.")
        exit(1)
    except NoOptionError as e:
        logger.error(
            f"Unable to proceed, missing key variables from Defender section of configuration file. Details: {e}")
        exit(1)

    # Makes sure all variables are set before proceeding.
    if not tenant_id or not client_id or not client_secret:
        logger.error(
            "Unable to proceed, missing MSDefender information in config file."
        )

    # Gets OAuth Token to that Defender API can be used.
    oauth_token = GetMSAuthToken(
        tenant_id,
        client_id,
        client_secret,
        logger=logger)
    
    # Pushes out all the extracted IoCs into the Defender instance.
    PushIOCsToDefender(oauth_token, iocs, logger=logger)


if __name__ == "__main__":
    Main()

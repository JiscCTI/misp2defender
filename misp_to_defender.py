#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2024 Jisc Services Limited
# SPDX-FileContributor: Luke Hopkins
# SPDX-License-Identifier: GPL-3.0-only

__author__ = "Luke Hopkins"
__copyright__ = "Copyright 2024, Jisc Services Limited"
__email__ = "Luke.Hopkins@jisc.ac.uk"
__license__ = "GPL-3.0-only"
__maintainer__ = "Luke Hopkins"
__status__ = "Beta"
__version__ = "0.0.1"

from configparser import ConfigParser, NoSectionError, NoOptionError
import logging
import os
import json

try:
    from pymisp import PyMISP
    from pymisp.exceptions import PyMISPError
except (ImportError, ModuleNotFoundError):
    print("PyMISP is not installed, cannot run. Run: pip install pymisp")
    exit(1)

try:
    import requests
except ImportError:
    print("requests library is not installed, cannot run. Run: pip install requests")
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

    # Start the current page at 1
    c_page = 1

    # Only retrieve 500 attributes per page
    PAGE_LIMIT = 500
    while True:
        try:
            logger.info(
                f"Searching MISP attributes for tags: {tag} with limit={PAGE_LIMIT}. Current Page: {c_page}")
            # Initiates a search on the pymisp instance for the tag(s). If multiple
            # tags are present, it will get all events that contain any of the
            # indiviudal tags specified (OR operation).
            # Paginates the results into 500 attributes per page.
            results = pymisp_instance.search(controller="attributes",
                                             tags=tag,
                                             limit=PAGE_LIMIT,
                                             page=c_page)

            attributes = results.get('Attribute', [])

            # Exit the loop if there is no more attributes to grab
            if not attributes:
                break

            # Loop through each attribute found in the current batch
            for attr in attributes:
                # Ensure that the IDS flag has been checked, and that the type
                # is mapable to defender.
                if (
                        attr["type"] in defender_map.keys()
                        and attr["to_ids"]):
                    # Stream the results back to the calling function
                    yield {
                        "indicatorType": defender_map[attr["type"]],
                        "indicatorValue": attr.get("value"),
                        "action": "Block",
                        "title": f"IoC from MISP Event {attr['event_id']}",
                        "description": f"IoC from MISP Event {attr['event_id']}",
                    }

            # Move to the next page of results.
            c_page += 1

        except Exception as e:
            logger.error("An error occurring when searching through MISP: {e}")
            break


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


def PushIOCsToDefender(auth_token, ioc_generator_obj, logger):
    # Pushes each individual IoC into the specified Defender instance, and
    # sets to block.
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }

    url = "https://api.securitycenter.microsoft.com/api/indicators/import"

    total_iocs_pushed = 0
    batch = []
    # Loops through the ioc generator object and pushes indicators into
    # defender in batches of 500 (API has a limit of 500 indicators per
    # request).
    for i, ioc_obj in enumerate(ioc_generator_obj, start=1):
        # Add IoC to current batch as we receive it from the ioc generator
        # object
        batch.append(ioc_obj)

        # Check if the batch is ready to be sent off, and then fire it into
        # defender.
        if len(batch) == 500:
            try:
                response = requests.post(
                    url, headers=headers, data=json.dumps({"Indicators": batch}))
                if response.status_code == 200:
                    logger.info(
                        f"Successfully pushed 500 Indicators to Defender in Batch:  {
                            i // 500}")
                else:
                    logger.info(
                        f"Error pushing batch {
                            i //
                            500}: {
                            response.text}")
            except Exception as e:
                logger.info(f"Error pushing IOCs to  Defender {e}")
            # Keep track of how many IoCs have been pushed.
            total_iocs_pushed += 500
            # Clear the batch to make way to send the next 500.
            batch.clear()

    # Push remaining IoCs for the last batch that don't quite meet the
    # len(batch) 500 limit.
    if batch:
        try:
            response = requests.post(
                url, headers=headers, data=json.dumps({"Indicators": batch}))
            if response.status_code == 200:
                logger.info(
                    f"Successfully pushed 500 Indicators to Defender in Batch: {
                        i // 500}")
            else:
                logger.info(f"Error pushing batch {i // 500}: {response.text}")
        except Exception as e:
            logger.info(f"Error pushing IOCs to Defender {e}")

    total_iocs_pushed += len(batch)

    logger.info(f"Total IoCs Pushed Into Defender: {total_iocs_pushed}")


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
    try:
        verify_tls = config.getboolean("MISP", "VerifyTLS")
    except ValueError:
        logger.error(
            "VerifyTLS variable in configuration file should be either 'true', 'false', 'yes', 'no', '1', or '0'.")
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

    misp_conn = EstablishMISPConn(
        base_url, auth_key, verify_tls, logger=logger)

    # Fetch IoCs from MISP in pages, then stream to Defender.
    ioc_generator_obj = GetIOCsFromMISP(misp_conn, tags, logger=logger)

    # Pushes out all the extracted IoCs into the Defender instance.
    PushIOCsToDefender(oauth_token, ioc_generator_obj, logger=logger)


if __name__ == "__main__":
    Main()

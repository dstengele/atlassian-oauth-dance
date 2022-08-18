#!/usr/bin/env python

import sys

from urllib.parse import parse_qsl
import requests
from requests import HTTPError
from requests_oauthlib import OAuth1
from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_TYPE_QUERY
import webbrowser
import click
from Crypto.PublicKey import RSA


@click.command()
@click.option(
    "--base-url",
    prompt="Base URL",
    help="The Base URL of the Atlassian Instance to connect to",
)
@click.option(
    "--app-type",
    type=click.Choice(["confluence", "jira"], case_sensitive=False),
    help="The Application we connect to (Jira or Confluence). This does not do anything at the moment.",
    default="jira",
)
@click.option(
    "--consumer-key",
    prompt="OAuth Consumer Key",
    help="The Consumer Key to use for OAuth",
)
@click.option(
    "--rsa-private-key",
    type=click.Path(resolve_path=True, dir_okay=False),
    help="Path to the RSA Private Key file to use for OAuth",
    default="private.pem",
)
def cli(base_url, app_type, consumer_key, rsa_private_key):
    request_token_url = f"{base_url}/plugins/servlet/oauth/request-token"
    base_authorization_url = f"{base_url}/plugins/servlet/oauth/authorize"
    access_token_url = f"{base_url}/plugins/servlet/oauth/access-token"

    # Check if private key file is valid and generate new one if neccessary
    try:
        with open(rsa_private_key, "r") as rsa_private_key_file:
            rsa_key_string = rsa_private_key_file.read()
            rsa_key = RSA.import_key(rsa_key_string)
    except (ValueError, FileNotFoundError):
        print("Key missing or invalid, generating new...")
        with open(rsa_private_key, "wb") as rsa_private_key_file, open("public.pem", "wb") as rsa_public_key_file:
            rsa_key = RSA.generate(2048)
            rsa_private_key_file.write(rsa_key.export_key())
            rsa_public_key_file.write(rsa_key.publickey().export_key())

    print(f"Please configure an applink with consumer key {consumer_key} and this private key:")
    print(rsa_key.publickey().export_key().decode())
    input("Press Enter when done...")

    # Get request token
    oauth = OAuth1(
        client_key=consumer_key,
        rsa_key=rsa_key.export_key().decode(),
        signature_method=SIGNATURE_RSA,
        signature_type=SIGNATURE_TYPE_QUERY,
        callback_uri="",
    )
    r = requests.post(request_token_url, verify=True, auth=oauth)
    try:
        r.raise_for_status()
    except HTTPError:
        print(f"Error while getting request token. Error was: {r.text}")
        sys.exit(1)
    request = dict(parse_qsl(r.text))
    request_token = request["oauth_token"]
    request_token_secret = request["oauth_token_secret"]

    # Authorize with user
    webbrowser.open(f"{base_authorization_url}?oauth_token={request_token}")
    input("Press Enter after authorizing...")

    # Fetch Access Token
    oauth = OAuth1(
        client_key=consumer_key,
        rsa_key=rsa_key.export_key().decode(),
        signature_method=SIGNATURE_RSA,
        signature_type=SIGNATURE_TYPE_QUERY,
        resource_owner_key=request_token,
        resource_owner_secret=request_token_secret,
    )
    r = requests.post(access_token_url, verify=True, auth=oauth)
    try:
        r.raise_for_status()
    except HTTPError:
        print(f"Error while getting access token. Error was: {r.text}")
        sys.exit(1)
    access = dict(parse_qsl(r.text))
    access_token = access.get("oauth_token")
    access_token_secret = access.get("oauth_token_secret")
    print(f"Access Token: {access_token}\nAccess Token Secret: {access_token_secret}")

    # Try it out
    oauth = OAuth1(
        client_key=consumer_key,
        rsa_key=rsa_key.export_key().decode(),
        signature_method=SIGNATURE_RSA,
        signature_type=SIGNATURE_TYPE_QUERY,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret,
    )
    r = requests.get(f"{base_url}/status", auth=oauth)
    try:
        r.raise_for_status()
    except HTTPError:
        print("Error when trying to use the new OAuth credentials!")
        sys.exit(1)


if __name__ == "__main__":
    cli()

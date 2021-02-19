#!/usr/bin/env python

from urllib.parse import parse_qsl
import requests
from requests import HTTPError
from requests_oauthlib import OAuth1
from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_TYPE_QUERY
import webbrowser
import click


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
    type=click.File("r"),
    prompt="RSA Private Key File",
    help="Path to the RSA Private Key file to use for OAuth",
)
def main(base_url, app_type, consumer_key, rsa_private_key):
    request_token_url = f"{base_url}/plugins/servlet/oauth/request-token"
    base_authorization_url = f"{base_url}/plugins/servlet/oauth/authorize"
    access_token_url = f"{base_url}/plugins/servlet/oauth/access-token"
    rsa_key = rsa_private_key.read()

    # Get request token
    oauth = OAuth1(
        client_key=consumer_key,
        rsa_key=rsa_key,
        signature_method=SIGNATURE_RSA,
        signature_type=SIGNATURE_TYPE_QUERY,
        callback_uri="",
    )
    r = requests.post(request_token_url, verify=True, auth=oauth)
    r.raise_for_status()
    request = dict(parse_qsl(r.text))
    request_token = request["oauth_token"]
    request_token_secret = request["oauth_token_secret"]

    # Authorize with user
    webbrowser.open(f"{base_authorization_url}?oauth_token={request_token}")
    input("Press Enter after authorizing...")

    # Fetch Access Token
    oauth = OAuth1(
        client_key=consumer_key,
        rsa_key=rsa_key,
        signature_method=SIGNATURE_RSA,
        signature_type=SIGNATURE_TYPE_QUERY,
        resource_owner_key=request_token,
        resource_owner_secret=request_token_secret,
    )
    r = requests.post(access_token_url, verify=True, auth=oauth)
    r.raise_for_status()
    access = dict(parse_qsl(r.text))
    access_token = access.get("oauth_token")
    access_token_secret = access.get("oauth_token_secret")
    print(f"Access Token: {access_token}\nAccess Token Secret: {access_token_secret}")

    # Try it out
    oauth = OAuth1(
        client_key=consumer_key,
        rsa_key=rsa_key,
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


if __name__ == "__main__":
    main()

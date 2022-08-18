# Atlassian-OAuth-Tool
This script allows you to do the OAuthDance with Atlassian applications
and get the Consumer Token and Consumer Token Secret parameters.

## Dependencies
* requests: Do HTTP Requests to Jira or Confluence
* requests-oauthlib: OAuth logic
* oauthlib: Helper CLasses for requests-oauthlib
* click: Used for the CLI

## Usage
Run with `poetry run dance --help` to see the available parameters. You need to
generate a RSA Key Pair beforehand and set up a Application Link with
it.

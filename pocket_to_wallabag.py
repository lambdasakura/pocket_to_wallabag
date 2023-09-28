#!/usr/bin/env python3

import requests
import webbrowser
import json
import sys

from env import *

def err_on_status_code(request, msg):
    if request.status_code != 200:
        print(f"{msg} : {r.status_code} - {r.text}")
        sys.exit(1)

def get_pocket_token(pocket_url, pocket_consumer_key, redirect_uri):

    headers = {'X-Accept': 'application/json'}
    payload = {
        'consumer_key': pocket_consumer_key,
        'redirect_uri': redirect_uri,
    }
    r = requests.post(f"{pocket_url}/oauth/request", data=payload, headers=headers)
    err_on_status_code(r, "[pocket] error while getting request token")
    pocket_request_token = r.json()['code']
    print(f"[pocket] request_token = {pocket_request_token}")

    webbrowser.open(f"https://getpocket.com/auth/authorize?request_token={pocket_request_token}&redirect_uri={redirect_uri}", new=2)
    print(f"if your browser did not open, please go to : https://getpocket.com/auth/authorize?request_token={pocket_request_token}&redirect_uri={redirect_uri}")
    input("If you have authorized the app, please press Enter to continue...")

    payload = {
        'consumer_key': pocket_consumer_key,
        'code': pocket_request_token,
    }
    r = requests.post(f"{pocket_url}/oauth/authorize", data=payload, headers=headers)
    err_on_status_code(r, "[pocket] error while getting access token")

    pocket_access_token = r.json()['access_token']
    print(f"[pocket] access_token = {pocket_access_token}")

    return pocket_access_token

def get_items_from_pocket(pocket_url, pocket_consumer_key, pocket_access_token):
    headers = {'X-Accept': 'application/json'}
    payload = {
        "consumer_key": pocket_consumer_key,
        "access_token": pocket_access_token,
        "state": "unread",
        "sort": "oldest",
        "detailType": "simple"
    }
    r = requests.post(f"{pocket_url}/get", data=payload, headers=headers)
    err_on_status_code(r, "[pocket] error while getting items")

    # create list of urls
    all_items = r.json()['list']
    urls = [item['given_url'] for item in all_items.values()]
    return urls

def get_wallabag_access_token(wallabag_url, wallabag_client_id, wallabag_client_secret, wallabag_username, wallabag_password):
    headers = {'X-Accept': 'application/json'}
    payload = {
        "grant_type": "password",
        "client_id": wallabag_client_id,
        "client_secret": wallabag_client_secret,
        "username": wallabag_username,
        "password": wallabag_password
    }
    r = requests.post(f"{WALLABAG_URL}/oauth/v2/token", data=payload, headers=headers)
    err_on_status_code(r, "[wallabag] error while getting access token")

    wallabag_access_token=r.json()['access_token']
    print(f"[wallabag] access_token = {wallabag_access_token}")
    return wallabag_access_token


def send_items_to_wallabag(wallabag_url, wallabag_client_id, wallabag_client_secret, wallabag_username, wallabag_password, urls):
    wallabag_access_token = get_wallabag_access_token(wallabag_url, wallabag_client_id, wallabag_client_secret, wallabag_username, wallabag_password)

    for index, url in enumerate(urls):
        headers = {
            "X-Accept": "application/json",
            "Authorization": f"Bearer {wallabag_access_token}"
        }

        payload = {
            "url": url,
            "tags": "pocket",
        }
        r = requests.post(f"{WALLABAG_URL}/api/entries.json", data=payload, headers=headers)
        if r.status_code == 401:
            # maybe token expired, try to get a new one
            wallabag_access_token = get_wallabag_access_token(wallabag_url, wallabag_client_id, wallabag_client_secret, wallabag_username, wallabag_password)
            headers = {
               "X-Accept": "application/json",
                "Authorization": f"Bearer {wallabag_access_token}"
            }
            r = requests.post(f"{WALLABAG_URL}/api/entries.json", data=payload, headers=headers)

        if r.status_code != 200:
            print(f"[wallabag] error while importing {index+1}/{len(urls)} {url} : {r.status_code} - {r.text}")
        else :
            print(f"[wallabag] success importing {index+1}/{len(urls)} : {url}")

    print("done :) gg! your pocket items were successfully migrated to wallabag")

if __name__ == "__main__":
    POCKET_ACCESS_TOKEN = get_pocket_token(POCKET_URL,POCKET_CONSUMER_KEY, REDIRECT_URI)
    urls = get_items_from_pocket(POCKET_URL, POCKET_CONSUMER_KEY, POCKET_ACCESS_TOKEN)
    send_items_to_wallabag(WALLABAG_URL, WALLABAG_CLIENT_ID, WALLABAG_CLIENT_SECRET, WALLABAG_USERNAME, WALLABAG_PASSWORD, urls)

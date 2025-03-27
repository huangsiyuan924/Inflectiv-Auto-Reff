import base64
import json
import logging
import os.path
import random
import time
import uuid
from datetime import datetime, timezone

import web3
from curl_cffi import requests
import requests as reqqq
from eth_account.messages import encode_defunct



session = reqqq.Session()

w3 = web3.Web3(web3.HTTPProvider("https://mainnet.infura.io/v3/", session=session))

HEADERS = {
    "accept": "application/json, text/plain, */*",
    # "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "authorization": "",
    "content-type": "application/json",
    "origin": "https://tapnodegame.inflectiv.ai",
    "priority": "u=1, i",
    "referer": "https://tapnodegame.inflectiv.ai/",
    "sec-ch-ua": '"Apple Safari";v="17", "iOS";v="17", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"iOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Telegram/iOS",
}


def update_token_with_metamask(wallet_dict, label, invite_code=None):
    private_key = wallet_dict[label]['priv_key']
    proxy = f"http://172.16.12.60:{wallet_dict[label]['port']}"
    account = w3.eth.account.from_key(private_key)
    address = account.address
    headers = {**HEADERS}
    for i in range(3):
        try:
            msg = f"""tapnodegame.inflectiv.ai wants you to sign in with your Ethereum account:

URI: https://tapnodegame.inflectiv.ai
Issued At: {datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')}"""
            encoded_bytes = base64.b64encode(msg.encode('utf-8'))
            encoded_msg = encoded_bytes.decode('utf-8')
            encoded_message = encode_defunct(text=msg)

            signed_message = w3.eth.account.sign_message(encoded_message, private_key=private_key)
            signature = "0x" + signed_message.signature.hex()
            # exit()
            auth_url = 'https://accounts.inflectiv.ai/realms/inflectiv/protocol/openid-connect/token'
            auth_data = {
                'client_id': 'tng-b384fb5d-28e0-47ba-9273-d7262aa911e0',
                'grant_type': 'password',
                'scope': 'openid email profile',
                'authFlow': 'wallet',
                'walletAddress': address.lower(),
                'walletSignature': signature,
                'walletMessage': encoded_msg,
                'walletBlockchain': 'eth',
                "walletType": 'metaMask'
            }
            headers['content-type'] = 'application/x-www-form-urlencoded'
            res = requests.post(url=auth_url, headers=headers, data=auth_data, proxy=proxy, timeout=60,
                                impersonate="safari15_5")
            token = res.json()['access_token']


            if not os.path.exists('tokens.json'):
                open('tokens.json', 'w', encoding='utf-8').write("{}")
            res = json.loads(open('tokens.json', 'r', encoding='utf-8').read())
            if label not in res.keys(): res[label] = {}
            res[label] = {"token": token, "port": wallet_dict[label]['port']}
            open('tokens.json', 'w', encoding='utf-8').write(json.dumps(res))
            print(f"{label} completed")
            try:
                headers['content-type'] ="application/json"

                register_data = {
                    'keycloakAccessToken': token,
                    'refBy': invite_code,
                    'username': address.lower()
                }
                register_url = 'https://api-tapnodegame.inflectiv.ai/api/auth/register'
                res  =requests.post(register_url, headers=headers, data=json.dumps(register_data), proxy=proxy, timeout=60,
                                impersonate="safari15_5")
                print(f"register: {res.json()['message']}")

            except Exception as e:
                print(f'register err: {e}')


            return token
        except Exception as e:
            logging.error(e)

    return None



if __name__ == '__main__':
    ref_data = json.loads(open('ref_codes.json', 'r', encoding='utf-8').read())
    ref_codes = [ref_data[key] for key in ref_data.keys()]

    wallet_dict = get_wallets()
    flg = False

    for label in wallet_dict.keys():
        update_token_with_metamask(wallet_dict, label, random.choice(ref_codes))

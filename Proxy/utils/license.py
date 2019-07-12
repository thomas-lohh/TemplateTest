import base64
import json
import requests
from requests.adapters import HTTPAdapter
from datetime import datetime
import jwt
import threading
import time


class LicenseValidator:
    def __init__(self, license_config):
        self.license_cache = {}
        self.license_type = license_config['type']
        self.server = license_config['server'].strip('/')
        self.validation_url_template = license_config['validation_url_template']
        self.oauth_config = license_config['oauth_config']

        if (not self.license_type) or (not self.server) or (not self.oauth_config):
            raise Exception("License config does't have required fields (type, server, oauth_config):\n{0}".format(json.dumps(
                license_config, indent=2)))

        self.session = requests.Session()
        self.session.mount(self.server, HTTPAdapter(max_retries=3))

        self.access_token = None
        self.renew_access_token_thread = threading.Thread(
            name="renew_access_token_thread",
            target=self.renew_access_token)
        self.renew_access_token_thread.daemon = True
        self.renew_access_token_thread.start()

    def get_access_token(self):
        token_url = self.server + '/oauth/token'
        try:
            r = self.session.post(token_url, json=self.oauth_config)
        except Exception as e:
            print('Token request error: {0}: {1}'.format(token_url, str(e)))
            return False

        if r.status_code != 200:
            print('Token request failed: {0}, {1}'.format(
                token_url, r.stauts_code))
            return False

        if not 'access_token' in r.json():
            print('No access token in response: {0}, content: {1}'.format(
                token_url, r.text))
            return False

        self.access_token = r.json()['access_token']
        print('Received access token: {0}, token = {1}...'.format(
            token_url, self.access_token[:20]))

        return True

    def renew_access_token(self):
        while True:
            try:
                if self.get_access_token():
                    # No need to verify token because it is used to access license service,
                    # not for protecting this service
                    jwt_token = jwt.decode(self.access_token, verify=False)
                    print('JWT access token:\n{0}'.format(
                        json.dumps(jwt_token, indent=2)))

                    expiration_time = datetime.utcfromtimestamp(
                        jwt_token['exp'])
                    print('Token expires at {0} UTC'.format(expiration_time))

                    sleep_time = (expiration_time -
                                  datetime.utcnow()).total_seconds() - 600
                else:
                    sleep_time = 60
            except Exception as e:
                print('Renew token error: {0}'.format(str(e)))
                sleep_time = 60

            print('Renew access token in {0} seconds'.format(sleep_time))
            time.sleep(sleep_time)

    def validate(self, api_key):
        if not api_key:
            return False, 401, 'Missing license key'

        if api_key in self.license_cache and datetime.datetime.now() < self.license_cache[api_key]:
            print('License key is valid: {0}, expiration: {1}'.format(
                api_key, str(self.license_cache[api_key])))
            return True, None, None

        if self.access_token == None:
            return False, 500, 'Cannot validate license'

        validation_url = self.server + \
            self.validation_url_template.replace('{service}', self.license_type).replace(
                '{api_key}', base64.b64encode(api_key.encode('utf-8')).decode('utf-8'))

        try:
            r = self.session.get(validation_url, headers={
                'Authorization': 'Bearer ' + self.access_token})
        except Exception as e:
            print('License validation error: {0}, {1}'.format(
                validation_url, str(e)))
            return False, 500, 'License validation error'

        if r.status_code != 200:
            print('License validation failed: {0}, {1}'.format(
                validation_url, r.status_code))
            return False, r.status_code, 'License validation error'

        print('License validaton success: {0}, response: {1}'.format(
            validation_url, r.text))

        res_json = r.json()
        if (not 'licenseCount' in res_json) or (res_json['licenseCount'] == 0):
            print('No license of {0} for license key {1}'.format(
                self.license_type, api_key))
            return False, 401, "Invalid license"

        self.license_cache[api_key] = datetime.datetime.now(
        ) + datetime.timedelta(hours=4)
        return True, None, None

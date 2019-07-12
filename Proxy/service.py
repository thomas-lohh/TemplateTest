from gevent.pywsgi import WSGIServer
from gevent import monkey

# Patch to make blocking calls non-blocking using greenlets to handle concurrent requests
monkey.patch_all()

import copy
from flask import Flask
from flask import request
from flask import abort
import json
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from logging import StreamHandler
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Summary
import socket
import traceback
from functools import wraps
from utils import license

import {app_module_name}

app = Flask(__name__)

# service options (config settings)
options = None

# for logging
logger = logging.getLogger('{app_module_name}')

# for license validation
license_validator = None

# for checks on images
MAX_SIZE = 6.5 * 1024 * 1024
MAX_IMAGE_PAGES = 2

# for Prometheus metrics
metrics_prefix = '{app_module_name}'
metrics_description_prefix = metrics_prefix.capitalize()
metrics = PrometheusMetrics(app)
hostname = socket.gethostname()
labels = {'status': lambda r: r.status_code,
        'path': lambda: request.path,
        'method': lambda: request.method,
        'hostname': hostname}
LOAD_TIME = Summary(metrics_prefix + '_module_loading_seconds', metrics_description_prefix + ' Time spent loading module')
# end of Prometheus metrics

def limit_content_length(max_length):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            cl = request.content_length
            if cl and cl > max_length:
                abort(413)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def limit_image_page(max_pages):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            payload_json = request.get_json()
            if payload_json:
                page_images = payload_json.get("page_images")
                if page_images and len(page_images) > max_pages:
                    abort(413, "Payload has too many image pages")
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/", methods=['POST', 'OPTIONS'])
@metrics.do_not_track()
@metrics.counter(metrics_prefix + 'http_request', metrics_description_prefix + 'Request latency counter by labels',
                labels=labels)
@metrics.histogram(metrics_prefix + 'http_request_latency', metrics_description_prefix + 'Request latencies by labels',
                labels=labels,
                buckets=(0.5, 1, 2.5, 5.0, 7.5, 10, 12.5, 15, 17.5, 20, 25, 30, 35, 40, 50, 75, 100, float("inf")),
)
@limit_content_length(MAX_SIZE)
@limit_image_page(MAX_IMAGE_PAGES)
def service():
    if request.method == 'OPTIONS':
        return json.dumps({}).encode('utf-8')
    elif request.method == 'POST':
        if not request.is_json: 
            abort(400, 'Invalid request payload in JSON format')

        if license_validator != None:
            valid, code, err = license_validator.validate(request.headers.get('X-UIPATH-License'))
            if not valid:
                abort(code, err)

        try:
            request_data = request.get_json()
            request_ip = request.access_route[0]
            context = {'request': {'data': request_data, 'ip': request_ip}}
            # process request
            response, telemetry = {app_module_name}.{app_predict_function}(context)
            return json.dumps(response).encode('utf-8')
        except Exception:
            print('Failed to process. See stacktrace below')
            traceback.print_exc()
            abort(500, "Failed to process")         
    else:
        raise NotImplementedError

@app.route("/modelinfo")
def info():
    try:
        return {app_module_name}.{app_info_function}()
    except Exception:
        print('App info is not available')

@app.route("/imageinfo")
def image_info():
    try:
        manifest = os.path.join(options['workdir'], options['manifest'])
        with open(manifest) as f:
            print(f.read())
    except Exception:
        print('Image info is not found')

@app.after_request
def apply_caching(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    response.headers['Access-Control-Max-Age'] = 1000
    # note that '*' is not valid for Access-Control-Allow-Headers
    response.headers['Access-Control-Allow-Headers'] = 'origin, x-csrftoken, content-type, accept'
    return response

def load_options(service_options_json):
    with open(service_options_json, 'r') as f:
        options = json.load(f)
    # verify the config
    required_keys = ['workdir', 'port', 'logging', 'license']
    for key in required_keys:
        if key not in options:
            print(f'Missing config option: {key}')
            sys.exit()
    return options

def config_logging(options):
    # these paths should be changed to match the deployment system
    logdir = options['logdir']
    if not os.path.exists(logdir):
        os.makedirs(logdir)

    loglevel = options['loglevel']
    logger.setLevel(loglevel)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # setup console logging
    console_handler = StreamHandler()
    console_handler.setLevel(loglevel)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    # setup file logging
    logfile, maxsize, backups = options['logfile'], options['rotation']['maxsize'], options['rotation']['backups']
    logfile = os.path.join(logdir, logfile)
    file_handler = RotatingFileHandler(logfile, maxBytes=maxsize, backupCount=backups)
    file_handler.setLevel(loglevel)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

@LOAD_TIME.time()
def main():
    # make sure the service is launched with options as argument
    sof = '.'.join(['service', 'options', 'json'])
    if len(sys.argv) <= 1 or not sof == sys.argv[1] or not os.path.isfile(sof):
        print(f'Syntax: {sys.argv[0]} {sof}')
        print('Error: config file missing')
        sys.exit()

    # load service options from external json
    global options
    options = load_options(sof)

    config_logging(options['logging'])

    global license_validator
    if options['license']['enabled']:
        license_validator = license.LicenseValidator(options['license'])

    # initialization of the module
    print('Initializing: {app_module_name}.{app_init_function}')
    {app_module_name}.{app_init_function}()
    print('Initialization complete')

    print('Serving: https://localhost:%s/' % options['port'])
    http_server = WSGIServer(('', options['port']), app)
    http_server.serve_forever()

if __name__ == '__main__':
    main()
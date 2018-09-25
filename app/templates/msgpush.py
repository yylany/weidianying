__author__ = 'liuxu'
import platform
import datetime
import logging
from flask import Flask
from flask_restful import Api
from flask_restful import Resource, reqparse
from flask import jsonify, make_response
from logging.handlers import RotatingFileHandler
from flask_uwsgi_websocket import GeventWebSocket
from collections import deque

ws_terminals = {}
backlog = deque(maxlen=10)


# LOG
def init_logger():
    # 配置LOG
    logger = logging.getLogger(__name__)
    # 输出到屏幕
    consolelog = logging.StreamHandler()
    logger.addHandler(consolelog)

    return logger


logger = init_logger()
logger.setLevel(10)

app = Flask(__name__)
api = Api(app)
websocket = GeventWebSocket(app)


class PushMessages(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('terminal_ip',
                                   type=str,
                                   required=True,
                                   help='terminal_ip required error')
        self.reqparse.add_argument('push_message',
                                   type=str,
                                   required=True,
                                   help='push_message required error')
        super(PushMessages, self).__init__()

    def post(self):
        req_args = self.reqparse.parse_args()
        terminal_ip = req_args['terminal_ip']
        push_message = req_args['push_message']

        logger.info('terminal_ip:{ip},push_message:{msg}'.format(ip=terminal_ip, msg=push_message))
        ws = ws_terminals.get(terminal_ip)
        logger.info(ws_terminals)
        logger.info(ws)
        if ws is not None and ws.connected:
            logger.info('send a msg!!!')
            ws.send(push_message)
        else:
            logger.info('save a msg!!!')
            msg = (terminal_ip, datetime.datetime.now(), push_message)
            backlog.append(msg)


@websocket.route('/message')
def PushMessage(ws):
    ip = ws.environ.get('REMOTE_ADDR')
    logger.info('ip is {ip} connected'.format(ip=ip))
    if ip is not None:
        ws_terminals[ip] = ws

    for msg in backlog:
        if msg[0] == ip:
            ws.send("{datetime} {msgtext}".format(datetime=msg[1], msgtext=msg[2]))

    while True:
        msg = ws.receive()
        if msg is not None:
            pass
        else:
            break

    del ws_terminals[ip]


# version1 route
version_1 = ""
api.add_resource(PushMessages, version_1 + '/push')

if __name__ == '__main__':
    app.run(host='0.0.0.0', gevent=100, debug=True)

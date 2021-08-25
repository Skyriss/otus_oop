#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
# from scoring import get_score, get_interests
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field:
    _type = None

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self._name = None

    def __set_name__(self, owner, name):
        self._name = name

    def __set__(self, owner, value):
        if self.required and value is None:
            raise AttributeError("Field '{}' is required".format(self._name))
        if not self.nullable and not value:
            raise ValueError("Field '{}' cannot have empty value".format(self._name))
        if value:
            if not isinstance(value, self._type):
                raise ValueError("Field '{}' must be '{}', but got '{}'".format(
                    self._name,
                    self._type,
                    type(value)
                ))
            self._validate(value)
        owner.__dict__[self._name] = value

    def __get__(self, instance, owner):
        return instance.__dict__[self._name]

    def _validate(self, value):
        pass


class CharField(Field):
    _type = str


class ArgumentsField(Field):
    _type = dict


class EmailField(CharField):
    _type = str

    def _validate(self, value):
        if '@' not in value or '.' not in value:
            raise ValueError("Email must contain '@' and '.' symbols")


class PhoneField(Field):
    _type = (str, int)

    def _validate(self, value):
        value = str(value)
        if len(value) != 11:
            raise ValueError("Phone number must be 11 digits long")
        if not value.startswith("7"):
            raise ValueError("Phone number must start with '7'")
        if not value.isdigit():
            raise ValueError("Phone number must contain only digits")


class DateField(Field):
    _type = str

    def _validate(self, value):
        _ = datetime.datetime.strptime(value, "%d.%m.%Y")


class BirthDayField(DateField):
    _type = str

    def _validate(self, value):
        bday_year = datetime.datetime.strptime(value, "%d.%m.%Y").year
        diff = datetime.datetime.now().year - bday_year
        if diff <= 0:
            raise ValueError("Birthday is too close")
        if diff >= 70:
            raise ValueError("Bithday is too far away")


class GenderField(Field):
    _type = int

    def _validate(self, value):
        if value not in GENDERS:
            raise ValueError("Gender must be one of '{}', but got '{}'".format(GENDERS, value))


class ClientIDsField(Field):
    _type = list

    def _validate(self, value):
        if not all([isinstance(item, int) for item in value]):
            raise ValueError("ClientIDs must be list of int")


class Request:

    def __init__(self):
        self.fields = [field for field, value in self.__class__.__dict__.items() if isinstance(value, Field)]

    def validate(self, kwargs):
        for field in self.fields:
            value = kwargs.get(field, None)
            setattr(self, field, value)

    def get_arguments(self):
        return {key: value for key, value in self.__class__.__dict__.items() if isinstance(value, Field)}


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self, kwargs):
        super().validate(kwargs)
        if not any([
            self.phone and self.email,
            self.first_name and self.last_name,
            self.gender is not None and self.birthday
        ]):
            raise AttributeError("any of pairs expected: 'phone/email', 'first name/last name', 'gender/birthday'")

class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        auth = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
        digest = hashlib.sha512(auth.encode("utf-8")).hexdigest()
    else:
        auth = request.account + request.login + SALT
        digest = hashlib.sha512(auth.encode("utf-8")).hexdigest()
    if digest == request.token:
        return True
    return False


def get_score(request, ctx, store):
    if isinstance(request, OnlineScoreRequest):
        return int(ADMIN_SALT) if ctx["is_admin"] else scoring.get_score(store, *request.get_arguments())
    return 200


def online_score_handler(request, ctx, store):
    online_score_request = OnlineScoreRequest()
    online_score_request.validate(request.arguments)
    ctx["has"] = request.arguments
    score = get_score(online_score_request, ctx, store)
    return {"score": score}, OK


def clients_interests_handler(request, ctx, store):
    clients_interests_request = ClientsInterestsRequest()
    clients_interests_request.validate(request.arguments)
    interests = {client_id: scoring.get_interests(store, client_id) for client_id in
                 clients_interests_request.client_ids}
    ctx["nclients"] = len(clients_interests_request.client_ids)
    return interests, OK


def method_handler(request, ctx, store):
    methods = {
        "online_score": online_score_handler,
        "clients_interests": clients_interests_handler,
    }
    try:
        method_request = MethodRequest()
        method_request.validate(request.get("body"))
        ctx["is_admin"] = method_request.is_admin
        if not check_auth(method_request):
            return "Auth failed", FORBIDDEN
        response, code = methods[method_request.method](method_request, ctx, store)
    except (AttributeError, ValueError, TypeError) as err:
        error_message = "Sorry, your request contains errors: {}".format(err)
        return error_message, INVALID_REQUEST
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except (IOError, json.JSONDecodeError):
            code = BAD_REQUEST
        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s",self.path, data_string, context["request_id"])
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s", e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s", opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

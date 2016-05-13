#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import hashlib
import hmac
import re
import json
import urllib2
import random
from string import letters
import database
#from google.appengine.ext import db

MEC = "vu10A010F0Tny89810lkd4n5"


# joins the path of current direcotry with template
temp_dir = os.path.join(os.path.dirname(__file__), 'templates')

# loads the file in jinja environment from temp_dir path
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(temp_dir), autoescape=True)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = str(make_secure_val(val))
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def gen_rand():
    length = 5
    return ''.join(random.choice(letters) for x in xrange(length))

    def gen_hash_pw(name, pw, salt=None):
        if not salt:
            salt = gen_rand()
        hashp = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, hashp)

    def valid_pw(name, password, h):
        salt = h.split(',')[0]
        return h == gen_hash_pw(name, password, salt)

'''
class Data(db.Model):
    username = db.StringProperty(required=True)
    email = db.EmailProperty(required=True)
    address = db.PostalAddressProperty()
    geopoints = db.GeoPtProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    rating = db.RatingProperty(required=True, default=0)
'''


class MainPage(Handler):

    def render_login_page(self, username="", password="", profession="", login_error=""):
        self.render("login.html", username=username, password=password,
                    profession=profession, login_error=login_error)

    def get(self):
        self.render_login_page()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        profession = self.request.get('profession')

        if username and password and profession:
            business = database.Business(username=username,
                                         password=password, profession=profession)
            business.put()

            if profession == "businessman":
                self.redirect("/start_b")
            elif profession == "farmer":
                self.redirect("/start_f")
        else:
            login_error = "You are missing something buddy"
            self.render_login_page(username, password, profession, login_error)


class BStartPage(webapp2.RequestHandler):

    def get(self):
        self.response.out.write("welcome businessman")

    def post(self):
        self.response.out.write("post method")


class FStartPage(webapp2.RequestHandler):

    def get(self):
        self.response.out.write("Welcome Farmers")

    def post(self):
        self.response.out.write("post method")


app = webapp2.WSGIApplication([
    ('/', MainPage), ('/start_b', BStartPage), ("/start_f", FStartPage)
], debug=True)

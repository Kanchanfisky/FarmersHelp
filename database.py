from google.appengine.ext import db
import hashlib
import random
from string import letters


class user_info(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    profession = db.StringProperty(required=True, choices=set[
                                   "farmer", "businessman"])
    created = db.DateTimeProperty(auto_now_add=True)
    rating = db.RatingProperty(required=True, default=0)
    email = db.EmailProperty(required=True)
    address = db.PostalAddressProperty()
    geopoints = db.GeoPtProperty()

    def by_id(cls, uid):
        return user_info.get_by_id(uid, parent=None)

    def by_name(cls, name):
        #u=db.GqlQuery("SELECT * FROM user_acc WHERE username='"+name+"'")
        u = user_info.all().filter('username =', name).get()
        return u

    def register(cls, username, password, email):
        password_protected = gen_hash_pw(username, password)
        return user_info(username=username, password=password_protected, email=email)

    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.password):
            return user


def get_random(length=5):
    return ''.join(random.choice(letters) for x in range(length))


def gen_hash_pw(name, pw, salt=None):
    if not salt:
        salt = gen_rand()
    hashp = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, hashp)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == gen_hash_pw(name, password, salt)

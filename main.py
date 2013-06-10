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

import hashlib
import hmac
import webapp2
import jinja2
import os
import random
import re
import time
import urllib2
from string import letters
from google.appengine.ext import db
from xml.dom import minidom
from gracenoteIDs import clientID, userID, albumSearchCover

secretKey = "BwWuOrchjptblMWljjbOxzapj"

# Set up our templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

# RegEx patterns for usernames, passwords, and emails
usernamePattern = "^[a-zA-Z0-9_-]{3,20}$"
passwordPattern = "^.{3,20}$"
emailPattern = "^[\S]+@[\S]+\.[\S]+$" 

# Handy functions
def makeSalt(length = 5):
	return "".join(random.choice(letters) for x in range(length))
	
def makePasswordHash(name, pwd, salt=None):
	if not salt:
		salt = makeSalt()
	h = hashlib.sha256(name + pwd + salt).hexdigest()
	return '%s,%s' % (salt, h)

def validatePassword(name, password, h):
	salt = h.split(",")[0]
	return h == makePasswordHash(name, password, salt)
	
def hashIt(s):
	return hmac.new(secretKey, s).hexdigest()
	
def make_secure_val(s):
	return "%s|%s" % (s, hashIt(s))
	
def check_secure_val(h):
	value = h.split("|")[0]
	if h == make_secure_val(value):
		return value
	else:
		return None

def validate_username(username):
	"""
	validating the username for our fake signup.
	"""
	if username:
		prog = re.compile(usernamePattern)
		match = prog.match(username)
		if match:
			return True
	
def validate_password(password):
	"""
	validating the password for our fake signup.
	"""
	if password:
		prog = re.compile(passwordPattern)
		match = prog.match(password)
		if match:
			return True

def validate_email(email):
	"""
	validating the email for our fake signup
	"""
	if email and email != "":
		prog = re.compile(emailPattern)
		match  = prog.match(email)
		if match:
			return True	
	else:
		return True
		
# General Handler with useful functions
class Handler(webapp2.RequestHandler):
	"""
	Main Handler to inherit from
	"""
	def write(self, *args, **kwargs):
		self.response.out.write(*args, **kwargs)
	
	def render_str(self, template, **params):
		jinjaTemplate = jinja_env.get_template(template)
		return jinjaTemplate.render(params)
	
	def render(self, template, **kwargs):
		self.write(self.render_str(template, **kwargs))


# Our User class
class User(db.Model):
	"""
	User db entry for username, password, and email
	"""
	username = db.StringProperty(required = True)
	hashedPassword = db.StringProperty(required = True)
	signupDate = db.DateTimeProperty(auto_now_add = True)
	email = db.StringProperty()
	
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)
		
	@classmethod
	def get_by_name(cls, username):
		return User.all().filter('username =', username).get()
	
	@classmethod
	def register(cls, username, password, email = None):
		hashedPassword = makePasswordHash(username, password)
		return User(username = username, hashedPassword = hashedPassword, email = email)
	
	@classmethod
	def login(cls, username, password):
		user = cls.get_by_name(username)
		if user and validatePassword(username, password, user.hashedPassword):
			return user

# Our Artist class
class Artist(db.Model):
	name = db.StringProperty(required = True)
	genre = db.StringProperty(required = True)
	
	@classmethod
	def get_artists(cls, artist):
		return Artist.all().filter('name =', artist).fetch(5)
		
# Our Album class
class Album(db.Model):
	title = db.StringProperty(required = True)
	artist = db.StringProperty(required = True)
	dateReleased = db.DateProperty(required = True)
	genre = db.StringProperty(required = True)
	
	@classmethod
	def get_album(cls, album):
		return Album.all().filter('album =', album).fetch(5)

# Our Review class
class Review(db.Model):
	album = db.StringProperty(required = True)
	artist = db.StringProperty(required = True)
	reviewer = db.StringProperty(required = True)
	reviewDate = db.DateTimeProperty(auto_now_add = True)
	reviewText = db.TextProperty(required = True)
	
	@classmethod
	def get_reviews_by_user(cls, user):
		return Review.all().filter('reviewer = ', user).order('-reviewDate').fetch(10)

# Our webpage handlers
class GreyMatterHandler(Handler):
	def get(self):
	
		if self.user:
			self.redirect("/home")
		else:
			self.render("greymatterreview.html")
	
	def post(self):
	
		login = self.request.get('loginbutton')
		signup = self.request.get('signupbutton')
		if signup:
			error = False
			self.username = self.request.get('newusername')
			self.password = self.request.get('newpassword')
			self.email = self.request.get('newemail')
	   
			parameters = {'newusernamevalue' : self.username, 'newemailvalue' : self.email}
	   
			if not validate_username(self.username):
				error = True
				parameters['error_username'] = "Invalid username" 
			elif not validate_password(self.password):
				error = True
				parameters['error_password'] = "Invalid password"
			elif not validate_email(self.email):
				error = True
				parameters['error_email'] = "Invalid email"
		   
			if error:
				self.render("greymatterreview.html", **parameters)
			else:
	   
				u = User.get_by_name(self.username)
	  
				if u:
					##redirect
					self.render('greymatterreview.html', error_username = "That user already exists")
				else:
					u = User.register(username=self.username, password=self.password, email=self.email)
		  
					u.put()
		  
					self.setCookie('user_id', str(u.key().id()))
		  
					self.redirect('/home')
		elif login:
			error = False
			self.username = self.request.get('username')
			self.password = self.request.get('password')
		
			parameters = {'username' : self.username}
		
			u = User.login(self.username, self.password)
				
			if u:
				self.response.headers['Content-Type'] = 'text/plain'
				self.setCookie('user_id', str(u.key().id()))
		   
				self.redirect('/home')
			else:
				parameters['login_error'] = "Invalid login"
				self.render("greymatterreview.html", **parameters)
				
	def setCookie(self, name, value):
		cookie = make_secure_val(value)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie))
	
	def readCookie(self, name):
		cookie = self.request.cookies.get(name)
		return cookie and check_secure_val(cookie)
	
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.readCookie('user_id')
		self.user = uid and User.by_id(int(uid))
		
class LoginHandler(GreyMatterHandler):
	def get(self):
		if self.user:
			self.redirect('/home')
		else:
			self.render('login.html')
	
	def post(self):
		error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		
		parameters = {'username' : self.username}
		
		if not validate_username(self.username):
			error = True
			parameters['error_username'] = "That's not a valid username" 
		if not validate_password(self.password):
			error = True
			parameters['error_password'] = "That's not a valid password"
		
		if error:
			self.render("login.html", **parameters)
		else:
		
			u = User.login(self.username, self.password)
				
			if u:
				self.response.headers['Content-Type'] = 'text/plain'
				self.setCookie('user_id', str(u.key().id()))
				
				self.redirect('/home')
			else:
				parameters['login_error'] = "Invalid login"
				self.render("login.html", **parameters)

class HomeHandler(GreyMatterHandler):
	def get(self):
		if self.user:
			reviews = Review.get_reviews_by_user(self.user.username)
			number = len(reviews)
			self.render("home.html", username=self.user.username, length=number, reviews=reviews)
		else:
			self.redirect('/')
			
class NewReviewHandler(GreyMatterHandler):
	def get(self):
		if self.user:
			self.render("newreview.html", url="", errorMessage="")
		else:
			self.redirect("/")
			
	def post(self):
		if not self.user:
			self.redirect("/")
		
		search = self.request.get('artistlookupbtn')
		inputAlbum = self.request.get('inputAlbum')
		submitReview = self.request.get('newreviewbtn')
		review = self.request.get('reviewbody')
		artist = self.request.get('artisthidden')
		album = self.request.get('albumhidden')
		
		if search and inputAlbum != "":
			xml = searchGracenote(inputAlbum)
			albums = parseXML(xml)
			
			if len(albums) > 0:
				self.render("newreview.html", albums=albums, errorMessage="")
			else:
				self.render("newreview.html", url="", errorMessage="Sorry, " \
					+ "no artists were found with that name")
		elif search and artistName == "":
			self.render("newreview.html", url="", errorMessage="Please enter " \
				+ "an artist to search for")
		elif submitReview and review and artist and album:
			newReview = Review(album=album, artist=artist, reviewer=self.user.username, \
							reviewText=review)
			newReview.put()
			time.sleep(1)
			self.redirect("/home")
		else:
			self.render("newreview.html", url="", errorMessage="Please " \
					+ "fill out each of the fields")

artistQuery = "<QUERIES><LANG>eng</LANG><AUTH><CLIENT>{0}</CLIENT><USER>{1}</USER></AUTH><QUERY CMD=\"ALBUM_SEARCH\"><TEXT TYPE=\"ARTIST\">{2}</TEXT></QUERY></QUERIES>"

def searchGracenote(album):
	req = urllib2.Request(url="https://c14927872.web.cddbp.net/webapi/xml/1.0/", data=albumSearchCover.format(clientID, userID, album), \
		headers={'Content-type': 'application/xml'})
	
	albumSearch = urllib2.urlopen(req)
	
	return albumSearch.read()
	
def parseAlbumEntry(album):
	albumDict = {}
	artist = album.getElementsByTagName("ARTIST")
	albumTitle = album.getElementsByTagName("TITLE")
	url = album.getElementsByTagName("URL")

	if len(albumTitle) > 0:
		albumDict['albumTitle'] = albumTitle[0].firstChild.wholeText
	else:
		albumDict['albumTitle'] = ""
	
	if len(artist) > 0:
		albumDict['artistName'] = artist[0].firstChild.wholeText
	else:
		albumDict['artistName'] = ""
	
	if len(url) > 0:
		albumDict['url'] = url[0].firstChild.wholeText
	else:
		albumDict['url'] = ""
	
	return albumDict

def parseXML(xml):
	albumList = []
	
	d = minidom.parseString(xml)
	albums = d.getElementsByTagName("ALBUM")
	if len(albums) < 1:
		return albumList
	
	for album in albums:
		albumDict = parseAlbumEntry(album)
		
		if albumDict not in albumList:
			albumList.append(albumDict)
	
	return albumList
		
class LogoutHandler(GreyMatterHandler):
	def get(self):
		self.logout()
		self.redirect('/')
		

# Make the app go!
app = webapp2.WSGIApplication([
    ('/?', GreyMatterHandler), ('/home/?', HomeHandler), ('/logout/?', LogoutHandler), \
    ('/newreview', NewReviewHandler)], debug=True)
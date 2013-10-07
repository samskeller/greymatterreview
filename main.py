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
# test

from cgi import escape
import datetime
import hashlib
import hmac
import webapp2
import jinja2
import json
import musicbrainzngs
import os
import random
import re
import time
import unicodedata
import urllib2
from string import letters
from google.appengine.ext import db
from google.appengine.api.datastore import Key
from xml.dom import minidom
from gracenoteIDs import clientID, userID, albumSearchCover, artistsSearch

secretKey = "BwWuOrchjptblMWljjbOxzapj"

# Set up our templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)
jinja_env.filters['escape'] = escape

# RegEx patterns for usernames, passwords, and emails
usernamePattern = "^[a-zA-Z0-9_-]{3,20}$"
passwordPattern = "^.{3,20}$"
emailPattern = "^[\S]+@[\S]+\.[\S]+$" 

musicbrainzngs.set_useragent(
    "grey-matter-review",
    "0.1",
    "https://github.com/samskeller/greymatterreview/",
)

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

def unescape(string):
	string = string.replace("&lt;", "<")
	string = string.replace("&gt;", ">")
	string = string.replace("&amp;", "&")
	return string
		
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
	age = db.IntegerProperty()
	followers = db.IntegerProperty()
	following = db.IntegerProperty()
	rating = db.FloatProperty()
	numberOfRatings = db.IntegerProperty()
	numberOfReviews = db.IntegerProperty()
	
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)
		
	@classmethod
	def get_by_name(cls, username):
		return User.all().filter('username =', username).get()
	
	@classmethod
	def register(cls, username, password, email=None, age=None, followers=0, following=0, rating=0.0, numberOfRatings=0, numberOfReviews=0):
		hashedPassword = makePasswordHash(username, password)
		return User(username = username, hashedPassword = hashedPassword, email = email, age = age, followers = followers, \
			following = following, rating = rating, numberOfRatings = numberOfRatings, numberOfReviews = numberOfReviews)
	
	@classmethod
	def login(cls, username, password):
		user = cls.get_by_name(username)
		if user and validatePassword(username, password, user.hashedPassword):
			return user

# Our Artist class
class Artist(db.Model):
	genre = db.StringProperty()
	
	@classmethod
	def get_artist(cls, artist):
		return Artist.all().filter('__key__ =', Key.from_path('Artist', artist)).get()
		
# Our Album class
class Album(db.Model):
	title = db.StringProperty(required = True)
	artist = db.StringProperty(required = True)
	dateReleased = db.DateProperty()
	genre = db.StringProperty()
	
	@classmethod
	def get_album(cls, album):
		return Album.all().filter('album =', album).fetch(5)
		
	@classmethod
	def get_album_by_key(cls, albumKey):
		return Album.all().filter('__key__ =', albumKey).get()
	
	@classmethod
	def get_albums_by_artist(cls, artist):
		return Album.all().filter('artist =', artist).fetch(10)

# Our Review class
class Review(db.Model):
	album = db.StringProperty(required = True)
	artist = db.StringProperty(required = True)
	reviewer = db.StringProperty(required = True)
	reviewDate = db.DateTimeProperty(auto_now_add = True)
	reviewText = db.TextProperty(required = True)
	rating = db.IntegerProperty()
	helpfulCount = db.IntegerProperty()
	
	@classmethod
	def get_reviews_by_user(cls, user):
		return Review.all().filter('reviewer = ', user).order('-reviewDate').fetch(10)
	
	@classmethod
	def get_review_by_album_artist(cls, album, artist):
		return Review.all().filter('album = ', album).filter('artist = ', artist).order('-reviewDate').fetch(10)
	
	@classmethod
	def get_latest_reviews(cls):
		return Review.all().order('-reviewDate').fetch(5)
		
class FollowPair(db.Model):
	follower = db.StringProperty(required = True)
	following = db.StringProperty(required = True)
	
	@classmethod
	def getFollowing(cls, user):
		return FollowPair.gql("WHERE follower = '" + user.username + "'")
	
	@classmethod
	def getFollowers(cls, user):
		return FollowPair.gql("Where following = '" + user.username + "'")
		
	@classmethod
	def isUserFollowingUser(cls, user1, user2):
		return FollowPair.all().filter('follower = ', user1.username).filter('following = ', user2.username).fetch(1)

# Our webpage handlers
class GreyMatterHandler(Handler):
	""" This is our main Grey Matter Review handler. All other handlers will inherit from
	this one. It will hold our user's information and deal with the cookie information as 
	well as the logout process."""
	
	def get(self):
	
		if self.user:
			self.redirect("/home")
		else:
			reviews = Review.get_latest_reviews()
		
			currentDate = datetime.datetime.utcnow()
			
			# Make a scrubbed version of the review
			scrubbedReviews = []
			for review in reviews:
				# Add the basics
				dict = {'reviewer': review.reviewer, 'artist': review.artist, \
					'album' : review.album}
					
				# Get the text of the review but limit it to 50 characters
				text = review.reviewText
				if len(review.reviewText) > 50:
					text = review.reviewText[:50] + "..."
				
				dict['reviewText'] = text
				
				print review.reviewDate
				
				# Figure out how many seconds from now this review happened
				dateDifference = currentDate - review.reviewDate	
						
				dict['secondsAgo'] = int(dateDifference.total_seconds())				
				scrubbedReviews.append(dict)
				
			self.render("greymatterreview.html", reviews=scrubbedReviews)
	
	def post(self):
		
		# Figure out whether they tried to log in or signup
		login = self.request.get('loginbutton')
		signup = self.request.get('signupbutton')
		if signup:
			error = False
			
			# Get the user entered fields
			self.username = self.request.get('newusername')
			self.password = self.request.get('newpassword')
			self.email = self.request.get('newemail')
	   
			parameters = {'newusernamevalue' : self.username, 'newemailvalue' : self.email}
	   		
	   		# Check for a valid username, password, and email
			if not validate_username(self.username):
				error = True
				parameters['error_username'] = "Invalid username" 
			elif not validate_password(self.password):
				error = True
				parameters['error_password'] = "Invalid password"
			elif not validate_email(self.email):
				error = True
				parameters['error_email'] = "Invalid email"
		   	
		   	# If any of them had an error, re-render the page and show the error
			if error:
				self.render("greymatterreview.html", **parameters)
			else:
	   			# Look to see if a user with this username already exists
				u = User.get_by_name(self.username)
	  
				if u:
					##redirect
					self.render('greymatterreview.html', error_username = "That user already exists")
				else:
					# Create a new user as all fields were valid and this username is unique
					u = User.register(username=self.username, password=self.password, email=self.email)
		  
		  			# Store the user in our db
					u.put()
		  
		  			# Set a cookie so the user stays logged in
					self.setCookie('user_id', str(u.key().id()))
		  
					self.redirect('/home')
		elif login:
			error = False
			self.username = self.request.get('username')
			self.password = self.request.get('password')
		
			parameters = {'username' : self.username}
			
			# Look to see if this username and password match with a user that we have
			u = User.login(self.username, self.password)
				
			if u:
				# We have a valid user, set a cookie and go to the home page
				self.response.headers['Content-Type'] = 'text/plain'
				self.setCookie('user_id', str(u.key().id()))
		   
				self.redirect('/home')
			else:
				# Invalid login attempt
				parameters['login_error'] = "Invalid login"
				self.render("greymatterreview.html", **parameters)
			
	# Setting a cookie allows the user to stay logged in while navigating through the page
	def setCookie(self, name, value):
		cookie = make_secure_val(value)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie))
	
	# Look to see if a cookie exists
	def readCookie(self, name):
		cookie = self.request.cookies.get(name)
		return cookie and check_secure_val(cookie)
	
	# Log out by setting a null cookie
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	
	# This runs with each new page load when a user is logged in, checks for the cookie we set
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.readCookie('user_id')
		self.user = uid and User.by_id(int(uid))

class HomeHandler(GreyMatterHandler):
	""" The handler for our home page"""
	def get(self):
		if self.user:
			# Get the reviews for this user to display as their profile feed
			reviews = Review.get_reviews_by_user(self.user.username)
			number = len(reviews)
			self.render("home.html", user=self.user, length=number, reviews=reviews)
		else:
			self.redirect('/')
			
class NewReviewHandler(GreyMatterHandler):
	""" The handler for the page to write a new review"""
	def get(self):
		if self.user:
			# Show the new review page
			self.render("newreview.html", url="", errorMessage="")
		else:
			self.redirect("/")
			
	def post(self):
		if not self.user:
			self.redirect("/")
		
		# Get stuff from the request to see which button the user pressed and 
		# what fields were filled in
		search = self.request.get('artistlookupbtn')
		inputAlbum = self.request.get('inputAlbum')
		submitReview = self.request.get('newreviewbtn')
		review = self.request.get('reviewbody')
		artist = self.request.get('artisthidden')
		album = self.request.get('albumhidden')
		rating = self.request.get('rating')
		
		print rating
		
		# If they hit the search button and input text into the album name field, look for the album
		if search and inputAlbum != "":
			# Search through Gracenote for this album name
			#xml = searchGracenoteAlbum(inputAlbum)
			#albums = parseXML(xml)
			albums = searchMusicBrainzAlbum(inputAlbum)
			
			# Render differently depending upon whether we found albums or not
			if len(albums) > 0:
				self.render("newreview.html", albums=albums, errorMessage="")
			else:
				self.render("newreview.html", url="", errorMessage="Sorry, " \
					+ "no artists were found with that name")
		elif search and artistName == "":
			# If the hit search but didn't enter an album name, throw up this message
			self.render("newreview.html", url="", errorMessage="Please enter " \
				+ "an artist to search for")
		elif rating == "":
			self.render("newreview.html", url="", errorMessage="Please enter " \
				+ "a rating number.")
		elif submitReview and review and artist and album:
			# If the user hit submit and there is a review, album, and artist there, save this review
			newReview = Review(album=album, artist=artist, reviewer=self.user.username, \
							reviewText=review, rating=int(rating))
			# Commit to the db
			newReview.put()
			
			# Update the user's number of reviews
			if self.user.numberOfReviews == None:
				self.user.numberOfReviews = 1
			else:
				self.user.numberOfReviews = self.user.numberOfReviews + 1
			
			self.user.put()
			
			# Add the artist to the db if it's not already there
			newArtist = Artist.get_or_insert(artist)
			
			# Add the album to the db if it's not already there
			newAlbum = Album.get_or_insert(artist+"$"+album, title=album, artist=artist)
			
			time.sleep(1)
			self.redirect("/reviews/%d" % newReview.key().id())
		else:
			self.render("newreview.html", url="", errorMessage="Please " \
					+ "fill out each of the fields")

artistQuery = "<QUERIES><LANG>eng</LANG><AUTH><CLIENT>{0}</CLIENT><USER>{1}</USER></AUTH><QUERY CMD=\"ALBUM_SEARCH\"><TEXT TYPE=\"ARTIST\">{2}</TEXT></QUERY></QUERIES>"

class FriendsHandler(GreyMatterHandler):
	""" The handler for the page that lists our user's followers and following"""
	def get(self):
		if self.user:
			# Get the followers and following for this user
			followingPairs = FollowPair.getFollowing(self.user)
			followingPairs = list(followingPairs)
			
			followerPairs = FollowPair.getFollowers(self.user)
			followerPairs = list(followerPairs)
			
			self.render("friends.html", followingPairs=followingPairs, followerPairs=followerPairs, potentials=None)
		else:
			self.redirect("/")
	
	def post(self):
		if self.user:
			searchFriends = self.request.get('searchfriendsbtn')
			searchName = self.request.get('searchfriendsname')
			newFriends = self.request.get_all('checkboxInput')
			
			# If we hit the button to search for friends
			if searchFriends and searchName:
				# Get all users with this name
				potentialFriends = User.all().filter('username =', searchName).fetch(10)
				
				potentialFriends = list(potentialFriends)
				
				if potentialFriends != None:
					self.render("friends.html", potentials=potentialFriends)
			
			# If we've selected users to follow
			elif newFriends:
				for newFriend in newFriends:
					# Make a new FollowPair with the user and the new friend
					newFriendPair = FollowPair(follower=self.user.username, following=str(newFriend))
					
					# Update the followers/following statistics for each user
					newFriendUser = User.get_by_name(newFriend)
					if newFriendUser != None:
						if newFriendUser.followers == None:
							newFriendUsers.followers = 1
						else:
							newFriendUser.followers = newFriendUser.followers + 1
						self.user.following = self.user.following + 1
						newFriendUser.put()
						self.user.put()
					
					newFriendPair.put()
					time.sleep(1)
					self.redirect("/friends")
			else:
				self.render("friends.html")
		else:
			self.redirect("/")

class UserHandler(GreyMatterHandler):
	""" The handler that shows the activity for a selected user"""
	def get(self, username):
		if self.user:
			# Display the reviews done by this other user
			otherUser = User.get_by_name(username)
			if otherUser == None:
				self.redirect("/")
			
			# Get reviews made by this user
			reviews = Review.get_reviews_by_user(username)
			number = len(reviews)
			
			# Look up and see if our user is following this user
			followPair = FollowPair.isUserFollowingUser(self.user, otherUser)
			
			following = False
			if followPair != None and len(followPair) > 0:
				following = True
			
			self.render("user.html", user=otherUser, length=number, reviews=reviews, following=following)
		else:
			self.redirect("/")
	
	def post(self, username):
		if self.user:
			# Get the other username from the AJAX request data
			otherUsername = self.request.get('user')

			# Find out if we're already following this person
			following = self.request.get("follow")
			
			if following == "true":
				# If we already are following this person, then this request must delete 
				# that following pair
				
				# Look up the other user
				otherUser = User.get_by_name(otherUsername)
				if otherUser != None:
					# Look up the FollowPair and delete it
					followingPair = FollowPair.isUserFollowingUser(self.user, otherUser)
					
					if len(followingPair) != 0:
						
						# Delete this FollowPair since we are no longer following this user
						FollowPair.delete(followingPair[0])
						
						# Update both users' followers/following numbers
						otherUser.followers = otherUser.followers - 1
						self.user.following = self.user.following - 1
						otherUser.put()
						self.user.put()
						
						time.sleep(1)
				
			else:
				# Make a new FollowPair with the user and the new friend
				newFriendPair = FollowPair(follower=self.user.username, following=otherUsername)
			
				# Update the followers/following statistics for each user
				newFriendUser = User.get_by_name(otherUsername)
				if newFriendUser != None:
					newFriendUser.followers = newFriendUser.followers + 1
					self.user.following = self.user.following + 1
					newFriendUser.put()
					self.user.put()
			
				newFriendPair.put()
				time.sleep(1)
			
			dict = {'user': otherUsername}
			self.response.headers['Content-Type'] = "application/json"
			self.response.out.write(json.dumps(dict))
			
		else:
			self.redirect("/")
		
class ReviewsHandler(GreyMatterHandler):
	""" The handler that lets the user search for aritsts/albms to find reviews."""
	def get(self):
		if self.user:
			self.render("reviews.html", artists=None, albums=None)
		else:
			self.redirect("/")
			
	def post(self):
		if self.user:
			searchbtn = self.request.get("searchbtn")
			inputText = self.request.get("searchinput")
			searchType = self.request.get("searchdropdown")
		
			# If the dropdown menu was set to artists and the user entered text, search for artists
			if inputText != "" and searchType == "artists":
				artists = searchMusicBrainzArtist(inputText)
				if len(artists) != 0:
					self.render("reviews.html", artists=artists, albums=None)
				else:
					self.render("reviews.html")
			# If the dropdown menu was set to albums and the user entered text, search for albums
			elif inputText != "" and searchType == "albums":
				albums = searchMusicBrainzAlbum(inputText)

				if len(albums) != 0:
					self.render("reviews.html", albums=albums, artists=None)
				else:
					self.render("reviews.html")
			else:
				self.redirect("/")
		else:
			self.redirect("/")

class ReviewPermalinkHandler(GreyMatterHandler):
	""" The handler that shows a single review."""
	def get(self, review_id):
		if self.user:
			# We look up reviews by their id number for the permalink page for that review
			review_id = int(review_id)
			review = Review.get_by_id(review_id)
			
			# Make sure we found a review
			if review != None:
				self.render("reviewPage.html", review=review)
			else:
				self.redirect("/")
		else:
			self.redirect("/")
			
class ArtistPermalinkHandler(GreyMatterHandler):
	""" The handler that shows all the albums for the given artist."""
	def get(self, artist_name):
		if self.user:
			# Unescape the artist's name
			artist_name = unescape(artist_name)
			
			# Search musicbrainz for the albums by that artist
			albums = searchMusicBrainzAlbumsByArtist(artist_name)
			
			# Make sure the search worked properly
			if albums != None:
				self.render("artistsPage.html", artist=artist_name, albums=albums)
			else:
				self.redirect("/")
		else:
			self.redirect("/")
			
class AlbumPermalinkHandler(GreyMatterHandler):
	""" The handler that shows all the reviews for a given album and artist."""
	def get(self, albumAndArtist):
		if self.user:
			# We separate the album and artist in the URL with a "+" sign
			pair = albumAndArtist.split("+")
			
			if len(pair) != 2:
				self.redirect("/")
			
			# The artist is the first part, the album is the second
			(artist, album) = pair
				
			# Look up all the reviews with for that particular album by that particular artist		
			reviews = Review.get_review_by_album_artist(album, artist)
				
			if reviews != None:
				self.render("albumPage.html", reviews=reviews, album=album, artist=artist)
			else:
				self.redirect("/")

		else:
			self.redirect("/")
	
	def post(self, artist):
		if self.user:
			# Get the username of the user that submitted the review and whether or not
			# our user thought it was useful
			username = self.request.get('user')
			useful = self.request.get('useful')
			
			# Get the user who did the review
			reviewer = User.get_by_name(username)
			if reviewer != None:
				# Calculate the delta for how their rating should change
				delta = 1.0 / (reviewer.numberOfRatings + 1)
				
				# Make the delta positive or negative
				if useful == 'false':
					delta = delta * -1
				
				print delta
				# Change the user's stats
				reviewer.numberOfRatings = reviewer.numberOfRatings + 1
				reviewer.rating = reviewer.rating + delta
				
				# Update the user
				reviewer.put()
			
			# Return some stuff to the post request
			dict = {'user': username}
			self.response.headers['Content-Type'] = "application/json"
			self.response.out.write(json.dumps(dict))

def searchMusicBrainzAlbum(album):
	""" searchMusicBrainzAlbum takes an album name as a string and returns a list of dictionaries,
	with each dictionary holding information about an album: artist name, album title, and id number."""
	
	result = musicbrainzngs.search_releases(release=album, limit=5)
	# On success, result is a dictionary with a single key:
	# "release-list", which is a list of dictionaries.
	results = []
	if not result['release-list']:
		return results
	for release in result['release-list']:
		# Make a new dictionary with the artist, album, and id number
		newDict = {'artist': release['artist-credit-phrase'], 'album': release['title']}
		
		# If we haven't already seen this one, add it to the results
		if newDict not in results:
			results.append(newDict)
	return results
	
def searchMusicBrainzAlbumsByArtist(artist):
	"""searchMusicBrainzAlbumsByArtists takes an artist name as a string and returns a list of album
	titles by the given artist."""

	result = musicbrainzngs.search_releases(artist=artist, limit=15)
	
	results = []
	titleTracker = []
	if not result['release-list']:
		return results
	for release in result['release-list']:
		
		# Make sure this is an album, not a single
		releaseGroup = release.get('release-group', None)
		if releaseGroup != None and releaseGroup.get('primary-type', 'Album') != "Album":
			continue
		
		# Make sure this is not a bootleg copy
		if release.get('status', '') != "Official":
			continue
			
		# Make sure this is the US version
		if release.get('country', '') != "US":
			continue
		
		labelName = ""
		labelInfo = release.get('label-info-list', None)
		
		if labelInfo != None:
			labelInfo = labelInfo[0]
			label = labelInfo.get('label', None)
			
			if label != None:
				labelName = label.get('name', '')
		
				
		newDict = {'artist': release['artist-credit-phrase'], 'title': release['title'], \
			'date': release['date'], 'label': labelName}
		
		print release
		
		# Make sure the artist is the one we were searching for and if so, add the album title
		if newDict['artist'] == artist and newDict['title'] not in titleTracker:
			results.append(newDict)
			titleTracker.append(newDict['title'])
	return results

def searchMusicBrainzArtist(artist):
	"""searchMusicBrainzArtist takes an artist name as a string and returns a list of artists
	that match the searched name."""
	
	result = musicbrainzngs.search_artists(artist=artist, limit=5)
	# On success, result is a dictionary with a single key:
	# "artist-list", which is a list of dictionaries.
	results = []
	if not result['artist-list']:
		return results
	for artist in result['artist-list']:
		
		# If we haven't seen this artist name yet, add it to the return list
		if artist['name'] not in results:
			results.append(artist['name'])
	return results
			
class LogoutHandler(GreyMatterHandler):
	def get(self):
		self.logout()
		self.redirect('/')
		

# Make the app go!
app = webapp2.WSGIApplication([
    ('/?', GreyMatterHandler), ('/home/?', HomeHandler), ('/logout/?', LogoutHandler), \
    ('/newreview/?', NewReviewHandler), ('/friends/?', FriendsHandler), \
    ('/user/(\w+)', UserHandler), ('/reviews/?', ReviewsHandler), \
    ('/reviews/(\d+)', ReviewPermalinkHandler), ('/artists/(.+)/?', ArtistPermalinkHandler), \
    ('/albums/(.+)/?', AlbumPermalinkHandler)], debug=True)

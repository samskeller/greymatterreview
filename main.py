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

# Set up our templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

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

class GreyMatterHandler(Handler):
	def get(self):
		self.render("greymatterreview.html")

# Make the app go!
app = webapp2.WSGIApplication([
    ('/?', GreyMatterHandler)], debug=True)
from datetime import datetime, timedelta
import logging
from flask import Flask, request, jsonify, redirect, render_template_string, url_for
import requests
import os

from app import *
from email_sender import send_email
from test_email import logger
from flask_cors import CORS
from waitress import serve


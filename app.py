import os
import json
import asyncio
from datetime import datetime
from functools import wraps
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import praw
from aiocache import Cache, SimpleMemoryCache
from dotenv import load_dotenv
import uuid
import re
import unicodedata

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Importing the correct configuration class from config.py
from config import ProductionConfig
app.config.from_object(ProductionConfig)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
bcrypt = Bcrypt(app)

# Initialize the Reddit API client
reddit = praw.Reddit(client_id=os.getenv('REDDIT_CLIENT_ID'),
                     client_secret=os.getenv('REDDIT_CLIENT_SECRET'),
                     user_agent=os.getenv('REDDIT_USER_AGENT'))

# Initialize the cache
cache = Cache(Cache.MEMORY)

# File path for storing search history
HISTORY_FILE = '_history.json'

# Global variable to store search history
_history = []

# Class definitions
class HistoryEntry:
    def __init__(self, id, episode_id, user_id, subreddit, query, time_period, start_date, end_date, results, date):
        self.id = id
        self.episode_id = episode_id
        self.user_id = user_id
        self.subreddit = subreddit
        self.query = query
        self.time_period = time_period
        self.start_date = start_date
        self.end_date = end_date
        self.results = results
        self.date = date

    def to_dict(self):
        return {
            'id': self.id,
            'episode_id': self.episode_id,
            'user_id': self.user_id,
            'subreddit': self.subreddit,
            'query': self.query,
            'time_period': self.time_period,
            'start_date': self.start_date,
            'end_date': self.end_date,
            'results': self.results,
            'date': self.date
        }

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    last_logout = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.approved}', '{self.is_admin}', '{self.last_login}', '{self.last_logout}')"

    def approve(self):
        self.approved = True
        db.session.commit()

    def make_admin(self):
        self.is_admin = True
        db.session.commit()

class Episode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Episode('{self.name}', '{self.created_at}')"

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref=db.backref('activities', lazy=True))

    def __repr__(self):
        return f"ActivityLog('{self.user_id}', '{self.action}', '{self.timestamp}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def load_history():
    """Load search history from the JSON file."""
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as file:
            history_data = json.load(file)
            history = [HistoryEntry(**entry) for entry in history_data]
    global _history
    _history = history
    return history

def save_history():
    global _history
    with open(HISTORY_FILE, 'w') as file:
        json.dump([entry.to_dict() for entry in _history], file, indent=4)

# Load the search history at startup
load_history()

def log_activity(user_id, action, details=None):
    activity = ActivityLog(user_id=user_id, action=action, details=details)
    db.session.add(activity)
    db.session.commit()

# Decorator to restrict access to admin only
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have the required permissions to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if the username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists. Please choose a different username.', 'danger')
            elif existing_user.email == email:
                flash('Email already exists. Please use a different email address.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created and is pending approval.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('episodes'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.approved:
                login_user(user, remember=True)
                user.last_login = datetime.utcnow()
                db.session.commit()
                log_activity(user.id, 'login')
                next_page = request.args.get('next')
                flash('Login successful', 'success')
                return redirect(next_page) if next_page else redirect(url_for('episodes'))
            else:
                flash('Your account is not approved yet.', 'warning')
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout')
    current_user.last_logout = datetime.utcnow()
    db.session.commit()
    logout_user()
    return redirect(url_for('logout_confirmation'))

@app.route('/logout_confirmation')
def logout_confirmation():
    return render_template('logout_confirmation.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/episodes', methods=['GET', 'POST'])
@login_required
def episodes():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        episode = Episode(name=name, description=description)
        db.session.add(episode)
        db.session.commit()
        flash('Episode created successfully', 'success')
        return redirect(url_for('episodes'))
    episodes = Episode.query.order_by(Episode.created_at.desc()).all()
    return render_template('episodes.html', episodes=episodes)

@app.route('/rename_episode/<int:episode_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def rename_episode(episode_id):
    episode = Episode.query.get_or_404(episode_id)
    if request.method == 'POST':
        new_name = request.form.get('name')
        episode.name = new_name
        db.session.commit()
        flash(f'Episode has been renamed to {new_name}.', 'success')
        return redirect(url_for('episodes'))
    return render_template('rename_episode.html', episode=episode)

@app.route('/delete_episode/<int:episode_id>', methods=['POST'])
@login_required
@admin_required
def delete_episode(episode_id):
    episode = Episode.query.get_or_404(episode_id)
    db.session.delete(episode)
    db.session.commit()
    flash(f'Episode {episode.name} has been deleted.', 'success')
    return redirect(url_for('episodes'))

@app.route('/select_episode/<int:episode_id>', methods=['POST'])
@login_required
def select_episode(episode_id):
    episode = Episode.query.get_or_404(episode_id)
    session['episode_id'] = episode.id
    flash(f'Working on episode: {episode.name}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    if 'episode_id' not in session:
        flash('Please select an episode to work on.', 'warning')
        return redirect(url_for('episodes'))
    episode = Episode.query.get_or_404(session['episode_id'])
    return render_template('dashboard.html', episode=episode)

def is_video_post(submission):
    """
    Check if a submission is a video post.
    """
    if submission.is_video:
        return True
    if 'v.redd.it' in submission.url:
        return True
    if submission.media and 'reddit_video' in submission.media:
        return True
    return False

def fetch_posts(subreddit, query, time_period, after, limit):
    if query:
        submissions = subreddit.search(query, time_filter=time_period, limit=limit, params={'after': after})
    else:
        submissions = subreddit.top(time_filter=time_period, limit=limit, params={'after': after})
    return list(submissions)

def find_matching_links(current_links, current_episode_id):
    matching_links = []
    for entry in _history:
        if entry.episode_id != current_episode_id:
            for title, link in entry.results:
                if link in current_links:
                    matching_links.append((title, link, entry.episode_id))
    return matching_links

def get_episode_names():
    episodes = Episode.query.all()
    return {ep.id: ep.name for ep in episodes}

import time

import time

def search_posts(subreddit_name, query, start_date=None, end_date=None, limit=300):
    if 'episode_id' not in session:
        flash('Please select an episode to work on.', 'warning')
        return redirect(url_for('episodes'))

    episode_id = session['episode_id']
    subreddit = reddit.subreddit(subreddit_name)
    ed_posts = []
    fetch_limit = 100  # Reddit API maximum per request

    # Ensure start and end dates are provided for custom date range
    if not start_date or not end_date:
        raise ValueError("A start date and end date are required.")

    # Parse start_date and end_date strings into datetime objects
    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")
    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")
    start_timestamp = int(start_date_obj.timestamp())
    end_timestamp = int(end_date_obj.timestamp())

    # Determine time range length in days
    time_range_days = (end_date_obj - start_date_obj).days

    # Adaptive fetching based on time range
    if time_range_days <= 7:  # Fetch weekly range
        time_period = 'week'
    elif time_range_days <= 30:  # Fetch monthly range
        time_period = 'month'
    elif time_range_days <= 365:  # Fetch yearly range
        time_period = 'year'
    else:  # For ranges older than one year, use "all time"
        time_period = 'all'
    
    after = None

    # Fetch posts using determined time period
    if time_period in ['week', 'month', 'year']:  # Use Reddit's standard time ranges
        while len(ed_posts) < limit:
            remaining_limit = min(fetch_limit, limit - len(ed_posts))
            fetched_batch = fetch_posts(subreddit, query, time_period, after, remaining_limit)

            if not fetched_batch:
                break

            # Filter for exact date range and video type as posts are fetched
            for post in fetched_batch:
                if is_video_post(post) and start_timestamp <= post.created_utc <= end_timestamp:
                    ed_posts.append(post)

            after = fetched_batch[-1].fullname if fetched_batch else None
            if len(fetched_batch) < fetch_limit:
                break

    else:  # Fetch large range for "all time" and filter afterward
        while len(ed_posts) < 10000:
            fetched_batch = fetch_posts(subreddit, query, 'all', after, fetch_limit)
            
            if not fetched_batch:
                break

            # Collect posts without filtering, for filtering after the loop
            ed_posts.extend(fetched_batch)
            after = fetched_batch[-1].fullname if fetched_batch else None

            time.sleep(1)  # Optional delay to handle rate limits

            if len(ed_posts) >= 10000:
                break

        # After fetching, filter posts for date range and video type
        ed_posts = [
            post for post in ed_posts
            if is_video_post(post) and start_timestamp <= post.created_utc <= end_timestamp
        ]

    # Sort posts by upvotes (score) from highest to lowest
    ed_posts.sort(key=lambda post: post.score, reverse=True)

    # Limit the results to the requested amount
    filtered_posts = ed_posts[:limit]

    # Extract titles and URLs for output
    link_list = [(post.title, f"https://www.reddit.com{post.permalink}", post.score) for post in filtered_posts]

    # Save history and log
    _data = {
        'id': str(uuid.uuid4()),
        'episode_id': episode_id,
        'user_id': current_user.id,
        'subreddit': subreddit_name,
        'query': query,
        'time_period': time_period,
        'start_date': start_date,
        'end_date': end_date,
        'results': link_list,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    _history.append(HistoryEntry(**_data))
    save_history()

    log_activity(current_user.id, 'search_posts', details=f'Subreddit: {subreddit_name}, Query: {query}, Date Range: {start_date} to {end_date}, Results: {len(link_list)} links, Sorted by upvotes")

    return link_list
  
@app.route('/search_posts', methods=['GET', 'POST'])
@login_required
def search_reddit_posts():
    if request.method == 'POST':
        subreddit_name = request.form.get('subreddit', '')
        query = request.form.get('query', '')
        time_period = request.form.get('time_period', 'all')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        limit = int(request.form.get('limit', 10))

        try:
            top_posts_links = search_posts(subreddit_name, query, time_period, start_date, end_date, limit)
            return render_template('top_posts.html', top_posts_links=top_posts_links)
        except ValueError as e:
            return render_template('top_posts.html', top_posts_links=None, error=str(e))
    return render_template('search_posts.html')

@app.route('/extract_usernames', methods=['GET', 'POST'])
@login_required
def extract_usernames():
    if request.method == 'POST':
        reddit_links = request.form['reddit_links']
        links = reddit_links.splitlines()

        # Use asyncio to fetch data for multiple links concurrently
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(fetch_data(links))
        loop.close()

        usernames = [{'username': result['username'], 'link': result['link']} for result in results if result and result['username']]
        log_activity(current_user.id, 'extract_usernames', details=f'Extracted usernames from {len(links)} links')

        return render_template('result.html', usernames=usernames, reddit_links=reddit_links)
    return render_template('extract_usernames.html')

@app.route('/find_clips', methods=['GET', 'POST'])
@login_required
def find_clips():
    if request.method == 'POST':
        subreddit_name = request.form.get('subreddit', '')
        titles = request.form.get('titles', '').splitlines()
        time_period = request.form.get('time_period', 'all')

        results = []

        for title in titles:
            search_results = reddit.subreddit(subreddit_name).search(title, time_filter=time_period)
            for post in search_results:
                if post.title.lower() == title.lower() and is_video_post(post):
                    results.append(f"https://www.reddit.com{post.permalink}")
                    break

        return render_template('clips_result.html', results=results)
    return render_template('find_clips.html')

@app.route('/view_history')
@login_required
def view_history():
    if 'episode_id' not in session:
        flash('Please select an episode to work on.', 'warning')
        return redirect(url_for('episodes'))
    
    episode_id = session['episode_id']
    episode = Episode.query.get_or_404(episode_id)
    search_history = load_history()  # Load the latest search history
    filtered_history = [entry for entry in search_history if entry.episode_id == episode_id]
    sorted_history = sorted(filtered_history, key=lambda x: datetime.strptime(x.date, '%Y-%m-%d %H:%M:%S'), reverse=True)
    return render_template('view_history.html', search_history=sorted_history, episode=episode)

@app.route('/delete_history/<uuid:history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    global _history
    _history = [entry for entry in _history if entry.id != str(history_id)]
    save_history()
    return redirect(url_for('view_history'))

@app.route('/copy_links/<uuid:history_id>', methods=['POST'])
@login_required
def copy_links(history_id):
    global _history
    entry = next((entry for entry in _history if entry.id == str(history_id)), None)
    if entry:
        links = "\n".join([link for title, link in entry.results])
        return jsonify({"links": links})
    return jsonify({"links": ""})

@app.route('/credits_generator', methods=['GET', 'POST'])
@login_required
def credits_generator():
    if 'episode_id' not in session:
        flash('Please select an episode to work on.', 'warning')
        return redirect(url_for('episodes'))

    episode_id = session['episode_id']
    episode = Episode.query.get_or_404(episode_id)
    
    usernames = []
    if request.method == 'POST':
        input_text = request.form.get('input_text', '')
        print(f"Received input text: {input_text}")  # Debug statement
        clip_names = extract_clip_names(input_text)
        print(f"Extracted clip names: {clip_names}")  # Debug statement
        usernames = generate_credits(clip_names)
        print(f"Generated usernames: {usernames}")  # Debug statement
    
    return render_template('credits_generator.html', usernames=usernames, episode=episode)

def extract_clip_names(input_text):
    lines = input_text.split('\n')
    clip_names = []
    for line in lines:
        if '* FROM CLIP NAME:' in line:
            clip_name = line.split('* FROM CLIP NAME:')[-1].strip().replace('.mp4', '')
            clip_name = clean_text(clip_name)  # Clean the clip name
            clip_names.append(clip_name)
    return clip_names

def generate_credits(clip_names):
    matching_usernames = []
    for clip_name in clip_names:
        found_usernames = find_usernames_for_clip(clip_name)
        matching_usernames.append(found_usernames[0] if found_usernames else 'No match')
    return matching_usernames

def find_usernames_for_clip(clip_name):
    matched_usernames = []
    for entry in _history:
        for title, link in entry.results:
            cleaned_title = clean_text(title)  # Clean the title
            if clip_name.lower() in cleaned_title.lower():  # Case-insensitive match
                usernames = extract_usernames_from_link(link)
                if usernames:
                    matched_usernames.extend(usernames)
    return matched_usernames

def extract_usernames_from_link(link):
    try:
        submission_id = link.split('/')[-3]
        submission = reddit.submission(submission_id)
        username = submission.author.name if submission.author else None
        return [username] if username else []
    except Exception as e:
        print(f"Error extracting username from link {link}: {e}")
        return []

def clean_text(text):
    # Remove special characters and normalize
    text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
    text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')
    return text.strip()

@app.route('/matching_tool')
@login_required
def matching_tool():
    if 'episode_id' not in session:
        flash('Please select an episode to work on.', 'warning')
        return redirect(url_for('episodes'))

    episode_id = session['episode_id']
    current_searches = [search for search in _history if search.episode_id == episode_id]
    current_links = [link for search in current_searches for title, link in search.results]
    
    matching_links = find_matching_links(current_links, episode_id)
    
    # Calculate percentage of matches
    unique_current_links = set(current_links)
    total_clips = len(unique_current_links)
    unique_matched_links = set(link for title, link, episode_id in matching_links)
    matched_clips = len(unique_matched_links)
    
    match_percentage = (matched_clips / total_clips) * 100 if total_clips > 0 else 0

    # Get episode names
    episode_names = get_episode_names()

    # Filter out any matches with invalid episode IDs
    valid_matching_links = [(title, link, episode_id) for title, link, episode_id in matching_links if episode_id in episode_names]

    if not valid_matching_links and matching_links:
        flash('Some matches were found, but the episodes they belong to no longer exist.', 'warning')

    matching_links_with_names = [(title, link, episode_names[episode_id]) for title, link, episode_id in valid_matching_links]

    return render_template('matching_tool.html', matching_links=matching_links_with_names, matched_clips=matched_clips, total_clips=total_clips, match_percentage=match_percentage)

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/activities')
@admin_required
def admin_activities():
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('admin_activities.html', activities=activities)

@app.route('/approve_user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.approve()
    flash(f'User {user.username} has been approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/decline_user/<int:user_id>', methods=['POST'])
@admin_required
def decline_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.approved:
        flash('Cannot decline an approved user.', 'warning')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been declined and removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/make_admin/<int:user_id>', methods=['POST'])
@admin_required
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.make_admin()
    flash(f'User {user.username} is now an admin.', 'success')
    return redirect(url_for('admin_dashboard'))

async def fetch_data(links):
    semaphore = asyncio.Semaphore(100)  # Set the concurrency limit
    tasks = []

    async with semaphore:
        # Create tasks to fetch data for each link concurrently
        for link in links:
            task = asyncio.create_task(extract_data_from_link(link.strip()))
            tasks.append(task)

        # Wait for all tasks to complete
        return await asyncio.gather(*tasks, return_exceptions=True)

async def extract_data_from_link(link):
    # Check if data is present in the cache
    if await cache.exists(link):
        return await cache.get(link)

    # Extract the original poster's username from Reddit comment link
    submission_id = link.split('/')[-3]
    submission = await asyncio.get_event_loop().run_in_executor(None, reddit.submission, submission_id)

    username = submission.author.name if submission.author else None

    result = {
        'link': link,
        'username': username
    }

    # Store the result in the cache
    await cache.set(link, result, ttl=60)  # Adjust the TTL (time to live) value as needed

    return result

if __name__ == '__main__':
    app.run(debug=True)

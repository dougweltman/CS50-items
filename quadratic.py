from cs50 import SQL
from flask import Flask, render_template, redirect, request, redirect, make_response, session, url_for, get_flashed_messages
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from time import mktime, gmtime

from helpers import apology, login_required, dh_to_ts, dhm_from_now, time_now, cookie_mix, generate_poll_key

app = Flask(__name__)


# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///polling.db")

# Set site URL
SITE_URL = ""

# Set the timestamp format used by SQLite database
timestamp_format = "%Y-%m-%d %H:%M:%S"

@app.route('/about')
def about():
    return render_template("about.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route('/register', methods = ["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("/register.html")
    else:
        if not request.form.get("email-address"):
            return apology("You must provide a username or email address.", 403)
        elif not request.form.get("password"):
            return apology("You must provide a password.", 403)
        elif not request.form.get("confirmation"):
            return apology("You must confirm your password.", 403)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Your password confirmation does not match your password.", 403)
        elif len(db.execute("SELECT email FROM users WHERE email = :email", email = request.form.get("email-address"))) == 1:
            # TODO: This should redirect to the login page and flash a message.
            return apology("Sorry, this username already exists. Try logging in.", 403)
        else:
            hashed_pw = generate_password_hash(request.form.get("password"))
            n = db.execute("INSERT INTO users (email, hashed_pw) VALUES (:email, :hashed_pw)", email=request.form.get("email-address"), hashed_pw=hashed_pw)
            if n is not None:
                resp = redirect(url_for("index"), code=303)
                return resp
            else:
                return redirect("/register", code=303)

@app.route('/login', methods = ["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        print("Method: POST")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = :username",
                          username=request.form.get("username"))
        print("Rows: ", rows)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hashed_pw"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route('/')
def index():
    # See if user is logged in.
    try:
        if session["user_id"]:
            toggle = True
    except:
            toggle = False
    
    # If user is logged in, take them to available_polls.
    if toggle:
        resp = redirect(url_for("available_polls"),code=303)
        return resp
    # If user isn't logged in, show them public polls they can take.
    else:
        #NEED TO DO THIS. POSSIBLY JUST REDIRECT TO /AVAILABLE_POLLS AND IMPROVE THAT PAGE FOR USERS NOT SIGNED IN. Todo.
        resp = redirect(url_for("available_polls"),code=303)
        return resp

@app.route('/setup', methods = ["GET", "POST"])
@login_required
def setup():
    error = None
    if (request.method == "GET"):
        return render_template("/setup.html")
    else:
        if not session["user_id"]:
            print("not logged in")
        else: print("user_id: ", session["user_id"])

        title_list = "poll_name", "poll_description", "organizer_name", "organizer_url", \
        "opt1", "opt2", "opt3", "opt4", "opt5", "opt6", "opt7", "opt8", "opt9", "opt10", "opt11", \
        "opt12", "tokens", "end_time", "featured"


        poll_title_list = ["poll_name", "poll_description", "organizer_name", "organizer_url", "tokens", "end_time", "featured"]
        poll_option_list = ["opt1", "opt2", "opt3", "opt4", "opt5", "opt6", "opt7", "opt8", "opt9", "opt10", "opt11", "opt12"]
        poll_inputs = {}
        option_inputs = []

        poll_inputs["poll_name"] = request.form.get("poll_name")
        poll_inputs["poll_description"] = request.form.get("poll_description")
        poll_inputs["organizer_name"] = request.form.get("organizer_name")
        poll_inputs["organizer_url"] = request.form.get("organizer_url")
        poll_inputs["tokens"] = request.form.get("tokens")
        
        if request.form.get("featured") == "on":
            poll_inputs["featured"] = 1
        else:
            poll_inputs["featured"] = 0
        
        try:
            end_days = request.form.get("end_time_days")
            end_hrs = request.form.get("end_time_hours")
            if end_days.isnumeric(): end_days = int(end_days)
            else: end_days = int(0)
            if end_hrs.isnumeric(): end_hrs = int(end_hrs)
            else: end_hrs = int(0)
            print(type(end_days), end_days, type(end_hrs), end_hrs)
            end = dh_to_ts(end_days, end_hrs, 0)
            poll_inputs["end_time"] = end
        except:
            return apology("Error accepting poll's end date.", 403)

        url_slug = generate_poll_key()

        # Load the contents corresponding to poll_option_list into poll_inputs
        for item in poll_option_list:
            poll_content = request.form.get(item)
            if poll_content == "":
                poll_content = None
            # To deal with blank entries, we skip writing them into option_inputs[].
            if poll_content is None:
                continue
            else:
                option_inputs.append(poll_content)
            
        print(option_inputs)
        print(poll_inputs)

        for i in range(len(option_inputs),12):
            option_inputs.append(None)
        
        print(option_inputs)
        
        if (
            poll_inputs["poll_name"] == None or 
            poll_inputs["organizer_name"] == None or 
            option_inputs[0] == None or 
            option_inputs[1] == None or 
            poll_inputs["tokens"] == None or 
            poll_inputs["end_time"] == None
            ):
                error = "Poll is missing some inputs."
                return redirect("/setup")
                #return render_template("setup.html", error, poll_inputs)
        else:
            # convert empty strings to None in poll_inputs{}
            #db.execute("INSERT INTO users (email, hashed_pw) VALUES (:email, :hashed_pw)", email=request.form.get("email-address"), hashed_pw=hashed_pw)
            id = db.execute("""INSERT INTO polls
            (user_id, option1, option2, option3, option4, option5,
            option6, option7, option8, option9, option10, option11, option12,
            featured, time_end, tokens_allocated, poll_title, poll_description,
            creator_display_name, creator_display_url, url_slug)
            VALUES (:user_id, :option1, :option2, :option3, :option4, :option5,
            :option6, :option7, :option8, :option9, :option10, :option11, :option12,
            :featured, :time_end, :tokens_allocated, :poll_title, :poll_description,
            :creator_display_name, :creator_display_url, :url_slug)""",\
            user_id = session["user_id"], \
            option1 = option_inputs[0], \
            option2 = option_inputs[1], \
            option3 = option_inputs[2], \
            option4 = option_inputs[3], \
            option5 = option_inputs[4], \
            option6 = option_inputs[5], \
            option7 = option_inputs[6], \
            option8 = option_inputs[7], \
            option9 = option_inputs[8], \
            option10 = option_inputs[9], \
            option11 = option_inputs[10], \
            option12 = option_inputs[11], \
            featured = poll_inputs["featured"],\
            time_end = poll_inputs["end_time"],\
            tokens_allocated = poll_inputs["tokens"],\
            poll_title = poll_inputs["poll_name"],\
            poll_description = poll_inputs["poll_description"],\
            creator_display_name = poll_inputs["organizer_name"],\
            creator_display_url = poll_inputs["organizer_url"],\
            url_slug = url_slug)

            print(id)

            # Ensure slug table includes new poll.
            db.execute("""INSERT INTO slugs
            (slug, poll_id) VALUES (:url_slug, :poll_id)""",
            url_slug = url_slug, poll_id = id)

            resp = redirect(url_for("setup_complete", url_slug = url_slug), code=303)
            return resp
            # resp = make_response(render_template("setup-complete.html", poll_url = SITE_URL + "/vote/" + str(id), end_time = poll_inputs["end_time"]), 303)
            #return resp
            
            #return redirect("setup_complete/"+str(id), code = 303)
        
@app.route('/vote/<url_slug>', methods=["GET", "POST"])
def vote(url_slug):
#need a way to ID this poll.
#variable poll_id will be an integer
    
    poll_id = slug_to_poll_id(url_slug)
    # Step 1: ensure user has not completed poll already.
    
    #Get info on the poll.
    respondents = db.execute("SELECT cookie, user_id FROM responses WHERE poll_id = :poll_id", poll_id = poll_id)
    print(respondents)
    # See if there's a cookie or other identifier.
    try:
        client_cookie = request.cookies.get("R-ID")
        print("1: Client cookie: ", client_cookie, type(client_cookie), repr(client_cookie))
    except:
        client_cookie = None
    print("2: Client cookie: ", client_cookie)

    try:
        user_id = session["user_id"]
    except:
        user_id = None
    print("User_ID: ", user_id)

    if (client_cookie != None or user_id != None):
        repeat_visitor = False
    else:
        repeat_visitor = True


    # If both are None, move ahead.
    # If either has a value, check those values.

    if ((client_cookie is not None) or (user_id is not None)):
        for n in range(len(respondents)):
            print(respondents[n]["cookie"])
            if user_id is not None:
                if user_id == respondents[n]["user_id"]:
                    # Set a cookie to prevent user from logging out and trying again.
                    resp = make_response("You cannot submit multiple ballots for the same poll. C")
                    if client_cookie is None:
                        cookie_contents = cookie_mix()
                        print("Cookie contents: ", cookie_contents)
                        resp.set_cookie("R-ID", cookie_contents, max_age = 180*60*60*24)
                        # Write cookie to user's earlier response so we can ID the user w/ a cookie as well as a user_id.
                        db.execute("INSERT INTO responses VALUE cookie = :cookie", cookie = cookie_contents)
                    return resp

                #This case seems weird, but possible. it means they weren't logged in on an earlier response but are logged in now. We should probably log the user ID as well. Todo
                elif respondents[n]["cookie"] == client_cookie:
                    resp = make_response("You cannot submit multiple ballots for the same poll. C & ID.")
                    return resp
            
            # This covers where we have a value for a cookie and NOT one for a user_id.
            else:
                if client_cookie == respondents[n]["cookie"]:
                    resp = make_response("You cannot submit multiple ballots for the same poll. C.")
                    return resp
    

    #Step 2: set up options.
    poll_params = db.execute("SELECT * FROM polls WHERE url_slug = :url_slug", url_slug = url_slug)
    options = poll_params[0]["option1"], poll_params[0]["option2"], poll_params[0]["option3"], poll_params[0]["option4"], poll_params[0]["option5"], poll_params[0]["option6"], poll_params[0]["option7"], poll_params[0]["option8"], poll_params[0]["option9"], poll_params[0]["option10"], poll_params[0]["option11"], poll_params[0]["option12"]
    print("POLL_PARAMS: ", poll_params)
    print("OPTIONS: ", options)

    if (request.method == "GET"):
        dhm_list = dhm_from_now(poll_params[0]["time_end"])
        
        # If user is trying to view an expired poll, send them to index.
        if dhm_list == None:
            return render_template("/available_polls")
        
        else:
            return render_template("vote.html", options = options, url_slug = poll_params[0]["url_slug"], tokens = poll_params[0]["tokens_allocated"],\
            end_date = dhm_list, title = poll_params[0]["poll_title"], description = poll_params[0]["poll_description"], \
            creator = poll_params[0]["creator_display_name"], creator_url = poll_params[0]["creator_display_URL"], repeat_visitor = repeat_visitor)
    else:
        # Store responses in a list.
        responses = []
        tokens_used = 0

        # Extract responses from options.
        for i in range(len(options)):
            choice = request.form.get("opt"+str(i+1))
            if choice is not None:
                if choice == "":
                    choice = None # Record blank responses as NULL. This is because otherwise it complicates how we count the results when it's time to tabulate, as we want to show both votes cast and number of respondents in favor, the latter's query using count()
                else:
                    choice = int(choice)
            responses.append(choice)
            print("options[i]: ", options[i])
            print("responses[i]: ", responses[i])
        
        # Step 3: error detection: what if an invalid number of ballots was submitted?
        # 3.1: calculate how much the ballots should have cost in terms of tokens.
        total_votes_cast = 0
        for response in responses:
            if response is not None:
                response = int(response)
                tokens_used += response**2
                total_votes_cast += response
        print("Total_votes_cast: ", total_votes_cast)
        # No need to set their cookies here because their responses were not recorded.
        if tokens_used > poll_params[0]["tokens_allocated"]:
            return apology("You submitted an invalid number of votes.", 403)
        elif tokens_used == 0:
            return apology("You submitted a blank ballot.", 403)
        
        
        # If the number of tokens used was valid, set a cookie and add the ballot to db.
        if client_cookie is None:
            client_cookie = cookie_mix()
            print("client_cookie: ", client_cookie)

        status = db.execute("INSERT INTO responses (poll_id, cookie, response1, response2, response3, response4, response5, response6, response7, response8, response9, response10, response11, response12, user_id) VALUES (:poll_id, :cookie, :response1, :response2, :response3, :response4, :response5, :response6, :response7, :response8, :response9, :response10, :response11, :response12, :user_id)",\
            poll_id = poll_params[0]["id"],\
            cookie = client_cookie,\
            response1 = responses[0],\
            response2 = responses[1],\
            response3 = responses[2],\
            response4 = responses[3],\
            response5 = responses[4],\
            response6 = responses[5],\
            response7 = responses[6],\
            response8 = responses[7],\
            response9 = responses[8],\
            response10 = responses[9],\
            response11 = responses[10],\
            response12 = responses[11],\
            user_id = user_id)

        # If submission is successful, prepare a completion page where user has option of sharing their response.
        # Consider creating a new 2D array to hold prompts & their responses
        
        response_matrix = []
        c = 0

        # take options and responses. if the option value is not None, then add it and the number of responses to response_matrix[][].
        # response_matrix[n][0] is the set of prompts. r_m[n][1] is the set of votes cast for each corresponding prompt n.

        for option in options:
            if option is not None:
                #Change all null votes to zero for reporting purposes.
                if responses[c] == None:
                    responses[c] == 0
                response_matrix.append([option, responses[c]])
                c += 1
        
        # Create ballot_id from response_id.
        ballot_id = "b"+generate_poll_key()

        # Create record of new ballot_id and response_id.
        db.execute("""
        INSERT INTO ballot_ids
        (response_id, ballot_id)
        VALUES (:response_id, :ballot_id)""",
        response_id = status, ballot_id = ballot_id)

        print("attempting redirects...")
        resp = redirect(url_for("ballot_overview", ballot_id = ballot_id), code=303)
        print("redirect object created:", repr(resp))
        resp.set_cookie("R-ID", client_cookie)
        print("Cookie set. About to return. Object: ", repr(resp))
        return resp


@app.route('/available_polls')
def available_polls():
    try:
        if session["user_id"]:
            toggle = True
        #    user_id = session["user_id"]
    except:
        toggle = False

    #try:
    #    if request.cookies.get("R-ID"):
    #        cookie = request.cookies.get("R-ID")
    #except:
    #    cookie = "gibberish" #Need a value for cookie that wouldn't be seen in the wild, so "None" might create problems.

    if toggle: # i.e., if user is logged in.
        user_id = session["user_id"]
        cookie = request.cookies.get("R-ID")
        # If logged in, get all public polls that are still ongoing that the user has not yet completed.
        # NOTE: This query uses the polls.user_id and responses.cookie to surface polls that the user has completed or has created.
        # Currently, this system excludes polls that have no responses yet (i.e., no queryable entries on the "responses" table)
        # Because these are polls the user can take, we need to ensure we're excluding polls the user has created, and ones he's taken.
        ongoing = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug
            FROM polls
            LEFT OUTER JOIN responses ON polls.id = responses.poll_id
            WHERE polls.time_end > datetime("now", "UTC") AND polls.featured = 1 AND (polls.user_id != :user_id AND responses.cookie != :cookie)
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            """, user_id = user_id, cookie = cookie)
        for item in ongoing:
        # Will need to make sure we're excluding polls the user has already completed. Come back to this. 
        #    if (item["cookie"] == cookie or item["user_id"] == user_id):
        #        onoing.pop(item)
            item["sharing_url"] = SITE_URL + "/vote/" + str(item["url_slug"])

        # Next, get all completed poll results for public polls the user *has* completed.
        # To show polls user has completed, include cookie condition here.
        completed_by_user = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id) 
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end < datetime("now", "UTC") AND featured = 1 AND (responses.user_id = :user_id OR responses.cookie = :cookie)
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            """, user_id = user_id, cookie = cookie)
        for item in completed_by_user:
            item["sharing_url"] = SITE_URL + "/result-details/" + str(item["url_slug"])

        # Finally, what are the completed poll results for public polls the user *hasn't* completed, but might be interested in?
        completed_in_general = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id) 
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end < datetime("now", "UTC") AND featured = 1 AND responses.user_id != :user_id
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            LIMIT 10
            """, user_id = user_id)
        for item in completed_in_general:
            item["sharing_url"] = SITE_URL + "/result-details/" + str(item["url_slug"])

        # Actually, let's make this the user's index page if they're logged in. They can also see the polls they've created, ongoing or completed.
        users_completed_polls = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id) 
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end < datetime("now", "UTC") AND polls.user_id = :user_id
            GROUP BY poll_id
            ORDER BY time_end DESC
            """, user_id = user_id)
        for item in users_completed_polls:
            item["sharing_url"] = SITE_URL + "/result-details/" + str(item["url_slug"])
        
        users_ongoing_polls = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id) 
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end > datetime("now", "UTC") AND polls.user_id = :user_id
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            """, user_id = user_id)
        for item in users_ongoing_polls:
            item["sharing_url"] = SITE_URL + "/vote/" + str(item["url_slug"])
        
        for i in range(len(ongoing)):
        # Use DHM list to generate string of time remaining in the poll.
            dhm_list = dhm_from_now(ongoing[i]["time_end"])
            if dhm_list[0] >= 1:
                ongoing[i]["time_remaining"] = str(dhm_list[0]) + " day(s) left"
            elif dhm_list[1] >= 1:
                ongoing[i]["time_remaining"] = str(dhm_list[1]) + " hour(s) left"
            else:
                ongoing[i]["time_remaining"] =  str(dhm_list[2]) + " minute(s) left"


        for i in range(len(users_ongoing_polls)):
        # Use DHM list to generate string of time remaining in the poll.
            dhm_list = dhm_from_now(users_ongoing_polls[i]["time_end"])
            if dhm_list[0] >= 1:
                users_ongoing_polls[i]["time_remaining"] = str(dhm_list[0]) + " day(s) left"
            elif dhm_list[1] >= 1:
                users_ongoing_polls[i]["time_remaining"] = str(dhm_list[1]) + " hour(s) left"
            else:
                users_ongoing_polls[i]["time_remaining"] =  str(dhm_list[2]) + " minute(s) left"
        
        # Let's perform a few checks here:
        print("\n__ongoing[]__:", ongoing)
        print("\n__completed_by_user[]__:", completed_by_user)
        print("\n__completed_in_general[]__:", completed_in_general)
        print("\n__users_completed_polls[]__:", users_completed_polls)
        print("\n__users_ongoing_polls[]__:", users_ongoing_polls)
        
        return render_template("available_polls.html", ongoing = ongoing, completed_by_user = completed_by_user, completed_in_general = completed_in_general, users_completed_polls = users_completed_polls, users_ongoing_polls = users_ongoing_polls)

    else:
        # If not logged in, get public polls that are still ongoing that do not match the user's cookie.
        cookie = request.cookies.get("R-ID")
        ongoing = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id)  
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end > datetime("now", "UTC") AND featured = 1 AND responses.cookie != :cookie
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            """, cookie = cookie)
        for item in ongoing:
            item["sharing_url"] = SITE_URL + "/vote/" + str(item["url_slug"])

        # Next, get all completed poll results for public polls the user *has* completed.
        completed_by_user = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id)  
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end < datetime("now", "UTC") AND featured = 1 AND responses.cookie = :cookie
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            """, cookie = cookie)
        for item in completed_by_user:
            item["sharing_url"] = SITE_URL + "/result-details/" + str(item["url_slug"])

        # What are the completed poll results for public polls the user *hasn't* completed, but might be interested in?
        completed_in_general = db.execute("""
            SELECT polls.id, poll_title, time_created, time_end, creator_display_name, url_slug, count(responses.response_id)  
            FROM polls JOIN responses ON polls.id = responses.poll_id
            WHERE time_end < datetime("now", "UTC") AND featured = 1 AND responses.cookie != :cookie
            GROUP BY poll_id
            ORDER BY count(responses.response_id) DESC
            LIMIT 10
            """, cookie = cookie)
        for item in completed_in_general:
            item["sharing_url"] = SITE_URL + "/result-details/" + str(item["url_slug"])

        
        for i in range(len(ongoing)):
            # Use DHM list to generate string of time remaining in the poll.
            dhm_list = dhm_from_now(ongoing[i]["time_end"])
            print(dhm_list)
            try:
                if dhm_list[0] >= 1:
                    ongoing[i]["time_remaining"] = str(dhm_list[0]) + " day(s) left"
                elif dhm_list[1] >= 1:
                    ongoing[i]["time_remaining"] = str(dhm_list[1]) + " hour(s) left"
                else:
                    ongoing[i]["time_remaining"] =  str(dhm_list[2]) + " minute(s) left"
                # dhm_list may be blank so the above may throw an error.
            except:
                continue


        
        return render_template("available_polls.html", ongoing = ongoing, completed_by_user = completed_by_user, completed_in_general = completed_in_general)

@app.route('/result-details/<url_slug>')
def result_details(url_slug):
# When a user clicks a completed poll (e.g., on index or available_polls), they can view the results page.
# First, get the basic details of the poll (not the options or response counts yet)
    poll_id = slug_to_poll_id(url_slug)
    
    poll_details_dict = db.execute("""
    SELECT
            polls.user_id,
            poll_title,
            poll_description,
            creator_display_name,
            creator_display_url,
            time_end,
            time_created,
            tokens_allocated,
            featured,
            url_slug,
            count(responses.response_id)
            FROM polls LEFT JOIN responses ON polls.id = responses.poll_id
            WHERE polls.id = :poll_id
            """, poll_id = poll_id)
    print(poll_details_dict)
    if not session:
        print("User is not signed in.")
        if poll_details_dict[0]["featured"] != 1:
            return apology("You do not have permission to access this poll. Try logging in.", 403)
    elif session["user_id"] != poll_details_dict[0]["user_id"]:
        print(poll_details_dict[0]["user_id"])
        if poll_details_dict[0]["featured"] != 1:
            print("Unauthorized attempt to access poll #"+str(poll_details_dict[0]["poll_title"]+"."))
            return apology("You do not have permission to access this poll.", 403)
    # Commented out until I can  improve the date/time handling between py and sql.
    # elif poll_details_dict[0]["time_end"] > datetime.now():
    #    return apology("Poll is still in progress.", 403)
    
    else:
    # Now that we've a) gotten the basic poll data, and b) addressed unauthorized access, we do two queries: the options, and the response tallies.
        poll_options_dict = db.execute("""
            SELECT option1, option2, option3, option4, option5, option6, option7, option8, option9, option10, option11, option12
            FROM polls
            WHERE id = :poll_id
            """, poll_id = poll_id)
        print(poll_options_dict)
        poll_responses_dict = db.execute("""
            SELECT sum(response1), sum(response2), sum(response3), sum(response4), sum(response5), sum(response6), sum(response7), sum(response8), sum(response9), sum(response10), sum(response11), sum(response12)
            FROM responses
            WHERE poll_id = :poll_id
            """, poll_id = poll_id)
        print(poll_responses_dict)
        poll_response_count_dict = db.execute("""
            SELECT count(response1), count(response2), count(response3), count(response4), count(response5), count(response6), count(response7), count(response8), count(response9), count(response10), count(response11), count(response12)
            FROM responses
            WHERE poll_id = :poll_id
            """, poll_id = poll_id)
        print(poll_response_count_dict)

        
        # This seems a very cumbersome and verbose way to do it, but it should work.
        poll_options_list = []
        for i in range(len(poll_options_dict[0])):
            s = "option" + str(i+1)
            #poll_responses_dict[0][s]
            if poll_options_dict[0][s] is not None:
                t = "sum(response" + str(i+1) + ")"
                u = "count(response" + str(i+1) + ")"
                poll_options_list.append([poll_options_dict[0][s], poll_responses_dict[0][t], poll_response_count_dict[0][u]])
        
        print("POLL OPTIONS LIST: ", poll_options_list)

        return render_template("result-details.html", poll_details_dict = poll_details_dict, poll_options_list = poll_options_list)

@app.route('/setup-complete/<url_slug>')
def setup_complete(url_slug):
    poll_id = slug_to_poll_id(url_slug)

    row = db.execute("SELECT time_end FROM polls WHERE id = :poll_id", poll_id = poll_id)
    print(row)
    end_time = row[0]["time_end"]
    poll_url = SITE_URL + "/vote/" + url_slug
    resp = make_response(render_template("setup-complete.html", poll_url = poll_url, end_time = end_time))
    return resp

@app.route("/ballot_overview/<ballot_id>")
def ballot_overview(ballot_id):
    response_id = ballot_id_to_response_id(ballot_id)
    ballot_url = SITE_URL + "/ballot_overview/" + ballot_id
    print("Share ballot fires. Response_id:", response_id)
    rows = db.execute("SELECT polls.*, responses.* FROM polls INNER JOIN responses ON polls.id = responses.poll_id WHERE response_id = :response_id", response_id = response_id)
    row = rows[0]
    # 1: PULL TOGETHER POLL_PARAMS
    keys = ["poll_title", "poll_description", "creator_display_URL", "creator_display_name", "time_created", "time_end", "tokens_allocated", "timestamp_created"]
    poll_params = {x:row[x] for x in keys}
    print("poll_params: ", poll_params)


    # 2: PULL TOGETHER RESPONSE MATRIX.
    response_matrix = []
    # 2.1: Begin by getting the options. If null, we're done.
    for i in range(1,12):
        if row["option"+str(i)] == None:
            continue
        else:
            if row["response"+str(i)] == None:
                row["response"+str(i)] = 0
            response_matrix.append([row["option"+str(i)], row["response"+str(i)]])
    
    print("response_matrix: ", response_matrix)
    
    # 3: CALCULATE TOKENS_USED AND TOTAL_VOTES_CAST
    tokens_used = 0
    total_votes_cast = 0
    for item in response_matrix:
        tokens_used += item[1]**2
        total_votes_cast += item[1]
    print("tokens_used: ", tokens_used, "total_votes_cast: ", total_votes_cast)
    # 4: FINISH.
    resp = make_response(render_template("ballot-overview.html", poll_params = poll_params, tokens_used = tokens_used, response_matrix = response_matrix, total_votes_cast = total_votes_cast, ballot_url = ballot_url))
    return resp

# There should be only one poll id for a key.
def slug_to_poll_id(slug):
    row = db.execute("""
        SELECT poll_id
        FROM slugs
        WHERE slug = :slug
        """, slug = slug)
    return row[0]["poll_id"]

def ballot_id_to_response_id(ballot_id):
    row = db.execute("""
    SELECT response_id
    FROM ballot_ids
    WHERE ballot_id = :ballot_id
    """, ballot_id = ballot_id)
    print(row)
    return row[0]["response_id"]

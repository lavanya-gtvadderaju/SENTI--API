# for authentication & authorization
import jwt
import joblib
from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity,create_refresh_token,set_refresh_cookies,unset_jwt_cookies
from jwt import DecodeError

from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from flask import flash
from datetime import datetime, timedelta
from jwt.exceptions import ExpiredSignatureError
from flask_jwt_extended import get_jwt

import pandas as pd
import nltk
import re
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import CountVectorizer

# Initialize the WordNetLemmatizer
df = pd.read_csv('data/preprocessed_data.csv')
#creating application & initialization flask
app = Flask(__name__)



# Download the stopwords corpus (only need to do this once)


# Get the set of English stopwords

lemmatizer = WordNetLemmatizer()
# Count Vectorization
count_vectorizer = CountVectorizer(max_features=5000)
count_fit_matrix = count_vectorizer.fit_transform(df['selected_text'].tolist())
svm_model = joblib.load("models/svm_model_count.pkl")


#mysql config
app.config['SECRET_KEY'] = 'wg4evfdg54ervge45grbtyhtr4'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Avani@123'
app.config['MYSQL_DB'] = 'senti_db'

#jwt config
app.config['JWT_SECRET_KEY'] = '8gyufbiejwk09jio3nfeh'
#specifing  where the JWTs will be expected & jwt stored in cookies
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
#paths to the access and refresh JWT cookies availbilty.  ()'/') - cookies will be accessible across all routes and paths.
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
#disabling CSRF protection for JWT tokens
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
#specifing  name of the access token cookie -'access_token'
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)


#nitializing MySQL-to perform database operations-executing queries, retrieving data, and modifying records
mysql = MySQL(app)
#handling the configuration and operation of JWTs
jwt = JWTManager(app)

#data structure for a user entity -to store and manipulate user-related data
# User model
class User:
    def __init__(self, user_id, email, password, fullname):
        self.fullname = fullname
        self.user_id = user_id
        self.email = email
        self.password = password

STOP_WORDS = set(stopwords.words('english'))
def remove_stop_word_func(input_text):
    #Remove urls
    if isinstance(input_text, str):
        text =  re.sub(r'http\S+', '', input_text)
    else:
        text =  input_text
    # Handle mentions (@usernames)
    if isinstance(text, str):
        text= re.sub(r'@\w+', '', text)

    # Handle hashtags
    if isinstance(text, str):
         text= re.sub(r'#\w+', '', text)

    # Handle emoticons (need to add more emoticons as needed)
    if isinstance(text, str):
        # For example, handling :) and :(
        text = re.sub(r':\)', ' happy ', text)
        text = re.sub(r':\(', ' sad ', text)
    # Step 6: Remove special characters and punctuation
    if isinstance(text, str):
        text= re.sub(r'[^\w\s]', '', text)
    # Step 7: Tokenize the text and selected_text columns
    if isinstance(text, str):
        words = word_tokenize(text)

    # Filter out the stopwords from the words
    filtered_words = [word for word in words if word.lower() not in STOP_WORDS]

    # Join the filtered words back into a sentence
    filtered_sentence = " ".join(filtered_words)
    
    return filtered_sentence

def lemmatize_text_func(input_text):
    words = nltk.word_tokenize(input_text)

    # Lemmatize each word in the sentence
    lemmatized_words = [lemmatizer.lemmatize(word) for word in words]
    
    return lemmatized_words


def count_vectorization_func(input_text):
    count_matrix = count_vectorizer.transform(input_text)
    print(count_matrix.shape)
    return count_matrix

def predict_func(count_matrix):
    prediction = svm_model.predict(count_matrix)
    return prediction
    

# associating ' /protected' URL path with the protected_route() function
@app.route('/protected')
# ensuring a valid JWT is present
@jwt_required()
def protected_route():
     
    current_user = get_jwt_identity()

    current_time = datetime.utcnow()
#  retrieving the expiration time ('exp') claim from the JWT
    if current_time > get_jwt().get('exp'):
        # Token has expired, generate a new access token and set it as a cookie
        refresh_token = create_refresh_token(identity=current_user)
        response = redirect(url_for('protected_route'))
        set_refresh_cookies(response, refresh_token)
        return response

    return jsonify(message='You are accessing a protected route', user=current_user), 200



@app.route('/')
@jwt_required(optional=True)
def index():
    #retrieving the value of the 'access_token' cookie from the request made to the '/' route
    access_token = request.cookies.get('access_token')
    current_user = None
    
# checking existence of access token value -  access_token' cookie is present in the request
    if access_token:
       # try-except block to handle potential exceptions
        try:
            #retrieving  user identity  from the current valid JWT 
            user_id = get_jwt_identity()
            #creating  cursor object for interaction & connection to the database 
            cur = mysql.connection.cursor()
            #executing a SQL query to select all columns (*) from the 'users' table where the 'user_id' column matches the user_id value
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            #fetching the result 
            user_data = cur.fetchone()
            #closing the cursor to release the database resources.
            cur.close()


#checking if user_data exists
            if user_data:
                # creating new User object using the retrieved user_data

                current_user = User(user_data[0], user_data[1], user_data[2], user_data[3])
        #exceptional handling when jwt has expired sign
        except ExpiredSignatureError:
            # Refresh the token
            refresh_token = create_refresh_token(identity=user_id)
            response = redirect(url_for('index'))
            set_refresh_cookies(response, refresh_token)
            return response
        except Exception:
            # Handle other exceptions if needed
            pass

    cur = mysql.connection.cursor()
    cur.execute("SELECT sentence_id, content FROM sentences")
    #fetching all the rows and storing in 'sentences'
    sentences = cur.fetchall()
    cur.close()
    #rendering the 'index.html' template
    data={'title':'SentiAI | Home'}
    return render_template('index.html', sentences=sentences, access_token=access_token, current_user=current_user,data=data)


#  handling the signup process for new users.
# associating it with the '/signup' URL path & specifing that the function should handle both GET and POST
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # checking if the current request is a POST
    if request.method == 'POST':
        #extracting  input values by the user in the signup form. 
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        print(fullname, email, password)
        #hashing the user input password
        hashed_password = generate_password_hash(password)
        #connection creation for interacting with data base
        cur = mysql.connection.cursor()
        #inserting  new row into the 'users' table
        cur.execute("INSERT INTO users (email, password, fullname) VALUES (%s, %s, %s)", (email, hashed_password, fullname))
        #commiting/saving the changes
        mysql.connection.commit()
        #closing the cursor
        cur.close()
        
        data={'title': "Senti | Login"}
        return render_template('login.html', message=f'{email} successfully registered. Please login.',data=data)
    
    data={'title': "Senti | Sign Up"}
    return render_template('signup.html', data=data)

#associating it with the '/login' URL path and to handle both GET and POST HTTP requests to this URL. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    # checking if the current request is a POST
    if request.method == 'POST':
        ##extracting  input values by the user in the login form
        email = request.form.get('email')
        password = request.form.get('password')
 #connection creation for interacting with data base
        cur = mysql.connection.cursor()
         #selecting  all columns  from the 'users' table where the 'email'
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        # fetching & retriving the result set-corresponding user data
        user_data = cur.fetchone()
        #closing the cursor
        cur.close()

        #checking user data existence and matching the hashed password to given password
        if user_data and check_password_hash(user_data[2], password):
            # creating new User object using the retrieved user_data
            user = User(user_data[0], user_data[1], user_data[2],user_data[3])
        #generating  access token -for user identification
            access_token = create_access_token(identity=user.user_id)
        #creating  redirect response to the 'index' route. 
            response = redirect(url_for('index'))
        # Set JWT token as a cookie
            response.set_cookie('access_token', access_token)  
            return response

        return jsonify({'message': 'Invalid email or password'}), 401
    
    data={'title': "Senti | Login"}
    return render_template('login.html',data=data)


@app.route('/logout')
def logout():
    # creating redirect response to the 'index' rout
    response = make_response(redirect(url_for('index')))
    #removing the 'access_token' key from the session dictionary
    session.pop('access_token', None)
    #deleting the 'access_token' cookie
    response.delete_cookie('access_token')
    return response

#  li = list(string.split(" ")

@app.route('/analyze', methods=['GET', 'POST'])        
#CHECKS  user provide a valid JSON Web Token (JWT)
@jwt_required()
def create_sentence():
    data={}
    data = {'title': 'Sentiment Analysis'}
    
    current_user=get_jwt_identity()
    if request.method == 'POST':
        #extract  INPUT values by the user in the sentence creation form
        sentence = request.form['content']
        data["sentence"] = sentence
        lowers = sentence.lower()
        data["lowers"] = lowers
        without_stop_words = remove_stop_word_func(lowers)
        data["without_stop_words"] = without_stop_words

        # Lemmatize each word in the sentence
        lemmatized_words = lemmatize_text_func(without_stop_words) #list
        data["lemmatized_words"] = lemmatized_words
        
        lemmatized_sentence = " ".join(lemmatized_words)
        #call predict function Here
        result = predict_func(count_vectorization_func([sentence]))
        # retrieving the user identity from the current valid JWT
        user_id = get_jwt_identity()
        #connection creation for interacting with data base
        cur = mysql.connection.cursor()
         #inserting  new row into the 'sentences' table
        cur.execute("INSERT INTO sentences (content,lowers,withoutstopword,lemmatized_sentence,sentiment,  user_id) VALUES (%s ,%s, %s,%s, %s, %s)", (sentence, lowers, without_stop_words, lemmatized_sentence, result, user_id))
        mysql.connection.commit()
        sentence_id=cur.lastrowid
        cur.close()

        ###return render_template('index.html', message=f'Sentence created successfully')
        ### return jsonify({'message': 'Sentence created successfully'}), 201
        
        # storing temporary message in the session.
        flash('Sentence analyzed successfully', 'success')
        return render_template('results.html', data=data, current_user =current_user,result=result,result_len=len(result) )
    return render_template('analyze.html', data=data, current_user =current_user)

#associating it with the '/sentence/<sentence_id>' URL path
@app.route('/sentence/<int:sentence_id>', methods=['GET'])
# specifying- user can access  route optionally with a valid JSON Web Token (JWT). 
@jwt_required(optional=True)
def get_sentence(sentence_id):
    data = {'title': 'Sentiment Analysis'}

    # retrieving the user identity from the current valid JWT
    user_id = get_jwt_identity()
     #retrieving the value of the 'access_token' cookie from the request. 
    access_token = request.cookies.get('access_token')
    current_user = None
    if access_token:
        #try-except block to handle potential exceptions
        try:
            #retrieving the user identity  from the current valid JWT 
            user_id = get_jwt_identity()
            cur = mysql.connection.cursor()
            #selecting all columns (*) from the 'users' table where the 'user_id' column matches the provided user_id.
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            # retrieving the result set corresponding to the user data fetched from the database.
            user_data = cur.fetchone()
            cur.close()

                # checking if user_data exists
            if user_data:
                 #creates a new User object using the retrieved user_data
                current_user = User(user_data[0], user_data[1], user_data[2], user_data[3])
        #handling the case when the JWT has an expired signature.
        except ExpiredSignatureError:
            # Refresh the token
            refresh_token = create_refresh_token(identity=user_id)
            response = redirect(url_for('index',data=data))
            set_refresh_cookies(response, refresh_token)
            return response
        except Exception:
            # Handle other exceptions if needed
            pass
    #checking if the current request is a GET request
    if request.method == 'GET':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM sentences WHERE sentence_id = %s", (sentence_id,))
        sentence = cur.fetchone()
        cur.close()
            #finding a matching sentence
        if sentence:
            print(sentence)
            print(type(sentence))
            data["content"] = sentence[1]
            data["lowers"] = sentence[2]
            data["without_stop_words"] = sentence[3]
            lemmatized_text = list(sentence[4].split(" "))
            # Lemmatize each word in the sentence
            data["lemmatized_words"] = lemmatized_text
            
            #call predict function Here
            # result = predict_func(count_vectorization_func(lemmatized_words))
            result = sentence[5]
            print(result)

            return render_template('results.html', data=data, current_user =current_user,result=result,result_len=len(result) )
        
        # return jsonify({'message': 'sentence not found'}), 404
        return render_template('404.html', current_user =current_user), 404

@app.route('/about')
@jwt_required(optional=True)
def about():
    user_id = get_jwt_identity()
    current_user=user_id
    data={'title': "Senti | About"}
    return render_template('about.html', current_user =current_user, data=data)
    

# Initialize the app
#checking if the current module is the main module
if __name__ == '__main__':
    # configuring the lifetime of a user session
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
    #configuring the expiration time for access tokens 
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=1)
    #configuring the expiration time for refresh tokens 
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=1)
    # run the app
    app.run(debug=True)



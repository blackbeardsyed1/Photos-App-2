from flask import Flask, request, jsonify
from flask_cors import CORS
from flask import request, jsonify, g
from azure.storage.blob import BlobServiceClient
import uuid
import pymongo
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import json
from bson import json_util


load_dotenv()

app = Flask(__name__)
CORS(app)

# MongoDB setup
client = os.getenv("AZURE_COSMOS_CONNECTIONSTRING")
client = pymongo.MongoClient(client)
db = client['photoapp']
photos = db['photos']
comments = db['comments']
ratings = db['ratings']
users = db['users']  # For storing users

SECRET_KEY = os.getenv("SECRET_KEY")

# def parse_json(data):
#     return json.loads(json_util.dumps(data))

def convert_to_json_serializable(input_data):
    """Converts MongoDB data to JSON-serializable format"""
    return json.loads(json_util.dumps(input_data))




# def upload_file_to_blob(file, filename):
#     try:
#         connect_str = os.getenv("BLOB_CONN")
#         if not connect_str:
#             raise ValueError("BLOB_CONN environment variable not set.")

#         container_name = "photo-container"
#         blob_service_client = BlobServiceClient.from_connection_string(connect_str)
#         container_client = blob_service_client.get_container_client(container_name)
#         blob_client = container_client.get_blob_client(filename)

#         # Upload directly using the FileStorage object
#         blob_client.upload_blob(file, overwrite=True)

#         return blob_client.url

#     except Exception as e:
#         print(f"Error during file upload: {e}")
#         raise



def store_media_in_azure_storage(file_data, target_filename):
    """Uploads a file to Azure Blob Storage and returns the URL"""
    try:
        connection_string = os.environ.get("BLOB_CONN")
        if connection_string is None:
            raise EnvironmentError("Azure Blob Storage connection string not configured")
        
        storage_container = "photo-container"
        blob_client_instance = BlobServiceClient.from_connection_string(connection_string)
        container_reference = blob_client_instance.get_container_client(storage_container)
        blob_reference = container_reference.get_blob_client(target_filename)

        # Perform the file upload operation
        blob_reference.upload_blob(file_data, overwrite=True)

        return blob_reference.url

    except Exception as upload_error:
        print(f"Failed to upload file to storage: {upload_error}")
        raise




# Function to generate JWT token
# def generate_token(user_id, username, role):
#     payload = {
#         "user_id": user_id,
#         "username": username,  
#         "role": role,
#         "exp": datetime.utcnow() + timedelta(hours=24)
#     }
#     return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def create_authentication_token(user_identifier, user_name, user_role):
    """Generates a JWT token for user authentication"""
    token_payload = {
        "user_id": user_identifier,
        "username": user_name,
        "role": user_role,
        "expiry": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")




# Middleware to check for valid JWT token
# def token_required(f):
#     @wraps(f)
#     def decorator(*args, **kwargs):
#         token = None
#         # Check for token in Authorization header
#         if "Authorization" in request.headers:
#             parts = request.headers["Authorization"].split(" ")
#             if len(parts) == 2 and parts[0].lower() == "bearer":
#                 token = parts[1]

#         if not token:
#             return jsonify({"error": "Authentication required", "message": "No token provided"}), 401
        
#         try:
#             data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#             current_user = users.find_one({"_id": data["user_id"]})
#             if not current_user:
#                 return jsonify({"error": "User not found", "message": "User account may have been deleted"}), 404
#             g.user = current_user
#             g.role = data["role"]
#             g.user_id = str(current_user["_id"])  # Store user ID as string
#         except jwt.ExpiredSignatureError:
#             return jsonify({"error": "Token expired", "message": "Please log in again"}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({"error": "Invalid token", "message": "Authentication failed"}), 401
#         except Exception as e:
#             return jsonify({"error": "Authentication error", "message": str(e)}), 401

#         return f(*args, **kwargs)
    
#     return decorator

# def check_role(required_role):
#     def wrapper(f):
#         @wraps(f)
#         def decorator(*args, **kwargs):
#             if not hasattr(g, "role"):
#                 return jsonify({"error": "Authorization error", "message": "User role not found"}), 403
#             if g.role != required_role:
#                 return jsonify({
#                     "error": "Permission denied",
#                     "message": f"Requires {required_role} role",
#                     "your_role": g.role
#                 }), 403
#             return f(*args, **kwargs)
#         return decorator
#     return wrapper

# @app.route('/signup', methods=['POST'])
# def signup():
#     username = request.json.get('username')
#     password = request.json.get('password')
    
#     if not username or not password:
#         return jsonify({"error": "Missing required fields"}), 400

#     # Check if the username already exists
#     existing_user = users.find_one({"username": username})
#     if existing_user:
#         return jsonify({"error": "Username already exists"}), 409

#     # Only allow consumer signups
#     new_user = {
#         "username": username,
#         "password": generate_password_hash(password),  # Hash the password
#         "role": "consumer",    # Force role to consumer
#         "created_at": datetime.utcnow()
#     }
#     result = users.insert_one(new_user)
    
#     # Generate JWT token for the new user
#     token = generate_token(str(result.inserted_id), username, "consumer")

#     return jsonify({
#         "message": "User created successfully",
#         "token": token,
#         "role": "consumer"
#     })




@app.route('/register', methods=['POST'])
def handle_user_registration():
    """Process new user registration requests"""
    user_name = request.json.get('username')
    passphrase = request.json.get('password')
    
    if not user_name or not passphrase:
        return jsonify({"error": "Required credentials not provided"}), 400

    # Verify username availability
    duplicate_user = users.find_one({"username": user_name})
    if duplicate_user:
        return jsonify({"error": "User account already exists"}), 409

    # Create new consumer account
    user_record = {
        "username": user_name,
        "password": generate_password_hash(passphrase),
        "role": "consumer",  # Enforced consumer role
        "created_at": datetime.utcnow()
    }
    insertion_result = users.insert_one(user_record)
    
    # Generate access token
    auth_token = create_authentication_token(
        user_identifier=str(insertion_result.inserted_id),
        user_name=user_name,
        user_role="consumer"
    )

    return jsonify({
        "message": "Account created successfully",
        "token": auth_token,
        "role": "consumer"
    })

# @app.route('/login', methods=['POST'])
# def login():
#     username = request.json.get('username')
#     password = request.json.get('password')
    
#     if not username or not password:
#         return jsonify({"error": "Missing username or password"}), 400

#     # Find user by username
#     user = users.find_one({"username": username})
#     if not user:
#         return jsonify({"error": "Invalid credentials"}), 401
    
#     # Check password
#     if not check_password_hash(user['password'], password):
#         return jsonify({"error": "Invalid credentials"}), 401
    
#     # Generate JWT token
#     token = generate_token(str(user["_id"]), user["username"], user["role"])

#     return jsonify({
#         "success": True,
#         "token": token,
#         "role": user["role"],
#         "message": "Login successful"
#     })



@app.route('/authenticate', methods=['POST'])
def process_user_authentication():
    """Handle user authentication requests"""
    user_name = request.json.get('username')
    passphrase = request.json.get('password')
    
    if not user_name or not passphrase:
        return jsonify({"error": "Username and password required"}), 400

    # Retrieve user account
    user_account = users.find_one({"username": user_name})
    if not user_account:
        return jsonify({"error": "Authentication failed"}), 401
    
    # Verify password
    if not check_password_hash(user_account['password'], passphrase):
        return jsonify({"error": "Authentication failed"}), 401
    
    # Create session token
    access_token = create_authentication_token(
        user_identifier=str(user_account["_id"]),
        user_name=user_account["username"],
        user_role=user_account["role"]
    )

    return jsonify({
        "success": True,
        "token": access_token,
        "role": user_account["role"],
        "message": "Authentication successful"
    })





# @app.route('/upload', methods=['POST'])
# def upload_photo():
#     auth_header = request.headers.get('Authorization')
#     if not auth_header or not auth_header.startswith("Bearer "):
#         return {"error": "Missing or invalid Authorization header"}, 401
        
#     token = auth_header.split(" ")[1]
#     decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#     print(token,"This is the token")
#     if 'file' not in request.files:
#         return jsonify({"error": "No file provided"}), 400
    
#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({"error": "No selected file"}), 400
    
#     title = request.form.get('title')
#     if not title:
#         return jsonify({"error": "Title is required"}), 400
    
#     try:
#         filename = str(uuid.uuid4()) + "_" + file.filename
#         blob_url = upload_file_to_blob(file, filename)
        
#         photo_data = {
#             "title": title,
#             "caption": request.form.get('caption', ''),
#             "location": request.form.get('location', ''),
#             "blob_url": blob_url,
#             "uploaded_by": decoded["username"],
#             "uploaded_at": datetime.utcnow(),
#             "username": decoded["username"]
#         }
        
#         photos.insert_one(photo_data)
        
#         return jsonify({
#             "message": "Photo uploaded successfully",
#             "photo": {
#                 "title": photo_data['title'],
#                 "blob_url": photo_data['blob_url'],
#                 "caption": photo_data['caption'],
#                 "location": photo_data['location']
#             }
#         })
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500



@app.route('/add-media', methods=['POST'])
def handle_media_upload():
    """Process media upload requests with authentication"""
    authorization_header = request.headers.get('Authorization')
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return {"error": "Invalid or missing authentication token"}, 401
        
    jwt_token = authorization_header.split(" ")[1]
    try:
        decoded_token = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
    except Exception as auth_error:
        return {"error": "Invalid authentication token"}, 401

    if 'file' not in request.files:
        return jsonify({"error": "Media file not provided"}), 400
    
    media_file = request.files['file']
    if media_file.filename == '':
        return jsonify({"error": "Empty file selection"}), 400
    
    media_title = request.form.get('title')
    if not media_title:
        return jsonify({"error": "Media title is required"}), 400
    
    try:
        unique_filename = f"{uuid.uuid4()}_{media_file.filename}"
        storage_url = store_media_in_azure_storage(media_file, unique_filename)
        
        media_metadata = {
            "title": media_title,
            "caption": request.form.get('caption', ''),
            "location": request.form.get('location', ''),
            "blob_url": storage_url,
            "uploaded_by": decoded_token["username"],
            "uploaded_at": datetime.utcnow(),
            "username": decoded_token["username"]
        }
        
        photos.insert_one(media_metadata)
        
        return jsonify({
            "message": "Media uploaded successfully",
            "media": {
                "title": media_metadata['title'],
                "blob_url": media_metadata['blob_url'],
                "caption": media_metadata['caption'],
                "location": media_metadata['location']
            }
        })
    except Exception as upload_error:
        return jsonify({"error": f"Upload failed: {str(upload_error)}"}), 500


# @app.route('/photos', methods=['GET'])
# def list_photos():
#     try:
#         photo_list = list(photos.find({}, {'_id': 0}))
#         return jsonify(photo_list)
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route('/media-items', methods=['GET'])
def retrieve_media_collection():
    """Fetch and return all media items from storage"""
    try:
        media_items = list(photos.find({}, {'_id': 0}))
        return jsonify(media_items)
    except Exception as query_error:
        return jsonify({
            "error": f"Failed to retrieve media collection: {str(query_error)}"
        }), 500


# @app.route('/photos/user', methods=['GET'])
# def list_user_photos():
#     try:
#         user_photos = list(photos.find({"uploaded_by": g.user_id}, {'_id': 0}))
#         return jsonify(user_photos)
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500



@app.route('/media-items/user', methods=['GET'])
def fetch_user_media_collection():
    """Retrieve all media items uploaded by the authenticated user"""
    try:
        user_media = list(photos.find({"uploaded_by": g.user_id}, {'_id': 0}))
        return jsonify(user_media)
    except Exception as retrieval_error:
        return jsonify({
            "error": f"Failed to fetch user media: {str(retrieval_error)}"
        }), 500



# @app.route('/photos/<photo_title>', methods=['GET'])
# def get_photo_details(photo_title):
#     try:
#         photo = photos.find_one({"title": photo_title}, {'_id': 0})
#         if not photo:
#             return jsonify({"error": "Photo not found"}), 404
        
#         # Get comments
#         photo_comments = list(comments.find({"photo_title": photo_title}, {'_id': 0}))
        
#         # Get average rating
#         rating_cursor = ratings.aggregate([
#             {"$match": {"photo_title": photo_title}},
#             {"$group": {"_id": "$photo_title", "average": {"$avg": "$rating"}}}
#         ])
#         average_rating = list(rating_cursor)
        
#         response = {
#             "photo": photo,
#             "comments": photo_comments,
#             "average_rating": average_rating[0]['average'] if average_rating else 0
#         }
        
#         return jsonify(response)
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

@app.route('/media-items/<media_title>', methods=['GET'])
def get_media_details(media_title):
    """Retrieve detailed information about a specific media item including comments and ratings"""
    try:
        # Retrieve media metadata
        media_item = photos.find_one({"title": media_title}, {'_id': 0})
        if not media_item:
            return jsonify({"error": "Media item not found"}), 404
        
        # Fetch associated comments
        item_comments = list(comments.find({"photo_title": media_title}, {'_id': 0}))
        
        # Calculate average rating
        rating_aggregation = ratings.aggregate([
            {"$match": {"photo_title": media_title}},
            {"$group": {
                "_id": "$photo_title", 
                "average": {"$avg": "$rating"}
            }}
        ])
        rating_results = list(rating_aggregation)
        
        response_data = {
            "media": media_item,
            "comments": item_comments,
            "average_rating": rating_results[0]['average'] if rating_results else 0
        }
        
        return jsonify(response_data)
    except Exception as query_error:
        return jsonify({
            "error": f"Failed to retrieve media details: {str(query_error)}"
        }), 500



# @app.route('/photos/<photo_title>/comment', methods=['POST'])
# def add_comment(photo_title):
#     text = request.json.get('text')
#     auth_header = request.headers.get('Authorization')
#     if not auth_header or not auth_header.startswith("Bearer "):
#         return {"error": "Missing or invalid Authorization header"}, 401
        
#     token = auth_header.split(" ")[1]
#     decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#     if not text:
#         return jsonify({"error": "Comment text is required"}), 400
    
#     try:
#         comment_data = {
#             "photo_title": photo_title,
#             "user_id": decoded["username"],
#             "username": decoded['username'],
#             "text": text,
#             "timestamp": datetime.utcnow()
#         }
        
#         comments.insert_one(comment_data)
#         return jsonify({"message": "Comment added successfully"})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route('/media-items/<media_title>/comments', methods=['POST'])
def create_media_comment(media_title):
    """Add a new comment to a specific media item"""
    comment_text = request.json.get('text')
    auth_header = request.headers.get('Authorization')
    
    # Validate authorization header
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"error": "Invalid or missing authentication token"}, 401
        
    # Decode and verify JWT token
    auth_token = auth_header.split(" ")[1]
    try:
        decoded_token = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
    except Exception as auth_error:
        return {"error": "Invalid authentication token"}, 401
    
    # Validate comment text
    if not comment_text:
        return jsonify({"error": "Comment content is required"}), 400
    
    try:
        # Prepare comment document
        new_comment = {
            "photo_title": media_title,
            "user_id": decoded_token["username"],
            "username": decoded_token['username'],
            "text": comment_text,
            "timestamp": datetime.utcnow()
        }
        
        # Store comment in database
        comments.insert_one(new_comment)
        
        return jsonify({
            "message": "Comment was successfully added",
            "comment": {
                "username": new_comment['username'],
                "text": new_comment['text']
            }
        })
    except Exception as db_error:
        return jsonify({
            "error": f"Failed to add comment: {str(db_error)}"
        }), 500
    



# @app.route('/photos/<photo_title>/rate', methods=['POST'])
# def add_rating(photo_title):
#     text = request.json.get('text')
#     auth_header = request.headers.get('Authorization')
#     if not auth_header or not auth_header.startswith("Bearer "):
#         return {"error": "Missing or invalid Authorization header"}, 401
        
#     token = auth_header.split(" ")[1]
#     decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#     rating = request.json.get('rating')
#     if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
#         return jsonify({"error": "Rating must be an integer between 1 and 5"}), 400
    
#     try:
#         # Check if user already rated this photo
#         existing_rating = ratings.find_one({
#             "photo_title": photo_title,
#             "user_id": decoded["username"]
#         })
        
#         if existing_rating:
#             ratings.update_one(
#                 {"_id": existing_rating['_id']},
#                 {"$set": {"rating": rating}}
#             )
#             message = "Rating updated successfully"
#         else:
#             rating_data = {
#                 "photo_title": photo_title,
#                 "user_id": decoded["username"],
#                 "username": decoded['username'],
#                 "rating": rating,
#                 "timestamp": datetime.utcnow()
#             }
#             ratings.insert_one(rating_data)
#             message = "Rating added successfully"
        
#         return jsonify({"message": message})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
    



@app.route('/media-items/<media_title>/ratings', methods=['POST'])
def submit_media_rating(media_title):
    """Submit or update a rating for a specific media item"""
    auth_header = request.headers.get('Authorization')
    
    # Validate authorization header
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"error": "Invalid or missing authentication token"}, 401
        
    # Decode and verify JWT token
    auth_token = auth_header.split(" ")[1]
    try:
        decoded_token = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
    except Exception as auth_error:
        return {"error": "Invalid authentication token"}, 401
    
    # Validate rating value
    rating_value = request.json.get('rating')
    if not rating_value or not isinstance(rating_value, int) or rating_value < 1 or rating_value > 5:
        return jsonify({"error": "Rating must be an integer between 1 and 5"}), 400
    
    try:
        # Check for existing rating
        user_rating = ratings.find_one({
            "photo_title": media_title,
            "user_id": decoded_token["username"]
        })
        
        if user_rating:
            # Update existing rating
            ratings.update_one(
                {"_id": user_rating['_id']},
                {"$set": {
                    "rating": rating_value,
                    "timestamp": datetime.utcnow()
                }}
            )
            response_message = "Rating updated successfully"
        else:
            # Create new rating
            rating_record = {
                "photo_title": media_title,
                "user_id": decoded_token["username"],
                "username": decoded_token['username'],
                "rating": rating_value,
                "timestamp": datetime.utcnow()
            }
            ratings.insert_one(rating_record)
            response_message = "Rating submitted successfully"
        
        return jsonify({
            "message": response_message,
            "rating": rating_value,
            "media_title": media_title
        })
    except Exception as db_error:
        return jsonify({
            "error": f"Failed to process rating: {str(db_error)}"
        }), 500


# @app.route('/photos/search', methods=['GET'])
# def search_photos():
#     query = request.args.get('q', '')
#     if not query:
#         return jsonify({"error": "Search query is required"}), 400
    
#     try:
#         regex_query = {'$regex': query, '$options': 'i'}  # 'i' for case insensitive
#         results = list(photos.find({
#             '$or': [
#                 {'title': regex_query},
#                 {'caption': regex_query},
#                 {'location': regex_query},
#                 {'username': regex_query}
#             ]
#         }, {'_id': 0}))
        
#         return jsonify(results)
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route('/health', methods=['GET'])
# def health_check():
#     return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route('/media-items/search', methods=['GET'])
def search_media_items():
    """Search media items by title, caption, location, or username"""
    search_term = request.args.get('q', '')
    if not search_term:
        return jsonify({"error": "Search term parameter is required"}), 400
    
    try:
        search_pattern = {'$regex': search_term, '$options': 'i'}  # Case insensitive search
        search_results = list(photos.find({
            '$or': [
                {'title': search_pattern},
                {'caption': search_pattern},
                {'location': search_pattern},
                {'username': search_pattern}
            ]
        }, {'_id': 0}))
        
        return jsonify({
            "results": search_results,
            "count": len(search_results),
            "search_term": search_term
        })
    except Exception as search_error:
        return jsonify({
            "error": f"Search failed: {str(search_error)}"
        }), 500

@app.route('/system-status', methods=['GET'])
def check_system_health():
    """Check the health status of the application"""
    return jsonify({
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "database": "connected",
            "storage": "available"
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
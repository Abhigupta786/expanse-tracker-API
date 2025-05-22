from dotenv import load_dotenv
from flask import Flask, jsonify, request
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from functools import wraps
from flask_cors import CORS
import jwt
import datetime
import os
import bcrypt
import datetime
import os

load_dotenv() 
# Flask app setup
app = Flask(__name__)
CORS(app)
SECRET_KEY = os.getenv('SECRET_KEY')

# MongoDB connection URI
uri = os.getenv('MONGO_URI')
# MongoDB client
client = MongoClient(uri, server_api=ServerApi('1'))
db = client['Expense-tracker']
users_collection = db['Users']
expenses_collection = db['Expenses']
groups_collection = db['Groups']


@app.route('/')
def home():
    try:
        client.admin.command('ping')
        return "✅ Connected to MongoDB successfully!"
    except Exception as e:
        return f"❌ MongoDB Connection Error: {e}"


# JWT decorator
def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token missing!'}), 403
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            setattr(request, 'user', data)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid Token!'}), 403
        return f(*args, **kwargs)

    return decorated


@app.route('/signup', methods=['POST'])
def signup():

    data = request.json
    if data is None:
        return jsonify({'error': 'Missing JSON body!'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required!'}), 400

    if users_collection.find_one(
        {'$or': [{
            'username': username
        }, {
            'email': email
        }]}):
        return jsonify({'error': 'User already exists!'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_user = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'role': 'user',
        'dateJoined': datetime.datetime.utcnow(),
        'groupId': None
    }
    result = users_collection.insert_one(new_user)

    token = jwt.encode(
        {
            'user_id': str(result.inserted_id),
            'username': username,
            'role': 'user',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        SECRET_KEY,
        algorithm='HS256')

    return jsonify({'token': token})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if data is None:
        return jsonify({'error': 'Missing JSON body!'}), 400

    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode(
            {
                'user_id': str(user['_id']),
                'username': username,
                'role': user.get('role', 'user'),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            },
            SECRET_KEY,
            algorithm='HS256')
        return jsonify({'token': token})

    return jsonify({'error': 'Invalid credentials!'}), 401


@app.route('/names', methods=['GET'])
@token_required
def get_names():
    names = users_collection.find({},
                                  {'password': 0})  # Exclude password field
    name_list = []
    for doc in names:
        user_data = {'username': doc['username'], 'userId': str(doc['_id'])}
        name_list.append(user_data)
    return jsonify(name_list)


@app.route('/group-names', methods=['GET'])
@token_required
def get_group_names():
    groups = groups_collection.find(
        {}, {'groupName': 1})  # Only include groupName field
    group_list = []
    for group in groups:
        group_data = {
            'groupId': str(group['_id']),
            'groupName': group['groupName']
        }
        group_list.append(group_data)
    return jsonify(group_list)


@app.route('/my-expenses', methods=['GET'])
@token_required
def my_expenses():
    username = request.user['username']

    # Step 1: Get all group names the user is a member of
    user_groups_cursor = groups_collection.find({'members': username})
    group_names = [group['groupName'] for group in user_groups_cursor]

    if not group_names:
        return jsonify({'error': 'No groups found for user'}), 404

    # Step 2: Find expenses where:
    # - groupName is in the list
    # - isDeleted is False
    # - isPaid is False
    # - share has at least one entry with member == username
    expenses_cursor = expenses_collection.find({
        'groupName': {
            '$in': group_names
        },
        'isDeleted': False,
        'isPaid': False,
        'share': {
            '$elemMatch': {
                'member': username
            }
        }
    })

    # Step 3: Format and return
    expense_list = []
    for doc in expenses_cursor:
        doc['_id'] = str(doc['_id'])  # Convert ObjectId to string
        expense_list.append(doc)

    return jsonify(expense_list), 200


@app.route('/group-expenses/<group_id>', methods=['GET'])
@token_required
def group_expenses(group_id):
    expenses = expenses_collection.find({
        'groupId': group_id,
        'isDeleted': False
    })
    expense_list = []
    for doc in expenses:
        doc['_id'] = str(doc['_id'])  # Ensure that _id is converted to string
        expense_list.append(doc)
    return jsonify(expense_list)


@app.route('/create-group', methods=['POST'])
@token_required
def create_group():
    data = request.json
    group_name = data.get('groupName')
    members = data.get('members', [])

    if not group_name:
        return jsonify({'error': 'Group name is required!'}), 400

    if groups_collection.find_one({'groupName': group_name}):
        return jsonify({'error': 'Group name already exists!'}), 409

    owner_username = request.user['username']

    if owner_username not in members:
        members.append(owner_username)

    group = {
        'groupName': group_name,
        'owner': owner_username,
        'members': members,
        'invitations': []  # initially empty
    }

    result = groups_collection.insert_one(group)

    return jsonify({
        'message': 'Group created!',
        'groupId': str(result.inserted_id)
    })


@app.route('/join-group', methods=['POST'])
@token_required
def join_group():
    data = request.json
    group_name = data.get('groupName')
    username = request.user['username']

    if not group_name:
        return jsonify({'error': 'Group name is required!'}), 400

    # Find the user by username
    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found!'}), 404

    user_id = str(user['_id'])

    # Find the group by name
    group = groups_collection.find_one({'groupName': group_name})
    if not group:
        return jsonify({'error': 'Group not found!'}), 404

    # Check if already a member
    if username in group.get('members', []):
        return jsonify({'error': 'User already in group.'}), 409

    # Check if already invited
    for invite in group.get('invitations', []):
        if invite['inv_id'] == user_id:
            return jsonify({'message': 'Join request already sent.'}), 200

    # Add to invitations
    groups_collection.update_one(
        {'groupName': group_name},
        {'$push': {
            'invitations': {
                'inv_id': user_id,
                'inv_name': username
            }
        }})

    return jsonify({'message': 'Join request sent!'})


@app.route('/my-groups', methods=['GET'])
@token_required
def my_groups():
    username = request.user['username']

    # Find all groups where the user is a member
    groups = groups_collection.find({'members': {'$in': [username]}})

    group_list = []
    for group in groups:
        group_list.append({
            'groupId': str(group['_id']),
            'groupName': group.get('groupName'),
            'groupOwner': group.get('owner'),
            'members': group.get('members', []),
            'invitations': group.get('invitations', [])
        })

    return jsonify(group_list)


@app.route('/group-invitation/<invite_id>', methods=['POST'])
@token_required
def handle_invitation(invite_id):
    data = request.get_json()
    action = data.get('action')

    if action not in ['approve', 'reject']:
        return jsonify({'error': 'Invalid action!'}), 400

    # Find the group that contains the invitation
    group = groups_collection.find_one({'invitations.inv_id': invite_id})

    if not group:
        return jsonify({'error': 'Invitation not found!'}), 404

    # Find the invitation details
    invitation = next((inv for inv in group.get('invitations', [])
                       if inv['inv_id'] == invite_id), None)
    if not invitation:
        return jsonify({'error': 'Invitation entry not found!'}), 404

    # Always remove the invitation
    groups_collection.update_one(
        {'_id': group['_id']},
        {'$pull': {
            'invitations': {
                'inv_id': invite_id
            }
        }})

    if action == 'approve':
        # Add to members only if action is approve
        groups_collection.update_one(
            {'_id': group['_id']},
            {'$addToSet': {
                'members': invitation['inv_name']
            }})
        return jsonify({
            'message':
            f"{invitation['inv_name']} has been added to the group."
        }), 200
    else:
        return jsonify({
            'message':
            f"Invitation for {invitation['inv_name']} has been rejected."
        }), 200


@app.route('/remove-member', methods=['POST'])
@token_required
def remove_member():
    data = request.get_json()
    group_name = data.get('groupName')
    member_name = data.get('memberName')

    if not group_name or not member_name:
        return jsonify({'error':
                        'Group name and member name are required!'}), 400

    group = groups_collection.find_one({'groupName': group_name})
    if not group:
        return jsonify({'error': 'Group not found!'}), 404

    # Only allow owner to remove members
    if group.get('owner') != request.user['username']:
        return jsonify({'error':
                        'Only the group owner can remove members.'}), 403

    if member_name == group.get('owner'):
        return jsonify({'error':
                        'Owner cannot be removed from the group!'}), 400

    # Remove the member
    result = groups_collection.update_one({'groupName': group_name},
                                          {'$pull': {
                                              'members': member_name
                                          }})

    if result.modified_count == 0:
        return jsonify(
            {'message':
             'Member was not in the group or already removed.'}), 200

    return jsonify(
        {'message': f'Member {member_name} removed from {group_name}.'}), 200


@app.route('/update-group', methods=['PUT'])
@token_required
def update_group():
    try:
        data = request.json
        group_name = data.get('groupName')
        new_members = data.get('members', [])

        if not group_name:
            return jsonify({'error': 'Group name is required.'}), 400

        # Find the group where the user is the owner
        group = groups_collection.find_one({
            'groupName': group_name,
            'owner': request.user['username']
        })

        if not group:
            return jsonify(
                {'error': 'Group not found or you are not the owner.'}), 404

        current_members = set(group.get('members', []))
        new_unique_members = [
            member for member in new_members if member not in current_members
        ]

        if new_unique_members:
            groups_collection.update_one(
                {'_id': group['_id']},
                {'$push': {
                    'members': {
                        '$each': new_unique_members
                    }
                }})

        return jsonify({'message': 'New members added successfully.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/add-expense', methods=['POST'])
@token_required
def add_expense():
    try:
        data = request.json
        title = data.get('title')
        amount = data.get('amount')
        groupname = data.get('groupname')
        paid_by = request.user['username']
        date = datetime.datetime.utcnow()

        if not title or amount is None or not groupname:
            return jsonify(
                {'error': 'Title, amount, and group name are required.'}), 400

        # Fetch the group
        group = groups_collection.find_one({'groupName': groupname})
        if not group:
            return jsonify({'error': 'Group not found.'}), 404

        members = group.get('members', [])
        if paid_by not in members:
            return jsonify({'error':
                            'You are not a member of this group.'}), 403

        if not members:
            return jsonify({'error': 'Group has no members.'}), 400

        # Calculate equal share
        equal_share = round(amount / len(members), 2)

        # Create share breakdown
        share = [{'member': m, 'amount': equal_share} for m in members]

        # Store expense (without groupId)
        expense = {
            'title': title,
            'amount': amount,
            'groupName': groupname,
            'paidBy': paid_by,
            'date': date,
            'share': share,
            'isDeleted': False,
            'isPaid': False
        }

        expenses_collection.insert_one(expense)

        return jsonify({'message': 'Expense added successfully!'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/my-payables', methods=['GET'])
@token_required
def my_payables():
    username = request.user['username']

    # Find expenses where the current user is a share member but not the payer
    expenses = expenses_collection.find({
        'share.member':
        username,
        'paidBy': {
            '$ne': username
        },
        '$or': [{
            'isDeleted': False
        }, {
            'isPaid': False
        }]
    })

    payables_dict = {}

    for expense in expenses:
        paid_to = expense['paidBy']
        for share in expense.get('share', []):
            if share['member'] == username:
                payables_dict[paid_to] = payables_dict.get(paid_to,
                                                           0) + share['amount']
                break

    # Format the response
    payables_summary = [{
        'paidTo': user,
        'amount': amount
    } for user, amount in payables_dict.items()]
    return jsonify(payables_summary)


@app.route('/my-receivings', methods=['GET'])
@token_required
def my_receivings():
    username = request.user['username']

    # Find expenses where current user is the payer
    expenses = expenses_collection.find({
        'paidBy':
        username,
        '$or': [{
            'isDeleted': False
        }, {
            'isDeleted': "false"
        }]
    })

    receivings_dict = {}

    for expense in expenses:
        for share in expense.get('share', []):
            member = share['member']
            if member != username:  # Exclude the payer themselves
                receivings_dict[member] = receivings_dict.get(
                    member, 0) + share['amount']

    # Format the response
    receivings_summary = [{
        'from': member,
        'amount': amount
    } for member, amount in receivings_dict.items()]
    return jsonify(receivings_summary)


if __name__ == '__main__':
    app.run(debug=True)

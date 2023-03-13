import socket
import signal
import sys
import random

# Read a command line argument for the port where the server
# must run.
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    print("Using default port 8080")

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
login_form = """
   <form action = "http://localhost:%d" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
""" % port
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = """
   <h1>Welcome!</h1>
   <form action="http://localhost:%d" method = "post">
   <input type = "hidden" name = "password" value = "new" />
   <input type = "submit" value = "Click here to Change Password" />
   </form>
   <form action="http://localhost:%d" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
""" % (port, port)

new_password_page = """
   <form action="http://localhost:%d" method = "post">
   New Password: <input type = "text" name = "NewPassword" /> <br/>
   <input type = "submit" value = "Submit" />
</form>
""" % port

#### Helper functions
# Printing.
def print_value(tag, value):
    print "Here is the", tag
    print "\"\"\""
    print value
    print "\"\"\""
    print

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)

# Read login credentials for all users
login_credentials = {}
with open('passwords.txt') as passwords:
    for item in passwords:
        username, password = item.strip().split()
        login_credentials[username] = password

# Read secret data of all users
secret_data = {}
with open('secrets.txt') as secrets:
    for item in secrets:
        username, secret = item.strip().split()
        secret_data[username] = secret

def update_password(username, new_password):
    login_credentials[username] = new_password
    with open('passwords.txt', 'w') as passwords:
        for username, password in login_credentials.items():
            passwords.write('{} {}\n'.format(username, password))
                    
# Dictionary that maps tokens to usernames
token_username = {}

### Loop to accept incoming HTTP connections and respond.
while True:
    client, addr = sock.accept()
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.split('\r\n\r\n')

    # Parse headers and entity body and perform various actions based on the user's input.
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)
    print_value('entity body', body)
    if 'action' in body and body.split('=')[1] == 'logout':
        # Logout action.
        html_content_to_send = logout_page
        headers_to_send = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n'
        
    elif 'password' in body and body.split('=')[1] == 'new':
        # New password action.
        html_content_to_send = new_password_page
        headers_to_send = ''

    elif 'NewPassword' in body:
        # Update password action.
        new_password = body.split('&')[0].split('=')[1]
        update_password(username, new_password)
        html_content_to_send = success_page + secret_data[username]
        headers_to_send = ''

        
    elif 'username' in body and 'password' in body:
        # We have login credentials, so let's try to log the user in.
        username = body.split('&')[0].split('=')[1]
        password = body.split('&')[1].split('=')[1]
        if username in login_credentials and login_credentials[username] == password:
            # Successful login.
            rand_val = int(random.getrandbits(64))
            token_username[rand_val] = username
            headers_to_send = "Set-Cookie: token=" + str(rand_val) + "\r\n"
            html_content_to_send = success_page + secret_data[username]
        else:
            # Bad credentials.
            headers_to_send = ''
            html_content_to_send = bad_creds_page
    elif 'Cookie' in headers:
        # We have a cookie, so let's check if it's valid.
        cookie = headers.split('Cookie: ')[1].split('\r\n')[0]
        token = cookie.split('=')[1]

        if(token):
            token = int(token)
            if token in token_username:
                # Valid cookie.
                username = token_username[token]
                html_content_to_send = success_page + secret_data[username]
                headers_to_send = ''
            else:
                # Invalid cookie.
                html_content_to_send = login_page
                headers_to_send = ''
    else:
        # Default: Login page.
        html_content_to_send = login_page
        headers_to_send = ''

    # Construct and send the final response back to the client.
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)
    client.send(response)
    client.close()
    print "Served one request/connection!"
    print
    
# We will never actually get here.
# Close the listening socket
sock.close()

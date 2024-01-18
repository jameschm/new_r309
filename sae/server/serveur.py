from datetime import *
from email_validator import *
from functools import *
from threading import *
from mysql.connector import Error
import getpass
import json
import logging
import mysql.connector
import socket
import threading
import time
import sys

DATABASE = {
    'host': 'localhost',
    'user': 'toto',
    'password': 'toto',
    'database': 'sae32'
}

chat_rooms = ["Général","BlaBla","Comptabilité","Informatique","Marketing"]
client_threads, connected_clients, user_topic_dict, user_id_dict, user_profile_dict, pending_requests = [], [], {}, {}, {}, {}
        
def handle_existing_user(conn):
    """
    Handles the authentication process for an existing user.

    Parameters:
    conn (socket): The connection socket object.

    Returns:
    None
    """
    for _ in range(3):
        identifiant = request_input(conn, "Enter your username: ")
        user_id_dict[conn] = identifiant
        user_profile_dict[identifiant] = conn

        if user_ban(identifiant):
            conn.send("You are banned!!!\n".encode())
            return conn.close()

        if user_kick(identifiant):
            conn.send("You have been kicked!!!\n".encode())
            return conn.close()

        mot_de_passe = request_input(conn, "Enter your password: ")

        if identifiant and mot_de_passe and authetificate_user(identifiant, mot_de_passe):
            conn.send("\n\nWelcome on MySocket!\n\n".encode())
            return
        else:
            conn.send("Incorrect credentials. Try again.\n".encode())

    conn.send("Too many failed attempts. Closing the connection. Please close the application.\n".encode())
    conn.close()

def store_message(identifiant, message_texte, current_topic, address):
    """
    Stores a message in the database.

    Parameters:
    - identifiant (int): The user identifier.
    - message_texte (str): The message text.
    - current_topic (str): The topic of the message.
    - address (str): The IP address of the sender.

    Returns:
    None
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO mess (utilisateur_id, message_texte, topic, adresse_ip) VALUES (%s, %s, %s, %s)",
                       (identifiant, message_texte, current_topic, address))
            conn.commit()
            logging.info(f"Message from {identifiant} stored.")
    except Error as err:
        logging.error(f"Error while saving message from {identifiant}: {err}")

def fetch_user_info(conn):
    """
    Fetches the user information from the database.

    Args:
        conn: The database connection object.

    Returns:
        A list of tuples containing the user identifier and status.
    """
    with conn.cursor(dictionary=True) as cur:
        cur.execute("SELECT identifiant, statut FROM users")
        return [(info['identifiant'], info['statut']) for info in cur.fetchall()]

def distribute_user_info(clients, flag_lock):
    """
    Distributes user information to connected clients.

    Args:
        clients (list): List of connected clients.
        flag_lock (threading.Lock): Lock object for synchronization.

    Returns:
        None
    """
    while not user_info_distribution_flag.is_set():
        with flag_lock:
            with mysql.connector.connect(**DATABASE) as connection:
                users_info = fetch_user_info(connection)

        if not users_info:
            time.sleep(3)
            continue

        users_info_str = json.dumps(users_info)
        active_clients = [(client, identifiant) for client, identifiant in clients if client.fileno() != -1]

        for client, _ in active_clients:
            try:
                client.send(f"users:{users_info_str}".encode())
            except Exception as e:
                print(f"Error sending information to {client}: {e}")

        time.sleep(3)

def valid_firstname(firstname):
    """
    Check if a firstname is valid.

    Parameters:
    firstname (str): The firstname to be validated.

    Returns:
    bool: True if the firstname is valid, False otherwise.
    """
    return firstname.replace(" ", "").isalpha()

def valid_name(name):
    """
    Vérifie si le nom donné est valide.

    Parameters:
    name (str): Le nom à vérifier.

    Returns:
    bool: True si le nom est valide, False sinon.
    """
    return name.replace(" ", "").isalpha()

def valid_email(email):
    """
    Check if an email address is valid.

    Args:
        email (str): The email address to be validated.

    Returns:
        bool: True if the email address is valid, False otherwise.
    """
    return bool(validate_email(email, check_deliverability=False, allow_smtputf8=False))

def valid_user_id(identifier):
    """
    Check if the given identifier is valid for a user.

    Parameters:
    identifier (str): The identifier to be checked.

    Returns:
    bool: True if the identifier is valid, False otherwise.
    """
    return len(identifier) > 3 and all(c.isalnum() for c in identifier)

def valid_password(password):
    """
    Check if a password is valid.

    Parameters:
    password (str): The password to be checked.

    Returns:
    bool: True if the password is valid, False otherwise.
    """
    return len(password) > 7 and any(map(str.isdigit, password)) and any(map(str.isalpha, password))

def collect_user_details(conn):
    """
    Collects user details from the client connection.

    Args:
        conn (connection): The client connection.

    Returns:
        dict: A dictionary containing the collected user details.
            The keys are 'nom', 'prenom', 'adresse_mail', 'identifiant', 'mot_de_passe'.
            The values are the user input for each detail.
    """
    details = ["nom", "prenom", "adresse_mail", "identifiant", "mot_de_passe"]
    prompts = ["Enter your last name: ", "Enter your first name: ", "Email address: ", "Enter your username: ", "Enter your password: "]
    validators = [valid_name, valid_firstname, valid_email, valid_user_id, valid_password]

    return {detail: request_valid_input(conn, prompt, validator) for detail, prompt, validator in zip(details, prompts, validators)}

def fetch_user(identifiant):
    """
    Fetches user information from the database based on the given identifier.

    Args:
        identifiant (str): The identifier of the user.

    Returns:
        tuple: A tuple containing the user's name, surname, identifier, IP address, and email address.
               Returns None if an error occurs during the retrieval process.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT nom, prenom, identifiant, adresse_ip, adresse_mail FROM users WHERE identifiant = %s", (identifiant,))
            return cur.fetchone()
    except Error as err:
        logging.error(f"MySQL error while retrieving profile information for {identifiant}: {err}")
        return None

def authetificate_user(id, pwd):
    """
    Authenticate a user with the given id and password.

    Args:
        id (str): The user's identifier.
        pwd (str): The user's password.

    Returns:
        bool: True if the user is authenticated, False otherwise.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE identifiant = %s AND mot_de_passe = %s", (id, pwd))
            result = cur.fetchone() is not None
            if result:
                update_user(id, 1)
            return result
    except Error as err:
        logging.error(f"MySQL error while authenticating {id}: {err}")
        return False

def user_registred(id):
    """
    Check if a user with the given id is registered in the database.

    Args:
        id (str): The identifier of the user.

    Returns:
        bool: True if the user is registered, False otherwise.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE identifiant = %s", (id,))
            return cur.fetchone() is not None
    except Error as err:
        logging.error(f"MySQL error while checking existence of {id}: {err}")
        return False
    

def user_ban(id):
    """
    Check if a user is banned.

    Args:
        id (int): The ID of the user.

    Returns:
        bool: True if the user is banned, False otherwise.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM sanct WHERE id = %s AND type_sanction = 'ban'", (id,))
            return cur.fetchone() is not None
    except Error as err:
        logging.error(f"MySQL error while checking ban status for {id}: {err}")
        return False

def user_kick(id):
    """
    Check if a user is currently kicked.

    Args:
        id (int): The ID of the user.

    Returns:
        bool: True if the user is currently kicked, False otherwise.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT date_fin_sanction FROM sanct WHERE id = %s AND type_sanction = 'kick' ORDER BY date_fin_sanction DESC LIMIT 1", (id,))
            res = cur.fetchone()
            return res is not None and datetime.now() < res[0]
    except Error as err:
        logging.error(f"MySQL error while checking kick status for {id}: {err}")
        return False
        
def handle_new_user(conn):
    """
    Handles a new user connection.

    Parameters:
    conn (socket): The socket connection for the new user.

    Returns:
    None
    """
    conn.send("Complete your profile.\n".encode())
    user_details = collect_user_details(conn)
    identifiant = user_details["identifiant"]
    user_id_dict[conn] = identifiant
    user_profile_dict[identifiant] = conn

    if user_registred(identifiant):
        conn.send("Username already taken. Try again!!!\n".encode())
    else:
        create_user(user_details["nom"], user_details["prenom"], user_details["adresse_mail"], identifiant, user_details["mot_de_passe"], retrieve_user(conn))
        save_authorization(identifiant, "General")
        conn.send(f"Welcome on MySocket {identifiant}!\n".encode())

def create_user(nom, prenom, adresse_mail, identifiant, mot_de_passe, adresse_ip):
    """
    Crée un nouvel utilisateur dans la base de données.

    Args:
        nom (str): Le nom de l'utilisateur.
        prenom (str): Le prénom de l'utilisateur.
        adresse_mail (str): L'adresse e-mail de l'utilisateur.
        identifiant (str): L'identifiant de l'utilisateur.
        mot_de_passe (str): Le mot de passe de l'utilisateur.
        adresse_ip (str): L'adresse IP de l'utilisateur.

    Returns:
        None
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO users (nom, prenom, adresse_mail, identifiant, mot_de_passe, adresse_ip, statut) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                       (nom, prenom, adresse_mail, identifiant, mot_de_passe, adresse_ip, 1))
            conn.commit()
            logging.info(f"User profile for {identifiant} successfully inserted.")
    except Error as err:
        logging.error(f"Error while inserting user profile for {identifiant}: {err}")

def save_authorization(identifiant, topic):
    """
    Saves the authorization for a user and a topic in the database.

    Parameters:
    - identifiant (str): The identifier of the user.
    - topic (str): The topic for which the authorization is granted.

    Returns:
    None
    """
    try:
        with mysql.connector.connect(user='username', password='password', host='localhost', database='database_name') as cnx, cnx.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM rights WHERE utilisateur = %s AND topic = %s", (identifiant, topic))
            if cursor.fetchone()[0] > 0:
                print(f"The authorization for {identifiant} and {topic} already exists.")
                return

            cursor.execute("INSERT INTO rights (utilisateur, topic) VALUES (%s, %s)", (identifiant, topic))
            cnx.commit()
    except mysql.connector.Error as err:
        print(f"MySQL error: {err}")

def retrieve_user(conn):
    """
    Retrieve the IP address of the connected user.

    Args:
        conn (socket): The socket connection.

    Returns:
        str: The IP address of the connected user.
    """
    return conn.getpeername()[0]

def create_user_a(conn):
    """
    Function to create a user on MySocket.

    Args:
        conn (socket): The connection object.

    Returns:
        None
    """
    conn.send("Welcome on MySocket!\n".encode())
    handlers = {"y": handle_existing_user, "n": handle_new_user}

    while (response := request_input(conn, "Do you already have an account? (y/n): ").lower()) not in handlers:
        conn.send("Invalid response. Please respond with 'y' or 'n'.\n".encode())

    handlers[response](conn)

def handle_topic_change(conn, msg, lock, clients):
    """
    Handles the topic change request from a client.

    Parameters:
    conn (socket): The client's connection socket.
    msg (str): The message containing the new topic.
    lock (threading.Lock): The lock used to synchronize access to the clients list.
    clients (list): The list of connected clients.

    Returns:
    None
    """
    user_id = user_id_dict[conn]
    new_topic = msg.split(":")[1].strip()
    if new_topic not in chat_rooms:
        conn.send("Invalid topic. Please choose from the available topics.".encode())
        return
    if new_topic != "BlaBla" and not user_authorizations(user_id, new_topic):
        if user_id in pending_requests:
            conn.send("You already have a pending request. Please wait.".encode())
        else:
            pending_requests[user_id] = new_topic
            conn.send(f"Your request to join {new_topic} is pending approval.".encode())
        return
    current_topic = user_topic_dict[user_id]
    with lock:
        clients.remove((conn, current_topic))
        clients.append((conn, new_topic))
    user_topic_dict[user_id] = new_topic
    conn.send(f"Welcome to the {new_topic} room!".encode())
    if new_topic == "BlaBla":
        save_authorization(user_id, new_topic)

def user_authorizations(user_id, topic):
    """
    Check if a user has authorizations based on their user_id and topic.

    Parameters:
    user_id (str): The user's identifier.
    topic (str): The topic to check authorizations for.

    Returns:
    bool: True if the user has authorizations, False otherwise.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE identifiant = %s AND mot_de_passe = %s", (user_id, topic))
            return cur.fetchone() is not None
    except Error as err:
        logging.error(f"Error while checking authorization for {user_id} and {topic}: {err}")
        return False

def handle_client(conn, addr, lock, running_flag, clients):
    """
    Handles the client connection and communication.

    Args:
        conn (socket): The client socket connection.
        addr (tuple): The client address (IP, port).
        lock (threading.Lock): The lock used for thread synchronization.
        running_flag (threading.Event): The flag indicating if the server is running.
        clients (list): The list of connected clients.

    Returns:
        None
    """
    try:
        print(f"Connected: {addr}.")
        create_user_a(conn)

        with lock:
            topic = "Général"
            user_id = user_id_dict[conn]
            user_topic_dict[user_id] = topic
            clients.append((conn, topic))
            conn.send(f"Welcome to {topic}!".encode())

        while True:
            msg = conn.recv(1024).decode()

            if msg.lower().startswith("change:"):
                handle_topic_change(conn, msg, lock, clients)
            elif msg.startswith("profile:request"):
                user_id = user_id_dict[conn]
                profile = fetch_user(user_id)
                profile_json = json.dumps(profile)
                conn.send(f"profile:{profile_json}".encode())
            elif msg.lower() == "bye":
                topic = user_topic_dict[user_id]
                print(f"Client {addr} left {topic}.")
                with lock:
                    clients.remove((conn, topic))
                break
            else:
                user_id = user_id_dict[conn]
                topic = user_topic_dict[user_id]
                store_message(user_id, msg, topic, addr[0])
                if not msg.lower().startswith("change:"):
                    broadcast(f"{msg}", clients, topic, user_id)

    except ConnectionResetError:
        print(f"Connection with {addr} reset by client.")
        handle_connection_reset(conn)
    except Exception as e:
        print(f"Exception with {addr}: {e}")
    finally:
        conn.close()

def broadcast(msg, recipients, topic, user_id):
    """
    Sends a message to all recipients subscribed to a specific topic.

    Parameters:
    - msg (str): The message to be sent.
    - recipients (list): A list of tuples containing the connection and recipient's topic.
    - topic (str): The topic to which the message is being sent.
    - user_id (str): The ID of the user sending the message. If None, "Unknown" is used.

    Returns:
    None
    """
    for conn, recipient_topic in recipients:
        if recipient_topic != topic: continue
        try:
            id_display = user_id or "Unknown"
            conn.send(f"[Topic {topic}] {id_display}: {msg}".encode())
        except (socket.error, socket.timeout) as e:
            logging.error(f"Error while sending message to user {id_display} on topic {topic}: {e}")

def handle_connection_reset(conn):
    """
    Handles a connection reset by updating the user status to 0.

    Parameters:
    conn (connection): The connection object.

    Returns:
    None
    """
    user_id = user_id_dict.get(conn)
    if user_id:
        update_user(user_id, 0)
    else:
        print("The connection is no longer in the dictionary.")

def update_user(identifiant, status):
    """
    Met à jour le statut d'un utilisateur dans la base de données.

    :param identifiant: L'identifiant de l'utilisateur.
    :type identifiant: str
    :param status: Le nouveau statut de l'utilisateur.
    :type status: str
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("UPDATE users SET statut = %s WHERE identifiant = %s", (status, identifiant))
            conn.commit()
    except Error as err:
        logging.error(f"MySQL error while updating status for {identifiant}: {err}")


def server(server_lock, server_running_flag, connected_clients):
    """
    This function represents the main server loop that handles client connections and commands.

    Parameters:
    - server_lock (threading.Lock): A lock object used for thread synchronization.
    - server_running_flag (list): A list containing a single boolean value indicating whether the server is running.
    - connected_clients (list): A list of tuples representing the connected clients and their associated topics.

    Returns:
    None
    """
    if not authenticate_to_server():
        return

    def handle_kill(_=None):
        with server_lock:
            server_running_flag[0] = False
        user_info_distribution_flag.set()
        for client, _ in connected_clients:
            try:
                client.send("Server is shutting down!!!".encode())
                client.close()
            except (socket.error, socket.timeout):
                pass
        print("Server has been stopped!!!")

    def handle_show(_=None):
        print("Pending requests:", *[f"- {id}: {tp}" for id, tp in pending_requests.items()])

    def handle_accept_or_refuse(command, accept=True):
        parts = command.split(" ")
        if len(parts) != 2:
            print(f"Incorrect command. Use '/{'accept' if accept else 'refuse'} identifier'.")
            return
        user_id = parts[1].strip()
        if user_id not in pending_requests:
            print(f"n pending request for {user_id}.")
            return
        conn = user_profile_dict[user_id]
        if accept:
            new_topic = pending_requests[user_id]
            old_topic = user_topic_dict[user_id]
            with server_lock:
                connected_clients.remove((conn, old_topic))
                connected_clients.append((conn, new_topic))
            user_topic_dict[user_id] = new_topic
            save_authorization(user_id, new_topic)
            conn.send(f"Welcome to the {new_topic} room!".encode())
            print(f"{user_id} - {new_topic} : accepted!")
        else:
            conn.send("Your request has been refused.".encode())
            print(f"{user_id} - {new_topic} : refused!")
        del pending_requests[user_id]

    def handle_ban_or_kick(cmd, ban=True):
        parts = cmd.split(" ")
        if len(parts) != 2:
            print(f"Invalid command. Use '/{'ban' if ban else 'kick'} id'.")
            return

        id = parts[1].strip()
        conn = user_profile_dict[id]
        apply_sanct(conn, id, 'ban' if ban else 'kick', server_lock)
        print(f"{id} {'banned' if ban else 'kicked'}.")

    def handle_shban_or_shkick(cmd, ban=True):
        print(f"{'Banned' if ban else 'Kicked'} users:")
        print("\n".join(f"- {id}" for id in (check_ban() if ban else check_kick())))

    def handle_unban_or_unkick(cmd, unban=True):
        parts = cmd.split(" ")
        if len(parts) != 2:
            print(f"Invalid command. Use '/{'unban' if unban else 'unkick'} id'.")
            return
        id = parts[1].strip()
        unban(id) if unban else unkick(id)
        
    def handle_help(_=None):
        print("\n".join([
            "Available commands:",
            "- help: Display all available commands.",
            "- /unkick identifier: Lift the kick sanction of a client.",
            "- /unban identifier: Lift the ban of a client.",
            "- shkick: Display the list of kicked clients.",
            "- shban: Display the list of banned clients.",
            "- /kick identifier: Apply a kick sanction (ban for 1 hour).",
            "- /ban identifier: Ban a client.",
            "- /refuse identifier: Refuse a room change request.",
            "- /accept identifier: Accept a room change request.",
            "- show: Display pending room change requests.",
            "- kill: Stop the server."
        ]))

    command_handlers = {
        "kill": handle_kill,
        "show": handle_show,
        "/accept": partial(handle_accept_or_refuse, accept=True),
        "/refuse": partial(handle_accept_or_refuse, accept=False),
        "/ban": partial(handle_ban_or_kick, ban=True),
        "/kick": partial(handle_ban_or_kick, ban=False),
        "shban": partial(handle_shban_or_shkick, ban=True),
        "shkick": partial(handle_shban_or_shkick, ban=False),
        "/unban": partial(handle_unban_or_unkick, unban=True),
        "/unkick": partial(handle_unban_or_unkick, unban=False),
        "help": handle_help
    }

    while server_running_flag[0]:
        try:
            cmd = input("Enter 'help' for commands : ").lower()
            handler = command_handlers.get(cmd.split()[0] if " " in cmd else cmd)
            handler(cmd) if handler else print("Invalid command. Use 'help' for commands.")
        except KeyboardInterrupt:
            print("\nServer interrupted.")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

def request_input(connection, message):
    """
    Sends a message to the client through the connection and waits for a response.

    Args:
        connection (socket): The connection object representing the client connection.
        message (str): The message to send to the client.

    Returns:
        str: The response received from the client.
    """
    connection.send(message.encode())
    return connection.recv(1024).decode()

def request_valid_input(conn, msg, valid_func):
    """
    Requests input from the client and validates it using the provided valid_func.

    Parameters:
    conn (socket): The client connection socket.
    msg (str): The message to display when requesting input.
    valid_func (function): A function that takes the input as a parameter and returns True if it is valid, False otherwise.

    Returns:
    str: The valid input received from the client.
    """
    while (inp := request_input(conn, msg)) and not valid_func(inp):
        conn.send("Invalid input. Please try again.\n".encode())
    return inp

def run_query(query, params=None):
    """
    Executes the given query on the database.

    Args:
        query (str): The SQL query to execute.
        params (tuple, optional): The parameters to pass to the query. Defaults to None.

    Raises:
        Error: If there is an error executing the query.

    Returns:
        None
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute(query, params or ())
            conn.commit()
    except Error as err:
        logging.error(f"Error executing query: {err}")

def authenticate_to_server():
    """
    Authenticates the user to the server.

    This function fetches the server credentials and prompts the user to enter their login and password.
    It validates the credentials by calling the validate_server function.
    If the credentials are valid, it logs a success message and returns True.
    If the credentials are invalid, it logs a warning message and allows the user to try again.
    If the maximum number of attempts is exceeded, it logs an error message and returns False.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    credentials = fetch_server()
    if not credentials:
        logging.info("n server credentials found. Registering new credentials.")
        insert_server(input("LOGIN: "), getpass.getpass("PASSWORD: "))
        logging.info("New credentials stored. Please restart the server.")
        return False

    for _ in range(100):
        login, password = input("Login: "), getpass.getpass("Password: ")
        if validate_server(login, password):
            logging.info("Authentication successful.")
            return True
        logging.warning("Invalid credentials. Please try again.")

    logging.error("Maximum number of attempts exceeded")
    sys.exit()

def validate_server(login, password):
    """
    Validates the server credentials by checking if the login and password match
    an entry in the 'serv' table in the database.

    Args:
        login (str): The login of the server.
        password (str): The password of the server.

    Returns:
        bool: True if the server credentials are valid, False otherwise.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM serv WHERE login = %s AND mot_de_passe = %s", (login, password))
            return cur.fetchone() is not None
    except Error as err:
        logging.error(f"MySQL error while validating server credentials: {err}")
        return False

def insert_server(login, password):
    """
    Insert server credentials into the database.

    Args:
        login (str): The login of the server.
        password (str): The password of the server.

    Raises:
        Error: If there is an error while inserting the server credentials into the database.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO serv (login, mot_de_passe) VALUES (%s, %s)", (login, password))
            conn.commit()
    except Error as err:
        logging.error(f"MySQL error while inserting server credentials: {err}")

def fetch_server():
    """
    Fetches the login and password of the server from the database.

    Returns:
        dict: A dictionary containing the login and password of the server.
              The keys are 'login' and 'mot_de_passe'.
              Returns None if there is an error retrieving the server credentials.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor(dictionary=True) as cur:
            cur.execute("SELECT login, mot_de_passe FROM serv LIMIT 1")
            return cur.fetchone()
    except Error as err:
        logging.error(f"MySQL error while retrieving server credentials: {err}")
        return None

def apply_sanct(conn, id, type_sanc, server_lock=None):
    """
    Applies a sanction to a connection.

    Args:
        conn (socket): The connection object.
        id (str): The ID of the user.
        type_sanc (str): The type of sanction to apply ("ban" or "kick").
        server_lock (threading.Lock, optional): The lock object for server synchronization. Defaults to None.
    """
    try:
        msg, log_msg = ("You have been banned!!!", f"{id} has been banned") if type_sanc == "ban" else ("You have been kicked for 1 hour!!!", f"{id} has been kicked for 1 hour")
        save_sanct(id, conn.getpeername()[0], type_sanc, server_lock)
        conn.send(msg.encode())
        logging.info(log_msg)
    except Exception as e:
        logging.error(f"Error while applying sanction: {e}")
    finally:
        try:
            conn.close()
        except Exception as close_err:
            logging.error(f"Error while closing connection: {close_err}")

def save_sanct(identifiant, adresse_ip, type_sanction, server_lock=None):
    """
    Enregistre une sanction dans la base de données.

    :param identifiant: L'identifiant de l'utilisateur sanctionné.
    :param adresse_ip: L'adresse IP de l'utilisateur sanctionné.
    :param type_sanction: Le type de sanction (kick ou ban).
    :param server_lock: Verrou du serv (optionnel).
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM sanct WHERE id = %s AND type_sanction = %s", (identifiant, type_sanction))
            conn.commit()

            if type_sanction == "kick":
                date_fin_sanction = datetime.now() + timedelta(hours=1)
                cur.execute(
                    "INSERT INTO sanct (id, adresse_ip, type_sanction, date_sanction, date_fin_sanction) VALUES (%s, %s, %s, %s, %s)",
                    (identifiant, adresse_ip, type_sanction, datetime.now(), date_fin_sanction)
                )
            elif type_sanction == "ban":
                cur.execute(
                    "INSERT INTO sanct (id, adresse_ip, type_sanction, date_sanction) VALUES (%s, %s, %s, %s)",
                    (identifiant, adresse_ip, type_sanction, datetime.now())
                )

            conn.commit()
    except Error as err:
        logging.error(f"MySQL error while connecting to the database: {err}")
        conn.rollback()

def unban(identifiant, server_lock=None):
    """
    Unbans a user identified by their 'identifiant' by deleting their ban sanction from the database.

    Args:
        identifiant (str): The identifier of the user to be unbanned.
        server_lock (Optional): A lock object used for synchronization (default: None).

    Raises:
        Error: If there is a MySQL error while connecting to the database.
        Exception: If there is an unexpected error while connecting to the database.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM sanct WHERE identifiant = %s AND type_sanction = 'ban'", (identifiant,))
            conn.commit()
            logging.info(f"{identifiant} has been unbanned.") if cur.rowcount else logging.info(f"n sanction against {identifiant}.")
    except Error as err:
        logging.error(f"MySQL error while connecting to the database: {err}")
    except Exception as err:
        logging.error(f"Unexpected error while connecting to the database: {err}")
        
def unkick(identifiant, server_lock=None):
    """
    Removes the 'kick' sanction for the specified identifier from the database.

    Args:
        identifiant (str): The identifier of the user to unkick.
        server_lock (Optional[Lock]): The lock object to synchronize access to the server (default: None).
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM sanct WHERE identifiant = %s AND type_sanction = 'kick'", (identifiant,))
            conn.commit()
            logging.info(f"{identifiant} has been unblocked.") if cur.rowcount else logging.info(f"n sanction against {identifiant}.")
    except Error as err:
        logging.error(f"MySQL error while connecting to the database: {err}")
    except Exception as err:
        logging.error(f"Unexpected error while connecting to the database: {err}")

def check_kick():
    """
    Retrieves the list of kicked clients from the database.

    Returns:
        A list of tuples containing the id and date of each kicked client.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id, date_sanction FROM sanct WHERE type_sanction = 'kick'")
            return [(row[0], row[1]) for row in cur.fetchall()]
    except Error as err:
        logging.error(f"MySQL error while retrieving kicked clients: {err}")
        return []

def check_ban():
    """
    Retrieves the IDs of clients who have been banned.

    Returns:
        list: A list of banned client IDs.
    """
    try:
        with mysql.connector.connect(**DATABASE) as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM sanct WHERE type_sanction = 'ban'")
            return [row[0] for row in cur.fetchall()]
    except Error as err:
        logging.error(f"MySQL error while retrieving banned clients: {err}")
        return []

def start_info(connected_clients, server_lock):
    """
    Starts the distribution of user information to connected clients.

    Args:
        connected_clients (list): List of connected clients.
        server_lock (threading.Lock): Lock object for thread synchronization.
    """
    global user_info_distribution_flag
    user_info_distribution_flag = threading.Event()
    user_info_distribution_flag.set()
    distribute_user_info(connected_clients, server_lock)
            
            
if __name__ == '__main__':
    port, server_running_flag, server_lock = 12345, [True], threading.Lock()
    user_info_distribution_flag = threading.Event()
    with socket.socket() as server_socket:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(99999)
        print("Server started.")

        shell_thread = threading.Thread(target=server, args=(server_lock, server_running_flag, connected_clients,))
        shell_thread.start()

        user_info_distribution_thread = threading.Thread(target=start_info, args=(connected_clients, server_lock))

        try:
            server_socket.settimeout(1.0)  

            while server_running_flag[0]:
                try:
                    connection, address = server_socket.accept()
                    print(f"Connection established with {address}")

                    client_thread = threading.Thread(target=handle_client, args=(connection, address, server_lock, server_running_flag, connected_clients))
                    client_thread.start()
                    
                    with server_lock:
                        connected_clients.append((connection, None))

                    if not user_info_distribution_thread.is_alive():
                        user_info_distribution_thread = threading.Thread(target=distribute_user_info, args=(connected_clients, server_lock))
                        user_info_distribution_thread.start()

                except socket.timeout:
                    pass

        except KeyboardInterrupt:
            print("\nServer interrupted.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        finally:
            for thread in client_threads:
                thread.join()

            if user_info_distribution_thread.is_alive():
                user_info_distribution_thread.join()

            shell_thread.join()
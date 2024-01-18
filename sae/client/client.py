from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtWidgets import *
import json, socket, sys


class Signal(QObject):
  """
  A class representing a signal.

  Attributes:
  - received (Signal): A signal indicating that a message has been received.
  - error (Signal): A signal indicating that an error has occurred.
  - update (Signal): A signal indicating that an update has occurred.

  Methods:
  None
  """
  received, error, update = Signal(str), Signal(str), Signal(list)

class Thread(QThread):
  """
  A custom QThread subclass for handling client communication.

  Args:
    client_socket (socket.socket): The client socket for communication.
    message_signal (QtCore.pyqtSignal): The signal for emitting messages.
    flag (list): A list containing a boolean flag for controlling the thread execution.
    wait_condition (QtCore.QWaitCondition): The wait condition for synchronization.
    mutex (QtCore.QMutex): The mutex for thread-safe access to shared resources.
  """

  def __init__(self, client_socket, message_signal, flag, wait_condition, mutex):
    super().__init__()
    self.client_socket, self.signal, self.flag, self.wait_condition, self.mutex = client_socket, message_signal, flag, wait_condition, mutex

  def run(self):
    try:
      while self.flag[0]:
        reply = self.client_socket.recv(1024).decode()
        if not reply: break
        self.signal.update.emit(json.loads(reply[6:])) if reply.startswith("users:") else self.signal.received.emit(reply)
    except (socket.error, socket.timeout) as e:
      self.signal.error.emit(f"Connection error: {e}")
    finally:
      self.msleep(100)
      with QMutexLocker(self.mutex): self.wait_condition.wakeAll()
      self.client_socket.close()

class Connection(QDialog):
  """
  A dialog window for server connection.

  Attributes:
    ip_entry (QLineEdit): The QLineEdit widget for entering the IP address.
    port_entry (QLineEdit): The QLineEdit widget for entering the port number.
    connect_button (QPushButton): The QPushButton widget for initiating the connection.

  Methods:
    __init__(self, parent=None): Initializes the Connection dialog window.
    connect(self): Connects to the server using the entered IP address and port number.
    is_valid_ip_port(ip, port): Checks if the entered IP address and port number are valid.
  """
  def __init__(self, parent=None):
    super().__init__(parent)
    self.setWindowTitle("Server Connection")
    self.setStyleSheet("""
      QDialog { background-color: #262626; font-family: 'Roboto', sans-serif; }
      QLabel { color: #F5F5F5; font-size: 15px; }
      QLineEdit { background-color: #303030; color: #F5F5F5; border: none; padding: 10px; margin: 10px 0; border-radius: 5px; }
      QPushButton { background-color: #3897f0; color: #F5F5F5; padding: 10px; border: none; border-radius: 5px; font-weight: 500; margin-top: 20px; }
      QPushButton:hover { background-color: #45a1f6; }
    """)
    self.resize(400, 200)
    layout = QVBoxLayout(self)
    self.ip_entry = QLineEdit(self, placeholderText="")
    self.port_entry = QLineEdit(self, placeholderText="")
    self.connect_button = QPushButton("Connect", self, clicked=self.accept)
    layout.addWidget(QLabel("IP Address:"))
    layout.addWidget(self.ip_entry)
    layout.addWidget(QLabel("Port:"))
    layout.addWidget(self.port_entry)
    layout.addWidget(self.connect_button)
    
  def connect(self):
    """
    Connects to the server using the entered IP address and port number.

    Returns:
      tuple: A tuple containing the IP address and port number if they are valid, otherwise (None, None).
    """
    ip = self.ip_entry.text()
    port = self.port_entry.text()
    return (ip, int(port)) if self.is_valid_ip_port(ip, port) else (None, None)
  
  @staticmethod
  def is_valid_ip_port(ip, port):
    """
    Checks if the entered IP address and port number are valid.

    Args:
      ip (str): The IP address to validate.
      port (str): The port number to validate.

    Returns:
      bool: True if the IP address and port number are valid, False otherwise.
    """
    return (lambda x: len(x) == 4 and all(0 <= int(i) <= 255 for i in x))(ip.split('.')) and port.isdigit() and 0 < int(port) < 65536


class TopicDialog(QDialog):
  """
  A dialog window for changing the topic.

  Args:
    options (list): A list of options for the topic selection.
    parent (QWidget, optional): The parent widget. Defaults to None.
  """

  def __init__(self, options, parent=None):
    super().__init__(parent)
    self.setWindowTitle("Change Topic")
    self.setStyleSheet("""
      QDialog { background-color: #262626; font-family: 'Roboto', sans-serif; }
      QLabel { color: #F5F5F5; font-size: 15px; }
      QComboBox { background-color: #303030; color: #F5F5F5; border: none; padding: 10px; margin: 10px 0; border-radius: 5px; min-width: 300px; }
      QPushButton { background-color: #3897f0; color: #F5F5F5; padding: 10px; border: none; border-radius: 5px; font-weight: 500; margin-top: 20px; }
      QPushButton:hover { background-color: #45a1f6; }
    """)
    layout = QVBoxLayout(self)
    self.comboBox = QComboBox(self)
    self.comboBox.addItems(options)
    self.connect_button = QPushButton("Connect", self, clicked=self.accept)
    layout.addWidget(QLabel("Select a new topic:"))
    layout.addWidget(self.comboBox)
    layout.addWidget(self.connect_button)

  def selectedTopic(self):
    """
    Get the currently selected topic.

    Returns:
      str: The currently selected topic.
    """
    return self.comboBox.currentText()

class MySocketGUI(QMainWindow):
  """
  A graphical user interface for the MySocket client application.

  Attributes:
    chat_text (QTextEdit): The text area for displaying chat messages.
    message_entry (QLineEdit): The input field for entering chat messages.
    send_button (QPushButton): The button for sending chat messages.
    users_list_widget (QListWidget): The list widget for displaying connected users.
    dock_widget (QDockWidget): The dock widget for displaying the list of connected users.
    toggle_button (QPushButton): The button for toggling the visibility of the dock widget.
    client_socket (socket.socket): The socket for communication with the server.
    receive_thread (Thread): The thread for receiving messages from the server.
  """

  def __init__(self):
    super().__init__()

class MySocketGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("MySocket")
        self.setGeometry(100, 100, 600, 400)
        self.showMaximized()
        self.setStyleSheet("""
            QWidget { background-color: #2C3E50; color: #ECF0F1; font-family: 'Roboto', sans-serif; }
            QPushButton { background-color: #3498DB; color: white; padding: 5px; border-radius: 5px; }
            QPushButton:hover { background-color: #2980B9; }
            QLabel { color: #ECF0F1; }
            QTextEdit, QLineEdit, QListWidget { background-color: #34495E; color: #ECF0F1; border: none; }
        """)

        # Chat layout
        header_label = QLabel("<h1>MySocket</h1>")
        header_label.setAlignment(Qt.AlignCenter)

        self.chat_text = QTextEdit(self)
        self.chat_text.setReadOnly(True)

        self.message_entry = QLineEdit(self)
        self.message_entry.returnPressed.connect(self.send_message) 

        self.send_button = QPushButton("Send", self)
        self.send_button.setFixedWidth(100)  
        self.send_button.clicked.connect(self.send_message)

        chat_layout = QVBoxLayout()
        chat_layout.addWidget(header_label)
        chat_layout.addWidget(self.chat_text)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.message_entry)
        bottom_layout.addWidget(self.send_button)

        chat_layout.addLayout(bottom_layout)

        self.users_widget = QWidget()
        
        titre_label = QLabel("Connected Clients", self)
        titre_label.setAlignment(Qt.AlignCenter)

        self.users_list_widget = QListWidget(self)
        self.users_list_widget.setMinimumWidth(150)
        self.users_list_widget.setMaximumWidth(200)
        self.users_list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.change_button = QPushButton("Change Topic", self)  
        self.change_button.clicked.connect(self.change_topic)

        users_layout = QVBoxLayout(self.users_widget)
        users_layout.addWidget(titre_label)
        users_layout.addWidget(self.users_list_widget)
        users_layout.addWidget(self.change_button)  

        # Dock widget
        self.dock_widget = QDockWidget(self)
        self.dock_widget.setWidget(self.users_widget)
        self.dock_widget.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.dock_widget)

        # Toggle button
        self.toggle_button = QPushButton(">", self)
        self.toggle_button.clicked.connect(self.toggle_dock)
        self.toggle_button.setStyleSheet("""
            font-family: 'Roboto', sans-serif;
            font-size: 24px;
            background-color: #3498DB;
            color: white;
            padding: 5px;
            border-radius: 5px;
        """)

        # Main layout
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.toggle_button) 
        main_layout.addLayout(chat_layout)
        self.central_widget = QWidget(self)
        self.central_widget.setLayout(main_layout)
        self.setCentralWidget(self.central_widget)

        self.mutex = QMutex()
        self.client_socket = socket.socket()
        self.flag = [True]
        self.wait_condition = QWaitCondition()
        self.receive_thread = Thread(self.client_socket, Signal(), self.flag, self.wait_condition, self.mutex)
        self.receive_thread.signal.received.connect(self.handle_message)
        self.receive_thread.signal.update.connect(self.update_widget)
        self.connect_to_server()

    def toggle_dock(self):
        if self.dock_widget.isVisible():
            self.dock_widget.hide()
            self.toggle_button.setText(">")
        else:
            self.dock_widget.show()
            self.toggle_button.setText("<")

    def connect_to_server(self):
        while True:
            connection_dialog = Connection(self)
            if connection_dialog.exec() != QDialog.Accepted:
                sys.exit()

            host, port = connection_dialog.connect()
            if not (host and port and self.valid_ip(host, port)):
                QMessageBox.warning(self, "Error", "Invalid IP address or port. Please try again.")
                continue

            try:
                self.client_socket.connect((host, port))
                self.receive_thread.start()
                break
            except Exception as e:
                self.show_error_dialog(f"Unable to connect to the server: {e}")
                
    def formatpro(self, data):
        return "\n".join(f"{f} : {d}" for f, d in zip(["Name", "First Name", "Identifier", "IP Address", "Email Address"], data)) if len(data) >= 5 else ""

    def handle_profile(self, info):
        msg_type = "Profile" if info and isinstance(info, list) else "Warning"
        msg_text = self.formatpro(info) if msg_type == "Profile" else "Profile data is not valid."
        QMessageBox.information(self, msg_type, msg_text)

    def show_information(self, title, profile_info):
        msg_box = QMessageBox(self, windowTitle=title, text=self.formatpro(profile_info), icon=QMessageBox.Information)
        msg_box.setStyleSheet("""
            QMessageBox { background-color: #ECF0F1; border: 2px solid #3498DB; }
            QLabel { color: #2C3E50; }
            QPushButton { background-color: #3498DB; color: white; padding: 5px; border-radius: 5px; }
            QPushButton:hover { background-color: #2980B9; }
        """)
        msg_box.addButton(QMessageBox.Ok)
        msg_box.exec_()

    def valid_ip(self, ip, port_text):
        if not str(port_text).isdigit(): return False
        try:
            socket.inet_pton(socket.AF_INET, ip)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
                test_socket.settimeout(1)
                test_socket.connect((ip, int(port_text)))
            return True
        except (socket.error, ValueError):
            return False

        
    def valid_port(self, port):
        return str(port).isdigit() and 0 < int(port) < 65536
    

    def show_error_dialog(self, msg):
        self.flag[0], self.client_socket = False, self.client_socket.close()
        QMetaObject.invokeMethod(self, "_show_error", Qt.QueuedConnection, Q_ARG(str, msg))

    def send_message(self):
        self.client_socket.send(self.message_entry.text().encode())
        self.message_entry.setText("")

    def change_topic(self):
        topic_dialog = TopicDialog(["Général", "BlaBla", "Comptabilité", "Informatique", "Marketing"], self)
        if topic_dialog.exec_() == QDialog.Accepted:
            self.client_socket.send(f"change:{topic_dialog.selectedTopic()}".encode())
            self.message_entry.clear()
    
    @Slot(str)
    def handle_message(self, msg):
        if msg.startswith("users:"):
            self.update_widget(json.loads(msg[6:]))
        elif msg.lower().startswith("profile:"):
            profile_data = json.loads(msg.split(":", 1)[1])
            self.handle_profile(profile_data) if isinstance(profile_data, list) and profile_data else QMessageBox.warning(self, "Avertissement", "Les données du profil ne sont pas valides.")
        else:
            self.chat_text.append(msg)
            cursor = self.chat_text.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.chat_text.setTextCursor(cursor)
       
    @Slot(str)
    def _show_error(self, msg):
        QMessageBox.critical(None, "Error", msg)

    @Slot(list)
    def update_widget(self, users_info):
        self.users_list_widget.clear()
        for user, status in users_info:
            self.users_list_widget.addItem(QListWidgetItem(f"{user} - {'Connected' if status == 1 else 'Disconnected'}"))
        for i in range(self.users_list_widget.count()):
            item = self.users_list_widget.item(i)
            username, _ = item.text().split(" - ")
            item.setText(f"{username} - {'Connected' if any(user_stat == (username, 1) for user_stat in users_info) else 'Disconnected'}")

    def closeEvent(self, event):
        if QMessageBox.question(self, 'Confirmation', 'Are you sure you want to quit?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.flag[0] = False
            self.client_socket.close()
            with QMutexLocker(self.mutex):
                self.wait_condition.wakeAll()
            self.receive_thread.finished.connect(self.receive_thread.quit)
            self.receive_thread.quit()
            self.receive_thread.wait()
            event.accept()
        else:
            event.ignore()

if __name__ == "__main__":
    app, client_gui = QApplication(sys.argv), MySocketGUI()
    client_gui.show()
    sys.exit(app.exec_())
import os
import hashlib
import json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QVBoxLayout, QDialog, QWidget,
    QPushButton, QLineEdit, QAction, QToolBar, QLabel, QMenu, QMessageBox, QInputDialog,QScrollArea,QGridLayout
)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtNetwork import QNetworkProxy
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QUrl


class WebBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(r"D:\IDE PROJECTS\Python\COLLEGE PROJECTS\browser.ico"))        
        self.setWindowTitle("Web Browser")
        self.setGeometry(100, 100, 1200, 800)
        
        self.master_password_file = "master_password.txt"  # Path to store the password hash

        self.credentials_file = "credentials.json"
        self.history_file = "history.txt"
        self.bookmarks_file = "bookmarks.txt"
        self.master_password_file = "master_password.txt"

        self.credentials = {}
        self.history = []
        self.bookmarks = []  # Initialize bookmarks

        self.load_credentials()
        self.load_history()
        self.load_bookmarks()  # Load bookmarks from file

        # Check if master password is set
        self.check_master_password()

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.setCentralWidget(self.tabs)

        self.create_menu_bar()
        self.create_toolbar()
        self.add_new_tab("https://www.google.com")

    ### Master Password ###
    def check_master_password(self):
        if not os.path.exists(self.master_password_file):
            # Prompt to set a master password if not already set
            QMessageBox.information(self, "Set Master Password", "You need to set a master password.")
            while True:
                password, ok = QInputDialog.getText(
                    self, "Set Master Password", "Enter a new master password:", QLineEdit.Password
                )
                if not ok or not password.strip():
                    QMessageBox.warning(self, "Invalid Input", "Master password cannot be empty.")
                    continue

                confirm_password, ok_confirm = QInputDialog.getText(
                    self, "Confirm Master Password", "Re-enter the master password:", QLineEdit.Password
                )
                if not ok_confirm or password != confirm_password:
                    QMessageBox.warning(self, "Mismatch", "Passwords do not match. Try again.")
                    continue

                # Hash and save the master password
                hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
                with open(self.master_password_file, "w") as f:
                    f.write(hashed_password)




                QMessageBox.information(self, "Success", "Master password has been set.")
                break

    
    
    def view_saved_credentials(self):
        """Display saved credentials after validating the master password."""
        if not self.validate_master_password():  # Validate master password first
            return  # Exit if the validation fails

        if not self.credentials:
            QMessageBox.information(self, "No Credentials", "No saved credentials found.")
            return

        # Create a dialog to show credentials
        dialog = QDialog(self)
        dialog.setWindowTitle("Saved Credentials")
        layout = QVBoxLayout()

        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QGridLayout(scroll_widget)

        for i, (url, data) in enumerate(self.credentials.items()):
            website_label = QLabel(f"Website: {url}")
            username_label = QLabel(f"Username: {data['username']}")
            password_label = QLabel(f"Password: {data['password']}")

            scroll_layout.addWidget(website_label, i, 0)
            scroll_layout.addWidget(username_label, i, 1)
            scroll_layout.addWidget(password_label, i, 2)

        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.close)
        layout.addWidget(close_button)

        dialog.setLayout(layout)
        dialog.exec_()


    def validate_master_password(self):
        if not os.path.exists(self.master_password_file):
            QMessageBox.critical(self, "Error", "Master password file is missing.")
            return False

        # Read the stored hashed password
        with open(self.master_password_file, "r") as f:
            stored_password = f.read().strip()

        # Prompt for the master password
        input_password, ok = QInputDialog.getText(
            self, "Master Password", "Enter your master password to proceed:", QLineEdit.Password
        )
        if not ok:
            return False

        # Hash the input password
        hashed_input_password = hashlib.sha256(input_password.encode('utf-8')).hexdigest()

        # Debugging: Print the stored hash and the hashed input password for comparison

        # Compare the hashes
        if hashed_input_password != stored_password:
            QMessageBox.warning(self, "Access Denied", "Invalid master password.")
            return False

        QMessageBox.information(self, "Access Granted", "Password is correct.")
        return True


    def create_menu_bar(self):
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("File")

        new_tab_action = QAction("New Tab", self)
        new_tab_action.triggered.connect(lambda: self.add_new_tab("https://www.google.com"))
        file_menu.addAction(new_tab_action)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        
        # Bookmarks menu
        self.bookmarks_menu = menu_bar.addMenu("Bookmarks")

        add_bookmark_action = QAction("Add Bookmark", self)
        add_bookmark_action.triggered.connect(self.add_bookmark)
        self.bookmarks_menu.addAction(add_bookmark_action)

        self.update_bookmarks_menu()

        # History menu
        history_menu = menu_bar.addMenu("History")

        view_history_action = QAction("View History", self)
        view_history_action.triggered.connect(self.view_history)
        history_menu.addAction(view_history_action)

        clear_history_action = QAction("Clear History", self)
        clear_history_action.triggered.connect(self.clear_history)
        history_menu.addAction(clear_history_action)

        # Credentials menu (View Passwords beside Bookmarks)
        
    def load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, "r") as f:
                return [line.strip() for line in f.readlines()]
        return []

    def save_history(self):
        with open(self.history_file, "w") as f:
            f.writelines(url + "\n" for url in self.history)

    def load_bookmarks(self):
        """Load bookmarks from the bookmarks file."""
        if os.path.exists(self.bookmarks_file):
            with open(self.bookmarks_file, "r") as f:
                self.bookmarks = [line.strip() for line in f.readlines()]
        else:
            self.bookmarks = []

    def save_bookmarks(self):
        """Save bookmarks to the bookmarks file."""
        with open(self.bookmarks_file, "w") as f:
            f.writelines(f"{bookmark}\n" for bookmark in self.bookmarks)
    def load_credentials(self):
        """Load credentials from the JSON file properly."""
        if os.path.exists(self.credentials_file):
            with open(self.credentials_file, "r") as f:
                try:
                    self.credentials = json.load(f)
                except json.JSONDecodeError:
                    QMessageBox.warning(self, "Error", "Failed to load credentials. The file may be corrupted.")
                    self.credentials = {}  # Reset to empty if loading fails
        else:
            self.credentials = {}  # Initialize if file doesn't exist

    def save_credentials(self):
        """Save the credentials to the JSON file."""
        with open(self.credentials_file, "w") as f:
            try:
                json.dump(self.credentials, f, indent=4)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save credentials: {e}")
                
    def create_menu_bar(self):
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("File")

        new_tab_action = QAction("New Tab", self)
        new_tab_action.triggered.connect(lambda: self.add_new_tab("https://www.google.com"))
        file_menu.addAction(new_tab_action)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # Bookmarks menu
        self.bookmarks_menu = menu_bar.addMenu("Bookmarks")

        add_bookmark_action = QAction("Add Bookmark", self)
        add_bookmark_action.triggered.connect(self.add_bookmark)
        self.bookmarks_menu.addAction(add_bookmark_action)

        self.update_bookmarks_menu()

        # History menu
        history_menu = menu_bar.addMenu("History")

        view_history_action = QAction("View History", self)
        view_history_action.triggered.connect(self.view_history)
        history_menu.addAction(view_history_action)

        clear_history_action = QAction("Clear History", self)
        clear_history_action.triggered.connect(self.clear_history)
        history_menu.addAction(clear_history_action)

    def update_bookmarks_menu(self):
        """Update the bookmarks menu dynamically."""
        self.bookmarks_menu.clear()

        add_bookmark_action = QAction("Add Bookmark", self)
        add_bookmark_action.triggered.connect(self.add_bookmark)
        self.bookmarks_menu.addAction(add_bookmark_action)

        for bookmark in self.bookmarks:
            bookmark_menu = QMenu(bookmark, self)

            open_action = QAction("Open", self)
            open_action.triggered.connect(lambda checked, url=bookmark: self.add_new_tab(url))
            bookmark_menu.addAction(open_action)

            remove_action = QAction("Remove", self)
            remove_action.triggered.connect(lambda checked, url=bookmark: self.remove_bookmark(url))
            bookmark_menu.addAction(remove_action)

            self.bookmarks_menu.addMenu(bookmark_menu)

    ### Toolbar ###

    def create_toolbar(self):
        self.toolbar = QToolBar("Navigation")
        self.addToolBar(self.toolbar)
    
        self.back_btn = QPushButton("<--")
        self.back_btn.clicked.connect(self.navigate_back)
        self.toolbar.addWidget(self.back_btn)

        self.forward_btn = QPushButton("-->")
        self.forward_btn.clicked.connect(self.navigate_forward)
        self.toolbar.addWidget(self.forward_btn)

        self.reload_btn = QPushButton("Reload")
        self.reload_btn.clicked.connect(self.reload_page)
        self.toolbar.addWidget(self.reload_btn)

        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.toolbar.addWidget(self.url_bar)

        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.navigate_to_url)
        self.toolbar.addWidget(self.go_btn)
        
        self.view_passwords_btn = QPushButton("view passwd")
        self.view_passwords_btn.clicked.connect(self.view_saved_credentials)
        self.toolbar.addWidget(self.view_passwords_btn)

        self.status = QLabel()
        self.statusBar().addWidget(self.status)

    ### Tab Management ###

    def add_new_tab(self, url):
        browser_tab = QWebEngineView()
        browser_tab.setUrl(QUrl(url))
        browser_tab.urlChanged.connect(self.update_url_bar)
        browser_tab.loadFinished.connect(lambda: self.check_for_login_form(browser_tab))
        browser_tab.loadFinished.connect(lambda: self.update_tab_title(browser_tab))

        i = self.tabs.addTab(browser_tab, "New Tab")
        self.tabs.setCurrentIndex(i)

        # Add to history
        self.add_to_history(url)

    def close_tab(self, index):
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)

    ### URL Bar and Navigation ###

    def update_tab_title(self, browser_tab):
        i = self.tabs.indexOf(browser_tab)
        if i >= 0:
            self.tabs.setTabText(i, browser_tab.title())

    def update_url_bar(self, url=None):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_url = current_tab.url()
            self.url_bar.setText(current_url.toString())
            self.add_to_history(current_url.toString())

    def navigate_to_url(self):
        input_text = self.url_bar.text().strip()
        if input_text.startswith("http://") or input_text.startswith("https://"):
            url = input_text
        elif "." in input_text:
            url = "http://" + input_text
        else:
            url = f"https://www.google.com/search?q={QUrl.toPercentEncoding(input_text).data().decode()}"

        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_tab.setUrl(QUrl(url))

        self.add_to_history(url)

    ### History Management ###

    def add_to_history(self, url):
        if url not in self.history:
            self.history.append(url)
            self.save_history()

    def view_history(self):
        history_str = "\n".join(self.history) if self.history else "No history available."
        QMessageBox.information(self, "History", history_str)

    def clear_history(self):
        self.history.clear()
        self.save_history()
        QMessageBox.information(self, "History Cleared", "Browsing history has been cleared.")

    ### Bookmarks Management ###

    def add_bookmark(self):
        """Add the current URL to the bookmarks."""
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            url = current_tab.url().toString()
            if url not in self.bookmarks:
                self.bookmarks.append(url)
                self.save_bookmarks()
                self.update_bookmarks_menu()
                QMessageBox.information(self, "Bookmark Added", f"Bookmarked: {url}")
            else:
                QMessageBox.information(self, "Bookmark Exists", f"Already bookmarked: {url}")

    def remove_bookmark(self, url):
        """Remove a bookmark."""
        if url in self.bookmarks:
            self.bookmarks.remove(url)
            self.save_bookmarks()
            self.update_bookmarks_menu()
            QMessageBox.information(self, "Bookmark Removed", f"Removed bookmark: {url}")
        else:
            QMessageBox.warning(self, "Error", "Bookmark not found.")
    ### Login Management ###

    def check_for_login_form(self, browser_tab):
        url = browser_tab.url().toString()
        domain_name = self.extract_website_name(url)

        # Auto-fill credentials if available
        if domain_name in self.credentials:
            username = self.credentials[domain_name]["username"]
            password = self.credentials[domain_name]["password"]

            # More robust JavaScript for form auto-fill
            script = f"""
                (function() {{
                    let usernameField = document.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[id*="user"], input[placeholder*="user"], input[placeholder*="email"]');
                    let passwordField = document.querySelector('input[type="password"], input[name*="pass"], input[id*="pass"], input[placeholder*="pass"]');
                    if (usernameField && passwordField) {{
                        usernameField.value = "{username}";
                        passwordField.value = "{password}";
                    }}
                }})();
            """
            browser_tab.page().runJavaScript(script)

        # Detect login forms and ask to save credentials if needed
        def detect_login_form(js_result):
            if js_result:
                username, ok_username = QInputDialog.getText(self, "Save Login", "Enter Username:")
                if not ok_username:
                    return
                password, ok_password = QInputDialog.getText(self, "Save Login", "Enter Password:", QLineEdit.Password)
                if not ok_password:
                    return

                # Prompt user for a simplified website name
                website_name, ok_website = QInputDialog.getText(self, "Website Name", "Enter the website name:")
                if not ok_website:
                    return

                # Save credentials
                if website_name not in self.credentials:
                    self.credentials[website_name] = {}

                self.credentials[website_name]["username"] = username
                self.credentials[website_name]["password"] = password
                self.save_credentials()
                QMessageBox.information(self, "Login Saved", f"Your login information has been saved for {website_name}.")

        # JavaScript to detect login forms
        browser_tab.page().runJavaScript("""
            !!document.querySelector('input[type="text"], input[type="email"]') && !!document.querySelector('input[type="password"]');
        """, detect_login_form)

    def extract_website_name(self, url):
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]  # Remove port if present
        domain_name = domain.replace("www.", "")  # Remove "www." prefix
        return domain_name


    ### Navigation Buttons ###

    def navigate_back(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_tab.back()

    def navigate_forward(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_tab.forward()

    def reload_page(self):
        current_tab = self.tabs.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_tab.reload()


if __name__ == "__main__":
    app = QApplication([])
    browser = WebBrowser()
    browser.show()
    app.exec_()
    
    
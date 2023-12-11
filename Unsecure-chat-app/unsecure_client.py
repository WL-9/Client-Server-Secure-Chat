import socket
import tkinter as tk
from tkinter import scrolledtext
import threading
import logging
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, filename='client.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')

class ClientApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Client's Application")
        self.master.geometry("400x300")
        self.master.configure(bg='black')

        # Styling
        font_style = ("Arial", 12)
        text_color = 'white'

        # Main frame
        main_frame = tk.Frame(master, padx=10, pady=10, bg='black')
        main_frame.pack(expand=True, fill='both')

        # Text box for messages
        self.messages_area = scrolledtext.ScrolledText(main_frame, state='disabled', font=font_style, bg='black', fg=text_color)
        self.messages_area.pack(expand=True, fill='both')

        # Lower frame for entry and button
        lower_frame = tk.Frame(main_frame, bg='black')
        lower_frame.pack(fill='x')

        # Entry box for typing messages with grey background
        self.entry_message = tk.Entry(lower_frame, font=font_style, bg='grey', fg='black')
        self.entry_message.pack(side='left', expand=True, fill='x')
        self.entry_message.bind("<Return>", self.send_message)

        # Send button with navy blue background and white text
        self.send_button = tk.Button(lower_frame, text="Send", command=self.send_message, bg='navy', fg='white')
        self.send_button.pack(side='right')

        self.client_socket = None

        threading.Thread(target=self.start_client, daemon=True).start()
        logging.info("Client started and attempting to connect to server.")

    def insert_message(self, sender, message):
        self.messages_area.configure(state='normal')

        # Get the current time in hours and minutes
        current_time = datetime.datetime.now().strftime("%H:%M")

        # Configure tags for message bubbles
        # For sent messages (dark green bubble, right aligned)
        self.messages_area.tag_configure('sent', background='#35530A', justify='right', 
                                        lmargin1=50, lmargin2=400, rmargin=50, 
                                        spacing3=5, wrap='word', relief='raised', borderwidth=6)
        
        # For received messages (dark blue bubble, left aligned)
        self.messages_area.tag_configure('received', background='#000033', justify='left', 
                                        lmargin1=50, lmargin2=50, rmargin=400, 
                                        spacing3=5, wrap='word', relief='raised', borderwidth=6)

        # Configure tags for the timestamp
        # Small, grey text aligned to the right for sent messages
        self.messages_area.tag_configure('timestamp_sent', foreground='grey', font=('Arial', 8), justify='right')
        # Small, grey text aligned to the left for received messages
        self.messages_area.tag_configure('timestamp_received', foreground='grey', font=('Arial', 8), justify='left')

        # Inserting newline for spacing before each message bubble
        self.messages_area.insert(tk.END, "\n", "space_tag")

        # Determine the tags based on sender and format the message
        message_tag = 'sent' if sender == "You" else 'received'
        timestamp_tag = 'timestamp_sent' if sender == "You" else 'timestamp_received'
        formatted_message = f"{message}\n"

        # Inserting the message with the bubble style
        self.messages_area.insert(tk.END, formatted_message, message_tag)

        # Inserting the timestamp
        self.messages_area.insert(tk.END, f"{current_time}  ", timestamp_tag)

        self.messages_area.configure(state='disabled')
        self.messages_area.yview(tk.END)
        
    def send_message(self, event=None):
        message = self.entry_message.get()
        if message:
            try:
                # Sending message in plain text over a non-SSL socket
                self.client_socket.sendall(message.encode('utf8'))
                self.insert_message("You", message)
                self.entry_message.delete(0, tk.END)
                logging.info("Message sent to server.")
            except Exception as e:
                logging.error(f"Failed to send message: {e}")
                self.insert_message("Client", "Failed to send message.")

    def start_client(self):
        try:
            # Connecting without SSL context
            self.client_socket = socket.create_connection(('localhost', 9999))
            logging.info("Connected to server.")

            # Start thread for receiving messages
            receive_thread = threading.Thread(target=self.receiving_messages)
            receive_thread.start()
        except Exception as e:
            logging.error(f"Client startup error: {e}")
            self.insert_message("Client", f"An error occurred: {e}")

    def receiving_messages(self):
        try:
            while True:
                message = self.client_socket.recv(1024)
                if not message:
                    break
                # Displaying received message in plain text
                self.insert_message("Partner", message.decode('utf8'))
                logging.info("Message received from server.")
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            self.insert_message("Client", f"Error receiving message: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
                self.insert_message("Client", "Connection closed.")
                logging.info("Server connection closed.")

root = tk.Tk()
app = ClientApp(root)
root.mainloop()
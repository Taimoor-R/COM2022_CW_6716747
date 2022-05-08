import sys
import getopt
import socket
import random
import queue
import base64
import hashlib
import psycopg2
from cryptography.fernet import Fernet
from threading import Thread
import os
import helper
import binascii
import time
#from mttkinter import *
from tkinter import *
#import mttkinter as tkinter
#import tkinter as tk
from tkinter import ttk
from queue import Queue, Full, Empty
from tkinter import filedialog as fd
from tkinter.messagebox import showinfo

def usernamesearch(usr,name): #searches if the user esistes in the data base if true returns true.
    name = "'"+name+"'"
    usr.execute("SELECT username FROM userdata WHERE EXISTS( SELECT * FROM userdata WHERE username=%s)" % (name))
    if ((usr.fetchone()) == None):
        print("WE ARE FALSE")
        return False
    else:
        return True

def usersearch(usr, name, key): # searches for the usener name and key it they both are true retruns true
    #usr.execute('SELECT COUNT(*) FROM userdata WHERE username = %s AND password = %s' % (name,key))
    key = "'"+key+"'"
    name = "'"+name+"'"
    usr.execute("SELECT username, password FROM userdata WHERE EXISTS( SELECT * FROM userdata WHERE username=%s AND password=%s)" % (name,key))
    if ((usr.fetchone()) == None):
        return False
    else:
        return True



class Client:
    def __init__(self, username, dest, port, root, key):
        self.server_addr = dest # stores server addr
        self.server_port = port # stores server port
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(None) # set time out to none
        self.sock.bind(('', random.randint(10000, 40000)))
        self.name = username # stores username of current user
        self.retransmission = 4 # Specifies Max number of retransmisions
        self.ack_list = Queue(0) # acknowledgements queue to store a list of acknowledgements
        self.packetinorder = Queue(0) # stores the packets recived in a queue so they can be retrived in order
        self.root = root # store the tinker variable/ console root
        self.root.geometry('400x390') #sets console width and height for GUI
        self.root.minsize(400, 390) # specifies min dims
        self.root.maxsize(400, 390) # specifies max dims
        #self.bg = PhotoImage(file = "chat.png")
        self.label = Label(root) # creates a label
        self.label.place(x=0,y=0, relwidth=1,relheight=1) # adjusts positon of label
        self.messages_frame = Frame(root) # creates frame
        self.my_msg = StringVar()  # For the messages to be sent.
        self.my_msg.set("Type your messages here.") # prints console message on GUI
        self.scrollbar = Scrollbar(self.messages_frame)  # To navigate through past messages.
        # Following will contain the messages.
        self.msg_list = Listbox(self.messages_frame, height=15, width=50, fg = '#228B22',yscrollcommand=self.scrollbar.set) # sets dim for GUI
        self.scrollbar.pack(side=RIGHT, fill=Y) # creates the postioning of the scrollbar
        self.msg_list.pack(side=LEFT, fill=BOTH) # postions the message display box
        self.msg_list.pack()
        self.messages_frame.pack()


        self.options = [ # creates options for a selection bar in GUI
        "Birthday",
        "Wedding",
        "House Warming",
        "Christmas Party"
        ]
        self.filename = StringVar() # variable to store file name
        self.opmsg = StringVar() # variable to display message
        self.opmsg.set("Select Invitation Type")
        self.OptionMenu = OptionMenu(root, self.opmsg,*self.options, command = self.invite_selection) # creates option menu
        self.OptionMenu.config(fg = '#228B22') # sets the foreground color
        self.OptionMenu["menu"].config(fg='#228B22')
        self.OptionMenu.pack(pady =5) #sets postioning of the option menu
        self.entry_field = Entry(root, fg = '#228B22', textvariable=self.my_msg) # creates an entry feild
        self.entry_field.bind('<FocusIn>', self.on_entry_click) # binds it with a onclick action
        #self.entry_field.bind("<Return>", self.start)
        self.entry_field.pack()
        self.send_button = Button(self.root, text="Send", command=self.start,bg = '#228B22', fg = '#228B22') # creates a send button
        self.send_button.bind("<Return>", self.start) # binds it to start the self.start function
        self.send_button.pack()

        self.send_button1 = Button(self.root, text="Quit", command=lambda:[self.quitmsg(),self.quit()],fg = '#228B22') # creation and styling of the quit button
        self.send_button1.pack(side= RIGHT,padx = 10)
        #self.open_button = Button(root,text='Open a File',command=self.file_selection_button)
        #self.open_button.pack(expand=True)


    def invite_selection(self,event): # invite selection function stores and displays invites avalible
        if self.opmsg.get() == "Birthday":
            self.filename.set("Birthday.txt")
        if self.opmsg.get() == "Wedding":
            self.filename.set("Wedding.txt")
        if self.opmsg.get() == "House Warming":
            self.filename.set("House_Warming.txt")
        if self.opmsg.get() == "Christmas Party":
            self.filename.set( "Christmas_party.txt")

    def send_ack_packet(self,seqno):
        Ack = helper.make_packet("ACK", int(seqno)+1, "")
        #bytes_to_send = str.encode(Ack)
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(Ack.encode('utf-8'))
        #bytes_to_send = self.encrypt_message(Ack)
        self.sock.sendto(
            bytes_to_send, (self.server_addr, self.server_port)
        )
        print("PACKET SENT[TAIMOOR CLIENT] ---->", Ack)

    def send_start_packet(self,sseq): # function to make and send a start packet to initiate transfer of packets
        Start = helper.make_packet("START", sseq, "") # sends START and sequence number
        #bytes_to_send = str.encode(Start)
        #bytes_to_send = self.encrypt_message(Start)
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(Start.encode('utf-8'))
        #self.msg_list.insert(END, "Packet Sent: " ,Start)
        #print("Start packet sent")
        self.sock.sendto(
            bytes_to_send, (self.server_addr, self.server_port)
        )  # sending packet to the server
        print("PACKET SENT[TAIMOOR CLIENT] ---->", Start)
    def send_end_packet(self, seqno): # function to make and send a end packet to initiate transfer of packets
        packet = helper.make_packet("END", seqno, "") # sends END and sequence number
        #bytes_to_send = str.encode(packet)
        #bytes_to_send = self.encrypt_message(packet)
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(packet.encode('utf-8'))
        self.sock.sendto(
            bytes_to_send, (self.server_addr, self.server_port)
        )  # sending packet to the server
        #self.msg_list.insert(END, "Packet Sent: " ,packet)
            #self.send_end_packet(seqno)
        print("PACKET SENT[TAIMOOR CLIENT] ---->", packet)
    def send_message(self, message, content):
        ''' used to create and send message'''
        msg = "%s$;%d$;%s" % (message,len(content),content) # makes body of packet as described in RFC: 2022

        #print(msg)
        seqno = random.randint(1,20)  # creates an instance of random sequenc number for each communication
        acked = True # acked set to true to keep loop running as it recives acknowledgements
        transmits = 0 # number of transmits = 0
        while acked:
            if transmits == self.retransmission:  # checks if max amount of retransmits has been made
                break
            try:
                tuple_ack = self.ack_list.get(timeout=0.3) # retrive ack form ack_list queue and wait for a 0.3 ms time out
                if tuple_ack[0] == (seqno+1): # check to see if ACK recived is the right one for the last packet sent as it should be sequence number +1
                    acked = False # set ack to true
                    break
            except queue.Empty: # if queue is empty the ack is set to false and the data packet is sent again after timeout of 0.3 seconds
                acked = True
                self.send_start_packet(seqno)
            transmits = transmits + 1 # increments number of retransmits
        #print("Transmits start ", transmits)
        #print("Message recived")
        seqno = seqno + 1 # increments the sequence number by one
        packet = helper.make_packet("DATA", seqno, msg)  # making packet of that message
        #print("Packet: ", packet)
        #cpacket = packet #for forced checksum
        #packet = packet + "1" #forced checksum
        #print("Checksum Force Modified in Packet: ", cpacket)
        #bytes_to_send = str.encode(cpacket)
        #self.msg_list.insert(END, "Packet Sent: " ,packet)
        #print("hellp")
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(packet.encode('utf-8'))
        #bytes_to_send = str.encode(packet)
        #bytes_to_send = self.encrypt_message(packet)
        acked = True
        transmits = 0  # resent the number of tranmits to 0
        while acked:
            if transmits == self.retransmission: # checks if max amount of retransmits has been made
                break
            try:
                tuple_ack = self.ack_list.get(timeout=0.3) # retrive ack form ack_list queue and wait for a 0.3 ms time out
                if tuple_ack[0] == (seqno+1): # check to see if ACK recived is the right one for the last packet sent as it should be sequence number +1
                    acked = False
                    break
            except queue.Empty: # if queue is empty the ack is set to false and the data packet is sent again after timeout of 0.3 seconds
                acked = True
                #bytes_to_send = str.encode(packet)
                bytes_to_send = fernet.encrypt(packet.encode('utf-8'))
                #bytes_to_send = self.encrypt_message(packet)
                self.sock.sendto(
                    bytes_to_send, (self.server_addr, self.server_port)
                )  # sending packet to the server
                print("PACKET SENT[TAIMOOR CLIENT] ---->", packet)
                '''
                Packet Duplication Test
                if (transmits == 0):
                    self.sock.sendto(
                        bytes_to_send, (self.server_addr, self.server_port)
                    )  # sending packet to the server
                    print("PACKET RE-SENT(DUPLICATE)[TAIMOOR CLIENT] ---->", packet)
                '''
            transmits = transmits + 1 # increments number of retransmits
            #packet = cpacket # forced checksum
        print("Transmits Data Packet ", transmits)
        seqno = seqno + 1 # increments the sequence number by one
        acked = True
        transmits = 0 # resent the number of tranmits to 0
        while acked:
            if transmits == self.retransmission: # checks if max amount of retransmits has been made
                break
            try:
                tuple_ack = self.ack_list.get(timeout=0.3) # retrive ack form ack_list queue and wait for a 0.3 ms time out
                if tuple_ack[0] == (seqno+1): # check to see if ACK recived is the right one for the last packet sent as it should be sequence number +1
                    acked = False
                    break
            except queue.Empty: # if queue is empty the ack is set to false and the data packet is sent again after timeout of 0.3 seconds
                acked = True
                self.send_end_packet(seqno)
            transmits = transmits + 1 # increments number of retransmits
        #print("Transmits start ", transmits)

    def receive_message(self): # Function to retive packets and parse them
        """Returns retrives message."""
        message = self.sock.recvfrom(14000)
        message_to_decode = message[0]
        fernet = Fernet(helper.priv_key_64)
        decoded_message = fernet.decrypt(message_to_decode).decode('utf-8')
        #decoded_message = self.decrypt_message(message_to_decode)
        #decoded_message = message[0].decode("utf-8")
        #decoded_message = decoded_message[0]
        #print('decoded_message' + decoded_message)
        #msg_type, seqno, data, checksum
        print("PACKET RECIVED[TAIMOOR CLIENT]  <----", decoded_message)
        msg_type, seqno, raw, checksum = helper.parse_packet(decoded_message)
        data_seg = raw.split('$;')
        return msg_type, seqno, data_seg, checksum

    def quitmsg(self): # function to deal with the quit message button on the GUI
        self.msg_list.insert(END, "Disconnecting") # prints disconneting
        self.msg_list.yview(END)
        print("Disconnecting")

    def quit(self): # function binded to the GUI quit button
        self.send_message("Disconnect", self.name) # sends a disconenction message
        sys.exit() # exits system

    def start(self):
        #function = input()
        function = self.my_msg.get() # gets input form the GUI console
        self.msg_list.insert(END, self.name + ": "+ function) # prints on GUI
        print(self.name + ": "+ function) # prints on terminal
        #print (function)
        self.my_msg.set("") # sets the GUI console to blank again
        function_split = list(function.split(" ")) # splits the function based on spaces
        function_split[0] = function_split[0].upper() # capalizes the letter to match one format to remove the issue of case sensitivity
        if function_split[0] == "LIST": # if the user requests a list

            message = "Request_Users_Present"
            self.send_message("Request_Users_Present","") # send an appropriate request to the server
            #self.msg_list.insert(END, self.name + ": "+ message)
            self.msg_list.yview(END) # changes the view of the GUI to the latest output

        elif function_split[0] == "INVITE": # if the user input is Invite
            if ( # we will check for errors such as if user name is present and if file is present
                function_split[-1] == ""
                or len(function_split) < 2
                or function_split[0] == function_split[-1]
            ):
                self.msg_list.insert(END, "Error : Invalid Command") # if they are not present we will give an error message and ask user to re enter
                print("Error : Invalid Command")
            elif (self.filename.get() == "" or self.filename.get() == "Select Invitation Type"): # if the file is not selected then another message is shown
                self.msg_list.insert(END, "Error : Please Select Invitation Type")
                print("Error : Please Select Invitation Type")
            else:
                try:
                    del function_split[0]
                    no_of_users = len(function_split) # gets the number of users to send the file to
                    for i in range (len(function_split)): #  ensures each name is not in diffrent cases so we will make it lower case
                        function_split[i] = function_split[i].lower()
                    #self.msg_list.insert(END, "FILE NAME: " + self.filename.get())
                    file_open = open(self.filename.get()) # opens the file
                    file_read = file_open.read()
                    function_msg = "$;".join(function_split) # joins rhe names withe the seperator specified in the rfc
                    function_msg = str(no_of_users) + "$;" + function_msg +"$;"+self.filename.get() + "$;" + file_read # creates content like specified in the rfc
                    message = "Send_invite"
                    self.send_message("Send_invite", function_msg) #send an appropriate request to the server
                    self.msg_list.insert(END, self.name + ": "+ message) # prints message on the GUI
                    self.msg_list.yview(END)
                    print(self.name + ": "+ message)
                except FileNotFoundError: # if file is not found throw an error with code specified in the RFC
                    self.msg_list.insert(END, "Error : FileNotFoundError")
                    print("Error : FileNotFoundError")

        elif function_split[0] == "HELP": # if the user input is help then print out a series of valid commands and inputs the user can make
            if len(function_split) == 1:
                self.msg_list.delete(0,'end')
                self.msg_list.insert(END, "Functions")
                self.msg_list.insert(END, "1) Available Users:")
                self.msg_list.insert(END, "     Input Format: List")
                self.msg_list.insert(END, "2) Sending Invitation:")
                self.msg_list.insert(END, "     A. Invite <number_of_users><username><username><username>")
                self.msg_list.insert(END, "     B. Invite <all>")
                self.msg_list.insert(END, "3) Help:")
                self.msg_list.insert(END, "     Input Format: Help")
                self.msg_list.insert(END, "4) Quit:")
                self.msg_list.insert(END, "     Input Format: Quit")
                self.msg_list.yview(END)
            else: # else if disconnect the user
                self.send_message("Disconnect", "")
                self.msg_list.insert(END, self.name + ": "+ message)
                self.msg_list.yview(END)
                print(self.name + ": "+ message)

        elif function_split[0] == "QUIT": # is a quit message is recived then send a disconnection message to the server to end connection
            if len(function_split) == 1:
                message = "Disconnecting"
                self.msg_list.insert(END, self.name + ": "+ message)
                self.msg_list.yview(END)
                print(self.name + ": "+ message)
                self.send_message("Disconnect", self.name) # send an appropriate request to the server
                time.sleep(0.2) # sleeps for 0.2 s before exiting
                sys.exit()
            else:
                self.send_message("Disconnect", "")
            self.msg_list.insert(END, self.name + ": "+ message)
            self.msg_list.yview(END)
            print(self.name + ": "+ message)
        else: # if the user input is in invald format throw an error and allow user to re-enter meeesage
            message ="incorrect userinput format"
            self.msg_list.insert(END, self.name + ": "+ message) # prints a appropriate message on the GUI
            self.msg_list.yview(END)
            print(self.name + ": "+ message) # prints a simliar messsge on the console
        self.opmsg.set("Select Invitation Type")

        '''
        This function recives messges form the server and deals with them accordingly
        '''
    def receive_handler(self):
        while(True):

            packet_type,seqno,data_seg1,checksum = self.receive_message() # recives message form the server
            #print(data_seg1)
            #print(data_seg)
            '''
            #Forced Packet Loss
            rand = random.randint(0, 10)
            if (rand < 3):
                print("Packet Force Lost: ", packet_type)
                continue
            '''
            if packet_type == "ACK": # checks if the checksum is valid and packet type
                self.ack_list.put((int(seqno),packet_type))  # if its an acknowledge adds it to a dictonary
            if(packet_type == 'START'):# checks if the checksum is valid and packet type
                self.send_ack_packet(seqno) # if its a start packet send a acknowledge packet
            if(packet_type == 'DATA'): # checks if the checksum is valid and packet type
                self.send_ack_packet(seqno) # if its a data packet send a acknowledge packet
                self.packetinorder.put(data_seg1)  # adds the data segment of the packet to a queue to retive later
            if(packet_type == 'END'): # checks if the checksum is valid and packet type
                self.send_ack_packet(seqno) # if its a end packet send a acknowledge packet
                data_seg = self.packetinorder.get() # retrives all the data packets in the queue that were saved before
                #print(data_seg)

                if data_seg[0] == "ERR_SERVER_FULL": # if the server is at maximum capacity
                    print("disconnected: Server Maxed Out") # An appropriate Error Message is printed
                    os._exit(0) # the system exits

                elif data_seg[0] == "ERR_USERNAME_TAKEN": # if an username is already taken an error message is recived
                    print("disconnected: username not available")  # An appropriate Error Message is printed
                    os._exit(0)  # system exits

                elif data_seg[0] == "ERR_UNAUTHORIZED_ACCESS": # if an username is already taken an error message is recived
                    print("disconnected: Unauthorized Access Denied ")  # An appropriate Error Message is printed
                    os._exit(0)  # system exits

                elif data_seg[0] == "Access_Granted":  # If the server has connected with the client sucessfully
                    self.msg_list.insert(END, "Connected to Server: " + self.server_addr + ":"+ str(self.server_port)) # prints an connected message on the GUI
                    self.msg_list.yview(END)
                    print("Connected to Server: " + self.server_addr + ":"+ str(self.server_port)) # Prints the same message on the console

                elif data_seg[0] == "Response_Users_Present": # an response to the List request is recived
                    user = data_seg[2]
                    del data_seg[0] # delete irrlavent data form the data segment to recover the user list
                    del data_seg[0]
                    u_list = " ".join(data_seg) # joins the userlist with a space
                    out_msg = "list: " + u_list
                    self.msg_list.insert(END, out_msg) # displays the userlist on the GUI
                    self.msg_list.yview(END)
                    print(out_msg) # displays the list on the console

                elif data_seg[0] == "Forward_invite": # the server forwarded an invite
                        #print("Data seg whole: ", data_seg)
                        user = data_seg[2] # extracts the user form the data segment
                        file_name = data_seg[3] # extracts file name form the data segment
                        message= data_seg[-1] # extracts the invite
                        #print("MSGED OF FIKE:" , msg)
                        del data_seg[0:4] # deletes the irrlavent data in the data seg
                        #message = " ".join(msg)
                        file_w = open(self.name + "_" + file_name, "w") # file reads and writes
                        file_w.write(message)
                        file_w.close()
                        #print("file:", user + ":", file_name)
                        msg_file = "file: " + user + ":" + file_name
                        self.msg_list.insert(END, msg_file) # display file retrived on the GUI
                        self.msg_list.yview(END)
                        print(msg_file) # display same message on the console

                elif data_seg[0] == "ERR_INVALID_FORMAT": # if the message recived is of an invalid format then
                    self.msg_list.insert(END, "disconnected: server received an unknown command") # disconnect the server
                    self.msg_list.yview(END)
                    print("disconnected: server received an unknown command") # print on the console same message
                    time.sleep(0.2)
                    os._exit(0)

        raise NotImplementedError
    def on_entry_click(self,event):
        """function that gets called whenever entry1 is clicked"""
        firstclick = True
        if firstclick: # if this is the first time they clicked it
            firstclick = False
            self.entry_field.delete(0, "end") # delete all the text in the entry

    def gui(self):
        '''
        Starts the GUI thread (mainloop) and initalizes a GUI
        '''
        msg = self.name + "$;" + self.key
        self.send_message("Join_Request", msg)
        ROOT.title("Welcome " + self.name)
        ROOT.tk.call('source', 'forest-light.tcl')

        style = ttk.Style(ROOT)
        style.theme_use('forest-light')
        ROOT.mainloop()

if __name__ == "__main__":

    PORT = 5056
    #DEST = "10.77.98.229"
    DEST = "localhost"
    USER_NAME = ""
    KEY = ""
    # establises connection to the cloud databse cockroachlabsdb.
    connection = psycopg2.connect(user="taimoornetworking",
                                      password="8zqiTvEhp-VwzCcxBm7Hcg",
                                      host="free-tier7.aws-eu-west-1.cockroachlabs.cloud",
                                      port="26257",
                                      database="bigger-unicorn-2234.defaultdb"
                                      )# Create a cursor to perform database operations

    usr = connection.cursor() #creades a usr object for the database for manimulation adding and deleting data
    usr.execute("SELECT version();")
    record = usr.fetchone()
    print("You are connected to Cloud Database - ", record, "\n")
    usr.execute("select exists(select * from information_schema.tables where table_name=%s)", ('userdata',)) # to check if the table exists already on the cloud database

    if((usr.fetchone()[0]) == False): # if the table doesnt exist this enables to create a cloud database
        create_table_query = '''CREATE TABLE userdata
          (ID SERIAL PRIMARY KEY     NOT NULL,
          USERNAME           TEXT    UNIQUE,
          PASSWORD           TEXT    NOT NULL
          CONNECTED          TEXT    NOT NULL); '''
        # Execute a command: this creates a new table
        usr.execute(create_table_query) # executes the query on the cloud server and creates the table
        connection.commit() #commits the changes to the cloud database.
        #print("Table created successfully in PostgreSQL ")
        usr.execute('ALTER TABLE %s ADD COLUMN %s text' % ('userdata', 'connected'))
        connection.commit()
    loginmsg = 'Please enter Name: '
    loginpasmsg = 'Please enter Password (Case Sensitive): '
    while(USER_NAME == "" or KEY == "" or usersearch(usr,USER_NAME, KEY) == False): # to check for username if it exists or not and if the name and key feild are not blank
        if(USER_NAME == ""):
            USER_NAME=input(loginmsg)
            USER_NAME = USER_NAME.lower()
        if (KEY == ""):
            KEY=input(loginpasmsg)
        if(usernamesearch(usr,USER_NAME) == False): # addes new user to the database
            postgres_insert_query = """ INSERT INTO userdata (username, password) VALUES (%s,%s)"""
            record_to_insert = (USER_NAME, KEY)
            usr.execute(postgres_insert_query, record_to_insert)
            connection.commit()
        elif(usersearch(usr,USER_NAME,KEY) == True): # checks if the user already exists
            break;
        elif(usersearch(usr,USER_NAME,KEY) == False): # checks for invalid password
            loginmsg = 'Please enter Name: '
            loginpasmsg = 'Please enter Valid Password Server Key (Case Sensitive): '
            KEY = ""
            USER_NAME = ""
        else:
            loginmsg = 'Please enter Unique Name: '
            loginpasmsg = 'Please enter Server Key (Case Sensitive): '
            KEY = ""
            USER_NAME = ""
    # Executing a SQL query


    '''
    print values in userdata table.
    s = "SELECT * FROM userdata"
    usr.execute(s)
    list_users = usr.fetchall()
    print(list_users)
    '''
    connection.close ()
    print(" ")
    print(" ")
    print("--------- WELCOME "+ USER_NAME+ " ---------")
    print(" ")
    print(" ")
    SKEY = ""
    while(SKEY == ""):
     SKEY=input("Please Enter Server Key for Access: ") # asks for server key (key = network)
    ROOT = Tk()
    S = Client(USER_NAME, DEST, PORT, ROOT, SKEY)
    try:
        T = Thread(target=S.receive_handler)
        T.daemon = True
        T.start() # Starts thread for client reciver handler function
        S.gui() # Starts the client function gui
    except (KeyboardInterrupt, SystemExit, ConnectionError):
        sys.exit()

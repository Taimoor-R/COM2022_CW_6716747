import sys
import getopt
import socket
import helper
import binascii
import random
import base64
import psycopg2
import hashlib
import os
from cryptography.fernet import Fernet
import queue
from threading import Thread
from queue import Queue, Full, Empty


class Server:
    def __init__(self, dest, port, S_key):
        self.server_addr = dest # stores server addr
        self.server_port = port # stores server port
        self.key = S_key # stores secret key for server needed to establish connection
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(None) # set time out to none
        self.sock.bind((self.server_addr, self.server_port))
        self.packetinorder = Queue(0) # priority queue to catch packets inorder by sequence number as key
        self.ack_dict = {} # normal queue to get acknowledge packets
        self.retransmission = 400
    def send_packet(self, message, address, content): # sending packets via a new thread multithreading
        thread_q = queue.Queue(0)
        self.ack_dict[address] = thread_q
        thread_S = Thread(
            target=self.send_message,
            args=(
                message,
                address,
                content,
                # self.ack[address],
            ),
        )
        thread_S.start()
    def send_start_packet(self, address, sseq): # function to make and send a start packet to initiate transfer of packets
        Start = helper.make_packet("START", sseq, "") # sends START and sequence number
        #bytes_to_send = str.encode(Start) # encodes Start Packet
        #print("Server: End Packet Sent to ", self.current_user(address))
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(Start.encode('utf-8'))
        self.sock.sendto(bytes_to_send, address)
        print("PACKET SENT[TAIMOOR SERVER] ---->", Start)

    def send_end_packet(self, address, seqno): # function to make and send a end packet to initiate transfer of packets
        packet = helper.make_packet("END", seqno, "") # sends END and sequence number
        #bytes_to_send = str.encode(packet) #encodes End Packet
        #print("Server: Start Packet Sent to ", self.current_user(address))
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(packet.encode('utf-8'))
        self.sock.sendto(bytes_to_send, address)
        print("PACKET SENT[TAIMOOR SERVER] ---->", packet)
        #self.send_end_packet(seqno)

    def send_message(self, message, address, content):
        '''creates and sends message'''
        msg = "%s$;%d$;%s" % (message,len(content),content) # makes body of packet as described in RFC: 2022
        #print(msg) prints message to see if format is correct
        #msg = helper.make_message(message, content)
        seqno = random.randint(1,20) # creates an instance of random sequenc number for each communication
        #print("i am here: at seqq : " , seqno) prints the current random sequence number
        acked = True # acked set to true to keep loop running as it recives acknowledgements
        transmits = 0 # number of transmits = 0
        while acked:
            if transmits == self.retransmission: # checks if max amount of retransmits has been made
                helper.user_List.remove(self.current_user(address))
                helper.user_List = sorted(helper.user_List)
                return
            try:
                tuple_ack = self.ack_dict[address].get(timeout=0.3) # retrive ack form ack_list queue and wait for a 0.3 ms time out
                if tuple_ack[0] == (seqno+1): # check to see if ACK recived is the right one for the last packet sent as it should be sequence number +1
                    #print ("i am in if statement for sequence number") debuffing too to check if the program was entering this if statement
                    acked = False # set ack to true
                    break # break out of try
            except queue.Empty: # if queue is empty the ack is set to false and the data packet is sent again after timeout of 0.3 seconds
                acked = True
                self.send_start_packet(address,seqno)
            transmits = transmits + 1 # increments number of retransmits

        seqno = seqno + 1 # increments the sequence number by one
        packet = helper.make_packet("DATA", seqno, msg)  # making packet of that message
        #bytes_to_send = str.encode(packet)
        fernet = Fernet(helper.priv_key_64)
        bytes_to_send = fernet.encrypt(packet.encode('utf-8'))
        #bytes_to_send = self.encrypt_message(packet)
        acked = True
        transmits = 0 # resent the number of tranmits to 0
        while acked:
            if transmits == self.retransmission:# checks if max amount of retransmits has been made
                helper.user_List.remove(self.current_user(address))
                helper.user_List = sorted(helper.user_List)
                return
            try:
                tuple_ack = self.ack_dict[address].get(timeout=0.3)# retrive ack form ack_list queue and wait for a 0.3 ms time out
                if tuple_ack[0] == (seqno+1):# check to see if ACK recived is the right one for the last packet sent as it should be sequence number +1
                    acked = False
                    break
            except queue.Empty: # if queue is empty the ack is set to false and the data packet is sent again after timeout of 0.3 seconds
                acked = True
                #bytes_to_send = str.encode(packet)
                #bytes_to_send = self.encrypt_message(packet)
                fernet = Fernet(helper.priv_key_64)
                bytes_to_send = fernet.encrypt(packet.encode('utf-8'))
                self.sock.sendto(bytes_to_send, address)
                print("PACKET SENT[TAIMOOR SERVER] ---->", packet)
                #Packet Duplication Test
            transmits = transmits + 1# increments number of retransmits
        #print("DAtA PACKET SENT", packet) used to check if correct data packet was being sent
        seqno = seqno + 1 # increments the sequence number by one
        acked = True
        transmits = 0 # resent the number of tranmits to 0
        while acked:
            if transmits == self.retransmission:# checks if max amount of retransmits has been made
                helper.user_List.remove(self.current_user(address))
                helper.user_List = sorted(helper.user_List)
                return
            try:
                tuple_ack = self.ack_dict[address].get(timeout=0.3)# retrive ack form ack_list queue and wait for a 0.3 ms time out
                if tuple_ack[0] == (seqno+1): # check to see if ACK recived is the right one for the last packet sent as it should be sequence number +1
                    acked = False
                    break
            except queue.Empty: # if queue is empty the ack is set to false and the data packet is sent again after timeout of 0.3 seconds
                acked = True
                self.send_end_packet(address,seqno)
            transmits = transmits + 1 # increments number of retransmits


    def receive_message(self): # Function to retive packets and parse them
        '''receives message'''
        fernet = Fernet(helper.priv_key_64)
        msg, address = self.sock.recvfrom(14000)
        msg_decode = fernet.decrypt(msg).decode('utf-8')
        print("PACKET RECIVED[TAIMOOR SERVER] <----", msg_decode)
        #msg_decode = msg.decode("utf")
        msg_parse = helper.parse_packet(msg_decode)
        #print("Server: Packet Recived: ", msg_parse)
        packet_type, seqno, data, checksum = msg_parse
        data_split = data.split('$;')
        return packet_type, data_split, address, seqno , checksum

    def send_ack_packet(self,seqno,address): # Function to send ACK packet
        Ack = helper.make_packet("ACK", int(seqno)+1, "")
        bytes_to_send = str.encode(Ack)
        bytes_to_send = self.encrypt_message(Ack)
        self.sock.sendto(bytes_to_send, address)
        print("PACKET SENT[TAIMOOR SERVER] ---->", Ack)

    def encrypt_message(self,message):
        fernet = Fernet(helper.priv_key_64)
        encrypted_message = fernet.encrypt(message.encode('utf-8'))
        return encrypted_message

    def current_user(self,address): # Function to check Current User sending requests to server
        for tuples in helper.name_Identifier:
            if address == tuples[1]:
                current_user = tuples[0]
        return current_user
    def recalchecksum(self,message): # function made to recalchecksum of the packets recived by client
        body_join= "$;".join(message)
        body = "%s" % (body_join)
        message= body.encode()
        checkrecal= str(binascii.crc32(message) & 0xffffffff)
        return checkrecal

    def start(self):
        connection = psycopg2.connect(user="taimoornetworking",
                                          password="8zqiTvEhp-VwzCcxBm7Hcg",
                                          host="free-tier7.aws-eu-west-1.cockroachlabs.cloud",
                                          port="26257",
                                          database="bigger-unicorn-2234.defaultdb"
                                          )# Create a cursor to perform database operations

        usr = connection.cursor() #creades a usr object for the database for manimulation adding and deleting data
        while(True):

            packet_type,data_seg1,address,seqno,checksum = self.receive_message()  # receives message form client and splits it
            #print("Print in server loop : ",data_seg1)

            #Force packet loss Code
            '''
            rand = random.randint(0, 7)
            print("random number: ", rand)
            if (rand < 4):
                print("Packet Force Lost")
                continue
            print("cont random: ", rand)
            '''
            if (packet_type == "ACK" and checksum == self.recalchecksum(data_seg1)) :# checks if the checksum is valid and packet type
                self.ack_dict[address].put((int(seqno),packet_type)) # if its an acknowledge adds it to a dictonary
                #self.ack_list.put((int(seqno),packet_type))
            if(packet_type == 'START' and checksum == self.recalchecksum(data_seg1)):# checks if the checksum is valid and packet type
                self.send_ack_packet(seqno,address) # if its a start packet send a acknowledge packet
            if(packet_type == 'DATA' and checksum == self.recalchecksum(data_seg1) and self.packetinorder.empty()):# checks if the checksum is valid and packet type
                self.send_ack_packet(seqno,address) # if its a data packet send a acknowledge packet
                self.packetinorder.put(data_seg1) # adds the data segment of the packet to a queue to retive later
            if(packet_type == 'END' and checksum == self.recalchecksum(data_seg1)):# checks if the checksum is valid and packet type
                self.send_ack_packet(seqno,address) # if its a end packet send a acknowledge packet
                data_seg = self.packetinorder.get() # retrives all the data packets in the queue that were saved before
                #print(data_seg)
                if data_seg[0] == "Join_Request":
                    if data_seg[2] in helper.user_List: # checks for user in the session management/ control list and if not presnet
                        message = "ERR_USERNAME_TAKEN" # sends a appropriate error message
                        self.send_packet(message, address, "")
                        print("List of Users: " ,helper.user_List)
                    elif helper.MAX_NUM_CLIENTS == len(helper.user_List): # checks for Max Number of User in the session management/ control list
                        message = "ERR_SERVER_FULL"
                        self.send_packet(message, address, "") # sends a appropriate error message
                        print("List of Users: " ,helper.user_List)
                    elif self.key != data_seg[-1]:
                        message = "ERR_UNAUTHORIZED_ACCESS"
                        self.send_packet(message, address, "") # sends a appropriate error message
                        print("List of Users: " ,helper.user_List)
                    else: # else if everything is fine and no errors are caught then
                        print("Connected: ", data_seg[2]) # print connected and the name of the user
                        helper.user_List.append(data_seg[2]) # add user to the user list / session list
                        helper.user_List = sorted(helper.user_List) # sort the userlist
                        user_porttuple = (data_seg[2], address) # add the user into a tuple with their address
                        helper.name_Identifier.append(user_porttuple) # append/ add the tuple into the name_Identifier list
                        d_name = data_seg[2]
                        #print("name: ", d_name)
                        sql_update_query = """Update userdata set connected = %s where username = %s"""
                        usr.execute(sql_update_query, ('TRUE', d_name.lstrip()))
                        connection.commit()
                        message = "Access_Granted" # reply back with a appropriate message response
                        self.send_packet(message, address, "")

                elif data_seg[0] == "Request_Users_Present": # if message recived is a Request_Users_Present then
                    message = "Response_Users_Present"
                    print("list:", self.current_user(address)) # print appropriate message and the user who requested it
                    users = helper.user_List # create a copy of the session list to send back to the user
                    content = " ".join(helper.user_List)
                    #print(content)
                    self.send_packet(message, address, content)

                elif data_seg[0] == "Send_invite":
                        print("PACKET DATA: ", data_seg)
                        print("file:", self.current_user(address))
                        user_file_sent = [] # list for files alreay sent to users
                        user_to_send = [] # stores users to send the invite to
                        address_to_send = () # stores the address of users to forward the invite to
                        data_string_manip = data_seg.copy() # making copy of the content of the DATA packet
                        #print("DATA STRING ORIG", data_string_manip) prints before data maipultion
                        del data_string_manip[0:-2]
                        #print("DATA STRING new", data_string_manip) #prints after data maniputlation
                        data_string_manip.insert(0, self.current_user(address)) # appending name of sender to message
                        #print("Data _ String _ manip: ", data_string_manip)
                        file_to_send = "$;".join(data_string_manip) # joins and makes a body content for the file to be sent
                        for i in range(3, 3 + int(data_seg[2])): # retrives users to forward the invite to from original packet content
                            user = data_seg[i]
                            user.lstrip()# removes white space before the username
                            #print("USERS TI SEND FILE:" , data_seg[i]) prints the user to send to check blank spalces
                            if user in helper.user_List:
                                #print("FILE TO SENT TO : ", data_seg[i]) print statement used to debug
                                user_to_send.append(data_seg[i]) # adds users to forward into a list
                            elif data_seg[3] == "all":
                                user_to_send = helper.user_List.copy()
                            else: # if user doesnot exist in the user_list of all users on the server the server prints non-existant user error
                                print("file:", self.current_user(address), "to non-existent user", data_seg[i]) #prints if person not present in list server prints this on server side
                        for i in range(len(user_to_send)):
                            user = user_to_send[i] # appends the chosen user to the user to send list
                            if user not in user_file_sent: # checks if the invite is already sent to a user if not then continues to send file ensures that duplicate file is not sent
                                for tuples in helper.name_Identifier: # extracts address of user in the name_Identifier list on the server
                                    if user == tuples[0]:
                                        address_to_send = tuples[1] # stores address of user to forward invite
                                user_file_sent.append(user) # adds user to to the user_file_sent List
                                self.send_packet("Forward_invite",address_to_send,file_to_send)# send message via the send_message function

                elif data_seg[0] == "Disconnect":  # if the recived message is a Disconnet message
                    u_name = (self.current_user(address)).lstrip()
                    print("User List Before Disconnet: ", helper.user_List)
                    sql_update_query = """Update userdata set connected = %s where username = %s"""
                    usr.execute(sql_update_query, ('FALSE', u_name))
                    connection.commit()
                    '''
                    #prints cloud database
                    s = "SELECT * FROM userdata"
                    usr.execute(s)
                    list_users = usr.fetchall()
                    print(list_users)
                    '''
                    if data_seg[2] == "": #print user disconnected on the server if there is an unknown command
                            print(
                                "disconnected:",
                                self.current_user(address),
                                "sent unknown command",
                            )
                            self.send_packet("ERR_INVALID_FORMAT", address, "") #sends an error messafe back to the client
                            helper.user_List.remove(self.current_user(address)) # remove user form the session list(user list)
                            helper.user_List = sorted(helper.user_List) # resort the list
                    elif data_seg[2] == self.current_user(address): # else if the username is sent then

                        helper.user_List.remove(self.current_user(address)) # remove from current session
                        helper.user_List = sorted(helper.user_List) # resort the list
                        print("Updated User List: ", helper.user_List)
                        print("disconnected:", self.current_user(address)) # print disconnection message
        raise NotImplementedError


if __name__ == "__main__":

    PORT = 5056 # decided port number
    DEST = "0.0.0.0" # maybe changed to communicate on difffrent machines on same network
    S_key = "network"
    SERVER = Server(DEST, PORT, S_key) # creates a server object
    try:
        SERVER.start() # starts the server
    except (KeyboardInterrupt, SystemExit, ConnectionError):
        exit()

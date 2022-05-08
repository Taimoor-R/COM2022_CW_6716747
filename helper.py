import binascii
import base64
import hashlib
from cryptography.fernet import Fernet

MAX_NUM_CLIENTS = 2 #Maximum number of clients that can connect to the server
user_List = [] # list of current users present on server session managment
name_Identifier = [] #list of user names and address in a tuple
'''
Creates Private Key Used for encryption and decryption
'''
priv_msg = 'networking'
priv_msg_encoded = priv_msg.encode(encoding='UTF-8')
priv_key = hashlib.md5(priv_msg_encoded).hexdigest()
priv_key = priv_key.encode(encoding='UTF-8')
priv_key_64 = base64.urlsafe_b64encode(priv_key)

'''
creates a packet as specified in the rfc:
Message Request/Response code|Sequence Number|Content(with seperator"$;")|Checksum of Content
'''
def make_packet(msg_type, seqno, msg):
    body = "%s|%d|%s|" % (msg_type, seqno, msg)
    checksum = str(binascii.crc32(msg.encode()) & 0xffffffff)
    packet = "%s%s" % (body, checksum)
    return packet

'''
Parses the packet into individual pieces of data that are returned to the client/server
'''
def parse_packet(message):
    pieces = message.split('|')
    #print("Peices: ",pieces)
    msg_type, seqno = pieces[0:2]
    checksum = pieces[-1]
    #print("Peices: ", pieces)
    data = '|'.join(pieces[2:-1])

    return msg_type, seqno, data, checksum

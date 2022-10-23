import socket
from threading import Thread
from colorama import Fore, Back, Style
# encryption library
import hmac
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# server's IP address
import re

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002  # port we want to use
separator_token = "<SEP>"  # we will use this to separate the client name & message

# initialize set of all connected client's sockets
client_sockets = set()
# initialize dict of all connected client's sockets and names
client_names = {}

# create a TCP socket
s = socket.socket()
# make the port as reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))
# listen for upcoming connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

# shared secret key
secretkey = b"password"
# creating keys based on shared secret key
kdf1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"1", iterations=390000, )
kdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"2", iterations=390000, )
kdf3 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"3", iterations=390000, )
kdf4 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"4", iterations=390000, )
kc = base64.urlsafe_b64encode(kdf1.derive(secretkey))
mc = base64.urlsafe_b64encode(kdf2.derive(secretkey))
ks = base64.urlsafe_b64encode(kdf3.derive(secretkey))
ms = base64.urlsafe_b64encode(kdf4.derive(secretkey))


def listen_for_client(cs):
    """
    This function keep listening for message from `cs` socket
    Whenever a message is received, processes it and sends to clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = cs.recv(1024)

        except Exception as e:
            # client no longer connected
            # remove it from the set
            print(f"[!] Error: {e}")
            client_sockets.remove(cs)
            del client_names[cs]
        else:
            # first decrypt message and compare hash
            fernet = Fernet(kc)  # decrypt message from client with client key
            decMessage = fernet.decrypt(msg)
            smac = decMessage.split("hashmac".encode())[1]
            smsg = decMessage.split("hashmac".encode())[0]
            message_digest2 = hmac.digest(key=mc, msg=smsg, digest="sha3_256")  # Mac from client with client MAc key
            if hmac.compare_digest(message_digest2, smac):
                msg = smsg.decode()  # message from client
                gname = msg
                if gname[0:3] == "s12" or gname[0:3] == "l12":
                    # client name for signing up or login
                    if gname[0] == "s":
                        string1 = re.search('s12(.*)<p>', gname)
                        string1 = string1.group(1)
                    elif gname[0] == "l":
                        string1 = re.search('l12(.*)<p>', gname)
                        string1 = string1.group(1)
                    passcode = gname.split('<p>')[-1]
                    pc = ""  # for checking password
                    flag = 0  # for checking name in file
                    file = open("names.txt", "a+")
                    file.close()
                    # client names in text file
                    namefile = open("names.txt", "r")

                    for line in namefile:  # Loop through the file line by line
                        # checking string is present in line or not
                        if string1 + "\n" == line:
                            pc = next(namefile)
                            flag = 1
                            break
                    namefile.close()
                    # checking condition for string found or not
                    if flag == 0 and gname[0] == "s":
                        # client signed up
                        namefile = open("names.txt", "a")
                        namefile.write(string1 + '\n')
                        namefile.write(passcode + '\n')
                        to_send = "ok12"
                        # first mac and encryption
                        message_digest1 = hmac.digest(key=ms, msg=to_send.encode(), digest="sha3_256")  # Mac from
                        # server with server MAc key
                        sending = to_send.encode() + "hashmac".encode() + message_digest1
                        fernet = Fernet(ks)  # encrypt message from server with server key
                        encMessage = fernet.encrypt(sending)
                        # finally, send the message
                        cs.send(encMessage)

                        # closing text file
                        namefile.close()
                        # new client
                        client_names[cs] = string1
                    elif flag == 1 and gname[0] == "s":
                        # is not unique and client name is incorrect
                        to_send = "no12"
                        # first mac and encryption
                        message_digest1 = hmac.digest(key=ms, msg=to_send.encode(), digest="sha3_256")  # Mac from
                        # server with server MAc key
                        sending = to_send.encode() + "hashmac".encode() + message_digest1
                        fernet = Fernet(ks)  # encrypt message from server with server key
                        encMessage = fernet.encrypt(sending)
                        # finally, send the message
                        cs.send(encMessage)
                        client_sockets.remove(cs)
                        del client_names[cs]
                    elif flag == 0 and gname[0] == "l":
                        # is unique and client name is incorrect
                        to_send = "no12"
                        # first mac and encryption
                        message_digest1 = hmac.digest(key=ms, msg=to_send.encode(), digest="sha3_256")  # Mac from
                        # server with server MAc key
                        sending = to_send.encode() + "hashmac".encode() + message_digest1
                        fernet = Fernet(ks)  # encrypt message from server with server key
                        encMessage = fernet.encrypt(sending)
                        # finally, send the message
                        cs.send(encMessage)
                        client_sockets.remove(cs)
                        del client_names[cs]
                    elif flag == 1 and gname[0] == "l":
                        # is not unique and client can log in
                        if pc == passcode + "\n":
                            to_send = "ok12"
                        else:
                            to_send = "no12"
                        # first mac and encryption
                        message_digest1 = hmac.digest(key=ms, msg=to_send.encode(), digest="sha3_256")  # Mac from
                        # server with server MAc key
                        sending = to_send.encode() + "hashmac".encode() + message_digest1
                        fernet = Fernet(ks)  # encrypt message from server with server key
                        encMessage = fernet.encrypt(sending)
                        # finally, send the message
                        cs.send(encMessage)
                        # new client
                        client_names[cs] = string1

                else:
                    # getting rcvr or rcvrs name
                    rcvr = msg.split(' ')[-1]
                    rcvrs = rcvr.split("--")
                    rcvrs.pop()
                    if msg[0] != "q":  # is not a quit alarm
                        # processing msg

                        # extracting sender name from msg
                        name = re.search('<_>(.*)<SEP>', msg)
                        name = name.group(1)

                        # removing rcvr name
                        msg = ' '.join(msg.split(' ')[:-1])

                        # creat message file for each client
                        msgfile = open(name + ".txt", "a+")
                        # save messages in file
                        msgfile.write(msg + "\n")
                        # closing message file
                        msgfile.close()
                if msg[0:3] != "s12" and msg[0:3] != "l12":
                    # sending message
                    if len(rcvrs) > 0:
                        # it means we are having conference
                        rcvrsocket = set()
                        # finding rcvr socket
                        i = 0
                        for r in rcvrs:
                            for key, value in client_names.items():
                                if r == value:
                                    rcvrsocket.add(key)
                                    i = 1
                            if i == 0:
                                alarm = "alarm" + r + " is not correct or connected"
                                to_send = alarm
                                # first mac and encryption
                                message_digest1 = hmac.digest(key=ms, msg=to_send.encode(),
                                                              digest="sha3_256")  # Mac from
                                # server with server MAc key
                                sending = to_send.encode() + "hashmac".encode() + message_digest1
                                fernet = Fernet(ks)  # encrypt message from server with server key
                                encMessage = fernet.encrypt(sending)
                                # finally, send the message
                                cs.send(encMessage)
                            i = 0
                        if len(rcvrsocket) != 0:
                            # specify all conference members to send in message
                            if msg[0:4] != "quit":
                                rcvrs.append(name)
                            if msg[0:4] == "quit":
                                # removing rcvr name
                                msg = ' '.join(msg.split(' ')[:-1])
                            confs = ""
                            for con in rcvrs:
                                confs = con + "--" + confs
                            msg = msg + " " + confs
                            # iterate over all connected sockets
                            for r in rcvrsocket:
                                for client_socket in client_sockets:
                                    # send the message
                                    if client_socket == r:
                                        to_send = msg
                                        # first mac and encryption
                                        message_digest1 = hmac.digest(key=ms, msg=to_send.encode(),
                                                                      digest="sha3_256")  # Mac from
                                        # server with server MAc key
                                        sending = to_send.encode() + "hashmac".encode() + message_digest1
                                        fernet = Fernet(ks)  # encrypt message from server with server key
                                        encMessage = fernet.encrypt(sending)
                                        # finally, send the message
                                        client_socket.send(encMessage)

                    else:
                        # it means we are having pv chat
                        rcvrsocket = 0
                        for key, value in client_names.items():
                            if rcvr == value:
                                rcvrsocket = key
                        if rcvrsocket == 0:
                            alarm = "alarm" + rcvr + " is not correct or connected"
                            to_send = alarm
                            # first mac and encryption
                            message_digest1 = hmac.digest(key=ms, msg=to_send.encode(), digest="sha3_256")  # Mac from
                            # server with server MAc key
                            sending = to_send.encode() + "hashmac".encode() + message_digest1
                            fernet = Fernet(ks)  # encrypt message from server with server key
                            encMessage = fernet.encrypt(sending)
                            # finally, send the message
                            cs.send(encMessage)
                        else:
                            # iterate over all connected sockets
                            for client_socket in client_sockets:
                                # send the message
                                if client_socket == rcvrsocket:
                                    to_send = msg
                                    # first mac and encryption
                                    message_digest1 = hmac.digest(key=ms, msg=to_send.encode(),
                                                                  digest="sha3_256")  # Mac from
                                    # server with server MAc key
                                    sending = to_send.encode() + "hashmac".encode() + message_digest1
                                    fernet = Fernet(ks)  # encrypt message from server with server key
                                    encMessage = fernet.encrypt(sending)
                                    # finally, send the message
                                    client_socket.send(encMessage)
            else:
                print(Fore.YELLOW + "integrity has been compromised")


while True:
    # we keep listening for new connections all the time
    client_socket, client_address = s.accept()
    print(Fore.CYAN + f"[+] {client_address} connected.")
    # add the new connected client to connected sockets
    client_sockets.add(client_socket)
    # start a new thread that listens for each client's messages
    t = Thread(target=listen_for_client, args=(client_socket,))
    # make the thread daemon, so it ends whenever the main thread ends
    t.daemon = True
    # start the thread
    t.start()
# ending = input()
# # a way to exit the program
# if ending.lower() == 'q':
#     break
# # close client sockets
# for cs in client_sockets:
#     cs.close()
# # close server socket
# s.close()

import socket
import sys
import time
from threading import Thread
from datetime import datetime
from colorama import Fore, Back, Style
# encryption library
import hmac
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# shared secret key
secretkey = b"password"
# creating key based on shared secret key
kdf1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"1", iterations=390000, )
kdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"2", iterations=390000, )
kdf3 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"3", iterations=390000, )
kdf4 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secretkey + b"4", iterations=390000, )
kc = base64.urlsafe_b64encode(kdf1.derive(secretkey))
mc = base64.urlsafe_b64encode(kdf2.derive(secretkey))
ks = base64.urlsafe_b64encode(kdf3.derive(secretkey))
ms = base64.urlsafe_b64encode(kdf4.derive(secretkey))

# server's IP address
# if the server is not on this machine,we should put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002  # server's port

separator_token = "<SEP>"  # separate the client name & message
name_separator = "<_>"  # separate the client name & date

# initialize TCP socket
s = socket.socket()
print(Fore.WHITE + f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print(Fore.CYAN + "[+] Connected.")

trytime = 0  # number of trying to enter correct name
fndlist = set()  # friend list
conlist = set()  # conference list
ok = 2  # checking the account

entered = 0  # client entered the account


def listen_for_messages():
    global conlist
    while True:
        message = s.recv(1024)  # rcv message from server and decrypt it
        fernet = Fernet(ks)  # decrypt message from server with server key
        decMessage = fernet.decrypt(message)
        smac = decMessage.split("hashmac".encode())[1]
        smsg = decMessage.split("hashmac".encode())[0]
        message_digest2 = hmac.digest(key=ms, msg=smsg, digest="sha3_256")  # Mac from server with server MAc key
        if hmac.compare_digest(message_digest2, smac):  # check for integrity
            message = smsg.decode()
            if message[0:10] == "Conference" or message[0:4] == "quit":
                conlist.clear()
                rcvr = message.split(' ')[-1]
                rcvrs = rcvr.split("--")
                rcvrs.pop()
                for c in rcvrs:
                    if c != name:
                        conlist.add(c)
                message = ' '.join(message.split(' ')[:-1])  # extracting rcvrs name

            if message[0:5] != "alarm" and message[0:4] != "quit":
                # extracting sender name from msg
                encmsg = message.split("<SEP>")[-1]
                fernet = Fernet(kc)  # decrypt message from client with client key
                decmsg = fernet.decrypt(encmsg.encode())

                message = message.replace(encmsg, decmsg.decode())
                message = message.replace(separator_token, ": ")
                message = message.replace("<_>", " ")
            if message[0:4] == "quit":
                message = message.split("quit")[-1]

            if message[0:5] == "alarm":
                message = message.split("alarm")[-1]

            print(Fore.BLUE + "\n" + message)
        else:
            print(Fore.YELLOW + "message has been altered!")


print(Fore.MAGENTA + "Hello and Welcome <3")
while True:
    command = input(Fore.WHITE + "For sign up enter s and for login enter l:  ")
    command = command.lower()
    if command == "s" or command == "l":
        break
while trytime < 3:

    # entering the login name
    if command == "l":
        name = input(Fore.WHITE + "Enter your name for logging in (it has to be only letters) : ")
    else:
        name = input(Fore.WHITE + "Enter your name for signing up (it has to be unique and only letters) : ")
    passcode = input("Enter your password : ")

    if name.isalpha():  # check if entered name id all letters
        # send the name for checking being unique
        if command == "l":
            sname = "l12" + name + "<p>" + passcode
        else:
            sname = "s12" + name + "<p>" + passcode

        # first mac and encryption
        message_digest1 = hmac.digest(key=mc, msg=sname.encode(), digest="sha3_256")  # Mac from client with client
        # Mac key
        sending = sname.encode() + "hashmac".encode() + message_digest1
        fernet = Fernet(kc)  # encrypt message from client with client key
        encMessage = fernet.encrypt(sending)
        # finally, send the message
        s.send(encMessage)

        message = s.recv(1024)
        fernet = Fernet(ks)  # decrypt message from server with server key
        decMessage = fernet.decrypt(message)
        smac = decMessage.split("hashmac".encode())[1]
        smsg = decMessage.split("hashmac".encode())[0]
        message_digest2 = hmac.digest(key=ms, msg=smsg, digest="sha3_256")  # Mac from server with server
        # Mac key

        if hmac.compare_digest(message_digest2, smac):
            message = smsg.decode()
            if message == 'ok12':
                ok = 1
            elif message == 'no12':
                ok = 0

            if ok == 1 and command == "s":
                print(Fore.GREEN + "sign up Successfully!  You can send massages now")
                entered = 1

            elif ok == 0 and command == "s":
                print(Fore.RED + name + " is not unique!    Try again later...")
                trytime = 4
            elif ok == 0 and command == "l":
                print(Fore.RED + name + " or password is incorrect!    Try again later...")
                trytime = 4
            elif ok == 1 and command == "l":
                print(Fore.GREEN + "Login Successfully!  You can send massages now")
                entered = 1
                # reading friends from its file into list
                file = open(name + "'s friends.txt", "a+")
                file.close()
                with open(name + "'s friends.txt") as file:
                    lines = file.readlines()
                    lines = [line.rstrip() for line in lines]
                for i in lines:
                    fndlist.add(i)

            if entered == 1:
                # make a thread that listens for messages to this client & print them
                t = Thread(target=listen_for_messages)
                # make the thread daemon, so it ends whenever the main thread ends
                t.daemon = True
                # start the thread
                t.start()

                # input section
                while True:
                    # input message we want to send to the server
                    command = input(Fore.LIGHTBLACK_EX + "select between q for quit, m for message, f for friend list, "
                                                         "c for conference: ")
                    # a way to exit the program
                    if command.lower() == 'q':
                        trytime = 4
                        break
                    # sending messages
                    if command.lower() == 'm':
                        rcvr = input(Fore.WHITE + "enter receiver name: ")
                        if rcvr in fndlist:
                            to_send = input()
                            # add the datetime, name and receivers
                            date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            msg = "[" + date_now + "] " + to_send

                            # encrypt message only for receiver
                            fernet = Fernet(kc)  # encrypt message from client with client key
                            encinput = fernet.encrypt(to_send.encode())
                            to_send = encinput.decode()

                            to_send = f"[{date_now}]{name_separator}{name}{separator_token}{to_send} {rcvr}"
                            # save message in file
                            msgfile = open(name + ".txt", "a+")
                            msgfile.write(msg + "\n")
                            # closing message file
                            msgfile.close()
                            # first mac and encryption
                            message_digest1 = hmac.digest(key=mc, msg=to_send.encode(), digest="sha3_256")   # Mac
                            # from client with client Mac key
                            sending = to_send.encode() + "hashmac".encode() + message_digest1
                            fernet = Fernet(kc)  # encrypt message from client with client key
                            encMessage = fernet.encrypt(sending)
                            # finally, send the message
                            s.send(encMessage)
                        else:
                            print(Fore.WHITE + "entered name does not belong to your friend list... you can add it by "
                                               "entering f")
                    # friend list
                    if command.lower() == 'f':
                        print(Fore.WHITE)
                        print(*fndlist, sep=", ")
                        fnd = input(Fore.WHITE + "enter your new friend name, to exit this section enter q, to delete "
                                                 "a friend name enter d: ")
                        if fnd.lower() != 'q' and fnd.lower() != 'd':
                            if fnd in fndlist:
                                print(Fore.WHITE + "already exists")
                            else:
                                fndlist.add(fnd)
                                print(Fore.GREEN + "added successfully!")
                        if fnd.lower() != 'q' and fnd.lower() == 'd':
                            fnd = input(Fore.WHITE + "enter your friend name to get deleted: ")
                            if fnd in fndlist:
                                fndlist.remove(fnd)
                                print(Fore.WHITE + "deleted successfully!")
                            else:
                                print(Fore.WHITE + "does not exist")
                        # adding friends to text file
                        with open(name + "'s friends.txt", "w+") as fndfile:
                            for item in fndlist:
                                fndfile.write("%s\n" % item)
                        # closing text file
                        fndfile.close()
                        if fnd.lower() == 'q':
                            continue
                    # conference
                    if command.lower() == 'c':
                        if len(conlist) >= 1:
                            to_send = input(Fore.WHITE + "enter message (for leaving the conference enter quit): ")
                            rcvrs = ""
                            for con in conlist:
                                rcvrs = con + "--" + rcvrs
                            if to_send != "quit":
                                # add the datetime, name and receivers
                                date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                # encrypt message only for receiver
                                fernet = Fernet(kc)  # encrypt message from client with client key
                                encinput = fernet.encrypt(to_send.encode())
                                to_send = encinput.decode()

                                msg = "Conference->[" + date_now + "] " + to_send
                                to_send = f"Conference->[{date_now}]{name_separator}{name}{separator_token}{to_send} {rcvrs}"

                                # save message in file
                                msgfile = open(name + ".txt", "a+")
                                msgfile.write(msg + "\n")
                                # closing message file
                                msgfile.close()
                            else:
                                to_send = to_send + name + " is out. " + rcvrs
                                conlist.clear()
                            # first mac and encryption
                            message_digest1 = hmac.digest(key=mc, msg=to_send.encode(), digest="sha3_256")   # Mac
                            # from client with client Mac key
                            sending = to_send.encode() + "hashmac".encode() + message_digest1
                            fernet = Fernet(kc)  # encrypt message from client with client key
                            encMessage = fernet.encrypt(sending)
                            # finally, send the message
                            s.send(encMessage)
                        else:
                            print(Fore.WHITE + "for conference enter at least 2 names from friend list, enter q when "
                                               "its done")
                            print(*fndlist, sep=", ")
                            con = "o"
                            conlist.clear()
                            i = 1
                            while con != "q":
                                print(Fore.WHITE)
                                con = input(str(i) + "'st friend: ")
                                if con.lower() != "q":
                                    if con in fndlist:
                                        conlist.add(con)
                                        i += 1
                                    else:
                                        print(Fore.WHITE + "entered name is wrong!")
                                con = con.lower()
                            if len(conlist) < 2:
                                print(Fore.WHITE + "for starting conference you need at least 2 friends, try again "
                                                   "later!")
                                conlist.clear()
        else:
            print(Fore.YELLOW + "message has been altered!")
    else:
        print(Fore.LIGHTBLUE_EX + "You can try again for " + str(2 - trytime) + " more time =)")
        trytime += 1

# close the socket
print("[+] Disconnected.")
s.close()
time.sleep(1)
sys.exit()

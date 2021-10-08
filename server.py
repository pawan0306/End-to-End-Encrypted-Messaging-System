import socket 
import _thread
import json
import threading
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import binascii

groupinfo = {}
groupkeys = {}
userinfo = {} 

def service(con): 
    global username
    global groupinfo
    global groupkeys

    while True:
        data = str(con.recv(1024),'utf-8').split()
        if data[0] == 'signup':
            usrdata = []
            username = data[1]
            if username in userinfo.keys():
                con.send(b'Username already exits')
                continue
            name = data[2]
            rollnum = data[3]
            password = data[4]
            port = data[5]
            userinfo[username] = [name, password, rollnum, port]
            con.send(b'Signedup Successfully')
        
        elif data[0] == 'login':
            username = data[1]
            password = data[2]
            if username not in userinfo.keys():
                con.send(b'0 Username Doesnt Exists')
                continue
            elif password != userinfo[username][1]:
                con.send(b'0 Incorrect Password')
                continue
            else:
                con.send(bytes('1 Logged in Successfully '+userinfo[username][2],'utf-8'))

        elif data[0] == 'get':
            if data[1] == 'ginfo':
                groupname = data[2]
                if groupname not in groupinfo.keys():
                    con.send(b'0')
                    continue
                con.send(bytes('1 '+(' '.join(groupinfo[groupname])),'utf-8'))
            else:
                username = data[2]
                if username not in userinfo.keys():
                    con.send(b'0')
                    continue
                con.send(bytes('1 '+userinfo[username][3],'utf-8'))

        elif data[0] == 'list':
            grp = {}
            for i in groupinfo.keys():
                grp[i]=len(groupinfo[i])
            con.send(bytes(json.dumps(grp),'utf-8'))
            
        elif data[0] == 'create':
            groupname = data[1]
            if groupname in groupinfo.keys():
                con.send(b'0 GroupName Already Exists')
                continue
            groupinfo[groupname] = [data[2]]
            groupkeys[groupname] = data[3]
            con.send(b'1 Group Created Successfully')
            
        elif data[0] == 'join':
            groupname = data[1]
            port = data[2]
            key = ''
            if groupname not in groupinfo.keys():
                key = str(binascii.hexlify(DES3.adjust_key_parity(get_random_bytes(24))),'utf-8')
                groupinfo[groupname] = []
                groupkeys[groupname] = key
            groupinfo[groupname].append(port)
            con.send(bytes(groupkeys[groupname],'utf-8'))

                
def start_server(portnum, id):
    soc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind(("127.0.0.1",portnum))
    soc.listen(10)
    i = 1
    while True:
        con, address = soc.accept()
        _thread.start_new_thread(service,(con,))
        print("Thread {} on Server {}".format(i,id))
        i += 1

def main():
    print("Welcome")
    
    t1 = threading.Thread(target = start_server, args = (8080,0))
    t2 = threading.Thread(target = start_server, args = (8081,1))
    t3 = threading.Thread(target = start_server, args = (8082,2))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()

main()
        


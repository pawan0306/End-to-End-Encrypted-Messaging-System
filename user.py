import socket
import _thread
import threading
import os
import crypto
import binascii
import json
import sys 
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import shutil
import time
 
groups = {}
userport = sys.argv[1]
name = ''
username = ''
userroll = sys.argv[2]
log = False
server_map = {0:8080,1:8081,2:8082}
class Estb_conn:

    def _respond(self,con):
        global groups
        
        en = crypto.Encrpytion()
        query = str(con.recv(1024),'utf-8').split()
        cmd = query[0]
        uname = query[1]
        secret_key = ""
        if cmd == 'msg':
            secret_key = Estb_conn._msg(con)
            data = str(con.recv(1024),'utf-8').split()
        else:
            uname = "GROUP {}:{}".format(query[1],query[2])
            secret_key = groups[query[1]]
            data = query[3:]

        if data[0] == 'y': 
            f = data[1]
            fname = f.split('/')[-1]
            en.encrypt_file(f,"encfile",secret_key)
            en.decrypt_file("encfile",fname,secret_key)
            os.remove("encfile")
            #shutil.copyfile(f,fname)
            print('{}:\nFILE: "{}"\n>>>'.format(uname,fname))
            
        else:
            size = int(data[1]) - len(data[2])
            mssge = str(en.decrypt_message(secret_key, data[2]),'utf-8')
            while size > 0:
                data = con.recv(1024)
                if not data:
                    break
                mssge += str(en.decrypt_message(secret_key, data),'utf-8')
                size = size - 1024
            print('{}:\n {}\n>>>'.format(uname, mssge),end='')


    def _msg(con):
        global userroll

        secret_key = ""
        en = crypto.Encrpytion()
        for i in range(3):
            primenum = en.getPrime()
            temp_key, final_key = en.diffiehellman1(primenum,userroll)
            mssge = '' + str(primenum) + ' ' + str(temp_key) + ' '
            con.send(bytes(mssge,'utf-8'))
            recieved_key = int(str(con.recv(1024),'utf-8'))
            secret_key += str(en.diffiehellman2(recieved_key,primenum,final_key))
        
        return secret_key.encode()



class Userservice:

    def signup(con):
        global userport

        name = input(">Enter NAME:")
        username = input(">Enter USERNAME:")
        password = input(">Enter PASSWORD:")
        tosend = 'signup ' + username + ' ' + name + ' ' + userroll + ' ' + password + ' ' + userport
        con.send(bytes(tosend,'utf-8'))
        ack = str(con.recv(100),'utf-8')
        print(">>>SERVER:{}".format(ack))    

    def login(con):
        global log
        global username
        global userroll
        
        usrname = input(">Enter USERNAME:")
        password = input(">Enter PASSWORD:")
        tosend = "login " + usrname + ' ' + password
        con.send(bytes(tosend,'utf-8'))
        ack = str(con.recv(100),'utf-8').split()
        if ack[0] == '0':
            print(">>>SERVER:{}".format(' '.join(ack[1:len(ack)])))
            return
        print(">>>SERVER:{}".format(' '.join(ack[1:len(ack)-1])))
        log = True
        username = usrname
        userroll = ack[-1]

    def create(con, query):
        global groups
        global log
        global userport

        if not log:
            print('>>>SERVER:Please Login')
            return
        gname = query[1]
        key = DES3.adjust_key_parity(get_random_bytes(24))
        tosend = '' + 'create' + ' ' + gname + ' ' + userport + ' ' + str(binascii.hexlify(key),'utf-8')
        con.send(bytes(tosend,'utf-8'))
        ack = str(con.recv(100),'utf-8').split(None,1)
        print(">>SERVER:{}".format(ack[1]))
        if ack[0] == '1':
            groups[gname] = key

    def _join(con, query):
        global groups

        if not log:
            print('>>>SERVER:Please Login')
            return
        gname = query[1]
        if gname in groups.keys():
            print(">>>SERVER: Already a member")
            return
        tosend = '' + 'join' + ' ' + gname + ' ' + userport
        con.send(bytes(tosend,'utf-8'))
        groups[gname] = binascii.unhexlify(con.recv(100))
        print(">>>SERVER: Successfully joined")

    def _list(con):
        global log

        if not log:
            print('>>>SERVER:Please Login')
            return
        tosend = b'list'
        con.send(tosend)
        lst = str(con.recv(2048),'utf-8')
        lst = json.loads(lst)
        print()
        for i in lst.keys():
            print(" {}: {}".format(i, lst[i]))

    def _send(con, query):
        global log

        if not log:
            print('>>>SERVER:Please Login')
            return
        if query[1] == 'GROUP':
            Userservice.grpmsg(con, query)
        else:
            Userservice.usrmsg(con, query)

    def usrmsg(con, query):
        global userroll

        tosend = 'get uinfo ' + query[1]
        con.send(bytes(tosend,'utf-8'))
        data = str(con.recv(100),'utf-8').split()
        if data[0] == '0':
            print("OPERATION FAILED***")
            return
        port = int(data[1])
        tmp_con =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp_con.connect(("127.0.0.1",port))
        tosend = 'msg ' + username + ' '
        tmp_con.send(bytes(tosend,'utf-8')) 
        secret_key = ""
        en = crypto.Encrpytion()
        for i in range(3):
            rec = str(tmp_con.recv(1024),'utf-8').split()
            primenum = int(rec[0])
            temp_key, final_key = en.diffiehellman1(primenum,userroll)
            tmp_con.send(bytes(str(temp_key),'utf-8'))
            recieved_key = int(rec[1])
            secret_key += str(en.diffiehellman2(recieved_key,primenum,final_key))
        secret_key = secret_key.encode()

        if query[2] == 'FILE':
            fname = query[3]
            time.sleep(0.1)
            tosend = ' y ' + fname + ' '
            tmp_con.send(bytes(tosend,'utf-8'))

        else:
            mssge = ' '.join(query[2:])
            enmsg = en.encrypt_message(secret_key,mssge)
            tosend = 'n ' + str(len(enmsg)) + ' ' + str(enmsg,'utf-8')
            tmp_con.send(bytes(tosend,'utf-8'))
        
        tmp_con.close()



    def grpmsg(con, query):
        global groups
        global username
        ports = {}
        en = crypto.Encrpytion()
        for i in groups.keys():
            tosend = bytes('get ginfo ' + i,'utf-8')
            con.send(tosend)
            data = str(con.recv(1024),'utf-8').split()
            if data[0] == '0':
                print("OPERATION FAILED***")
                return
            ports[i] = data[1:] 
        if query[2] == 'FILE':
            fname = query[3]
            for i in ports.keys():
                #en.encrypt_file(fname,'soutput',groups[i])
                header = bytes(('grp ' + i + ' ' + username + ' ' + 'y ' + fname + ' '),'utf-8')
                for j in ports[i]:
                    if j == userport:
                        continue
                    Userservice.sendmsg(header, j)
                #os.remove('soutput')
        else:
            msg = ' '.join(query[2:])
            for i in ports.keys():
                enmsg = en.encrypt_message(groups[i], msg)
                header = 'grp '+ i + ' ' + username + ' ' + 'n ' + str(len(enmsg)) + ' ' + str(enmsg,'utf-8')
                for j in ports[i]:
                    if j == userport:
                        continue
                    #print(j)
                    Userservice.sendmsg(header, j) 

    def sendmsg(header, port):

        tmp_con =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp_con.connect(("127.0.0.1",int(port)))
        tmp_con.send(bytes(str(header),'utf-8'))
        tmp_con.close()

    def usr_service():
        global groups
        global username
        global server_map
        global userroll

        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(userroll)%3
        con.connect(('127.0.0.1',server_map[port]))
        while True:
            query = input('>>>').split()
            cmd = query[0]
            if cmd == "SIGNUP":
                Userservice.signup(con)

            elif cmd == "LOGIN":
                Userservice.login(con)
            
            elif cmd == 'CREATE':
                Userservice.create(con, query)
                
            elif cmd == 'JOIN':
                Userservice._join(con, query)

            elif cmd == 'LIST':
                Userservice._list(con)

            elif cmd == "SEND":
                Userservice._send(con, query)
            
def create_conn():
    global userport

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1',int(userport)))
    s.listen(10)
    while True:
        con, address = s.accept()
        obj = Estb_conn()
        _thread.start_new_thread(obj._respond,(con,))

def main():
    e1 = Userservice
    t1 = threading.Thread(target = e1.usr_service, args = ())
    t2 = threading.Thread(target = create_conn, args = ()) 
    t1.start()
    t2.start()
    t1.join()
    t2.join()

main()
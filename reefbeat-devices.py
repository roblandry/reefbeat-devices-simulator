#!/usr/bin/python3
import os
import sys
from   http.server import BaseHTTPRequestHandler, HTTPServer
import json
from types import SimpleNamespace
from threading import Thread,Event
import subprocess
import time
from signal import pthread_kill, SIGTSTP
import pathlib
import traceback

class MyServer(HTTPServer):
    def __init__(self, handler,config):
        self.config = config
        self._db={}
        #Test if local IP exists
        must_create_ip=True
        for line in subprocess.Popen(
              ["ip", "addr", "show", "dev", "eth0"],
                stdout=subprocess.PIPE).communicate()[0].splitlines():
            if 'inet '+config.ip in str(line):
                must_create_ip=False
                break
        if must_create_ip:
            subprocess.Popen(["ip", "addr", "add", config.ip+"/24", "dev", "eth0"])
            print("Creating IP: %s "%config.ip)
            time.sleep(3)
        super().__init__((self.config.ip,self.config.port), handler)
        #fetch all_data and put them in cache
        for file_p in list(pathlib.Path().rglob("data")):
            file_s=str(file_p)
            path = file_s.replace('/data','')
            self._db[path]={}
            with open(file_s) as f:
                if file_s.endswith('description.xml/data'):
                    data=f.read()
                else:
                    data = json.loads(json.dumps(json.load(f)).replace("__REEFBEAT_DEVICE_IP__",self.config.ip))
                self._db[path]['data']=data
            with open(file_s.replace('/data','/access.json')) as f:
                access=json.load(f)
                self._db[path]['access']=access
        #print(json.dumps(self._db,sort_keys=True, indent=4))

        
class HttpServer(BaseHTTPRequestHandler):
    def get_data(self,path):
        if path[0]=='/':
            path= path[1:]
        return self.server._db[self.server.config.base_url+"/"+path]['data']

    def is_allow(self,path,method):
        if method in self.server._db[self.server.config.base_url+"/"+path[1:]]['access']['rights']:
            return True
        else:
            self.send_response(404)
            self.end_headers()
            return False
            
    def log_message(self,format, *args):
        return 


    def log_reqst(self,method):
        content_length_str = self.headers.get('Content-Length')
        data=""
        if content_length_str:
            data=self.rfile.read(int(content_length_str))
        print("%s: %s %s (%s)"%(self.server.config.name,method,format(self.path),data))
    
    def do_GET (self):
        self.log_reqst("GET")
        data = self.get_data(self.path)
        if data and self.is_allow(self.path,"GET"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(json.dumps(data),'utf8'))

    def do_POST (self):
        self.log_reqst("POST")
        #content_length_str = self.headers.get('Content-Length')
        #print("RFILE: %s"%self.rfile.read(int(content_length_str)))
        if self.path=='off':
            return
            
        data=self.get_data(self.path)
        if data and self.is_allow(self.path,"POST"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}','utf8'))
        elif not data:
            self.send_response(404)
            self.end_headers()

    def do_PUT (self):
        self.log_reqst("PUT")
        data=self.get_data(self.path)
        if data and self.is_allow(self.path,"PUT"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes('{"success":true}','utf8'))
        elif not data:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        self.log_reqst("DELETE")
        if self.path=='off':
           
            return
        if self.is_allow(self.path,"DELETE"):
            pass

def ServerProcess(config):
    conf=json.loads(json.dumps(config), object_hook=lambda d: SimpleNamespace(**d))
    if conf.enabled:
        try:
            print("HTTP Server [%s] %s:%d running - Use Ctrl-C to terminate"%(conf.name,conf.ip,conf.port))
            httpd = MyServer(HttpServer,conf)
            while True:
                httpd.handle_request()
        except Exception as e:
            if os.geteuid() != 0:
                print("Acquiring 'sudo' privileges ...")
                os.system("sudo python{} {}".format(sys.version_info[0], ' "' + '" "'.join(sys.argv) + '"'))
            else:
                print("Unable to start server")
                print(e)

if __name__ == "__main__":
    with open('config.json') as f:
        #confs = json.load(f, object_hook=lambda d: SimpleNamespace(**d))
        confs = json.load(f)

    threads=[]
    for conf in confs['devices']:
        thread = Thread(target = ServerProcess, args = [conf])
        threads+=[thread]
        thread.start()
        
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("Bye")
    time.sleep(2)
    subprocess.run(["sudo","pkill","-9","-f","sudo ./reefbeat-devices.py"])

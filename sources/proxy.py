import argparse
import threading
import logging
import signal
import sys
import click
import os
import asyncio

from flask import Flask, request, Response, make_response
from datetime import datetime

from .printing import print, log, Strings
from .http import Requests, Empty_response, Raw_Request
from .intruder import Intruder

class Arguments():

    def get_arguments(self):
        """
        Get arguments from command line.
        """
        parser = argparse.ArgumentParser(description='~~~~~~~~~~ WASSUP Website (proxified) ?? ~~~~~~~~~~')
        # Fuzzing stuff
        parser.add_argument('-u', "--url", help='Url to test',)
        parser.add_argument('-r', "--raw-request", help='Raw request prepared with the placeholder',)
        parser.add_argument("-d", "--data", default=None, help="Add POST data")
        parser.add_argument("-H", "--headers", default=None, action="append", help="Add extra Headers (syntax: -H \"test: test\" -H \"test2: test3\")")
        parser.add_argument("-S", "--placeholder", default="§")
        parser.add_argument("--force-ssl", default=False, help="Force https when using raw-request", action="store_true")
        parser.add_argument("-ur", "--url-raw", default=None, help="Force usage of a specific URL to make the raw request. Default: Using the Host header")
        # tool settings
        parser.add_argument('-v', '--verbosity', action='count', default=1, help='verbosity level (3 levels available)')
        parser.add_argument("--throttle", help="throttle between the requests, default 0.0", default=0, type=int)
        parser.add_argument('-re', "--allow-redirects", default=False, action="store_true", help='Allow HTTP redirects')

        parser.add_argument("--chrome-debug-port", dest="chrome_port",help='Specify the port of an exposed chrome remote debugging port (to use an already opened chrome instance)', default=None)
        parser.add_argument("--proxy-method", help='Get the payloads from an other tool via a loopback HTTP server with a specific method', default=None, choices=["GET", "POST"])
        parser.add_argument("--only-new-pages", help='Spawn a new page of the headless browser for each payload', default=False, action="store_true")
        parser.add_argument("--proxy-port", help='Get the payloads from an other tool via a loopback HTTP server with a specific port', default=8080, type=int)

        parser.add_argument("--prefix", help='Prefix for all elements of the wordlist',default=str())
        parser.add_argument("--suffix", help='Suffix for all elements of the wordlist',default=str())
        parser.add_argument("--timeout", default=20, type=int)
        parser.add_argument("--retry", default=False, action="store_true")
        parser.add_argument("--verify-ssl", default=False, action="store_true")
        parser.add_argument("-X", "--method", default="GET", help="HTTP method to use")
        parser.add_argument("-f", "--filter", help="Filter positives match with httpcode,to exclude one, prefix \"n\", examples: -f n204 -f n403", action="append", default=[])
        parser.add_argument("-T", "--tamper",help="Use tamper scripts located in the tamper directory (you can make your own), ou can also chain them (processed in the order)", default=[], action="append")
        parser.add_argument("-ut", "--untamper",help="Unprocess tampered payload to see what is the real payload unprocessed", default=False, action="store_true")
        parser.add_argument("-tf", "--time-filter",help='Specify the time range that we\'ll use to accept responses (format: >3000 or <3000 or =3000 or >=3000 or <=3000', action="append", default=[])
        parser.add_argument("-lf", "--length-filter",help='Specify the length range that we\'ll use to accept responses (format: >3000 or <3000 or =3000 or >=3000 or <=3000', action="append", default=[])
        # base request stuff
        parser.add_argument("-B", "--use-base-request", help="Use the strategy to compare responses against a base request to reduce noise",action="store_true", default=False)
        parser.add_argument('-b', "--base-payload",help="Payload for base request", default="Fuzzing")
        parser.add_argument("--ignore-base-request", default=False, action="store_true", help="Force testing even if base request failed")
        parser.add_argument("-timed", "--time-difference", default=2, type=int, help="Define a time difference where base_request will not be equal to the current_request, ie base request took 1 second and current took 2 seconds, they are different until time_different>=1")
        parser.add_argument("-textd", "--text-difference-ratio", default=0.98, type=float, help="Define a text difference where base_request.text will not be equal to the current_request.text, ie base_request matches current_request at 98%%, they are different until time_different>=0.98")
        parser.add_argument("--ratio-type", default="quick", help="Use a quick ratio of a normal one, quick is faster, normal is for very short pages")
        parser.add_argument("-m", '--match-base-request',action="store_true", default=False, help="Match the base request to find pages identical to your base payload")
        parser.add_argument('-mh', "--match-headers",help="Extends the match algorithm to the headers", default=False, action="store_true")
        parser.add_argument('-eh', "--exclude-headers",help="Exclude a header while extending the match algorithm to the headers", default=[], action="append")

        # parser.add_argument('-o', '--dumpHtml', help='file to dump html content')
        # parser.add_argument("-q", "--quiet", help="tell the program to output only the results",
        #                     default=False, action="store_true")
        self.args = parser.parse_args()
        return self.validate_arguments()

    def validate_arguments(self,):
        """
        Validate arguments.
        """
        if self.args.url is None and self.args.raw_request is None:
            log("[!] You must specify a url to test (-u) or a request file (-r) !", type="fatal")
            exit(1)

        self.tampers = None
        if len(self.args.tamper) > 0:
            self.tampers = []
            for tamper in self.args.tamper:
                loaded = self.load_tamper(tamper)
                self.tampers.append(loaded)
                self.check_tamper(loaded)
            
        if self.args.raw_request is not None:
            try:
                with open(self.args.raw_request) as f:
                    self.args.raw_request = f.read()
            except Exception as e:
                log(f"Failed to open the raw request file !", type="critical")
                exit(1)
        
        if len(
            set(filter(None, [
                self.args.url,
                self.args.raw_request
            ])
            )
        ) > 1:
            log("You've specified more that one method to make requests, that's dumb :/ -u OR -r!", type="critical")
            exit(1)
    
        self.load_headers()
        return self.args
    
    def find_place(self):
        """
        Find the place where to put the payload.
        """
        self.place = list()
        if self.args.data is not None and self.args.placeholder in self.args.data:
            self.place.append("data")
        if self.args.url is not None and self.args.placeholder in self.args.url or\
             self.args.url_raw is not None and self.args.placeholder in self.args.url_raw:
            self.place.append("url")
        if self.args.placeholder in "".join([k+v for k,v in self.args.headers.items()]):
            self.place.append("headers")
        if self.args.raw_request is not None and self.args.placeholder in self.args.raw_request:
            # defined later when parsing
            self.place.append("raw")
        
        if len(self.place) == 0:
            log(f"You mush specify the placeholder \"{self.args.placeholder}\" where you're trying to fuzz !", type="critical")
            exit(1)
 
    def load_tamper(self, module):
        module_path = f"tampers.{module}"

        if module_path in sys.modules:
            return sys.modules[module_path]
        try:
            load = __import__(module_path, fromlist=[module])
        except ModuleNotFoundError:
            log(f"Could not find the module \"{module}\" !", type="fatal")
            log(f"Here is the list of available modules: {', '.join([x[:-3] for x in os.listdir('tampers/') if x.endswith('.py')])}", type="debug")
            exit(1)
        except Exception as e:
            log(f"Failed to load the module {module}, please make sure you've put it in the tampers directory", type="critical")
            log(f"Here is your stacktrace: {e}", type="debug")
            exit(1)
        else:
            return load
    
    def load_headers(self,):
        """
        Load headers from the file.
        """
        headers_temp = dict()
        if self.args.headers is not None:
            for header in self.args.headers:
                if ":" in header:
                    key, value = header.split(": ")
                    headers_temp[key] = value
                else:
                    headers_temp[header] = str()
        self.args.headers = headers_temp
    
    def check_tamper(self, tamper):
        try:
            dummyCheck = tamper.process("Th1s Is @ Nice DummyCheck …")
            log(f"[*] Dummy check for the tamper module loaded: \"Th1s Is @ Nice DummyCheck …\" -> \"{dummyCheck}\"", type="debug")
            if isinstance(dummyCheck, bytes):
                log(f"Your tamper script should only return string and not bytes ! can't continue...", type="error")
                exit(1)
        except Exception as e:
            log(f"An exception occured in your tamper script !", type="critical")
            log(f"Hint: Can you find the 'process' function in your tamper script ?\n Stack trace: {e}", type="debug")
            exit(1)

class Wordlist():

    def __init__(self,tampers, prefix, suffix):
        self.tampers = tampers
        self.prefix = prefix
        self.suffix = suffix
        self.payload_list = list()
        

    def gen_payload(self,base_payload):
        self.payload_list.append(base_payload)
        return self.apply_tamper(f"{self.prefix}{base_payload}{self.suffix}")
        
    def apply_tamper(self, payload):
        if self.tampers is None or len(self.tampers) < 0:
            return payload
        tempo = payload
        for tamper in self.tampers:
            try:
                tempo = tamper.process(tempo)
                if isinstance(tempo, bytes):
                    log(f"Your tamper script should only return string and not bytes ! can't continue...", type="critical")
                    log(f"It translates {payload} to -> {tempo}", type="debug")
                    exit(1)
            except Exception as e:
                log(f"An exception occured in your tamper script ! Below is the stack trace of your script.", type="critical")
                log(f"Error: {e}", type="debug")
                exit(1)
        return tempo
    
    def unapply_tamper(self, payload):
        tempo = payload
        for tamper in self.tampers[::-1]:
            try:
                if not "unprocess" in dir(tamper):
                    log(f"To use untamper functionnality, you need a function 'unprocess' in your tamper script !", type="fatal")
                    exit(1)
                tempo = tamper.unprocess(tempo)
                if isinstance(tempo, bytes):
                    log(f"Your tamper script should only return string and not bytes ! can't continue...", type="critical")
                    log(f"It translates {payload} to -> {tempo}", type="debug")
                    exit(1)
                
            except Exception as e:
                log(f"An exception occured in your tamper script \"{tamper}\"! Below is the stack trace of your script.", type="critical")
                log(f"Error: {e}", type="debug")
                exit(1)
        return tempo

class Proxy():

    def __init__(self, args):
        self.arguments_object = args
        self.args = self.arguments_object.get_arguments()
        self.arguments_object.find_place()
        self.start_date = datetime.now()
        self.port = self.args.proxy_port
        self.load_request()
        
    def load_request(self,):
        if self.args.url is not None:
            self.requests = Requests(
                    method=self.args.method, 
                    timeout=self.args.timeout, 
                    throttle=self.args.throttle, 
                    allow_redirects=self.args.allow_redirects, 
                    verify_ssl=self.args.verify_ssl, 
                    retry=self.args.retry,
                    headers=self.args.headers)
        elif self.args.raw_request is not None:
            
            raw_request_parsed = Raw_Request(self.args.raw_request, self.args.url_raw, self.args.force_ssl)
            raw_request_parsed.parse_raw_request()
            raw_request_parsed.build_url()
            method, url, headers, data = \
                 raw_request_parsed.method, raw_request_parsed.url, raw_request_parsed.headers, raw_request_parsed.data
            
            self.args.method = method
            self.args.url = url
            self.args.headers.update(headers)
            self.args.data = data if not self.args.data else self.args.data

            self.requests = Requests(
                    method=self.args.method, 
                    timeout=self.args.timeout, 
                    throttle=self.args.throttle, 
                    allow_redirects=self.args.allow_redirects, 
                    verify_ssl=self.args.verify_ssl, 
                    retry=self.args.retry,
                    headers={k: v for k,v in self.args.headers.items() if not self.args.placeholder in v and not self.args.placeholder in k})
    
    def gen_wordlist(self):
        self.wordlist = Wordlist(
                                tampers=self.arguments_object.tampers, 
                                prefix=self.args.prefix, 
                                suffix=self.args.suffix)
    
    def start_proxy(self):
        app = Flask("Supp-proxy")
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        def secho(text, file=None, nl=None, err=None, color=None, **styles):
            pass

        def echo(text, file=None, nl=None, err=None, color=None, **styles):
            pass

        click.echo = echo
        click.secho = secho
        """
        @app.after_request
        def apply_caching(response):
            response.headers["Server"] = "Fu Flask for your headers"
            return response"""

        @app.route("/classic", methods=["GET", "POST"])
        def classic():
            body = dict(request.form)
            get_args = dict(request.args)
            if not 'sup' in list(body.keys()) + list(get_args.keys()):
                return "You must send a 'sup' argument to the proxy to work properly !"
            body.update(get_args)
            response = self.forward_request_classic(body)
            response_obj = make_response(response.content)
            
            for k,v in response.headers.items():
                # ban some headers that breaks things
                if k in ["Transfer-Encoding"]:
                    continue
                response_obj.headers[k] = v

            return response_obj, response.status_code
        
        @app.route("/headless", methods=["GET", "POST"])
        def headless():
            
            body = dict(request.form)
            get_args = dict(request.args)
            if not 'sup' in list(body.keys()) + list(get_args.keys()):
                return "You must send a 'sup' argument to the proxy to work properly !"
            body.update(get_args)
            
            response = asyncio.run(self.forward_request_headless(body))
            
            response_obj = make_response(response.text)
            
            for k,v in response.headers.items():
                # ban some headers that breaks things
                if k.lower() in ["transfer-encoding"]:
                    continue
                v = v.replace("\n","")
                response_obj.headers[k] = v
            return response_obj, response.status_code
                        

        app.run(host="127.0.0.1", port=self.port, debug=False, use_reloader=False)

    def prepare(self):
        def signal_handler(sig, frame):
            log(f"Caught ctrl+c, stopping...", type="warning")            
            exit(1)
        signal.signal(signal.SIGINT, signal_handler)

        self.gen_wordlist()
        self.print(1, Strings.banner, color="yellow")
        self.intruder = Intruder(self.args, self.arguments_object.place, self.wordlist)
        if self.args.use_base_request:
            log(f"[+] Requesting base request", type="info")
            self.intruder.do_base_request()
            if self.intruder.base_request is None:
                log(f"Base request failed !", type="critical")
                if not self.args.ignore_base_request:
                    log(f"To ignore this and continue, append flag --ignore-base-request", type="debug")
                    exit(1)  
                log(f"Ignoring base request failed (the base request is not useless)", type="warning")
                self.intruder.base_request = Empty_response()
            if len(self.intruder.base_request.text) > 100:
                base_request_text_top = self.intruder.base_request.text[:50]
                base_request_text_bottom = self.intruder.base_request.text[-50:]
            else:
                base_request_text_top = self.intruder.base_request.text
                base_request_text_bottom = ""


            self.print(1, Strings.base_request_details.format(
                status=self.intruder.base_request.status_code,
                content_len=len(self.intruder.base_request.text),
                total_seconds=self.intruder.base_request.elapsed.total_seconds(),
                text_top=base_request_text_top,
                text_bottom=base_request_text_bottom),
                color=self.intruder.requests.color_status_code(self.intruder.base_request)
            )
        self.print(1, Strings.results_header, color="white")
        
    def forward_request_classic(self, args):

        status, response, parameter, full_payload = self.intruder.start_request(args["sup"])
        parameter_print = full_payload
        if self.args.untamper:
            parameter_print = self.wordlist.unapply_tamper(full_payload)
        if status:
            if response is None:
                response = Empty_response()
            self.print(1, Strings.results.format(
                time=datetime.now().strftime("%H:%M:%S"),
                payload_index=f"{self.wordlist.payload_list.index(parameter)}",
                payload_len=len(self.wordlist.payload_list),
                status=response.status_code,
                length=len(response.text),
                response_time=f"{response.elapsed.total_seconds():.6f}",
                payload=parameter_print),
                    color=self.intruder.requests.color_status_code(response))
            return response
        self.print(1, Strings.results.format(
                time=datetime.now().strftime("%H:%M:%S"),
                payload_index=f"{self.wordlist.payload_list.index(parameter)}",
                payload_len=len(self.wordlist.payload_list),
                status=response.status_code,
                length=len(response.text),
                response_time=f"{response.elapsed.total_seconds():.6f}",
                payload=parameter_print),
                    color=self.intruder.requests.color_status_code(response), end=f"{' '*os.get_terminal_size()[1]}\r")
        return response

    
    async def forward_request_headless(self, args):
        status, response, parameter, full_payload = await self.intruder.start_request_headless(args["sup"])
        parameter_print = full_payload
        if self.args.untamper:
            parameter_print = self.wordlist.unapply_tamper(full_payload)
        if status:
            if response is None:
                response = Empty_response()
            self.print(1, Strings.results.format(
                time=datetime.now().strftime("%H:%M:%S"),
                payload_index=f"{self.wordlist.payload_list.index(parameter)}",
                payload_len=len(self.wordlist.payload_list),
                status=response.status_code,
                length=len(response.text),
                response_time=f"{response.elapsed.total_seconds():.6f}",
                payload=parameter_print),
                    color=self.intruder.requests.color_status_code(response))
            return response
        self.print(1, Strings.results.format(
                time=datetime.now().strftime("%H:%M:%S"),
                payload_index=f"{self.wordlist.payload_list.index(parameter)}",
                payload_len=len(self.wordlist.payload_list),
                status=response.status_code,
                length=len(response.text),
                response_time=f"{response.elapsed.total_seconds():.6f}",
                payload=parameter_print),
                    color=self.intruder.requests.color_status_code(response), end=f"{' '*os.get_terminal_size()[1]}\r")
        return response
    def print(self, verbosity=0, *args, **kwargs):
        if self.args.verbosity <= verbosity:
            print(*args, **kwargs)

def main():
    args = Arguments()
    proxy = Proxy(args)
    proxy.prepare()
    proxy.start_proxy()




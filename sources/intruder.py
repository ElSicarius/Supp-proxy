
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from .http import Requests, Request
from .printing import log
from .differs import Differs

class Intruder():
    def __init__(self, args, place, wordlist):
        self.args = args
        self.place = place
        self.wordlist = wordlist
        self.requests = Requests( method=args.method, 
                                timeout=args.timeout, 
                                throttle=args.throttle, 
                                allow_redirects=args.allow_redirects, 
                                verify_ssl=args.verify_ssl, 
                                retry=args.retry,
                                independant_chrome=args.chrome_port)
        self.futures = set()
        self.fill_statuscode_specs()
        self.fill_time_spent_specs()
        self.fill_text_length_specs()
    
    def fill_statuscode_specs(self):
        self.status_code_specs = {"allow":set(), "deny":set()}

        def gen_statuses(base):
            if len(base) < 3:
                end = f"{str(int(base[0], 10) +1):0<3}"
            else:
                end = str(int(base)+1)

            base = f"{base:0<3}"
            return {int(x) for x in range(int(base, 10), int(end, 10))}
        
        if len(self.args.filter) == 0 :
                self.status_code_specs["allow"] = {"any"}
                return
        for spec in self.args.filter:
            if spec[0] == "n":
                self.status_code_specs["deny"] = self.status_code_specs["deny"].union(gen_statuses(spec.strip("nx")))
            else:
                self.status_code_specs["allow"] = self.status_code_specs["allow"].union(gen_statuses(spec.strip("x")))
        
        if len(self.status_code_specs["allow"]) == 0:
            self.status_code_specs["allow"].add("any")
            
    def fill_time_spent_specs(self):
        self.time_spent_specs = {"above": set(), "lower": set(), "equals": set()}
        for spec in self.args.time_filter:
            if spec.startswith(">"):
                if spec[1] == "=":
                    self.time_spent_specs["equals"].add(float(spec.strip(">=<")))
                self.time_spent_specs["above"].add(float(spec.strip(">=<")))
                continue
            if spec.startswith("<"):
                if spec[1] == "=":
                    self.time_spent_specs["equals"].add(float(spec.strip("<=>")))
                self.time_spent_specs["lower"].add(float(spec.strip("<=>")))
                continue
            if spec.startswith("="):
                self.time_spent_specs["equals"].add(float(spec.strip("=><")))
                continue
            log(f"Error while parsing time filter, unknown operand '{spec[0]}'", type="critical")
    
    def fill_text_length_specs(self):
        self.text_length_specs = {"above": set(), "lower": set(), "equals": set()}
        for spec in self.args.length_filter:
            if spec.startswith(">"):
                if spec[1] == "=":
                    self.text_length_specs["equals"].add(float(spec.strip(">=<")))
                self.text_length_specs["above"].add(float(spec.strip(">=<")))
                continue
            if spec.startswith("<"):
                if spec[1] == "=":
                    self.text_length_specs["equals"].add(float(spec.strip("<=>")))
                self.text_length_specs["lower"].add(float(spec.strip("<=>")))
                continue
            if spec.startswith("="):
                self.text_length_specs["equals"].add(float(spec.strip("=><")))
                continue
            log(f"Error while parsing length filter, unknown operand '{spec[0]}'", type="critical")

    def is_status_code_in_specs(self, status_code):
        if status_code not in self.status_code_specs["deny"] and \
            (status_code in self.status_code_specs["allow"] or "any" in self.status_code_specs["allow"]):
            return True
        return False

    def is_response_time_in_specs(self, time_elapsed):
        if len(self.time_spent_specs['equals']) == 0 and \
            len(self.time_spent_specs["above"]) == 0 and \
                len(self.time_spent_specs["lower"]) == 0:
                return True
        for equals in self.time_spent_specs["equals"]:
            if time_elapsed == equals:
                return True
        for lower in self.time_spent_specs["lower"]:
            if time_elapsed < lower:
                return True
        for above in self.time_spent_specs["above"]:
            if time_elapsed > above:
                return True
        return False

    def is_response_len_specs(self, response_len):
        if len(self.text_length_specs['equals']) == 0 and \
            len(self.text_length_specs["above"]) == 0 and \
                len(self.text_length_specs["lower"]) == 0:
                return True
        for equals in self.text_length_specs["equals"]:
            if response_len == equals:
                return True
        for lower in self.text_length_specs["lower"]:
            if response_len < lower:
                return True
        for above in self.text_length_specs["above"]:
            if response_len > above:
                return True
        return False

    def prepare_request_and_send(self, payload, base_payload):
        req = Request(self.args.url, self.args.data, self.args.headers, self.args.method, payload, self.args.placeholder, self.place)
        return base_payload, payload, self.do_request(req)
    
    async def prepare_request_and_send_headless(self, payload, base_payload):
        req = Request(self.args.url, self.args.data, self.args.headers, self.args.method, payload, self.args.placeholder, self.place)
        return base_payload, payload, await self.do_request_headless(req)
    
    def do_base_request(self):
        req = Request(self.args.url, self.args.data, self.args.headers, self.args.method, self.args.base_payload, self.args.placeholder, self.place)
        self.base_request = self.do_request(req)
        self.difflib = Differs(self.args.base_payload, self.args.time_difference, self.args.text_difference_ratio, self.args.ratio_type)
        return self.base_request

    def do_request(self, req):
        return self.requests.request_object_handler(req)
    
    async def do_request_headless(self, req):
        return await self.requests.request_object_handler_headless(req)

    def start_request(self, payload):
        tampered = self.wordlist.gen_payload(payload)
        base_payload, full_payload, response = self.prepare_request_and_send(tampered, payload)
       
                
        if response is None:
            log(f"A problem occured while fetching the link, your internet might be broken. param: {base_payload}", type="critical")
            # Accept response
            return True, response, base_payload, full_payload
            
        
        # Base request checks
        if self.args.use_base_request:
            if self.base_request is not None:
                identical = self.difflib.is_identical(self.base_request, response, base_payload, self.args.match_headers, self.args.exclude_headers)
                if identical:
                    if not self.args.match_base_request:
                        return False, response, base_payload, full_payload
                        
                else:
                    if self.args.match_base_request:
                        return False, response, base_payload, full_payload
        # FILTERS CHECKS
        if not self.is_status_code_in_specs(response.status_code):
            # reject response
            return False, response, base_payload, full_payload
            
        if not self.is_response_time_in_specs(response.elapsed.total_seconds()):
            # reject response
            return False, response, base_payload, full_payload
            
        if not self.is_response_len_specs(len(response.text)):
            # reject response
            return False, response, base_payload, full_payload
            
        return True, response, base_payload, full_payload
    
    async def start_request_headless(self, payload):
        tampered = self.wordlist.gen_payload(payload)
        base_payload, full_payload, response = await self.prepare_request_and_send_headless(tampered, payload)
       
                
        if response is None:
            log(f"A problem occured while fetching the link, your internet might be broken. param: {base_payload}", type="critical")
            # Accept response
            return True, response, base_payload, full_payload
            
        
        # Base request checks
        if self.args.use_base_request:
            if self.base_request is not None:
                identical = self.difflib.is_identical(self.base_request, response, base_payload, self.args.match_headers, self.args.exclude_headers)
                if identical:
                    if not self.args.match_base_request:
                        return False, response, base_payload, full_payload
                        
                else:
                    if self.args.match_base_request:
                        return False, response, base_payload, full_payload
                        


        # FILTERS CHECKS
        if not self.is_status_code_in_specs(response.status_code):
            # reject response
            return False, response, base_payload, full_payload
            
        if not self.is_response_time_in_specs(response.elapsed.total_seconds()):
            # reject response
            return False, response, base_payload, full_payload
            
        if not self.is_response_len_specs(len(response.text)):
            # reject response
            return False, response, base_payload, full_payload
            
        return True, response, base_payload, full_payload
        
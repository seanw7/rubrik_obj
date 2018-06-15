import requests
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



token = None


class RubrikObject(object):
    """To Initialize this object, you must pass in your Rubriks' IP, and a valid username and password"""
    def __init__(self, server, username, password, token_id=None, session_id=None, api_url = None, cluster_id = None, cluster_name = None,
    cluster_timezone = None, headers = None, gold_sla_id = None, silver_sla_id = None, bronze_sla_id = None, sla_domains = None, vcenter_id = None,
    vcenter_username = None, vcenter_cert = None, vcenter_primary_cluster = None, current_search = None):
        self.server = server
        self.password = password
        self.username = username
        self.token_id = token_id
        self.session_id = session_id
        self.api_url = api_url
        self.cluster_id = cluster_id
        self.cluster_name = cluster_name
        self.cluster_timezone = cluster_timezone
        self.headers = headers
        self.gold_sla_id = gold_sla_id
        self.silver_sla_id = silver_sla_id
        self.bronze_sla_id = bronze_sla_id
        self.sla_domains = sla_domains
        self.vcenter_id = vcenter_id
        self.vcenter_username = vcenter_username
        self.vcenter_cert = vcenter_cert
        self.vcenter_primary_cluster = vcenter_primary_cluster
        self.current_search = current_search
        self.login()

    def login(self):
        """This method posts user login data and gets an oauth token, then saves the token data in the object for future api calls"""
        #self.session = requests.get('https://' + self.server + '/api/v1')
        session = requests.post('https://' + self.server + '/api/v1/session', verify = False, auth = (self.username, self.password))
        session_token = session.json()
        self.session_id = session_token['id']
        self.token_id = 'Bearer ' + session_token['token']
        self.api_url = 'https://' + self.server + '/api/v1'
        self.headers = {'Content-Type': 'application/json', 'Authorization': self.token_id}
        print("Initialized connection to Rubrik. IP: {}, User: {}".format(self.server, self.username))
        print(session_token)
        return session_token

    def exit_session(self):
        """This method closes the session and invalidates the session token."""
        req = requests.delete(self.api_url + '/session/me', verify = False, headers = self.headers)
        return req

    def get_VMList(self):
        """This method returns a list of all VMs on the rubrik cluster"""
        vm_list = requests.get('https://' + self.server + '/api/v1/vmware/vm', verify = False, headers = self.headers)
        vm_list_json = vm_list.json()
        return vm_list_json

    def get_CurrentClusters(self):
        """This method gets the cluster id of the current rubrik cluster"""
        req = requests.get(self.api_url + '/cluster/me', verify = False, headers = self.headers)
        req_json = req.json()
        self.cluster_id = req_json['id']
        return req_json

    def get_ClusterInfo(self):
        """This method returns info about the rubrik cluster"""
        if not self.cluster_id:
            self.get_CurrentClusters()
        req = requests.get(self.api_url + '/cluster/' + self.cluster_id , verify = False, headers = self.headers)
        #curl -X GET "https://$cluster_address/api/v1/cluster/
        req_json = req.json()
        self.cluster_name = req_json['name']
        self.cluster_timezone = req_json['timezone']
        return req_json

    def get_SLA_Domains(self):
        """This method obtains data about the SLA domain levels in the rubrik cluster"""
        if not self.cluster_id:
            self.get_CurrentClusters()

        req = requests.get(self.api_url + '/sla_domain', verify = False, headers = self.headers)
        req_json = req.json()
        sla_domains = {}
        for SLA in req_json['data']:
            sla_domains[SLA['name']] = SLA['id']
            if SLA['name'] == 'Gold':
                self.gold_sla_id = SLA['id']
            if SLA['name'] == 'Silver':
                self.silver_sla_id = SLA['id']
            if SLA['name'] == 'Bronze':
                self.bronze_sla_id = SLA['id']
        #self.gold_sla_id = req_json['data']['']
        #self.silver_sla_id = req_json['']
        #self.bronze_sla_id = req_json['']
        self.sla_domains = sla_domains
        #return sla_domains
        return req_json

    def Describe_SLA_Domain(self, domain_name):
        """This method takes in an SLA domain name and returns info about it"""
        if not self.cluster_id:
            self.get_CurrentClusters()
        if not self.sla_domains:
            self.get_SLA_Domains()

        req = requests.get(self.api_url + '/sla_domain/' + self.sla_domains[domain_name], verify = False, headers = self.headers)
        req_json = req.json()

        return req_json

    def Create_SLA_Domain(self, domain_name, frequencies, allowedBackupWindows, firstFullAllowedBackupWindows, localRetentionLimit, archivalSpecs, replicationSpecs):
        """This method will take in a domain name and required data and create an SLA Domain"""
        # MAYBE NOT THE BEST THING TO USE!!!
        frequencies = []
        allowedBackupWindows = []
        firstFullAllowedBackupWindows = []
        localRetentionLimit = ''
        archivalSpecs = []
        replicationSpecs = []

        data = {'name': domain_name, 'frequencies': frequencies, 'allowedBackupWindows': allowedBackupWindows, 'firstFullAllowedBackupWindows': firstFullAllowedBackupWindows, 'localRetentionLimit': localRetentionLimit, 'archivalSpecs': archivalSpecs, 'replicationSpecs': replicationSpecs}

        req = requests.post(self.api_url + '/sla_domain', verify = False, headers = self.headers, data = data)
        req_json = req.json()

        return req_json

    def Modify_SLA_Domain(self, domain_name, frequencies, allowedBackupWindows, firstFullAllowedBackupWindows, localRetentionLimit, archivalSpecs, replicationSpecs):
        """This method will take in a domain name and required data and create an SLA Domain"""
        # MAYBE NOT THE BEST THING TO USE!!!
        frequencies = []
        allowedBackupWindows = []
        firstFullAllowedBackupWindows = []
        localRetentionLimit = ''
        archivalSpecs = []
        replicationSpecs = []

        if not self.cluster_id:
            self.get_CurrentClusters()
        if not self.sla_domains:
            self.get_SLA_Domains()


        data = {'name': domain_name, 'frequencies': frequencies, 'allowedBackupWindows': allowedBackupWindows, 'firstFullAllowedBackupWindows': firstFullAllowedBackupWindows, 'localRetentionLimit': localRetentionLimit, 'archivalSpecs': archivalSpecs, 'replicationSpecs': replicationSpecs}

        req = requests.post(self.api_url + '/sla_domain' + self.sla_domains[domain_name], verify = False, headers = self.headers, data = data)
        req_json = req.json()

        return req_json

    def get_vCenter_Servers(self):
        req = requests.get(self.api_url + '/vmware/vcenter', verify = False, headers = self.headers)
        req_json = req.json()

        vcenter_servers = {}
        print("Req_Json data:")
        print(req_json['data'][1])
        # vcenter['hostname'] is the vcenter_address; vcenter['id'] is the vcenter_id; vcenter['username'] is the vcenter_admin; vcenter['caCerts'] is the ca_cert for the vcenter; vcenter['primaryClusterId'] is the cluster_id
        self.vcenter_id = req_json['data'][0]['id']
        self.vcenter_username = req_json['data'][0]['username']
        self.vcenter_cert = req_json['data'][0]['caCerts']
        self.vcenter_primary_cluster = req_json['data'][0]['primaryClusterId']  # This should be equal to the rubriks cluster_id
        for vcenter in req_json['data']:
            vcenter_servers[vcenter['hostname']] = {'vcenter_id': vcenter['id'], 'vcenter_username': vcenter['username'], 'vcenter_cert': vcenter['caCerts']}
        print('vcenter_server_json: ')
        print(vcenter_servers)
        return req_json

    def refresh_medadata(self):
        req = requests.post(self.api_url + '/vmware/vcenter/' + self.vcenter_id + '/refresh', verify = False, headers = self.headers)
        req_json = req.json()

        return req_json

    def get_esxi_hypervisors(self):
        self.get_CurrentClusters()
        req = requests.get(self.api_url + '/vmware/host?primary_cluster_id=' + self.cluster_id, verify = False, headers = self.headers)
        req_json = req.json()

        return req_json

    def search_for_vm(self, search_for, sla_domain_id='UNPROTECTED', num_limit=1):
        if not isinstance(num_limit, int):
            raise ValueError('keyword argument must be an integer')
        req = requests.get(self.api_url + '/vmware/vm?effective_sla_domain_id=' + sla_domain_id +'&limit=' + str(num_limit) + '&offset=0&name=' + search_for, verify = False, headers = self.headers)
        req_json = req.json()
        vm_data = {}
        newest_vm_id = req_json['data']
        #list_comp = [{obj['id']: obj} for obj in req_json['data']]
        current_search = [{obj['id']: {'moid': obj['moid'], 'vcenter_id': obj['vcenterId'], 'hostname': obj['hostName'], 'name': obj['name']}} for obj in req_json['data']]
        self.current_search = current_search

        #print(req_json['data'])
        # len_of_search = len(req_json)
        # try:
        #
        #     if len_of_search == 0:
        #         print("Couldn't find any VMs with those search parameters")
        #         return req_json
        #     elif len_of_search == 1:
        #         vm_data[req_json['data'][0]]
        #         return req_json['data'][0]
        #
        #     elif len_of_search > 1:
        #
        #         for obj in req_json['data']:
        #             print('GREATER THAN OR EQUAL TO 1 RESULTS')
        #             print(obj)
        #
        #         #for VM in req_json['data']:
        #         #    VM
        #         return req_json['data']
        #
        #
        # except:
        #     return "Couldn't find a VM with those search parameters"
        # #print(newest_vm_id)
        #return req_json
        print(current_search)
        return req_json['data']

    def describe_vm(self, vm_id=None):
        """This method will search for a VM_ID and attempt to describe. Otherwise if there is a current search
           cached in the object. It will attempt to describe all VM's in the input"""
        all_vms = []

        if vm_id:
            req = requests.get(self.api_url + '/vmware/vm/' + str(vm_id), verify = False, headers = self.headers)
            #print(req.url)
            req_json = req.json()
            all_vms.append(req_json)

        elif self.current_search:
            input_list=self.current_search

            input_list = list(input_list)

            #print("Searching for...")
            #print( search_for)
            #print(input_list)
            for vm in input_list:
                #print(vm)
                for key, value in vm.items():

                    #print(key)
                    req = requests.get(self.api_url + '/vmware/vm/' + str(key), verify = False, headers = self.headers)
                    #print(req.url)
                    req_json = req.json()
                    all_vms.append(req_json)
                    #print(req_json)

        return all_vms

    def search_VM_Files(self, vm_id=None, file_path=None):
        """MPORTANT: The snapshot used in this task must be indexed. Indexing makes the file system structure of the data
        available to the Rubrik cluster. To determine whether a snapshot has been successfully indexed, send a GET request
        to /vmware/vm/snapshot/{id} as described in the 'Retrieving snapshot information' section of Snapshot management.
        Look at the value of indexState. A value of 1 means the snapshot has been indexed. A value of 0 means the snapshot
        has not been indexed."""
        all_vms = []
        correct_path = file_path.replace('/', '%2F')


        if vm_id and file_path:
            req = requests.get(self.api_url + '/vmware/vm/' + str(vm_id) + '/search?path=' + correct_path , verify = False, headers = self.headers)

            print(req.url)
            #print(req.url)
            req_json = req.json()
            all_vms = req_json
            #all_vms.append(req_json)


        elif self.current_search and file_path:
            input_list=self.current_search
            input_list = list(input_list)

            for vm in input_list:
                for key, value in vm.items():
                    req = requests.get(self.api_url + '/vmware/vm/' + str(key) + '/search?path=' + correct_path, verify = False, headers = self.headers)
                    print(req.url)
                    req_json = req.json()
                    all_vms.append(req_json)
                    #print(req_json)

        else:
            return "Missing a keyword, check that 'file_path' exists"


        return all_vms

    def browse_VM_Files_Snapshot(self, vm_id=None, file_path=None):
        all_vms = []
        correct_path = file_path.replace('/', '%2F')


        if vm_id and file_path:
            req = requests.get(self.api_url + '/vmware/vm/' + snapshot_id + '/search?path=' + correct_path , verify = False, headers = self.headers)

            print(req.url)
            #print(req.url)
            req_json = req.json()
            all_vms = req_json
            all_vms.append(req_json)


        elif self.current_search and file_path:
            input_list=self.current_search
            input_list = list(input_list)

            for vm in input_list:
                for key, value in vm.items():
                    req = requests.get(self.api_url + '/vmware/vm/' + snapshot_id + '/browse?path=' + correct_path, verify = False, headers = self.headers)
                    print(req.url)
                    req_json = req.json()
                    all_vms.append(req_json)
                    #print(req_json)

        else:
            return "Missing a keyword, check that 'file_path' exists"


        return all_vms

    def get_snapshot_data(self, vm_id=None):
        all_vms = []
        if self.current_search and not vm_id:
            print("Current search is cached, and didn't receieve a VM_ID to test against")
            print(self.current_search)
            input_list=self.current_search
            input_list = list(input_list)

            for vm in input_list:
                for key, value in vm.items():
                    req = requests.get(self.api_url + '/vmware/vm/' + str(key) + '/snapshot', verify = False, headers = self.headers)
                    print(req.url)
                    req_json = req.json()

                    if req_json['total'] == 0:
                        print("VM_ID: {}, doesn't appear to have any snapshots stored".format(key))
                        response = "VM_ID: {}, doesn't appear to have any snapshots stored".format(key)
                        all_vms.append(response)
                    else:
                        all_vms.append(req_json)



        elif vm_id:
            req = requests.get(self.api_url + '/vmware/vm/' + str(vm_id) + '/snapshot', verify = False, headers = self.headers)
            req_json = req.json()
            all_vms = req_json

        return all_vms

    def take_snapshot(self, vm_id=None):

        req = requests.post(self.api_url + '/vmware/vm/' + str(vm_id) + '/snapshot', verify=False, headers=self.headers)
        req_json = req.json()

        return req_json

            #req = requests.get(self.api_url + '/vmware/vm/' + search_for, verify = False, headers = self.headers)
if __name__ == '__main__':

    # This command initializes the RubrikObject with the ip, username, and password of the variables with the same name.
    rub_obj = RubrikObject(rubrik_ip, username, password)
    # This command searches the vcenter for a VM with Sean in the name, and limits to 3 results
    rub_obj.search_for_vm('Sean', num_limit=3)


    rub_obj.get_snapshot_data(vm_id='VirtualMachine:::d667276f-bafe-4acb-9263-acde6bc09b21-vm-9363')
    # This command takes a snapshot of the vm_id, VM
    rub_obj.take_snapshot(vm_id='VirtualMachine:::d667276f-bafe-4acb-9263-acde6bc09b21-vm-9363')
    rub_obj.describe_vm()

    # This shows the files @ /root, inside the vm, with vm_id. as listed in the key word.
    rub_obj.search_VM_Files(vm_id='VirtualMachine:::d667276f-bafe-4acb-9263-acde6bc09b21-vm-9363', file_path="/root")
    #rub_obj.describe_vm("vCenter:::d667276f-bafe-4acb-9263-acde6bc09b21")

    rub_obj.get_vCenter_Servers()

    #rub_obj.get_esxi_hypervisors()
    #rub_obj.refresh_medadata()
    #rub_obj.login()
    print(rub_obj.vcenter_id)
    rub_obj.token_id
    rub_obj.cluster_id
    rub_obj.server
    rub_obj.Describe_SLA_Domain('SQLDB')
    rub_obj.headers
    rub_obj.get_SLA_Domains()
    rub_obj.sla_domains
    rub_obj.silver_sla_id
    rub_obj.gold_sla_id
    rub_obj.get_VMList()
    #rub_obj.get_CurrentClusters()
    #print(rub_obj.cluster_id)
    rub_obj.exit_session()
    rub_obj.login()
    rub_obj.get_CurrentClusters()
    rub_obj.get_ClusterInfo()
    print(rub_obj.cluster_timezone)

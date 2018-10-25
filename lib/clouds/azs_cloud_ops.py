#!/usr/bin/env python

# /*******************************************************************************
# Copyright (c) 2018 IBM Corp.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# /*******************************************************************************

# /*******************************************************************************
# Copyright (c) 2015 DigitalOcean, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0
#
# /*******************************************************************************



'''
    Created on October 3, 2018
    Azure Stack Object Operations Library
    @author: Jeffrey A. Robinson

    Definitions
        vmc - Virtual Machine Container

'''

##########
#
#   Custom classes
#
########################################
class Instance:
    def constructor(self, vm_instance, private_ip, private_dns, public_ip = None, public_dns = None):
        self.instance = vm_instance

        self.public_ip = public_ip
        self.public_dns = public_dns

        self.private_ip = private_ip
        self.private_dns = private_dns


##########
#
#   CBTool
#
########################################
from lib.auxiliary.code_instrumentation import trace, cbdebug, cberr, cbwarn, cbinfo, cbcrit
from .shared_functions import CldOpsException, CommonCloudFunctions

##########
#
# Common
#
########################################
import string
import random
import time
import socket

##########
#
#   AzureStack Python
#
########################################

# Helpers
from azure.common.credentials import ServicePrincipalCredentials
from azure.profiles import KnownProfiles
from msrestazure.azure_cloud import get_cloud_from_metadata_endpoint
from msrestazure.azure_exceptions import CloudError

# Services
from azure.mgmt.resource.resources.resource_management_client import ResourceManagementClient
from azure.mgmt.compute.compute_management_client import ComputeManagementClient
from azure.mgmt.network.network_management_client import NetworkManagementClient
from azure.mgmt.storage.storage_management_client import StorageManagementClient

##########
#
#   Helper methods
#
########################################

def get_default_error_response():
    '''
    Description:
        Returns the default error status and message
    '''
    _status = 100
    _msg = "An error has occurred, but no error message was captured"
    return _status, _msg


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

##########
#
#   Azure Stack Commands Object
#
########################################



class AzsCmds(CommonCloudFunctions):

    @trace
    def __init__(self, pid, osci, expid=None):
        '''
        Not 100% sure what is going to be passed in
        '''
        CommonCloudFunctions.__init__(self, pid, osci)
        # Idk
        self.pid = pid
        self.osci = osci
        self.expid = expid

        # clients
        self.resource_client = None
        self.compute_client = None
        self.storage_client = None
        self.network_client = None

    ########
    #
    #   Mandatory
    #
    ################################
    @trace
    def vmccleanup(self, obj_attr_list):
        '''
        Description:
            Lists all instances (and if supported, volumes) named by CloudBench and removes these.

        Notes:
            Instances (and Volumes) created by CB are always prefixed by cb-<USERNAME>-<CLOUD NAME>-

            This method is invoked when --hard_reset or --soft_reset is used to start the tool

        Attributes:
            Required:
                access
                api_key
                secret_key
                name
                cloud_name

        '''
        _status, _msg = get_default_error_response()

        # Connect to Azure Stack
        self.connect(
            obj_attr_list["access"], obj_attr_list["credentials"], obj_attr_list["name"])

        try:
            # Get the list of resource groups
            _resourceGroups = self.resource_client.resource_groups.list()

            self.common_messages("VMC", obj_attr_list,
                                 "cleaning up resources", 0, '')

            for _resourceGroup in _resourceGroups:
                cbdebug("Removing resource group: " +
                        _resourceGroup.Name, True)
                delete_async_operation = self.resource_client.resource_groups.delete(
                    _resourceGroup.Name)
                delete_async_operation.wait()
                time.sleep(int(obj_attr_list["update_frequency"]))

            _status = None
            _msg = None
        except Exception, ex:
            _status = 23
            _msg = str(ex)
        finally:
            if(_msg == None):
                _status, _msg = self.common_messages(
                    "VMC", obj_attr_list, "cleaned up", _status, _msg)
            return _status, _msg

    @trace
    def vmcregister(self, obj_attr_list):
        '''
        Description:
            Creates a record, inside CloudBench's ObjectStore, for each of the specified
            VMC (i.e., Virtual Machine Container, one of the four Concrete Objects).

        Notes:
            Does NOTHING with allocating resources, only cleanup at most.

            If supported by the Cloud's API (e.g., OpenStack), individual host discovery is performed within this method.

            May invoke the vmccleanup method if instructed to do so (i.e., CB was invoked with --hard_reset or --soft_reset


        Attributes:
            Required:
                mgt_001_provisioning_request_originated
                name
                access
                credentials
                discover_hosts

            Optional:
                cleanup_on_attach

            Set:
                cloud_ip
                cloud_hostname
                arrival
                hosts
                host_list
                host_count
                mgt_002_provisioning_request_sent
                mgt_003_provisioning_request_completed
        '''
        _status, _msg = get_default_error_response()

        # Get start time
        _time_mark_prs = int(time.time())
        obj_attr_list["mgt_002_provisioning_request_sent"] = _time_mark_prs - \
            int(obj_attr_list["mgt_001_provisioning_request_originated"])

        try:
            if "cleanup_on_attach" in obj_attr_list and obj_attr_list["cleanup_on_attach"] == "True":
                _status, _msg = self.vmccleanup(obj_attr_list)
            else:
                _status = 0

            _status, _msg, _hostname = self.connect(
                obj_attr_list["access"],
                obj_attr_list["credentials"],
                obj_attr_list["name"]
            )

            obj_attr_list["cloud_hostname"] = _hostname + \
                "_" + obj_attr_list["name"]
            obj_attr_list["cloud_ip"] = socket.gethostbyname(
                _hostname) + "_" + obj_attr_list["name"]
            obj_attr_list["arrival"] = int(time.time())

            _time_mark_prc = int(time.time())

            obj_attr_list["mgt_003_provisioning_request_completed"] = _time_mark_prc - _time_mark_prs

            _status = 0
            _msg = None
        except Exception, msg:
            _msg = str(msg)
            _status = 23
        finally:
            return self.common_messages("VMC", obj_attr_list, "registered", _status, _msg)

    @trace
    def vmcunregister(self, obj_attr_list):
        '''
        Description:
            Removes the record of a given VMC Concrete Object from CB's ObjectStore

        Notes:
            Usually, invokes the vmccleanup method (this behavior is controlled by the cleanup_on_detach
            VMC attribute


        Attributes:
            Required:
                access
                api_key
                secret_key
                name
                cloud_name

        '''
        _status, _msg = get_default_error_response()

        try:

            _time_mark_drs = int(time.time())

            if "mgt_901_deprovisioning_request_originated" not in obj_attr_list:
                obj_attr_list["mgt_901_deprovisioning_request_originated"] = _time_mark_drs

            obj_attr_list["mgt_902_deprovisioning_request_sent"] = _time_mark_drs - \
                int(obj_attr_list["mgt_901_deprovisioning_request_originated"])

            if "cleanup_on_detach" in obj_attr_list and obj_attr_list["cleanup_on_detach"] == "True":
                _status, _msg = self.vmccleanup(obj_attr_list)

            _time_mark_prc = int(time.time())
            obj_attr_list["mgt_903_deprovisioning_request_completed"] = _time_mark_prc - _time_mark_drs

            _status = 0
        except Exception, msg:
            _msg = str(msg)
            _status = 23
        finally:
            return self.common_messages("VMC", obj_attr_list, "unregistered", _status, _msg)

    @trace
    def vmcreate(self, obj_attr_list):
        '''
        Description:
            Creates a single instance on a given Cloud Region/Zone/DataCenter (i.e., VMC)

        Notes:
            Instances are always named with the aforementioned cb-<USERNAME>-<CLOUD NAME>- prefix

            If the Cloud's API supports so (list of capabilities), one additional data volume per VM
            (controlled by the VM attribute cloud_vv=<SIZE IN GB> is also created.

            During the multiple steps of Virtual Machine/Application Instance creation, the following methods
            will be invoked: connect, is_vm_running, is_vm_ready, get_ip_address, get_images, get_networks


        Attributes:
            Required:
                access
                credentials
                vmc_name
                cloud_vm_name
                security_groups
                mgt_001_provisioning_request_originated
                cloud_rv_iops
                boot_volume_imageid1
                size
                key_name
                update_frequency


            Optional:
                cloud_rv
                cloud_rv_type
                cloud_vv_instance

            Set:
                last_known_state
                mgt_002_provisioning_request_sent
                config_drive
                cloud_vm_uuid
                instance_obj

        '''
        _status, _msg = get_default_error_response()
        try:
            _instance = False
            _reservation = False

            self.determine_instance_name(obj_attr_list)
            self.determine_key_name(obj_attr_list)

            obj_attr_list["last_known_state"] = "about to connect to " + \
                self.get_description() + " manager"

            self.take_action_if_requested(
                "VM", obj_attr_list, "provision_originated")

            self.connect(obj_attr_list["access"], obj_attr_list["credentials"],
                         obj_attr_list["vmc_name"])

            if self.is_vm_running(obj_attr_list):
                _msg = "An instance named \"" + obj_attr_list["cloud_vm_name"]
                _msg += " is already running. It needs to be destroyed first."
                _status = 187
                cberr(_msg)
                raise CldOpsException(_msg, _status)

            # "Security groups" must be a list
            _security_groups = []
            _security_groups.append(obj_attr_list["security_groups"])

            _time_mark_prs = int(time.time())
            obj_attr_list["mgt_002_provisioning_request_sent"] = _time_mark_prs - \
                int(obj_attr_list["mgt_001_provisioning_request_originated"])

            obj_attr_list["last_known_state"] = "about to send create request"

            self.get_images(obj_attr_list)
            self.get_networks(obj_attr_list)

            obj_attr_list["config_drive"] = False

            if "cloud_rv_type" not in obj_attr_list:
                obj_attr_list["cloud_rv_type"] = "standard"

            self.common_messages("VM", obj_attr_list, "creating", 0, '')
        except CldOpsException, obj :
            _status = obj.status
            _msg = str(obj.msg)
        except Exception, msg :
            _msg = str(msg)
            _status = 23
        finally:
            if "instance_obj" in obj_attr_list :
                del obj_attr_list["instance_obj"]
            del obj_attr_list["cloud_vv_instance"]

            return self.common_messages("VM", obj_attr_list, "created", _status, _msg)

    @trace
    def vmdestroy(self, obj_attr_list):
        '''
        Description:
            Deletes a single instance on a given Cloud Region/Zone/DataCenter (i.e., VMC)

        Notes:
            If the instance has a data volume associated to it, it is also deleted
            During the deletion, the following methods will be invoked: connect, is_vm_running

        '''

        _status,_msg = get_default_error_response()

        try:

            _time_mark_drs = int(time.time())
            if "mgt_901_deprovisioning_request_originated" not in obj_attr_list :
                obj_attr_list["mgt_901_deprovisioning_request_originated"] = _time_mark_drs

            obj_attr_list["mgt_902_deprovisioning_request_sent"] = \
                _time_mark_drs - int(obj_attr_list["mgt_901_deprovisioning_request_originated"])

            if not self.compute_client:
                self.connect(obj_attr_list["access"], obj_attr_list["credentials"], \
                         obj_attr_list["vmc_name"])

            _wait = int(obj_attr_list["update_frequency"])
            _max_tries = int(obj_attr_list["update_attempts"])
            _curr_tries = 0


            _rgn = obj_attr_list("resource_group_name")
            _instance = _instance = self.get_instances(obj_attr_list, "vm")


            if _instance :
                self.common_messages("VM", obj_attr_list, "destroying", 0, '')

                time.sleep(_wait)
                while self.is_vm_running(obj_attr_list) and _curr_tries < _max_tries :
                    time.sleep(_wait)
                    _curr_tries += 1

            _os_disk_name = _instance.instance.storage_profile.os_disk.name
            _data_disks  = _instance.instance.data_disks

            _delete_async_operation = self.compute_client.virtual_machines.delete(_rgn, _instance.instance.name)
            _delete_async_operation.wait()

            _time_mark_drc = int(time.time())
            obj_attr_list["mgt_903_deprovisioning_request_completed"] = _time_mark_drc - _time_mark_drs

            # Delete VHDs associated with VM
            self.compute_client.disks.delete(_rgn,_os_disk_name)
            for _dd in _data_disks:
                self.compute_client.disks.delete(_rgn,_dd.name)
        except Exception, ex:
            _msg = str(ex)
            _status = 23
        finally:
            return self.common_messages("VM", obj_attr_list, "destroyed", _status, _msg)

    @trace
    def test_vmc_connection(self, cloud_name, vmc_name, access, credentials, key_name, \
                            security_group_name, vm_templates, vm_defaults, vmc_defaults) :
        '''
        Description:
            During the initial Cloud attachment operation (at CB's startup) perform
            all the sanity checks (networks, SSH keys, images) needed to make sure
            that this cloud is useable with the credentials supplied by the Experimenter.

        Notes:
            During the testing, the following methods will be invoked: connect,
            check_networks, check_ssh_key, check_images
        '''
        try :
            _status, _msg = get_default_error_response()
            self.connect(access, credentials, vmc_name)

            self.generate_rc(cloud_name, vmc_defaults, '')

            _key_pair_found = self.check_ssh_key(vmc_name, self.determine_key_name(vm_defaults), vm_defaults)
            _security_group_found = self.check_security_group(vmc_name, security_group_name)

            if not (_key_pair_found and _security_group_found) :
                _msg = ": Check the previous errors, fix it (using " + self.get_description() + "'s web"
                _msg += " GUI (AWS Console) or ec2-* CLI utilities"
                _status = 1178
                raise CldOpsException(_msg, _status)

            _status = 0

        except CldOpsException, obj :
            _msg = str(obj.msg)
            _status = 2

        except Exception, msg :
            _msg = str(msg)
            _status = 23

        finally :
            return self.common_messages("VMC", {"name" : vmc_name }, "connected", _status, _msg)

    @trace
    def is_vm_running(self, obj_attr_list):
        '''
        Description:
            This method, invoked in a polling manner multiple methods, ensure that
            a given instance exists and started its boot process (e.g., it is state,
            as reported from the cloud) is RUNNING or ACTIVE)

        Notes:
            Used by both vmcreate and vmdestroy methods.
        '''
        try:
            if "instance_obj" not in obj_attr_list :
                _instance = self.get_instances(obj_attr_list, "vm")
            else :
                _instance = obj_attr_list["instance_obj"]

            if _instance :
                _instance_state = _instance.instance.provisioning_state
            else :
                _instance_state = "non-existent"

            if _instance_state == "running" :
                return True
            else :
                return False
        except Exception, ex :
            _msg = str(ex)
            cberr(_msg)
            _status = 23
            raise CldOpsException(_msg, _status)

    @trace
    def is_vm_ready(self, obj_attr_list):
        '''
        Description:
            This method, invoked in a polling manner multiple methods, ensure that
            a given instance exists, is running and has an IP address (assigned by
            the Cloud) associated with it.

        Notes:
            Used by the method vmcreate
        '''
        if self.is_vm_running(obj_attr_list) :
            if self.get_ip_address(obj_attr_list) :
                obj_attr_list["last_known_state"] = "running with ip assigned"
                return True
            else :
                obj_attr_list["last_known_state"] = "running with ip unassigned"
                return False
        else :
            obj_attr_list["last_known_state"] = "not running"
            return False


###
#
# Mandatory, but different?
#
################################################

    @trace
    def get_description(self):
        '''
        Description:
            Returns a string specifying the Cloud's "long name"
        '''
        return "AzureStack cloud"

    @trace
    def connect(self, access, credentials, vmc_name, ARM_ENDPOINT="", SUBSCRIPTION_ID="", TENANT_ID=""):
        '''
        Description:
            Establishes a connection to the Cloud's API Endpoint

        Notes:
            Typically one connection per VMC

            Some native python clients are not thread-safe, and might required the storing of
            individual, per-instance connection in a python dictionary (look for osk_cloud_ops.py for an example)
        '''
        KnownProfiles.default.use(KnownProfiles.v2017_03_09_profile)

        mystack_cloud = get_cloud_from_metadata_endpoint(ARM_ENDPOINT)

        subscription_id = SUBSCRIPTION_ID
        credentials = ServicePrincipalCredentials(
            client_id=access,
            secret=credentials,
            tenant=TENANT_ID,
            cloud_environment=mystack_cloud
        )

        self.resource_client = ResourceManagementClient(
            credentials, subscription_id, base_url=mystack_cloud.endpoints.resource_manager)
        self.compute_client = ComputeManagementClient(
            credentials, subscription_id, base_url=mystack_cloud.endpoints.resource_manager)
        self.storage_client = StorageManagementClient(
            credentials, subscription_id, base_url=mystack_cloud.endpoints.resource_manager)
        self.network_client = NetworkManagementClient(
            credentials, subscription_id, base_url=mystack_cloud.endpoints.resource_manager)

        return 0, None, ARM_ENDPOINT

    @trace
    def check_networks(self, vmc_name, vm_defaults):
        '''
        Description:
            During the initial Cloud attachment operation (at CB's startup), check if the networks specified
            in the cloud configuration file are present.

        Notes:
            Used by the method test_vmc_connection

        '''
        return 0, "NOT SUPPORTED"

    @trace
    def check_images(self, vmc_name, vm_templates, access):
        '''
        Description:
            During the initial Cloud attachment operation (at CB's startup), check how many of the images
            specified in the cloud-specific template (e.g., ~/cbtool/configs/templates/_npc.txt) are
            present on the cloud.

        '''
        return 0, "NOT SUPPORTED"

    @trace
    def discover_hosts(self, obj_attr_list, start):
        '''
        Description:
            If the Cloud API's supports it, the method vmcregister will
            invoke this method to perform host discovery
        '''

        return 0, "NOT SUPPORTED"

#####
#
# Helpers
#
###########################

    @trace
    def get_ip_address(self, obj_attr_list):
        '''
        Description:
            Get an instance's IP address

        Notes:
            Used by the method is_vm_ready
        '''

        try :
            _host_name = None
            _ip_address = None

            if obj_attr_list["run_netname"] == "private" :
                _hostname = obj_attr_list["instance_obj"].private_dns
                _ip_address = obj_attr_list["instance_obj"].private_ip
            else :
                _hostname = obj_attr_list["instance_obj"].public_dns
                _ip_address = obj_attr_list["instance_obj"].public_ip

            obj_attr_list["cloud_hostname"] = _hostname
            obj_attr_list["run_cloud_ip"] = _ip_address

            obj_attr_list["prov_cloud_ip"] = _ip_address

            # NOTE: "cloud_ip" is always equal to "run_cloud_ip"
            #   JR - Then why even have it?
            obj_attr_list["cloud_ip"] = obj_attr_list["run_cloud_ip"]

            return True
        except:
            return False

    @trace
    def get_instances(self, obj_attr_list, obj_type = "vm"):
        '''
        Description:
            Returns a python object that represents a created instance.

        Notes:
            Used by the method is_vm_ready
            Returns an Instance object declared at the top of the file.
        '''

        _status, _msg = get_default_error_response()
        _rgn = obj_attr_list["resource_group_name"]
        _vm_name = obj_attr_list["cloud_vm_name"]

        _result = None
        _public_ip = None
        _public_dns = None
        _private_ip = None
        _private_dns = None

        try:

            _vm_instance = None

            try:
                _vm_instance = self.compute_client.virtual_machines.get(_rgn, _vm_name)
            except:
                return None

            _nic_ids = _vm_instance.network_profile.network_interfaces

            #
            #   In Azure/AzureStack virtual machines don't hold network configuration but
            #   rather has a network interface identifier.  We need to get this resource.
            #
            for _nic_id in _nic_ids:
                _id = _nic_id.id
                _name = _id.split('/')[-1]
                _nic = self.network_client.network_interfaces.get(_rgn, _name)
                if _nic.private_ip_address != None:
                    _private_ip = _nic.private_ip_address
                    _private_dns = _vm_instance.os_profile.computer_name
                if _nic.public_ip_address != None:
                    _private_ip = _nic.public_ip_address.ip_address
                    _private_dns =_nic.dns_settings.domain_name_label

            return Instance(_vm_instance, _private_ip, _private_dns, _public_ip, _public_dns)
        except CloudError, er:
            _status = 10
            _msg = str(er.message)
            raise CldOpsException(_msg, _status)

    @trace
    def get_images(self, obj_attr_list):
        '''
        Description:
            Before creating the instance, queries the cloud and obtains information about the
            image which is about to be used

        Notes:
            In order to put more stress on the Cloud's API, this is method is invoked, during
            vmcreate for each individual VM
        '''
        try:
            _region = obj_attr_list['cloud_name']
            _publisher = 'Microsoft'
            _offer = 'cbtool'
            _sku = obj_attr_list["imageid1"]
            _version = 'latest'

            _candidate_image = self.compute_client.virtual_machine_images.get(
            _region, _publisher, _offer, _sku, _version)

            if _candidate_image:
                obj_attr_list["imageid1"] = _candidate_image.name
                obj_attr_list["boot_volume_imageid1"] = _candidate_image.id
                _status = 0
                _msg = "Image found"
            else:
                _status = 404
                _msg = "Image Name (" + obj_attr_list["imageid1"] + \
                    ") not found: Please check if the defined image name is present on this " + \
                    self.get_description()

                raise CldOpsException(_msg, _status)
        except CloudError, er:
            _status = 10
            _msg = str(er.message)
        except Exception, ex:
            _status = 23
            _msg = str(ex)
        finally:
            if _status:
                cberr(_msg)
                raise CldOpsException(_msg, _status)
            return _status == 0

    @trace
    def get_networks(self, obj_attr_list):
        '''
        Description:
            Before creating the instance, queries the cloud and obtains information about the
            network which is the VM about to be attached to

        Notes:
            In order to put more stress on the Cloud's API, this is method is invoked, during
            vmcreate for each individual VM

            Azure/AzureStack does not support this.
        '''
        return 0, "NOT SUPPORTED"

########
#
# Optional operations
#
################################

    @trace
    def vm_placement(self, object_attr_list):
        '''
        Description:
            If the Cloud API supports the identification and addressing of individual hosts,
            this method will be invoked during vmcreate to place specific instances into
            specific hosts.
        '''
        return 0, "NOT SUPPORTED"

    @trace
    def vmcapture(self, object_attr_list):
        '''
        Description:
            Take a running instance, stop it, create a bootable image, then delete the instance.
        '''
        return 0, "NOT SUPPORTED"

    @trace
    def vmrunstate(self, obj_attr_list):
        '''
        Description:
            Translates the CBTOOL API call/CLI command vmrunstate into start/stop/save/resume/suspend
            operations on the cloud.
        '''
        _status, _msg = get_default_error_response()
        try:

            _ts = obj_attr_list["target_state"]
            _cs = obj_attr_list["current_state"]
            _rgn = obj_attr_list["resource_group_name"]

            self.connect(obj_attr_list["access"], obj_attr_list["credentials"], \
                         obj_attr_list["vmc_name"])

            if "mgt_201_runstate_request_originated" in obj_attr_list :
                _time_mark_rrs = int(time.time())
                obj_attr_list["mgt_202_runstate_request_sent"] = \
                    _time_mark_rrs - obj_attr_list["mgt_201_runstate_request_originated"]

            self.common_messages("VM", obj_attr_list, "runstate altering", 0, '')

            _instance = self.get_instances(obj_attr_list, "vm")

            if _instance :
                if _ts == "fail" :
                    self.compute_client.virtual_machines.power_off(_rgn, _instance.instance.name)
                elif _ts == "save" :
                    self.compute_client.virtual_machines.power_off(_rgn, _instance.instance.name)
                elif (_ts == "attached" or _ts == "resume") and _cs == "fail" :
                    self.compute_client.virtual_machines.start(_rgn, _instance.instance.name)
                elif (_ts == "attached" or _ts == "restore") and _cs == "save" :
                    self.compute_client.virtual_machines.start(_rgn, _instance.instance.name)

            _time_mark_rrc = int(time.time())
            obj_attr_list["mgt_203_runstate_request_completed"] = _time_mark_rrc - _time_mark_rrs

            _msg = "VM " + obj_attr_list["name"] + " runstate request completed."
            cbdebug(_msg)

            _status = 0
        except Exception, msg :
            _msg = str(msg)
            _status = 23
        finally:
            return self.common_messages("VM", obj_attr_list, "runstate altered", _status, _msg)

    @trace
    def vmmigrate(self, object_attr_list):
        '''
        Description:
            Allows instances to be removed from one host to another.
        '''

        return 0, "NOT SUPPORTED"

    @trace
    def vmresize(self, obj_attr_list):
        '''
        Description:
            Allows instances to have its number of virtual CPUs or Memory size dynamically altered
        '''
        return 0, "NOT SUPPORTED"

    @trace
    def imgdelete(self, obj_attr_list):
        '''
        Description:
            Allows images (created by a Cloud user, for instance by issuing the CBTOOL API
            call/CLI command vmcapture) to be deleted
        '''
        return 0, "NOT SUPPORTED"
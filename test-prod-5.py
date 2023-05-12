import boto3
import time
from datetime import date, datetime
import json
from datetime import datetime
import sys
from botocore.exceptions import ClientError
import logging
import os
import sys
import requests
# from utils.common import load_account_metadata
import csv

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get('logLevel', 'INFO')))
        

# stackSetName = os.environ.get('stackSetName',"ITSLayer1-SPOKE-IAM-CLDTRL-PRD") #569
stackSetName = os.environ.get('stackSetName',"ITSLayer1-SPOKE-IAM-CLDTRL-NPD") # 1237
# L1Account = os.environ.get('L1Account',"920112648628") # dev
L1Account = os.environ.get('L1Account',"354379781696") # prod

allRegions = [
"us-east-1","us-east-2","us-west-1","us-west-2",
"af-south-1","ap-east-1","ap-south-1","ap-northeast-3",
"ap-northeast-2","ap-northeast-1","ap-southeast-1","ap-southeast-2",
"ca-central-1","eu-central-1","eu-west-1","eu-west-2",
"eu-west-3","eu-south-1","eu-north-1","me-south-1",
"sa-east-1"]

client = boto3.client('cloudformation')

def go():
    child_cred = assume_to_child_account(L1Account)
    stack_dict = cft_list_stack_instances(child_cred, stackSetName)
    
    c = 978
    length = len(stack_dict)
    for stack in stack_dict[978:1000]:
        try:
            c+=1
            print(f"---Account Count----{c}--- {stack['Account']} of {length}")
            nova_data = load_account_metadata(stack['Account'])
            if nova_data and not isinstance(nova_data,int):
                print("Layer 0 Deployed:: ",nova_data['account']['layer_zero_deployed'])
                print("Account Status :: ",nova_data['account']['cbilling']['account_status'])
                print("Account:: ",stack['Account'])
                print("Region:: ",stack['Region'])
                try:
                    if nova_data['account']['layer_zero_deployed'] and nova_data['account']['cbilling']['account_status'] == 'ACTIVE':
                        child_cred = assume_to_child_account(stack['Account'])
                        for reg in allRegions:
                            print(f"-----------fetching data for region {reg} and account:: {stack['Account']}----------")
                            client = boto3.client('ec2', region_name=reg,aws_access_key_id=child_cred['AccessKeyId'],
                                aws_secret_access_key=child_cred['SecretAccessKey'],aws_session_token=child_cred['SessionToken'])
                            
                            r = client.describe_instances(
                                Filters=[
                                    {
                                        'Name': 'iam-instance-profile.arn',
                                        'Values': [
                                            f"arn:aws:iam::{stack['Account']}:instance-profile/EC2SSMAgentProfile",
                                        ]
                                    },
                                ]
                            )
                            # print(r)
                            if r['Reservations']:
                                try:
                                    iam = boto3.client('iam', region_name=reg,aws_access_key_id=child_cred['AccessKeyId'],
                                aws_secret_access_key=child_cred['SecretAccessKey'],aws_session_token=child_cred['SessionToken'])

                                    response = iam.get_instance_profile(
                                            InstanceProfileName="DCSSSMAccessProfile"
                                        )

                                    roles = response['InstanceProfile']['Roles']
                                    for role in roles:
                                        role_exist = False
                                        if role['RoleName'] == "DCSSSMAccessRole":
                                            role_exist = True
                                            profile_exist = True
                                            break
                                except Exception as e:
                                    print("*******exception::******",e)
                                    profile_exist = False
                                    role_exist = False
                                with open("ec2-prod-5.csv", "a") as file:
                                    file.write(f"{stack['Account']},{reg},{r['Reservations'][0]['Instances'][0]['InstanceId']},{nova_data['account']['managed_service_provider']['name']},{profile_exist},{role_exist},{nova_data['account']['work_load']}\n")
                                    print("data added to csv file")
                            else:
                                print("No instances found for the instance profile")
                               
                    else:
                        print("IGNORE")
                except Exception as e:
                    print(e)
            else:
                print("Account Id not found in the DB:: ", nova_data)
        except Exception as e:
            print("e::",e)
            print(sys.exc_info()[-1].tb_lineno)
            with open("ec2-exception-file-prod-5.csv", "a") as exception_file:
                exception_file.write(f"{stack['Account']},{e}\n")
            print("exception added to the csv file")

def assume_to_child_account(account):
    
    sts_client = boto3.client('sts')
    child_account_assume_role = "DCSLayer0/Layer0_Audit"
    role_arn = f'arn:aws:iam::{account}:role/{child_account_assume_role}'
    print(f'Assuming role: {role_arn}; Account: {account}')
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f'create_roles_new_account{datetime.now().strftime("%Y%m%d%H%M%S%f")}'
    )

    return assumed_role['Credentials']


def cft_list_stack_instances(child_cred, stackSetName):
    print("Getting accounts from stack set "+stackSetName)
    client_ = boto3.client('cloudformation',
                                region_name="us-east-1",
                                aws_access_key_id=child_cred["AccessKeyId"],
                                aws_secret_access_key=child_cred["SecretAccessKey"],
                                aws_session_token=child_cred["SessionToken"])

    response = client_.list_stack_instances(
    StackSetName=stackSetName)
    instances = response['Summaries']
    while response.get('NextToken'):
        response = client_.list_stack_instances(
                    StackSetName=stackSetName,
                    NextToken=response['NextToken'])
        instances.extend(response['Summaries'])

    print("Total instance from the Stack set:: ",len(instances))
    return instances


def load_account_metadata(account_id):
    """Get account metadata from Nova API"""

    nova_report_url = f"http://nova.dcs.deloitte.com/api/report/account?account_id={account_id}"
    nova_api_key = "b4fe4ccd-99c2-a129-f0a8-c555cb4724d2"

    headers = {
        'nova-x-api-key': nova_api_key,
        'User-Agent': "PostmanRuntime/7.17.1",
        'Accept': "*/*",
        'Cache-Control': "no-cache",
        'Postman-Token': "c9eacdbd-cdad-43e6-adea-931232fcb8ad,01db3bc8-1059-4aa7-9103-e3ab1f8a889b",
        'Accept-Encoding': "gzip, deflate",
        'Referer': "http://nova.dcs.deloitte.com/api/report/accounts",
        'Connection': "keep-alive",
        'cache-control': "no-cache",
        "Accept-Version": "nova.2022-05-03",
    }

    
    response = requests.get(f"{nova_report_url}", headers=headers)
    
    if response.status_code == 200:
        novaData = response.json()
        # print(f'Processed Nova data: {novaData}')
        return novaData
    elif response.status_code == 404:
        # print(f"Failed to get account details: {response.status_code}")
        return novaData


go()

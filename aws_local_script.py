#!/usr/bin/env python

import boto3
import time
from datetime import date, datetime
import json
from datetime import datetime
import sys
from botocore.exceptions import ClientError
import logging
import os
import requests
# from common.layers.utils.lib.utils.common import get_aws_client

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get('logLevel', 'INFO')))


stackSetName = 'ITSLayer1-SPOKE-IAM-CLDTRL-PRD' # Prod
stackSetName = 'ITSLayer1-SPOKE-IAM-CLDTRL-NPD' # Dev

L1Account = "354379781696"  # Prod
L1Account = "920112648628"  # Dev
region = 'us-east-1'
allRegions = [
"us-east-1","us-east-2","us-west-1","us-west-2"
"af-south-1","ap-east-1","ap-south-1","ap-northeast-3",
"ap-northeast-2","ap-northeast-1","ap-southeast-1","ap-southeast-2"
"ca-central-1","eu-central-1","eu-west-1","eu-west-2",
"eu-west-3","eu-south-1","eu-north-1","me-south-1",
"sa-east-1"]

client = boto3.client('cloudformation','us-east-1',
    aws_access_key_id="ASIA5MOX42G2PHEBZAPQ",
    aws_secret_access_key="EpmOwplzY2KWGN9wCp0fNtFZzTxUSdGRVh66ZIt8",
    aws_session_token="IQoJb3JpZ2luX2VjEP3//////////wEaCXVzLWVhc3QtMSJHMEUCIQDLdFppQV008No3I0+OtTZOQ/KkdVJab6rzKH4xVjdbjgIgalABawP7ywJj5jm+FXuo41jvdByflVDnRvtQlY3n5DQqnQMIpf//////////ARADGgw5MjAxMTI2NDg2MjgiDDc7hoVUWa6RvSiBOSrxAliPv/C/VYELdKHX7Fs1Q5gaC2XUJfoHvMb8G4Lgec3TZ8MblK3p11WnBaXboEe0J8JCtYAZBUo3glNAyLj1OPPFFg/1Y0FkpN1jORikuKA137H5+3tGdhr41gGmOjyMo4z1cUTw+/4yEguzpLtAsx8i7elwHVcu97QZTl2fe0BqeGf5097FGE7Qnwip5qy6rPzLRKNyACYFty1Ge30cUlskUs8iBTcs8jq1iSA2R6IPClGwz5dHWSJSrM0YztogtvMcjiLwmgO+ZtDAndJ7c5HrvaIL3x54mJdG9Wj3w7ez8Psvcdu8yLn3q2awk2p7v5tnmCiG2zHgAyK1ldjvUfZDGf+di3m/uWz8w0wTMv0xZIQuI/DfKFPRBCGgvh1bv57lMFtpdvSTF8nlIRqj7eukyQgA48sKuvsQFqvQgqOXCjkrHYcW1B9lkpvaetVhYPFraN7FBg2C3BviTLqlO35XpU+FcyKguUixUG6iNEZYqjD3o4KgBjqaAXUHPF6ob0W0NYKhbeyVEI199I+Al2s4BIJSldaBKUiB8P1iZQTbcSqkuo+fJ4Uz4UG1jn+97tRlNLZHECK+1Dqx2RcYEedksekqF8jMHgmNnmm6Ar7yu+YrfjnjhosK3LJzU1+hJyTxF8DPjLLWs6KAPU5aO65x+S9naLA5qrQXB8i15yO6PTH744nID+a18oeqslO9/sF0Ahw=")

print("client:::",client)

def go(client):
    stack_dict = cft_list_stack_instances(stackSetName)
    c = 0
    for stack in stack_dict:
        c+=1
        print(f"--------------------------------{c}--------------------------------")
        nova_data = load_account_metadata(stack['Account'])
        if nova_data["Success"]:
            print("Layer 0 Deployed:: ",nova_data['account']['layer_zero_deployed'])
            print("Account Status :: ",nova_data['account']['cbilling']['account_status'])
            print("Account:: ",stack['Account'])
            print("Region:: ",stack['Region'])
            try:
                if nova_data['account']['layer_zero_deployed'] and nova_data['account']['cbilling']['account_status'] == 'ACTIVE':
                    child_cred = assume_to_child_account(stack['Account'])
                    for region_name in allRegions:
                        client = boto3.client('ec2',region_name=region_name, aws_access_key_id=child_cred['AccessKeyId'],
                            aws_secret_access_key=child_cred['SecretAccessKey'],aws_session_token=child_cred['SessionToken'])
                        r = client.describe_instances(
                            Filters=[
                                {
                                    'Name': 'iam-instance-profile.arn',
                                    'Values': [
                                        f"arn:aws:iam::{stack['Account']}:instance-profile/EC2SSMAgentMonitoring",
                                    ]
                                },
                            ]
                        )
                        print('**********Describe EC2 data**********************')
                        print(r)
                        # add details to CSV file
                        print('********************************')
                else:
                    print("IGNORE")


            except Exception as e:
                print(e)
        else:
            print("***************NOVA EXCEPTION:::******************", nova_data)

def assume_to_child_account(account):
    try:
        sts_client = boto3.client('sts','us-east-1',
    aws_access_key_id="ASIAURD5P7MRCB3NXAN4",
    aws_secret_access_key="rCvXCLy172kxUL7wYMc/4mh6K9DmEaLo6LuF5LK+",
    aws_session_token="IQoJb3JpZ2luX2VjEMv//////////wEaCXVzLWVhc3QtMSJIMEYCIQDxf8g3H8lE3nMvQk/vq/IG7HqDx5J9O5ypWm6BGCnZiwIhAPm3eNf12TybCKuxlYYz9mBOCeP3/xDWArdENY1FJSavKpQDCHQQAxoMMzExNjQ4MzIwMjkwIgwfzl1P512+558OUzcq8QIHHOk7ixJeFw/h/aB++8x27M9E2hfVQFb0ZrumzjaCGHSXzOZ6tApKJc+o0GnB6P9itklPMofxGGTNybdH2isZLWaR4JcZcxPEbPr5FEx9QZSd8qvw1njw1DppDYWzJ8oc05AOHWr3cnHdtNKyiatRzOpsi7ZfKCVi28HFNgTdRj97RM9Nlr87WosFy2jDPyYUKpz/UDWDA6l0ZtqdwX3DMZiQjNXuKQo0B/LG/b/0Ynm7885n4JdgPaJroQgt2jts/H5GXFWqufO7TAMv1Z6TJ//XvMaiB04Y/sy9+q7QaiHT4BIbef1xhq9XC9dloUYbExAp7+ri45FlIZKA69lCl9i/VCI4eGKCmmVuEtxBV27gM+AsGTBA6kaBbsa0qic5t8mEj4Uc7l8CNSRt/9VrI3zCOPPUTV/TdIVQL1MTTlEgTRq2vzIgL9XiD5zF1zkRvUQxkD5bGxIOjokPuZnej7gnDL5iDCJiXbReiYMeql0wrbH3nwY6mQHTYHNRunwULxJygBGjujf5+GBfireIv0bBUjVmRPv3RQ51MMbOIOzMZpSoJXgnCEcUvuo4inj2ss+CEL22TVmSXyk+bpC3iGMRWxVcbsQ1sy+Y/eLkkIL4tiPjJtxFO0VNoCGgJCC/s4TuMYqpyBS8yM+3guErckchBxav9skomSRiv0/6MJ2sCLS2f7vitGzURQJDhR17ZYU=")

        child_account_assume_role = "DCSLayer0/DCSGovernance"
        child_account_assume_role = "ITSLayer1/ITSGovernanceRole"
        role_arn = f'arn:aws:iam::{account}:role/{child_account_assume_role}'
        print(f'Assuming role: {role_arn}; Account: {account}')
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'create_roles_new_account{datetime.now().strftime("%Y%m%d%H%M%S%f")}'
        )
    except ClientError as err:
        print("Exception:::",err)        
        raise Exception(f"Account {account} doesn't exist.")

    return assumed_role['Credentials']


def cft_list_stack_instances(stackSetName):
    print("Getting accounts from stack set "+stackSetName)
    unique_instances = list()
    client_ = boto3.client('cloudformation','us-east-1',
    aws_access_key_id="ASIA5MOX42G2PHEBZAPQ",
    aws_secret_access_key="EpmOwplzY2KWGN9wCp0fNtFZzTxUSdGRVh66ZIt8",
    aws_session_token="IQoJb3JpZ2luX2VjEP3//////////wEaCXVzLWVhc3QtMSJHMEUCIQDLdFppQV008No3I0+OtTZOQ/KkdVJab6rzKH4xVjdbjgIgalABawP7ywJj5jm+FXuo41jvdByflVDnRvtQlY3n5DQqnQMIpf//////////ARADGgw5MjAxMTI2NDg2MjgiDDc7hoVUWa6RvSiBOSrxAliPv/C/VYELdKHX7Fs1Q5gaC2XUJfoHvMb8G4Lgec3TZ8MblK3p11WnBaXboEe0J8JCtYAZBUo3glNAyLj1OPPFFg/1Y0FkpN1jORikuKA137H5+3tGdhr41gGmOjyMo4z1cUTw+/4yEguzpLtAsx8i7elwHVcu97QZTl2fe0BqeGf5097FGE7Qnwip5qy6rPzLRKNyACYFty1Ge30cUlskUs8iBTcs8jq1iSA2R6IPClGwz5dHWSJSrM0YztogtvMcjiLwmgO+ZtDAndJ7c5HrvaIL3x54mJdG9Wj3w7ez8Psvcdu8yLn3q2awk2p7v5tnmCiG2zHgAyK1ldjvUfZDGf+di3m/uWz8w0wTMv0xZIQuI/DfKFPRBCGgvh1bv57lMFtpdvSTF8nlIRqj7eukyQgA48sKuvsQFqvQgqOXCjkrHYcW1B9lkpvaetVhYPFraN7FBg2C3BviTLqlO35XpU+FcyKguUixUG6iNEZYqjD3o4KgBjqaAXUHPF6ob0W0NYKhbeyVEI199I+Al2s4BIJSldaBKUiB8P1iZQTbcSqkuo+fJ4Uz4UG1jn+97tRlNLZHECK+1Dqx2RcYEedksekqF8jMHgmNnmm6Ar7yu+YrfjnjhosK3LJzU1+hJyTxF8DPjLLWs6KAPU5aO65x+S9naLA5qrQXB8i15yO6PTH744nID+a18oeqslO9/sF0Ahw=")


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
    nova_api = f"https://nova.dcs.deloitte.com/"
    nova_api = f"https://novadev.dcs.deloitte.com/"
    nova_api_key = "b4fe4ccd-99c2-a129-f0a8-c555cb4724d2"

    nova_uri = f'api/account?account_id={account_id}'
    nova_url = f'{nova_api}/{nova_uri}'
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",

        "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiJhMWUwNDY3MC03Zjg0LTQ2MjUtYjMwNy01YmRiZmM1ZTRlZjAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8zNmRhNDVmMS1kZDJjLTRkMWYtYWYxMy01YWJlNDZiOTk5MjEvIiwiaWF0IjoxNjc3NzU5MzU1LCJuYmYiOjE2Nzc3NTkzNTUsImV4cCI6MTY3Nzc2Mzk1MywiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhUQUFBQWtZaURkMkJSM0JjT1BOVDUwakM4UFYrZmJEeW43MFhqTjNsdkY5OXZhcmQreHJFcGYxbk8rY3hMeFJPbVNvaFAiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiYTFlMDQ2NzAtN2Y4NC00NjI1LWIzMDctNWJkYmZjNWU0ZWYwIiwiYXBwaWRhY3IiOiIxIiwiZmFtaWx5X25hbWUiOiJ1c2l0c25vdmFkZXZzdmMiLCJncm91cHMiOlsiMTIzMTEwMDctYmI3OS00YmRiLThjMjQtMzU1YjY0YmM2YjNmIiwiNWZlYzRmMTYtZmVkMC00ZmIzLWI5MzgtZTdkMGNiZmYyMmYyIiwiMmVjZDM3NDQtYTI3OC00MDQ2LTkwYmEtNzk4MzBjZWZmYzBiIiwiYzI3ODI2ODgtYTU4Yy00YzY1LWExZDItY2ZkZWM0ZjlkMTk5Il0sImlwYWRkciI6IjEwMy43Ni4yMzIuMTY5IiwibmFtZSI6InVzaXRzbm92YWRldnN2YyIsIm9pZCI6ImFkMDZkMjk5LWJjMmYtNDA4Ny1hNjY3LTA5NTRjOTk3ZWUyMCIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0yMzg0NDcyNzYtMTA0MDg2MTkyMy0xODUwOTUyNzg4LTI2MDQ3MjAiLCJyaCI6IjAuQVNZQThVWGFOaXpkSDAydkUxcS1Scm1aSVhCRzRLR0VmeVZHc3dkYjJfeGVUdkFtQUkwLiIsInNjcCI6Ikdyb3VwTWVtYmVyLlJlYWQuQWxsIFVzZXIuUmVhZCIsInN1YiI6IjhrVXNfOGk3dVRwWXdoX2VjdGg4R3IwY1Etd1g1VjJiRkEwd2dzbWtXLUEiLCJ0aWQiOiIzNmRhNDVmMS1kZDJjLTRkMWYtYWYxMy01YWJlNDZiOTk5MjEiLCJ1bmlxdWVfbmFtZSI6InVzaXRzbm92YWRldnN2Y0BkZWxvaXR0ZS5jb20iLCJ1cG4iOiJ1c2l0c25vdmFkZXZzdmNAZGVsb2l0dGUuY29tIiwidXRpIjoia0o4SVA5QUJWMGlXTTZid0JpektBQSIsInZlciI6IjEuMCJ9.bDzmsgJ-oHJC37CEvkqJSMdu2cEwZr9kV1xwjwPtg_A07qlTzdApTgrmbF9dhbOjXjzFnV9S31HkqSTFX8HT_JdqN5-kxUn5AVxpZrLNeJFZ-UPIPV3CXcNEa4kxqrBrDY5SiwJ1VUVB_RTEhvFPKK9bIOYRlsQUZCUTvCvAqb-Bi21mvUPMKQEOTmpDTuAuPbH_Eq0FDEcc-t6MOVlh0M3E8tZrYYusAUPU1FMo5rqGnOzccm63yfNnU2pZdOaPfeTv-0LwTYdaRjYUawoe0njv92ZsnLk40onjFojbOAJqzL1wUT5vHMSzD60D0eR6K8zWjDSb4HPPl6xFZX1TRA"
        }
    response = requests.get(nova_url, headers=headers, verify=True)
    print("nova response code::", response.status_code)
    if response.status_code == 200:
        novaData = response.json()
        novaData['Success'] = True
        # logger.debug(f'Processed Nova data: {novaData}')
        return novaData
    elif response.status_code == 404:
        logger.debug(f"Failed to get account details: {response.status_code}")
        novaData= {}
        novaData['Success'] = False
        return novaData



go(client)



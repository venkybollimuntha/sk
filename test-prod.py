# import boto3
# import time
# from datetime import date, datetime
# import json
# from datetime import datetime
# import sys
# from botocore.exceptions import ClientError
# import logging
# import os
# import sys
# import requests
# # from utils.common import load_account_metadata
# import csv

# logger = logging.getLogger(__name__)
# logger.setLevel(logging.getLevelName(os.environ.get('logLevel', 'INFO')))
        
# account = ['021365338423', '026427244252', '051994682883', '084970654249', '097795456520', '121964457821', '174295623751', '190367388287', '194928253959', '212271771810', '241396937347', '286814544202', '315724403350', '362629117613', '365379373575', '388634006099', '424467068503', '437813383155', '446521373869', '496900188711', '509386356242', '540791212970', '550882646259', '552923642514', '569594090084', '616864236654', '650149263190', '667485214512', '698031681033', '701862677052', '705566307488', '727456174053', '731923714466', '753455713898', '753904791510', '785183849335', '785817577328', '788247499336', '816813650017', '828170655941', '839326706163', '855484158442', '886015701061', '903662551929', '911444749492', '911593296289', '918824989007', '929888664800', '947692952239', '956058981677', '982693706514', '983350415204', '053082227562', '065911132104', '093916721094', '157812473613', '161775556864', '166449560162', '188831284171', '204485639007', '232144315514', '345595150906', '381173206319', '420924285556', '440708338928', '481383093164', '516386627390', '523471060002', '540656245819', '543492705153', '543691652517', '545560008065', '553697376517', '556759822564', '558067152068', '570051990040', '580375422572', '597442721103', '607851404322', '611480974551', '618222675128', '622913598307', '625466519857', '662929856130', '688120237422', '702011104433', '717090925392', '749257892087', '764230540928', '769553063621', '769985493362', '791422305768', '791959462774', '829955684988', '831587722162', '898483634510', '924473885417', '932346075053', '960841581879', '989504077972', '997715449024']


# client = boto3.client('iam')

# def assume_to_child_account(account):
    
#     sts_client = boto3.client('sts')
#     child_account_assume_role = "DCSLayer0/DCSTempRole"
#     role_arn = f'arn:aws:iam::{account}:role/{child_account_assume_role}'
#     print(f'Assuming role: {role_arn}; Account: {account}')
#     assumed_role = sts_client.assume_role(
#         RoleArn=role_arn,
#         RoleSessionName=f'create_roles_new_account{datetime.now().strftime("%Y%m%d%H%M%S%f")}'
#     )

#     return assumed_role['Credentials']


# child_cred = assume_to_child_account(account)
# client_ = boto3.client('iam',
#                                 region_name="us-east-1",
#                                 aws_access_key_id=child_cred["AccessKeyId"],
#                                 aws_secret_access_key=child_cred["SecretAccessKey"],
#                                 aws_session_token=child_cred["SessionToken"])
# max_roles = 1000
# roles = []
# marker = None
# while True:
#     if marker:
#         response = client_.list_roles(MaxItems=max_roles, Marker=marker)
#     else:
#         response = client_.list_roles(MaxItems=max_roles)
#     roles += response['Roles']
#     if 'IsTruncated' in response and response['IsTruncated']:
#         marker = response['Marker']
#     else:
#         break

# print(len(roles))
# exemptRoles= [
#     "Create_SAML_Provider",
#     "AWS_DCS_FullAdmin",
#     "AWSCloudFormationStackSetExecutionRole",
#     "ITSLayer1StackSetExecutionRole",
#     "DCSLayer0PreBoot",
#     "DCS-TempRole-Admin",
#     "AWS_CON_Admin",
#     "Automated_Provisioning"
#   ]


# # Loop through each role and attach a policy to it
# for role in roles:
#     if role['RoleName'] in exemptRoles:
#         print(f"---------------------> This role {role['RoleName']} is excempted!!!!")
#         continue

#     try:
#         role_name = role['RoleName']
#         policy_arn = f'arn:aws:iam::{account}:policy/DenyITSLayer1PlatformModification' # Replace with the ARN of the policy you want to attach

#         # Attach the policy to the role
#         # iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        
#         print(f"Attached policy {policy_arn} to role {role_name}")
#     except Exception as e:
#         print("****************error:: ",e)


# def go():
#     child_cred = assume_to_child_account(L1Account)
#     stack_dict = cft_list_stack_instances(child_cred, stackSetName)

    
#     c = 0
#     length = len(stack_dict)
#     out = {}
#     for stack in stack_dict:
#         try:
#             c+=1
#             # print(f"---Account Count----{c}--- {stack['Account']} of {length}")
#             nova_data = load_account_metadata(stack['Account'])
#             if nova_data and not isinstance(nova_data,int):

#                 if nova_data['account']['cbilling']['account_status'] == "ACTIVE":
#                     out[stack['Account']] = stack['StatusReason']
#                     print("added to dict")

#                 # print(f"Account Status :: {stack['Account']} :: {nova_data['account']['cbilling']['account_status']}")
#             else:
#                 print("Account Id not found in the DB:: ", nova_data)
#         except Exception as e:
#             print("e::",e)
#             print(sys.exc_info()[-1].tb_lineno)
#             with open("ec2-exception-file-prod.csv", "a") as exception_file:
#                 exception_file.write(f"{stack['Account']},{e}\n")
#             print("exception added to the csv file")
#     print()
#     print(out)
#     print()

# def assume_to_child_account(account):
    
#     sts_client = boto3.client('sts')
#     child_account_assume_role = "DCSLayer0/Layer0_Audit"
#     role_arn = f'arn:aws:iam::{account}:role/{child_account_assume_role}'
#     print(f'Assuming role: {role_arn}; Account: {account}')
#     assumed_role = sts_client.assume_role(
#         RoleArn=role_arn,
#         RoleSessionName=f'create_roles_new_account{datetime.now().strftime("%Y%m%d%H%M%S%f")}'
#     )

#     return assumed_role['Credentials']


# def cft_list_stack_instances(child_cred, stackSetName):
#     print("Getting accounts from stack set "+stackSetName)
#     client_ = boto3.client('cloudformation',
#                                 region_name="us-east-1",
#                                 aws_access_key_id=child_cred["AccessKeyId"],
#                                 aws_secret_access_key=child_cred["SecretAccessKey"],
#                                 aws_session_token=child_cred["SessionToken"])

#     response = client_.list_stack_instances(
#     StackSetName=stackSetName,
#     Filters=[
#         {
#             'Name': 'LAST_OPERATION_ID',
#             'Values': '60141489-b0bc-1d82-3fa8-dd0548805b4d'
#         },
#         {
#             'Name': 'DETAILED_STATUS',
#             'Values': 'FAILED'
#         },

#     ],)


#     instances = response['Summaries']
#     while response.get('NextToken'):
#         response = client_.list_stack_instances(
#     StackSetName=stackSetName,
#     Filters=[
#         {
#             'Name': 'LAST_OPERATION_ID',
#             'Values': '60141489-b0bc-1d82-3fa8-dd0548805b4d'
#         },
#         {
#             'Name': 'DETAILED_STATUS',
#             'Values': 'FAILED'
#         },

#     ],
#     NextToken=response['NextToken'])
#         instances.extend(response['Summaries'])

#     print("Total instance from the Stack set:: ",len(instances))
#     return instances


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
# #'021365338423', '026427244252',

# accounts = ['051994682883', '084970654249', '097795456520', '121964457821', '174295623751', '190367388287', '194928253959', '212271771810', '241396937347', '286814544202', '315724403350', '362629117613', '365379373575', '388634006099', '424467068503', '437813383155', '446521373869', '496900188711', '509386356242', '540791212970', '550882646259', '552923642514', '569594090084', '616864236654', '650149263190', '667485214512', '698031681033', '701862677052', '705566307488', '727456174053', '731923714466', '753455713898', '753904791510', '785183849335', '785817577328', '788247499336', '816813650017', '828170655941', '839326706163', '855484158442', '886015701061', '903662551929', '911444749492', '911593296289', '918824989007', '929888664800', '947692952239', '956058981677', '982693706514', '983350415204', '053082227562', '065911132104', '093916721094', '157812473613', '161775556864', '166449560162', '188831284171', '204485639007', '232144315514', '345595150906', '381173206319', '420924285556', '440708338928', '481383093164', '516386627390', '523471060002', '540656245819', '543492705153', '543691652517', '545560008065', '553697376517', '556759822564', '558067152068', '570051990040', '580375422572', '597442721103', '607851404322', '611480974551', '618222675128', '622913598307', '625466519857', '662929856130', '688120237422', '702011104433', '717090925392', '749257892087', '764230540928', '769553063621', '769985493362', '791422305768', '791959462774', '829955684988', '831587722162', '898483634510', '924473885417', '932346075053', '960841581879', '989504077972', '997715449024']

def assume_to_child_account(account):
    
    sts_client = boto3.client('sts')
    child_account_assume_role = "DCSLayer0/DCSTempRole"
    role_arn = f'arn:aws:iam::{account}:role/{child_account_assume_role}'
    print(f'Assuming role: {role_arn}; Account: {account}')
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f'create_roles_new_account{datetime.now().strftime("%Y%m%d%H%M%S%f")}'
    )

    return assumed_role['Credentials']

# c = 0
# for account in accounts[0:20]:
#     c=c+1
#     try:
#         print(f"iteation {c} of total {len(accounts)}")
        # child_cred = assume_to_child_account(account)
        # iam = boto3.client('iam',
        #                                 region_name="us-east-1",
        #                                 aws_access_key_id=child_cred["AccessKeyId"],
        #                                 aws_secret_access_key=child_cred["SecretAccessKey"],
        #                                 aws_session_token=child_cred["SessionToken"])

    #     policy_arn = f'arn:aws:iam::{account}:policy/DenyITSLayer1PlatformModification'
    #     response = iam.list_entities_for_policy(PolicyArn=policy_arn)
    #     paginator = iam.get_paginator('list_entities_for_policy')
    #     response_iterator = paginator.paginate(
    #         PolicyArn=policy_arn,
    #         PaginationConfig={
    #             'PageSize': 1000, # number of results per page
    #         }
    #     )

    #     for page in response_iterator:
    #         entities = page['PolicyGroups'] + page['PolicyUsers'] + page['PolicyRoles']

    #         # Detach the policy from each entity
    #         for entity in entities:
    #             time.sleep(1)
                
    #             entity_type = list(entity.keys())[0]
            
    #             entity_name = entity[entity_type]

    #             if "GroupName" in entity_type:
    #                 iam.detach_group_policy(GroupName=entity_name, PolicyArn=policy_arn)
    #                 print("Group detached")
    #             elif "UserName" in entity_type:
    #                 iam.detach_user_policy(UserName=entity_name, PolicyArn=policy_arn)
    #                 print("username detached")
    #             elif "RoleName" in entity_type:
    #                 iam.detach_role_policy(RoleName=entity_name, PolicyArn=policy_arn)
    #                 print("role detached")

    #         # Delete the policy
    #         try:
    #             iam.delete_policy(PolicyArn=policy_arn)
    #             print(f"Deleted policy")
    #         except Exception:
    #             response = iam.list_policy_versions(
    #                 PolicyArn=policy_arn
    #             )

    #             # Delete each version of the policy
    #             for version in response['Versions']:
    #                 if not version['IsDefaultVersion']:
    #                     response = iam.delete_policy_version(
    #                         PolicyArn=policy_arn,
    #                         VersionId=version['VersionId']
    #                     )

    #             # Delete the policy itself
    #             response = iam.delete_policy(
    #                 PolicyArn=policy_arn
    #             )
    #             print("Deleted Policy in Exception")

    # except Exception as e:
    #     print("Exception:::", e, sys.exc_info()[-1].tb_lineno)

# ============================================================================



stackSetName = "DCSLayer0-TempRole"
import boto3
import requests
def cft_list_stack_instances( stackSetName):
    print("Getting accounts from stack set "+stackSetName)
    client_ = boto3.client('cloudformation',
                                region_name="us-east-1")

    response = client_.list_stack_instances(
    StackSetName=stackSetName)
    instances = []

    for account in response['Summaries']:
        instances.append(account['Account'])

    while response.get('NextToken'):
        response = client_.list_stack_instances(
                    StackSetName=stackSetName,
                    NextToken=response['NextToken'])
        for account in response['Summaries']:
            instances.append(account['Account'])

    return instances


out = cft_list_stack_instances(stackSetName)  

print(len(out))
print(out)
# active_accounts = []
# deleted_accounts = []
# c = 0
# for x in out:
#     print(f"Running account {c} of {len(out)}")
#     c+=1
#     try:
#         nova_data = load_account_metadata(x)
#         if nova_data['account']['cbilling']['account_status'] == "ACTIVE":
#             active_accounts.append(nova_data['account']['cbilling']['account_id'])
            
#         else:
#             deleted_accounts.append(nova_data['account']['cbilling']['account_id'])
            
#     except Exception as e:
#         print("Exception ::",e)

# print(active_accounts)
# print("------------Deleted Accounts----------------")
# print(deleted_accounts)

# =============================================================================

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

roles_to_delete = ["TenableIO", "ITSGovernance", "cloudscript_validate", "TaggingAPIRole","DenyITSLayer1PlatformModification"]

accounts = ["307492883559"]
# Iterate over each account and remove the specified roles
c = 0
for account in accounts[0:50]:
    print(f"iterating {c} of {len(accounts)}")
    c+=1
    try:
        child_cred = assume_to_child_account(account)
        iam = boto3.client('iam',
                                        region_name="us-east-1",
                                        aws_access_key_id=child_cred["AccessKeyId"],
                                        aws_secret_access_key=child_cred["SecretAccessKey"],
                                        aws_session_token=child_cred["SessionToken"])
        
        # Iterate over each role and detach all policies before deleting
        for role in roles_to_delete:
            if role == "DenyITSLayer1PlatformModification":
                try:
                    policy_arn = f'arn:aws:iam::{account}:policy/DenyITSLayer1PlatformModification'
                    response = iam.list_entities_for_policy(PolicyArn=policy_arn)
                    paginator = iam.get_paginator('list_entities_for_policy')
                    response_iterator = paginator.paginate(
                        PolicyArn=policy_arn,
                        PaginationConfig={
                            'PageSize': 1000, # number of results per page
                        }
                    )

                    for page in response_iterator:
                        entities = page['PolicyGroups'] + page['PolicyUsers'] + page['PolicyRoles']

                        # Detach the policy from each entity
                        for entity in entities:
                            time.sleep(1)
                            
                            entity_type = list(entity.keys())[0]
                        
                            entity_name = entity[entity_type]

                            if "GroupName" in entity_type:
                                iam.detach_group_policy(GroupName=entity_name, PolicyArn=policy_arn)
                                print("Group detached")
                            elif "UserName" in entity_type:
                                iam.detach_user_policy(UserName=entity_name, PolicyArn=policy_arn)
                                print("username detached")
                            elif "RoleName" in entity_type:
                                iam.detach_role_policy(RoleName=entity_name, PolicyArn=policy_arn)
                                

                        # Delete the policy
                        try:
                            iam.delete_policy(PolicyArn=policy_arn)
                            print(f"Deleted policy")
                        except Exception:
                            response = iam.list_policy_versions(
                                PolicyArn=policy_arn
                            )

                            # Delete each version of the policy
                            for version in response['Versions']:
                                if not version['IsDefaultVersion']:
                                    response = iam.delete_policy_version(
                                        PolicyArn=policy_arn,
                                        VersionId=version['VersionId']
                                    )

                            # Delete the policy itself
                            response = iam.delete_policy(
                                PolicyArn=policy_arn
                            )
                            print("Deleted Policy in Exception")

                except Exception as e:
                    print("=============================>Exception:::", e, sys.exc_info()[-1].tb_lineno)
            try:
                attached_policies = iam.list_attached_role_policies(RoleName=role)['AttachedPolicies']
                for policy in attached_policies:
                    iam.detach_role_policy(RoleName=role, PolicyArn=policy['PolicyArn'])
                    print(f"Detached policy {policy['PolicyName']} from role {role}")
                    
                iam.delete_role(RoleName=role)
                print(f"Deleted role {role} from account {account}")
            except iam.exceptions.NoSuchEntityException:
                print(f"Role {role} not found in account {account}")
    except Exception as e:
        print(f"==============================>Error while processing account {account}: {e}")

        


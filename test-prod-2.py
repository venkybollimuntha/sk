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

# accounts = [ '051994682883', '084970654249', '097795456520', '121964457821', '174295623751', '190367388287', '194928253959', '211695053472', '212271771810', '241396937347', '286814544202', '315724403350', '362629117613', '365379373575', '388634006099', '424467068503', '437813383155', '446521373869', '496900188711', '509386356242', '540791212970', '550882646259', '552923642514', '569594090084', '616864236654', '650149263190', '667485214512', '698031681033', '701862677052', '705566307488', '727456174053', '731923714466', '753455713898', '753904791510', '785183849335', '785817577328', '788247499336', '816813650017', '828170655941', '839326706163', '855484158442', '886015701061', '903662551929', '911444749492', '911593296289', '918824989007', '929888664800', '947692952239', '956058981677', '982693706514', '983350415204', '053082227562', '065911132104', '093916721094', '157812473613', '161775556864', '166449560162', '188831284171', '204485639007', '232144315514', '345595150906', '381173206319', '420924285556', '440708338928', '481383093164', '516386627390', '523471060002', '540656245819', '543492705153', '543691652517', '545560008065', '553697376517', '556759822564', '558067152068', '570051990040', '580375422572', '597442721103', '607851404322', '611480974551', '618222675128', '622913598307', '625466519857', '662929856130', '688120237422', '702011104433', '717090925392', '749257892087', '764230540928', '769553063621', '769985493362', '791422305768', '791959462774', '829955684988', '831587722162', '898483634510', '924473885417', '932346075053', '960841581879', '989504077972', '997715449024']

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

# c = 60
# for account in accounts[40:60]:
#     c=c+1
#     try:
#         print(f"iteation {c} of total {len(accounts)}")
#         child_cred = assume_to_child_account(account)
#         iam = boto3.client('iam',
#                                         region_name="us-east-1",
#                                         aws_access_key_id=child_cred["AccessKeyId"],
#                                         aws_secret_access_key=child_cred["SecretAccessKey"],
#                                         aws_session_token=child_cred["SessionToken"])

#         policy_arn = f'arn:aws:iam::{account}:policy/DenyITSLayer1PlatformModificationPolicy'
#         response = iam.list_entities_for_policy(PolicyArn=policy_arn)
#         paginator = iam.get_paginator('list_entities_for_policy')
#         response_iterator = paginator.paginate(
#             PolicyArn=policy_arn,
#             PaginationConfig={
#                 'PageSize': 1000, # number of results per page
#             }
#         )
#         for page in response_iterator:
#             entities = page['PolicyGroups'] + page['PolicyUsers'] + page['PolicyRoles']

#             # Detach the policy from each entity
#             for entity in entities:
#                 time.sleep(1)
                
#                 entity_type = list(entity.keys())[0]
            
#                 entity_name = entity[entity_type]

#                 if "GroupName" in entity_type:
#                     iam.detach_group_policy(GroupName=entity_name, PolicyArn=policy_arn)
#                     print("Group detached")
#                 elif "UserName" in entity_type:
#                     iam.detach_user_policy(UserName=entity_name, PolicyArn=policy_arn)
#                     print("username detached")
#                 elif "RoleName" in entity_type:
#                     iam.detach_role_policy(RoleName=entity_name, PolicyArn=policy_arn)
#                     print("role detached")

#             # Delete the policy
#             try:
#                 iam.delete_policy(PolicyArn=policy_arn)
#                 print(f"Deleted policy")
#             except Exception:
#                 response = iam.list_policy_versions(
#                     PolicyArn=policy_arn
#                 )

#                 # Delete each version of the policy
#                 for version in response['Versions']:
#                     if not version['IsDefaultVersion']:
#                         response = iam.delete_policy_version(
#                             PolicyArn=policy_arn,
#                             VersionId=version['VersionId']
#                         )

#                 # Delete the policy itself
#                 response = iam.delete_policy(
#                     PolicyArn=policy_arn
#                 )
#                 print("Deleted Policy in Exception")

#     except Exception as e:
#         print("Exception:::", e, sys.exc_info()[-1].tb_lineno)



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

roles_to_delete = ["TenableIO", "ITSGovernance", "cloudscript_validate", "TaggingAPIRole","DenyITSLayer1PlatformModification"]

accounts = ['008530717892', '010753539596', '014296065027', '016937230970', '026194564518', '038059618311', '047685407929', '051469546478', '062130537180', '063376279610', '073146838139', '077240679103', '084407457870', '095611350051', '099325924796', '103896790399', '119343329730', '124524166810', '135755270796', '142332166808', '151434629482', '161391293302', '168849861669', '171762472359', '178790212740', '184405994032', '212921778948', '222531082059', '225658821723', '226603863404', '227841379693', '235513223743', '237366858765', '245250269795', '251072340318', '254263703118', '269475816966', '292210083552', '294745394203', '306182918611', '307036839104', '307492883559', '327639925109', '328235541546', '340826808143', '345889295625', '347913913427', '354716619065', '359252437790', '363220349094', '363235117348', '368276533222', '368404118071', '373943505089', '385078759766', '397051564974', '403053226718', '413145654121', '413418342606', '413990510913', '428677740062', '432089771844', '436310111307', '441012919436', '442888752927', '453919366994', '470306404467', '474547691682', '479008266961', '480022745122', '483078657402', '489537064020', '502327753374', '503351113243', '512171866621', '522328802007', '524275599438', '529277024000', '534534201911', '534846924117', '535700223023', '537671715099', '547043556405', '547509476297', '551019182106', '561320747596', '584630848692', '589892584776', '590506744596', '594239924270', '595353211380', '606511248153', '634691564906', '640234854210', '644849997084', '644993791984', '647087774510', '647885244255', '652437243948', '658062093174', '659789841918', '661881507687', '688405658638', '695506696950', '696344538400', '721880670703', '724311065114', '738731325101', '740166810819', '745576527420', '747602229289', '748278030583', '766245584008', '767507899515', '775595962189', '776440666163', '791968533226', '801334471752', '802825831136', '808458935611', '814566149193', '819418488580', '822274905021', '824349500053', '834357290412', '836073812853', '848219600572', '848793886259', '858141963590', '858526972147', '862094248680', '874896561479', '875752141512', '881051476853', '886674288950', '895081226716', '910997097838', '918223892161', '927753750267', '928599649920', '931334696467', '936639518272', '941819694106', '955038580167', '955621810722', '957304465555', '958991296092', '964131740148', '971295728977', '971552591868', '986038433815', '989150551987', '994920118214', '997069924264', '999954735781']

# Iterate over each account and remove the specified roles
c = 100
for account in accounts[100:]:
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







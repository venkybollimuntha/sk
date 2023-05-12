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
        

# # stackSetName = os.environ.get('stackSetName',"ITSLayer1-SPOKE-IAM-CLDTRL-PRD") #569
# stackSetName = os.environ.get('stackSetName',"ITSLayer1-SPOKE-IAM-CLDTRL-NPD") # 1237
# # L1Account = os.environ.get('L1Account',"920112648628") # dev
# L1Account = os.environ.get('L1Account',"354379781696") # prod

# allRegions = [
# "us-east-1","us-east-2","us-west-1","us-west-2",
# "af-south-1","ap-east-1","ap-south-1","ap-northeast-3",
# "ap-northeast-2","ap-northeast-1","ap-southeast-1","ap-southeast-2",
# "ca-central-1","eu-central-1","eu-west-1","eu-west-2",
# "eu-west-3","eu-south-1","eu-north-1","me-south-1",
# "sa-east-1"]

# client = boto3.client('cloudformation')

# def go():
#     child_cred = assume_to_child_account(L1Account)
#     stack_dict = cft_list_stack_instances(child_cred, stackSetName)
    
#     c = 170
#     length = len(stack_dict)
#     for stack in stack_dict[170:200]:
#         try:
#             c+=1
#             print(f"---Account Count----{c}--- {stack['Account']} of {length}")
#             nova_data = load_account_metadata(stack['Account'])
#             if nova_data and not isinstance(nova_data,int):
#                 print("Layer 0 Deployed:: ",nova_data['account']['layer_zero_deployed'])
#                 print("Account Status :: ",nova_data['account']['cbilling']['account_status'])
#                 print("Account:: ",stack['Account'])
#                 print("Region:: ",stack['Region'])
#                 try:
#                     if nova_data['account']['layer_zero_deployed'] and nova_data['account']['cbilling']['account_status'] == 'ACTIVE':
#                         child_cred = assume_to_child_account(stack['Account'])
#                         for reg in allRegions:
#                             print(f"-----------fetching data for region {reg} and account:: {stack['Account']}----------")
#                             client = boto3.client('ec2', region_name=reg,aws_access_key_id=child_cred['AccessKeyId'],
#                                 aws_secret_access_key=child_cred['SecretAccessKey'],aws_session_token=child_cred['SessionToken'])
                            
#                             r = client.describe_instances(
#                                 Filters=[
#                                     {
#                                         'Name': 'iam-instance-profile.arn',
#                                         'Values': [
#                                             f"arn:aws:iam::{stack['Account']}:instance-profile/EC2SSMAgentProfile",
#                                         ]
#                                     },
#                                 ]
#                             )
#                             # print(r)
#                             if r['Reservations']:
#                                 try:
#                                     iam = boto3.client('iam', region_name=reg,aws_access_key_id=child_cred['AccessKeyId'],
#                                 aws_secret_access_key=child_cred['SecretAccessKey'],aws_session_token=child_cred['SessionToken'])

#                                     response = iam.get_instance_profile(
#                                             InstanceProfileName="DCSSSMAccessProfile"
#                                         )

#                                     roles = response['InstanceProfile']['Roles']
#                                     for role in roles:
#                                         role_exist = False
#                                         if role['RoleName'] == "DCSSSMAccessRole":
#                                             role_exist = True
#                                             profile_exist = True
#                                             break
#                                 except Exception as e:
#                                     print("*******exception::******",e)
#                                     profile_exist = False
#                                     role_exist = False
#                                 with open("ec2-prod-3.csv", "a") as file:
#                                     file.write(f"{stack['Account']},{reg},{r['Reservations'][0]['Instances'][0]['InstanceId']},{nova_data['account']['managed_service_provider']['name']},{profile_exist},{role_exist},{nova_data['account']['work_load']}\n")
#                                     print("data added to csv file")
#                             else:
#                                 print("No instances found for the instance profile")
                               
#                     else:
#                         print("IGNORE")
#                 except Exception as e:
#                     print(e)
#             else:
#                 print("Account Id not found in the DB:: ", nova_data)
#         except Exception as e:
#             print("e::",e)
#             print(sys.exc_info()[-1].tb_lineno)
#             with open("ec2-exception-file-prod-3.csv", "a") as exception_file:
#                 exception_file.write(f"{stack['Account']},{e}\n")
#             print("exception added to the csv file")

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
#     StackSetName=stackSetName)
#     instances = response['Summaries']
#     while response.get('NextToken'):
#         response = client_.list_stack_instances(
#                     StackSetName=stackSetName,
#                     NextToken=response['NextToken'])
#         instances.extend(response['Summaries'])

#     print("Total instance from the Stack set:: ",len(instances))
#     return instances


# def load_account_metadata(account_id):
#     """Get account metadata from Nova API"""

#     nova_report_url = f"http://nova.dcs.deloitte.com/api/report/account?account_id={account_id}"
#     nova_api_key = "b4fe4ccd-99c2-a129-f0a8-c555cb4724d2"

#     headers = {
#         'nova-x-api-key': nova_api_key,
#         'User-Agent': "PostmanRuntime/7.17.1",
#         'Accept': "*/*",
#         'Cache-Control': "no-cache",
#         'Postman-Token': "c9eacdbd-cdad-43e6-adea-931232fcb8ad,01db3bc8-1059-4aa7-9103-e3ab1f8a889b",
#         'Accept-Encoding': "gzip, deflate",
#         'Referer': "http://nova.dcs.deloitte.com/api/report/accounts",
#         'Connection': "keep-alive",
#         'cache-control': "no-cache",
#         "Accept-Version": "nova.2022-05-03",
#     }

    
#     response = requests.get(f"{nova_report_url}", headers=headers)
    
#     if response.status_code == 200:
#         novaData = response.json()
#         # print(f'Processed Nova data: {novaData}')
#         return novaData
#     elif response.status_code == 404:
#         # print(f"Failed to get account details: {response.status_code}")
#         return novaData


# go()

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
# for account in accounts[60:80]:
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

accounts = ['003866754167', '003896315085', '004629961456', '005241645787', '005333532456', '008530717892', '009296111214', '009464921414', '010753539596', '010817157965', '012095546580', '012680939556', '014296065027', '015257350768', '016937230970', '017432556837', '017456215898', '017848332886', '018649475058', '022618988199', '023146164982', '026194564518', '027393114528', '028568440897', '030974280115', '031007339471', '033014299223', '033246515043', '035778782477', '035825521573', '037355734743', '037388063884', '038059618311', '041149546493', '042115301607', '043262203499', '047685407929', '047807787807', '051469546478', '051724048437', '051799833889', '052346183910', '053070086514', '054273887971', '055064962277', '055798325468', '055840983865', '056895686976', '062130537180', '063353051663', '063376279610', '066979683739', '067154635066', '068757897087', '070036689193', '070660504732', '072706165844', '073146838139', '077240679103', '080656668290', '084407457870', '084582856213', '086573493719', '086574853384', '087549363555', '088220075168', '088475525986', '088563067471', '089587160124', '090446900710', '091115685892', '091284928336', '092960230608', '093441740690', '095611350051', '097020054916', '097107211992', '098556162587', '099325924796', '101177931550', '103896790399', '103917580387', '105723104798', '106456323084', '107282117866', '107831069545', '109640153986', '109997849406', '110557118724', '110633459663', '110912366499', '111535522048', '112558980097', '114535277687', '114727038176', '115154971638', '117523786847', '117725889170', '118974102263', '119203704260', '119343329730', '120152586068', '122994942344', '123906516738', '124524166810', '129330666742', '130220492427', '131660845369', '132027580256', '133143185602', '133550674684', '133762489993', '135185876313', '135755270796', '136473818407', '138233832997', '142332166808', '142646231261', '144627418504', '144635163526', '146003574029', '148094740375', '149477848214', '149878268794', '150316879294', '150767860677', '151434629482', '152223477882', '152898684328', '153592066989', '153685446838', '153714429732', '153951089943', '159602377297', '159861609278', '159921825654', '160339976030', '161391293302', '161394336152', '161636799113', '162022282563', '164398058260', '167393382127', '168849861669', '170140899813', '171762472359', '172067301824', '172832121763', '172863928423', '175091774301', '175924461164', '175930311790', '175956104120', '178790212740', '184405994032', '185020060020', '185284577515', '186861417013', '187528728268', '188529011465', '193361093508', '193412282603', '193854970547', '197821584623', '198092089923', '199570988326', '200228513821', '200543695574', '201823333330', '205063679632', '205707500197', '208421051549', '210264310230', '210579071845', '210798437721', '211101344176', '211593031182', '211600541199', '212921778948', '213911605817', '214979362845', '215611426819', '216542771521', '217360121513', '218515608600', '220933860874', '221292848939', '222531082059', '223441765792', '224244178360', '225658821723', '225832781273', '226603863404', '227841379693', '227937082667', '228115329917', '231716799145', '231972052922', '231974784973', '232162000477', '233127284560', '233256077443', '235513223743', '237366858765', '238557733178', '238820089267', '238970376046', '239205171373', '239537226757', '240044539051', '245250269795', '246197285750', '246585516170', '246698818014', '246938629297', '247048948584', '251072340318', '251985550364', '252323805874', '252365818154', '254263703118', '256489642696', '256706112543', '256867917700', '259692210398', '261934197954', '263128578697', '264944699463', '266396698525', '266955691786', '266980808703', '268522796693', '269475816966', '269734407326', '270950599001', '271937290370', '272606000076', '275380584232', '277167574796', '279462431622', '279743555714', '280522856839', '282752622212', '283503555640', '283520033493', '284328782567', '284760807629', '286058688319', '287248264930', '288228195021', '288952646112', '292210083552', '294745394203', '295562148805', '296916826127', '297486902890', '298561899742', '300801515163', '306182918611', '307036839104', '307141129713', '307492883559', '308360630103', '309416070659', '309727501936', '312807674804', '314285588528', '314448338500', '315370314208', '315952988300', '316461870015', '316625284770', '320199641064', '320510073098', '321267289192', '321376957942', '323911653333', '324789170316', '327639925109', '328235541546', '328705181099', '329783930457', '330374005851', '330459082734', '332607986083', '334734394521', '335893736669', '337910336443', '340826808143', '340942712854', '342122824633', '342416616976', '342472205137', '342788227825', '344161786867', '345404735839', '345889295625', '347913913427', '354716619065', '359252437790', '361804686539', '363220349094', '363235117348', '364513602188', '365111145171', '365655694970', '366087731140', '366779305333', '366862120963', '367409673491', '368276533222', '368404118071', '369770340971', '370020434536', '372203661552', '373758253227', '373943505089', '374367240544', '375028686807', '376614162583', '376756837763', '377602907415', '380906577769', '384921830497', '385078759766', '385397780492', '385644467038', '386372166532', '386423219226', '386880889362', '386951795368', '391931929196', '394326658915', '396547825296', '397051564974', '403053226718', '403398797571', '406236698787', '406850891275', '407922971056', '410993274172', '413145654121', '413418342606', '413990510913', '415134345932', '416842063547', '418363115654', '419451308158', '420525251589', '421953516327', '423930725445', '426743316697', '428677740062', '429242996634', '431231529702', '432089771844', '434331732926', '436310111307', '438050491659', '438720243151', '440737389801', '440856099504', '441012919436', '441340786764', '442888752927', '443249815747', '444895787476', '445066270436', '446334086509', '447344437245', '447718312100', '448309204918', '448362402750', '449510142326', '450542789652', '451268808790', '453919366994', '454708018951', '455771646044', '456082790337', '458178772538', '458599620270', '461075792974', '461639330540', '462532790342', '463479487416', '463680094014', '465638941851', '467325410942', '470306404467', '471936325112', '472167960556', '472274473037', '473144355006', '474547691682', '477760339841', '479008266961', '480022745122', '480208011542', '480475536219', '483078657402', '484163937975', '486238640158', '486528187221', '486653307662', '488283147041', '489537064020', '490290534637', '491271408797', '491642886103', '492634300165', '492906408022', '493857221609', '494101600798', '495693388953', '497315343129', '498536333823', '498711219760', '500482683615', '500980881293', '502327753374', '503351113243', '503741562442', '504762789322', '505828008366', '506633848063', '506696121897', '507297579984', '507458175641', '512171866621', '512382550508', '513764142827', '514036822646', '515808197273', '515993956937', '517564158377', '518664229968', '522328802007', '524275599438', '524658522586', '525103131843', '526450483356', '526529371479', '527490275647', '529005549134', '529277024000', '529976655406', '531268065622', '531329070867', '531569583280', '531659201158', '534534201911', '534846924117', '535700223023', '537671715099', '537849064119', '542172426746', '543315275728', '544133436431', '544510848374', '544734843935', '546138792195', '547043556405', '547509476297', '547934214792', '548659743877', '550812425828', '551019182106', '552291554780', '552903841159', '553514781467', '556525398552', '558610732496', '559651534567', '560024577736', '561320747596', '561546907559', '564066165061', '565133027204', '567664804420', '568533325689', '570696484411', '572961371493', '573292697388', '573313377656', '576524227815', '578066212474', '578316533664', '578660118980', '578941406071', '581047588350', '581775067842', '581985365737', '583190184710', '583303984486', '583345763035', '583608845417', '584199283902', '584630848692', '584974054351', '586482989402', '586805444392', '588773227252', '589727330895', '589892584776', '590506744596', '592564898892', '592597120121', '594239924270', '595353211380', '596896391463', '598716746971', '601615387933', '602644925125', '604318285507', '604723096881', '606511248153', '609468539593', '611120875422', '614092787540', '616194183804', '616614454022', '619153066025', '623701539211', '625001204664', '625125552135', '628157037413', '629026071019', '630958910218', '634691564906', '637454724728', '637839024236', '638334832935', '639536544457', '640234854210', '641441075861', '641938356393', '643596949585', '644784173767', '644849997084', '647087774510', '647885244255', '648585965371', '650018817833', '651509282451', '652125692913', '652437243948', '652993727289', '653060988075', '654075011442', '654174153064', '656483505048', '658062093174', '659789841918', '661045825192', '661881507687', '663321287581', '666800176692', '667027443162', '667723493591', '667900912763', '670161819556', '671629789513', '675248765338', '675771396901', '677167808438', '679245664611', '679578327390', '680162656405', '680660665682', '681628658461', '682654310819', '684560741695', '688405658638', '689468357458', '690318954491', '694345650500', '694674735136', '695382570272', '695506696950', '696344538400', '696360193991', '697312559295', '697642837822', '699486026393', '699736171795', '700777391571', '703183665370', '704025107641', '705494424374', '705854351142', '712231335908', '713018753281', '714967854867', '716751674484', '720257876889', '720745720430', '721880670703', '723175378301', '724311065114', '725260281549', '726750907807', '729469735401', '730031397153', '735837376890', '736530749364', '737192344670', '738731325101', '739295643645', '740166810819', '743027775537', '744946510523', '745576527420', '747329189279', '747602229289', '748278030583', '750369583115', '753880925017', '755216844945', '758843481727', '759209259634', '763269149154', '763639998517', '764490523317', '766245584008', '766533495919', '766554992149', '767507899515', '767813017116', '767848537480', '770600390810', '770817124419', '771557547238', '771645514271', '773318300432', '773467821022', '775595962189', '776440666163', '777601016429', '778075340046', '779529038689', '784441283169', '785786920527', '789476507634', '791968533226', '794501456704', '794569136533', '796402573673', '801074580788', '801334471752', '802825831136', '807394297581', '808458935611', '809498814746', '809887086749', '810358558433', '810686302806', '814566149193', '816919933351', '819418488580', '821346124874', '821816138949', '822274905021', '822566085433', '822955369949', '823523588426', '824349500053', '824943661652', '826919501912', '827687231818', '828059665819', '828471328199', '828707026805', '829331138793', '830458620727', '830960023363', '831213597264', '831428250184', '831811033311', '834357290412', '834501561769', '834806916487', '836073812853', '836346912461', '837289689095', '837626969847', '837956138358', '838910886206', '841003316687', '841307960404', '841764116136', '844702767392', '845115198660', '845663238523', '847198424597', '848219600572', '848793886259', '849045193397', '849379670310', '850795100153', '852472875055', '853713850743', '858141963590', '858526972147', '858857573117', '860178592278', '860680429784', '862094248680', '862140534462', '864080733145', '865408716471', '865654561421', '866203773640', '868521031821', '868874314265', '869371544050', '870562742571', '871834102260', '874896561479', '875314453109', '875752141512', '877180364429', '881051476853', '881451740496', '882722950271', '883454950117', '883784239155', '886674288950', '887119163707', '890591524509', '891047194812', '892095653963', '893007952058', '893649511657', '893725561486', '895081226716', '895796344347', '896284331846', '897265563406', '899956852123', '902077756344', '904898881486', '910380970013', '910997097838', '912681226107', '913412532161', '913593522947', '914462607210', '915814505567', '916396089121', '916943954658', '917232550581', '917303654463', '918223892161', '918704104394', '919367393195', '920078571165', '920815465273', '924069284639', '924235240336', '924294269964', '925017383941', '926372856456', '927753750267', '928599649920', '930328442017', '931334696467', '932207706514', '936639518272', '937767124938', '938247196952', '941819694106', '942973508166', '943654527978', '944713022036', '948310893572', '948837575101', '948948595631', '952135726105', '954695687190', '954738915509', '954742235303', '955038580167', '955116103754', '955621810722', '957304465555', '958991296092', '960102767444', '960956162241', '961972215724', '964131740148', '964530035547', '965266634360', '965817487737', '966309006358', '970120047911', '971295728977', '971552591868', '971557445175', '971836208243', '973653897100', '974255779466', '974936500263', '975204971987', '978553898267', '979212527518', '985410213753', '986038433815', '987148916101', '989150551987', '990148784831', '990223392234', '991022102975', '992200855368', '992908013717', '993017681120', '993932001969', '994920118214', '996010827026', '997069924264', '997205032839', '997667771749', '998732324712', '999954735781']

# Iterate over each account and remove the specified roles
c = 600
for account in accounts[600:700]:
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

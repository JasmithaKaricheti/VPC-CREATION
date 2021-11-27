import json
import logging
import datetime as dt
import time
import boto3
from botocore import ClientError

myclient = boto3.client('ec2')

def createpolicy(policy_name):
    try:
        my_managed_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AcceptVpcPeeringConnection",
                        "ec2:AcceptVpcEndpointConnections",
                        "ec2:AllocateAddress",
                        "ec2:AssignIpv6Addresses",
                        "ec2:AssignPrivateIpAddresses",
                        "ec2:AssociateAddress",
                        "ec2:AssociateDhcpOptions",
                        "ec2:AssociateRouteTable",
                        "ec2:AssociateSubnetCidrBlock",
                        "ec2:AssociateVpcCidrBlock",
                        "ec2:AttachClassicLinkVpc",
                        "ec2:AttachInternetGateway",
                        "ec2:AttachNetworkInterface",
                        "ec2:AttachVpnGateway",
                        "ec2:AuthorizeSecurityGroupEgress",
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:CreateCarrierGateway",
                        "ec2:CreateCustomerGateway",
                        "ec2:CreateDefaultSubnet",
                        "ec2:CreateDefaultVpc",
                        "ec2:CreateDhcpOptions",
                        "ec2:CreateEgressOnlyInternetGateway",
                        "ec2:CreateFlowLogs",
                        "ec2:CreateInternetGateway",
                        "ec2:CreateLocalGatewayRouteTableVpcAssociation",
                        "ec2:CreateNatGateway",
                        "ec2:CreateNetworkAcl",
                        "ec2:CreateNetworkAclEntry",
                        "ec2:CreateNetworkInterface",
                        "ec2:CreateNetworkInterfacePermission",
                        "ec2:CreateRoute",
                        "ec2:CreateRouteTable",
                        "ec2:CreateSecurityGroup",
                        "ec2:CreateSubnet",
                        "ec2:CreateTags",
                        "ec2:CreateVpc",
                        "ec2:CreateVpcEndpoint",
                        "ec2:CreateVpcEndpointConnectionNotification",
                        "ec2:CreateVpcEndpointServiceConfiguration",
                        "ec2:CreateVpcPeeringConnection",
                        "ec2:CreateVpnConnection",
                        "ec2:CreateVpnConnectionRoute",
                        "ec2:CreateVpnGateway",
                        "ec2:DeleteCarrierGateway",
                        "ec2:DeleteCustomerGateway",
                        "ec2:DeleteDhcpOptions",
                        "ec2:DeleteEgressOnlyInternetGateway",
                        "ec2:DeleteFlowLogs",
                        "ec2:DeleteInternetGateway",
                        "ec2:DeleteLocalGatewayRouteTableVpcAssociation",
                        "ec2:DeleteNatGateway",
                        "ec2:DeleteNetworkAcl",
                        "ec2:DeleteNetworkAclEntry",
                        "ec2:DeleteNetworkInterface",
                        "ec2:DeleteNetworkInterfacePermission",
                        "ec2:DeleteRoute",
                        "ec2:DeleteRouteTable",
                        "ec2:DeleteSecurityGroup",
                        "ec2:DeleteSubnet",
                        "ec2:DeleteTags",
                        "ec2:DeleteVpc",
                        "ec2:DeleteVpcEndpoints",
                        "ec2:DeleteVpcEndpointConnectionNotifications",
                        "ec2:DeleteVpcEndpointServiceConfigurations",
                        "ec2:DeleteVpcPeeringConnection",
                        "ec2:DeleteVpnConnection",
                        "ec2:DeleteVpnConnectionRoute",
                        "ec2:DeleteVpnGateway",
                        "ec2:DescribeAccountAttributes",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeCarrierGateways",
                        "ec2:DescribeClassicLinkInstances",
                        "ec2:DescribeCustomerGateways",
                        "ec2:DescribeDhcpOptions",
                        "ec2:DescribeEgressOnlyInternetGateways",
                        "ec2:DescribeFlowLogs",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeIpv6Pools",
                        "ec2:DescribeLocalGatewayRouteTables",
                        "ec2:DescribeLocalGatewayRouteTableVpcAssociations",
                        "ec2:DescribeKeyPairs",
                        "ec2:DescribeMovingAddresses",
                        "ec2:DescribeNatGateways",
                        "ec2:DescribeNetworkAcls",
                        "ec2:DescribeNetworkInterfaceAttribute",
                        "ec2:DescribeNetworkInterfacePermissions",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribePrefixLists",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeSecurityGroupReferences",
                        "ec2:DescribeSecurityGroupRules",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeStaleSecurityGroups",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeTags",
                        "ec2:DescribeVpcAttribute",
                        "ec2:DescribeVpcClassicLink",
                        "ec2:DescribeVpcClassicLinkDnsSupport",
                        "ec2:DescribeVpcEndpointConnectionNotifications",
                        "ec2:DescribeVpcEndpointConnections",
                        "ec2:DescribeVpcEndpoints",
                        "ec2:DescribeVpcEndpointServiceConfigurations",
                        "ec2:DescribeVpcEndpointServicePermissions",
                        "ec2:DescribeVpcEndpointServices",
                        "ec2:DescribeVpcPeeringConnections",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeVpnConnections",
                        "ec2:DescribeVpnGateways",
                        "ec2:DetachClassicLinkVpc",
                        "ec2:DetachInternetGateway",
                        "ec2:DetachNetworkInterface",
                        "ec2:DetachVpnGateway",
                        "ec2:DisableVgwRoutePropagation",
                        "ec2:DisableVpcClassicLink",
                        "ec2:DisableVpcClassicLinkDnsSupport",
                        "ec2:DisassociateAddress",
                        "ec2:DisassociateRouteTable",
                        "ec2:DisassociateSubnetCidrBlock",
                        "ec2:DisassociateVpcCidrBlock",
                        "ec2:EnableVgwRoutePropagation",
                        "ec2:EnableVpcClassicLink",
                        "ec2:EnableVpcClassicLinkDnsSupport",
                        "ec2:ModifyNetworkInterfaceAttribute",
                        "ec2:ModifySecurityGroupRules",
                        "ec2:ModifySubnetAttribute",
                        "ec2:ModifyVpcAttribute",
                        "ec2:ModifyVpcEndpoint",
                        "ec2:ModifyVpcEndpointConnectionNotification",
                        "ec2:ModifyVpcEndpointServiceConfiguration",
                        "ec2:ModifyVpcEndpointServicePermissions",
                        "ec2:ModifyVpcPeeringConnectionOptions",
                        "ec2:ModifyVpcTenancy",
                        "ec2:MoveAddressToVpc",
                        "ec2:RejectVpcEndpointConnections",
                        "ec2:RejectVpcPeeringConnection",
                        "ec2:ReleaseAddress",
                        "ec2:ReplaceNetworkAclAssociation",
                        "ec2:ReplaceNetworkAclEntry",
                        "ec2:ReplaceRoute",
                        "ec2:ReplaceRouteTableAssociation",
                        "ec2:ResetNetworkInterfaceAttribute",
                        "ec2:RestoreAddressToClassic",
                        "ec2:RevokeSecurityGroupEgress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:UnassignIpv6Addresses",
                        "ec2:UnassignPrivateIpAddresses",
                        "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
                        "ec2:UpdateSecurityGroupRuleDescriptionsIngress"
                    ],
                    "Resource": "*"
                }
            ]
        }

        response = myclient.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(my_managed_policy))
        print(response)
        logging.info("Policy created", 'AmazonVPCFullAccess')
    except ClientError:
        logging.exception("Policy creation  %s failed", 'AmazonVPCFullAccess')
        raise


def attachUserPolicy():
    try:
        response = client.attach_user_policy(
            UserName='myvpc',  # Name of user
            PolicyArn='arn:aws:iam::aws:policy/AmazonVPCFullAccess'
            # Policy ARN which you want to assign to user
        )
        print(response)
        logging.info("Attach policy %s from user %s.", 'myvpc', 'arn:aws:iam::aws:policy/AmazonVPCFullAccess')
    except ClientError:
        logging.exception("Attaching policy %s to user %s failed", 'myvpc',
                          'arn:aws:iam::aws:policy/AmazonVPCFullAccess')
        raise


#myami = 'ami-0629230e074c580f2'

vpc=myclient.create_vpc(CidrBlock='10.0.0.0/16')

tag = vpc.create_tags(Tags=[{'Key': 'Name', 'Value': 'demo-vpc'}])
vpc.wait_until_available()
time.sleep(10)
sub1=myclient.crete_subnet(CidrBlock='10.0.20.0/24',VpcId=vpc.id)
tag1 = sub1.create_tags(Tags=[{
    'Key':'Name',
    'Value':'public'
}])

ig = myclient.create_internet_gateway()
vpc.attach_internet_gateway(InternetGatewayId=ig.id)
print(ig.id)

route_table = vpc.create_route_table()
route = route_table.create_route(
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=ig.id
)
print(route_table.id)

myclient.create_subnet(CidrBlock='192.168.10.0/28',VpcId=vpc.id)


response = route_table.associate_with_subnet(SubnetId=sub1)
print(response)

G_name = input("Enter group_name:")
print(G_name)

sec_group = myclient.create_security_group(
    GroupName=G_name, Description='slice_0 sec group', VpcId=vpc.id)
sec_group.authorize_ingress(
    CidrIp='0.0.0.0/0',
    IpProtocol='icmp',
    FromPort=-1,
    ToPort=-1
)
print(sec_group.id)

Image_id = input("Enter ami:")
print(Image_id)

instances = myclient.create_instances(
    ImageId=Image_id, InstanceType='t2.micro', MaxCount=1, MinCount=1,
    NetworkInterfaces=[
        {'SubnetId': sub1, 'DeviceIndex': 0, 'AssociatePublicIpAddress': True, 'Groups': [sec_group.group_id]}])
instances[0].wait_until_running()
print(instances[0].id)




import boto3
from vpc_endpoint_utils import (
    get_ec2_client,
    get_instance_network_details,
    lookup_service_events_and_filter_by_instance,
    analyze_endpoint_usage,
    select_subnets_for_ha,
    select_route_tables_for_ha,
    check_existing_endpoint,
)

SELF_FUNCTION_NAME = "check_vpc_endpoint_presence"
lambda_client = boto3.client("lambda")

# Boto3 CloudTrail 클라이언트 캐싱 (선택적이지만 권장)
_cloudtrail_clients = {}


def get_cloudtrail_client(region):
    # 지정된 리전의 CloudTrail 클라이언트를 반환 (캐싱 사용)
    if region not in _cloudtrail_clients:
        try:
            _cloudtrail_clients[region] = boto3.client("cloudtrail", region_name=region)
        except Exception as e:
            print(
                f"오류: 리전 '{region}'에 대한 CloudTrail 클라이언트를 생성할 수 없습니다. {e}"
            )
            return None
    return _cloudtrail_clients[region]


def lambda_handler(event, context=None):
    """
    event: {
        "instance_id": "i-xxxx",
        "region": "ap-northeast-2",
        "days": 1,   # optional
        "hours": 12  # optional
    }
    """
    instance_id = event.get("instance_id")
    region = event.get("region")
    days = event.get("days")
    hours = event.get("hours")

    if not instance_id or not region:
        return {"statusCode": 400, "body": "instance_id와 region은 필수입니다."}

    # 1. CloudTrail 이벤트 조회 및 분석
    events_list = lookup_service_events_and_filter_by_instance(
        region, instance_id, days=days, hours=hours
    )
    if not events_list or (hasattr(events_list, "empty") and events_list.empty):
        return {
            "statusCode": 200,
            "body": f"인스턴스 '{instance_id}' 관련 대상 서비스 트래픽을 찾을 수 없습니다.",
        }

    print("this is events_list", events_list)

    # 2. 엔드포인트 미사용 분석
    potential_missing = analyze_endpoint_usage(events_list)
    if not potential_missing:
        return {
            "statusCode": 200,
            "body": f"분석 결과, 인스턴스 '{instance_id}' 트래픽에 대해 VPC 엔드포인트 생성이 필요한 경우가 감지되지 않았습니다.",
        }

    print("this is potential_missing", potential_missing)

    # 3. 인스턴스 네트워크 정보 조회
    network_details = get_instance_network_details(region, instance_id)
    if not network_details:
        return {
            "statusCode": 500,
            "body": f"인스턴스({instance_id}) 네트워크 정보 조회 실패",
        }
    vpc_id = network_details["vpc_id"]
    instance_security_group_ids = network_details["security_group_ids"]

    ec2_client = get_ec2_client(region)
    if not ec2_client:
        return {"statusCode": 500, "body": f"EC2 클라이언트 생성 실패 ({region})"}

    results = []
    for missing in potential_missing:
        service = missing["service"]
        rgn = missing["region"]
        if rgn != region:
            continue
        endpoint_type = "Gateway" if service == "S3" else "Interface"
        service_name_to_create = f"com.amazonaws.{region}.{service.lower() if service != 'ECR' else 'ecr.dkr'}"
        existing = check_existing_endpoint(ec2_client, vpc_id, service_name_to_create)
        if existing:
            results.append(
                {
                    "service": service,
                    "region": region,
                    "status": "already_exists",
                    "endpoint_id": existing[0]["VpcEndpointId"],
                    "message": f"이미 VPC '{vpc_id}'에 '{service_name_to_create}' 엔드포인트가 존재하여 생성을 건너뜁니다.",
                }
            )
            continue
        creation_params = {
            "VpcEndpointType": endpoint_type,
            "VpcId": vpc_id,
            "ServiceName": service_name_to_create,
            "TagSpecifications": [
                {
                    "ResourceType": "vpc-endpoint",
                    "Tags": [
                        {"Key": "Name", "Value": f"{vpc_id}-{service}-endpoint"},
                        {"Key": "CreatedFromReferenceInstance", "Value": instance_id},
                    ],
                }
            ],
        }
        if endpoint_type == "Gateway":
            route_table_ids, rt_info = select_route_tables_for_ha(ec2_client, vpc_id)
            if not route_table_ids:
                results.append(
                    {
                        "service": service,
                        "region": region,
                        "status": "fail",
                        "message": f"라우트 테이블 자동 선택 실패: {rt_info}",
                    }
                )
                continue
            creation_params["RouteTableIds"] = route_table_ids
        elif endpoint_type == "Interface":
            subnet_ids, sn_info = select_subnets_for_ha(ec2_client, vpc_id)
            if not subnet_ids:
                results.append(
                    {
                        "service": service,
                        "region": region,
                        "status": "fail",
                        "message": f"서브넷 자동 선택 실패: {sn_info}",
                    }
                )
                continue
            creation_params["SubnetIds"] = subnet_ids
            creation_params["SecurityGroupIds"] = instance_security_group_ids
            creation_params["PrivateDnsEnabled"] = True
        try:
            response = ec2_client.create_vpc_endpoint(**creation_params)
            vpc_endpoint_info = response.get("VpcEndpoint", {})
            new_endpoint_id = vpc_endpoint_info.get("VpcEndpointId")
            current_state = vpc_endpoint_info.get("State")

            print("this is new_endpoint_id", new_endpoint_id)

            if new_endpoint_id:
                results.append(
                    {
                        "service": service,
                        "region": region,
                        "status": "created",
                        "endpoint_id": new_endpoint_id,
                        "state": current_state,
                    }
                )
            else:
                results.append(
                    {
                        "service": service,
                        "region": region,
                        "status": "fail",
                        "message": "엔드포인트 생성 API 호출은 성공했으나, 응답에서 ID를 찾을 수 없습니다.",
                    }
                )
        except Exception as e:
            results.append(
                {
                    "service": service,
                    "region": region,
                    "status": "fail",
                    "message": f"엔드포인트 생성 실패: {e}",
                }
            )
    return {"statusCode": 200, "body": results}

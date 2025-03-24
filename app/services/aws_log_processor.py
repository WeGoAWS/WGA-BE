# app/services/aws_log_processor.py
import json
import gzip
import botocore.exceptions
from app.core.config import settings
import time
import random
from app.services.bedrock_service import invoke_bedrock_model

# CloudTrail 로그 분석 프롬프트 템플릿
LOG_ANALYSIS_PROMPT = """
Analyze the following AWS CloudTrail log and determine if there are any security risks.

Log Data:
{log_event}

- Identify potential security risks.
- Clearly explain the risk level (Low, Medium, High).
- Provide recommendations if needed.
- Indicate if this event is normal or suspicious.
- Provide a summary of the event in a short, human-readable format.
"""

# IAM 정책 분석 프롬프트 템플릿
POLICY_ANALYSIS_PROMPT = """
Based on the following CloudTrail log and the user's current permissions, recommend IAM policy modifications.

CloudTrail Log:
{log_event}

Current Permissions:
{current_permissions}

- Only remove permissions if they are **clearly unnecessary** based on the log.
- If a permission has been used multiple times, do not remove it.
- If additional permissions are needed, provide them.
- If the log suggests a need for more restrictive permissions, recommend policy adjustments.
- Provide a reason for each change.

Format your response exactly as:
REMOVE: <permissions or None>
ADD: <permissions or None>
Reason: <Clear explanation in one sentence.>
"""

def find_latest_cloudtrail_files(s3_client, bucket_name, prefix, file_count):
    """Find latest CloudTrail log files in S3"""
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    if "Contents" in response and response["Contents"]:
        sorted_files = sorted(response["Contents"], key=lambda x: x["LastModified"], reverse=True)
        latest_files = [file["Key"] for file in sorted_files[:file_count]]
        return latest_files
    else:
        raise FileNotFoundError("No CloudTrail logs found in S3.")

def get_cloudtrail_logs(s3_client, bucket_name, file_key):
    """Get CloudTrail logs from S3 file"""
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    with gzip.GzipFile(fileobj=response["Body"]) as gz:
        logs = json.loads(gz.read().decode("utf-8"))
    return logs

def get_latest_events(logs, count):
    """Get latest events from CloudTrail logs"""
    records = logs.get("Records", [])
    records.sort(key=lambda x: x.get("eventTime", ""), reverse=True)
    return records[:count]

def get_user_permissions(iam_client, user_arn):
    """Get IAM permissions for a user"""
    if user_arn.endswith(":root"):
        print(f"Skipping root user: {user_arn}")
        return []
    if ":user/" in user_arn:
        user_name = user_arn.split("user/")[-1]
    elif ":assumed-role/" in user_arn:
        print(f"Skipping assumed-role: {user_arn}")
        return []
    else:
        raise ValueError(f"Invalid IAM ARN format: {user_arn}")
    
    permissions = set()
    try:
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        for policy in attached_policies:
            policy_arn = policy["PolicyArn"]
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)["PolicyVersion"]["Document"]
            for statement in policy_document.get("Statement", []):
                if "Action" in statement:
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        permissions.add(actions)
                    else:
                        permissions.update(actions)
        inline_policies = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
        for policy_name in inline_policies:
            policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
            for statement in policy_document.get("Statement", []):
                if "Action" in statement:
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        permissions.add(actions)
                    else:
                        permissions.update(actions)
    except botocore.exceptions.ClientError as e:
        print(f"Error fetching IAM policies for {user_name}: {e}")
        return []
    return list(permissions)

def analyze_log(log):
    """Analyze a CloudTrail log entry using Bedrock or fallback to rule-based analysis"""
    try:
        # Try to use Bedrock API
        prompt = LOG_ANALYSIS_PROMPT.format(log_event=json.dumps(log, indent=4))
        response = invoke_bedrock_model(prompt)
        
        # Access the response text based on Claude API structure
        if "content" in response and isinstance(response["content"], list) and len(response["content"]) > 0:
            content_item = response["content"][0]
            if "text" in content_item and content_item["type"] == "text":
                return content_item["text"]
        return "Analysis failed: Invalid response format"
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        
        # Fallback to rule-based analysis if Bedrock is throttled
        if "ThrottlingException" in str(e):
            return rule_based_log_analysis(log)
        
        return f"Analysis failed: {str(e)}"
        
def rule_based_log_analysis(log):
    """Fallback analysis when Bedrock API is throttled"""
    # Extract key information from the log
    event_name = log.get("eventName", "Unknown")
    event_source = log.get("eventSource", "Unknown").replace(".amazonaws.com", "")
    source_ip = log.get("sourceIPAddress", "Unknown")
    
    # Basic risk assessment based on event name
    risk_level = "Low"
    recommendations = []
    
    # Check for sensitive actions
    sensitive_actions = [
        "Create", "Delete", "Update", "Modify", "Put", "Attach", 
        "Detach", "Enable", "Disable", "Revoke", "AuthorizeSecurityGroup"
    ]
    
    if any(action in event_name for action in sensitive_actions):
        risk_level = "Medium"
        recommendations.append("Review this action to ensure it was authorized.")
    
    # Check for IAM or permission-related events
    if "iam" in event_source.lower() or "sts" in event_source.lower():
        risk_level = "Medium"
        if "Policy" in event_name or "Role" in event_name or "User" in event_name:
            risk_level = "High"
            recommendations.append("Verify this IAM change was authorized and follows least privilege principle.")
    
    # Check for security-related events
    if "security" in event_source.lower() or "guard" in event_source.lower() or "config" in event_source.lower():
        risk_level = "Medium"
        recommendations.append("Verify this security configuration change was authorized.")
    
    # Check for unusual IP addresses (simplified)
    if source_ip not in ["internal", "aws-service", "127.0.0.1"] and not source_ip.startswith("10.") and not source_ip.startswith("192.168."):
        recommendations.append(f"Verify that access from IP {source_ip} is expected.")
    
    # Determine if event seems normal or suspicious
    event_status = "Normal" if risk_level == "Low" else "Potentially suspicious"
    
    # Build the response
    analysis = f"""
Risk assessment for event {event_name} from {event_source}:

- Risk Level: {risk_level}
- Status: {event_status}
- Summary: {event_name} was performed via {event_source}"""
    
    if recommendations:
        analysis += "\n\nRecommendations:\n"
        for i, rec in enumerate(recommendations, 1):
            analysis += f"{i}. {rec}\n"
    
    return analysis

def analyze_policy(log, user_arn, iam_client):
    """Analyze IAM policy based on CloudTrail log using Bedrock or fallback to rule-based analysis"""
    try:
        current_permissions = get_user_permissions(iam_client, user_arn)
        prompt = POLICY_ANALYSIS_PROMPT.format(
            log_event=json.dumps(log, indent=4),
            current_permissions=json.dumps(current_permissions, indent=4)
        )
        response = invoke_bedrock_model(prompt)
        
        # Access the response text based on Claude API structure
        response_text = ""
        if "content" in response and isinstance(response["content"], list) and len(response["content"]) > 0:
            content_item = response["content"][0]
            if "text" in content_item and content_item["type"] == "text":
                response_text = content_item["text"]
        
        result = {"REMOVE": [], "ADD": [], "Reason": ""}
        for line in response_text.strip().split("\n"):
            if line.startswith("REMOVE:"):
                perms = line.replace("REMOVE:", "").strip()
                if perms != "None":
                    result["REMOVE"].append(perms)
            elif line.startswith("ADD:"):
                perms = line.replace("ADD:", "").strip()
                if perms != "None":
                    result["ADD"].append(perms)
            elif line.startswith("Reason:"):
                result["Reason"] = line.replace("Reason:", "").strip()
        return result
    except Exception as e:
        print(f"Error in policy analysis: {e}")
        
        # Fallback to rule-based analysis if Bedrock is throttled
        if "ThrottlingException" in str(e):
            return rule_based_policy_analysis(log, current_permissions)
        
        return {"REMOVE": [], "ADD": [], "Reason": f"Policy analysis failed: {str(e)}"}

def rule_based_policy_analysis(log, current_permissions):
    """Fallback policy analysis when Bedrock API is throttled"""
    result = {"REMOVE": [], "ADD": [], "Reason": ""}
    
    # Extract key information from the log
    event_name = log.get("eventName", "Unknown")
    event_source = log.get("eventSource", "Unknown").replace(".amazonaws.com", "")
    
    # Basic analysis based on service and action
    service = event_source.split(".")[0] if "." in event_source else event_source
    
    # Map the event to likely required permissions
    required_permission = f"{service}:{event_name}"
    
    # Check if user already has permissions that match the service
    has_service_wildcard = False
    has_specific_action = False
    
    for perm in current_permissions:
        if f"{service}:*" in perm:
            has_service_wildcard = True
        if required_permission.lower() in perm.lower():
            has_specific_action = True
    
    # Simple policy recommendations
    if not has_service_wildcard and not has_specific_action:
        result["ADD"].append(required_permission)
        result["Reason"] = f"User performed {event_name} on {service} but doesn't have explicit permission for this action."
    elif has_service_wildcard:
        # Suggest tightening permissions if they have wildcard access
        result["REMOVE"].append(f"{service}:*")
        result["ADD"].append(required_permission)
        result["Reason"] = "Replace wildcard permission with specific action permissions for better security."
    else:
        result["Reason"] = "Current permissions appear appropriate for the observed activity."
    
    return result

def save_analysis_to_s3(s3_client, bucket_name, file_key, analysis_results):
    """Save analysis results to S3"""
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=json.dumps(analysis_results, indent=4),
        ContentType="application/json"
    )

def process_aws_logs(session, aws_bucket_name, aws_log_prefix, output_bucket_name, output_file_key, file_count=5, event_count=5, delay_between_calls=2):
    """Process AWS CloudTrail logs"""
    # Create AWS clients
    s3_client = session.client("s3")
    iam_client = session.client("iam")
    
    # Find and process logs
    all_logs = []
    aws_file_keys = find_latest_cloudtrail_files(s3_client, aws_bucket_name, aws_log_prefix, file_count)
    for file_key in aws_file_keys:
        logs = get_cloudtrail_logs(s3_client, aws_bucket_name, file_key)
        all_logs.extend(logs.get("Records", []))
    all_logs.sort(key=lambda x: x.get("eventTime", ""), reverse=True)
    latest_events = all_logs[:event_count]
    
    # Analyze logs with rate limiting
    analysis_results = []
    for i, log in enumerate(latest_events):
        user_arn = log.get("userIdentity", {}).get("arn", "unknown")
        
        # Add delay between API calls to avoid throttling
        if i > 0:
            # Add a small random jitter to the delay to prevent synchronized retries
            jitter = random.uniform(0, 0.5)
            time.sleep(delay_between_calls + jitter)
            
        security_analysis = analyze_log(log)
        
        # Add another delay before the second API call
        time.sleep(delay_between_calls)
        
        policy_recommendation = analyze_policy(log, user_arn, iam_client)
        analysis_results.append({
            "log_event": log,
            "user_arn": user_arn,
            "analysis_comment": security_analysis,
            "policy_recommendation": policy_recommendation
        })
    
    # Save results to S3
    save_analysis_to_s3(s3_client, output_bucket_name, output_file_key, analysis_results)
    
    return analysis_results
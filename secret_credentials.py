import boto3

# sqs = boto3.client("sqs",
#                    aws_access_key_id="secret-id",
#                    aws_secret_access_key="secret-key",
#                    region_name="us-east-1",
#                    endpoint_url="http://localhost:4566")
#
# queue_url="http://localhost:4566/000000000000/mymessage_queue"
# response = sqs.send_message(QueueUrl=queue_url, MessageBody=("teste de mensagem"))
# print(response)
from botocore.exceptions import ClientError

secret_name = "my_secret"
region_name = "us-east-1"

# session = boto3.session.Session()
# secrets_client = boto3.client("secretsmanager", region_name=region_name)
# secret_arn = "arn:aws:secretsmanager:us-east-1:000000000000:secret:my_secret-a7d21d"
# auth_token = secrets_client.get_secret_value(SecretId=secret_arn).get('my_secret')
client = boto3.client(
    service_name='secretsmanager',
    aws_access_key_id="secret-id",
    aws_secret_access_key="secret-key",
    region_name=region_name,
    endpoint_url="http://localhost:4566",
    verify=False
)

try:
    # get_secret_value_response = client.list_secrets()
    get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    print(get_secret_value_response)
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceNotFoundException':
        print("The requested secret " + secret_name + " was not found")
    elif e.response['Error']['Code'] == 'InvalidRequestException':
        print("The request was invalid due to:", e)
    elif e.response['Error']['Code'] == 'InvalidParameterException':
        print("The request had invalid params:", e)
    elif e.response['Error']['Code'] == 'DecryptionFailure':
        print("The requested secret can't be decrypted using the provided KMS key:", e)
    elif e.response['Error']['Code'] == 'InternalServiceError':
        print("An error occurred on service side:", e)
else:
    # Secrets Manager decrypts the secret value using the associated KMS CMK
    # Depending on whether the secret was a string or binary, only one of these fields will be populated
    if 'SecretString' in get_secret_value_response:
        text_secret_data = get_secret_value_response['SecretString']
        print(text_secret_data)
    else:
        binary_secret_data = get_secret_value_response['SecretBinary']


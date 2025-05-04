import boto3
import os

AWS_REGION = "ap-south-1"
S3_BUCKET = "secure-file-storage-bucket-1"
DYNAMODB_TABLE = "FileMetadata"

s3 = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE)

def upload_file_to_s3(local_path, s3_filename):
    s3.upload_file(local_path, S3_BUCKET, s3_filename)
    return f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_filename}"

def download_file_from_s3(s3_filename, local_path):
    s3.download_file(S3_BUCKET, s3_filename, local_path)

def store_metadata(metadata):
    table.put_item(Item=metadata)

def get_metadata(file_id):
    response = table.get_item(Key={'file_id': file_id})
    return response.get('Item')

def get_files_for_recipient(recipient_email):
    response = table.scan(
        FilterExpression='recipient = :email',
        ExpressionAttributeValues={':email': recipient_email}
    )
    return [item['file_id'] for item in response.get('Items', [])]

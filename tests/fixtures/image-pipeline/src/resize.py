import boto3

s3 = boto3.client("s3")


def handler(event, context):
    original = s3.get_object(Bucket="image-pipeline-uploads", Key=event["key"])
    s3.put_object(
        Bucket="image-pipeline-thumbnails", Key="thumbs/" + event["key"], Body=original["Body"]
    )

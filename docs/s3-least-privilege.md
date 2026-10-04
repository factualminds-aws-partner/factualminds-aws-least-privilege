# S3 least privilege

S3 authorization has two levels, and a correct folder-level policy needs both handled
separately:

- **Bucket-level actions** such as `s3:ListBucket` are authorized on the bucket ARN
  (`arn:aws:s3:::bucket`). Listing is limited to a folder with the `s3:prefix` condition key.
- **Object-level actions** such as `s3:GetObject` are authorized on object ARNs
  (`arn:aws:s3:::bucket/key`).

A common mistake is to grant `s3:ListBucket` on `bucket/uploads/*`, which matches nothing, and
then to "fix" it by granting `s3:*` on the bucket. fmaws never does either.

## Configuration

```yaml
resources:
  s3:
    - bucket: ecommerce-assets
      prefixes: [uploads/, product-images/]
      actions: [read, write, list]
      multipart: false         # large uploads
      versioned: false         # version-aware operations
      bucket_location: false   # s3:GetBucketLocation
      kms_key: 1234abcd-...    # SSE-KMS key ID or ARN
      account_id: "999900001111"   # only for a bucket owned by another account
```

Result:

```json
{
  "Effect": "Allow",
  "Action": "s3:ListBucket",
  "Resource": "arn:aws:s3:::ecommerce-assets",
  "Condition": { "StringLike": { "s3:prefix": ["product-images/*", "uploads/*"] } }
},
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": [
    "arn:aws:s3:::ecommerce-assets/product-images/*",
    "arn:aws:s3:::ecommerce-assets/uploads/*"
  ]
}
```

## Actions

| `actions` value | IAM actions | Level |
|---|---|---|
| `read` | `s3:GetObject` | object |
| `write` | `s3:PutObject` | object |
| `delete` | `s3:DeleteObject` | object |
| `list` | `s3:ListBucket` with `s3:prefix` | bucket |

| Option | Adds |
|---|---|
| `versioned: true` | `s3:GetObjectVersion` for `read`, `s3:DeleteObjectVersion` for `delete`, `s3:ListBucketVersions` for `list` |
| `multipart: true` | `s3:AbortMultipartUpload` and `s3:ListMultipartUploadParts` for `write`. Initiating, uploading parts and completing are authorized by `s3:PutObject` |
| `bucket_location: true` | `s3:GetBucketLocation` on the bucket |
| `kms_key` | `kms:Decrypt` for `read`, `kms:GenerateDataKey` for `write`, plus `kms:Decrypt` for multipart writes, on that key only, with `kms:ViaService` set to S3 in the configured region |
| `account_id` | `s3:ResourceAccount` condition on every statement for the bucket, and a reminder that the owner's bucket policy must also allow the access |

`s3:ListBucketMultipartUploads` is not added: it lists in-progress uploads for a bucket and is
not needed to perform a multipart upload.

## Prefix rules

| Input | Meaning |
|---|---|
| no `prefixes`, `""`, `/`, `*` | The whole bucket: objects `bucket/*`, listing without a prefix condition |
| `uploads`, `uploads/`, `/uploads/` | The folder `uploads/`: objects `bucket/uploads/*`, listing `uploads/*` |
| `a/b/c` | The nested folder `a/b/c/` |
| `uploads/img-*` | A raw key prefix: objects `bucket/uploads/img-*` |
| `up*loads/`, `a?b/` | Rejected. A wildcard inside a prefix would broaden access |

- Duplicate and equivalent prefixes collapse into one.
- A nested prefix keeps only what its parent does not already grant. `read` on `uploads/` plus
  `read, write` on `uploads/tmp/` yields `GetObject` on `uploads/*` and `PutObject` on
  `uploads/tmp/*`.
- Sibling prefixes with the same actions share a statement with two resources. The scope stays
  the two folders.
- A declared folder is never widened to the bucket.
- Several entries for the same bucket are combined with the same rules.

`s3:prefix` uses `uploads/*`, which also matches the request for the folder itself
(`prefix=uploads/`), because `*` matches the empty string.

## Buckets found by discovery

When a bucket is discovered but not declared, fmaws does not know which folders the application
uses. It grants `s3:GetObject` on the whole bucket, lowers the confidence, and lists the bucket
under "Unconfirmed access". Declare the bucket with its prefixes to tighten it. When an AWS SDK
call with a literal bucket name is found, the actions are inferred from the calls in that file
(`get_object` is `read`, `put_object` is `write`, `list_objects_v2` is `list`).

## Validation

Bucket names must be valid S3 bucket names. Names or prefixes containing wildcards, whitespace,
quotes or newlines are rejected with exit code 2.

## References

- [Actions, resources, and condition keys for Amazon S3](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html)
- [Controlling access to a bucket with user policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/walkthrough1.html)
- [Multipart upload API and permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html#mpuAndPermissions)
- [Protecting data with SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)

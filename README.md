# aws-roles-analyzer
Script that parse CloudTrail logs and analyze IAM roles activity

# Usage
```
Usage of ./aws-roles-analyzer:
  -concurrency int
        Number of concurrent threads (default 20)
  -dirName string
        Path for CloudTrail logs
  -roleName string
        Role name for analyze
  -userName string
        User name for analyze
```

- Download logs from CloudTrail s3 bucket somewhere locally, for example: `export ACCOUNT_ID=123456789012; mkdir /tmp/cloudtrail && aws s3 sync s3://cloudtrail-logs-bucket/AWSLogs/${ACCOUNT_ID}/CloudTrail/us-east-1/2019/12 /tmp/cloudtrail`
- Run script for AWS role or for specified user, for example `go run main.go -dirName /tmp/cloudtrail -roleName webapp`

If you want to build binary, just run `go build -o aws-role-analyzer .`

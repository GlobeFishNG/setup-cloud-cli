# Setup Cloud CLI

There are several profiles as below for our CI/CD kubernetes cluster.
- aws-us (default)
- aws-cn
- aliyun
- aliyun-prod

Below are 2 examples for Aliyun and AWS. After a profile is configured, cloud cli ([aliyun](https://help.aliyun.com/product/29991.html) or [aws](https://aws.amazon.com/cn/cli/)) will have proper permissions to manipulate corresponding cloud resources.

```yaml
jobs:
  build:
    runs-on: ubuntu-18.04
    steps:
      - name: Setup Cloud CLI
        uses: GlobeFishNG/setup-cloud-cli@v1
        with:
          profile: aliyun
      - run: |
          aliyun oss cp oss://example-bucket/example-file.json .
```

```yaml
jobs:
  build:
    runs-on: ubuntu-18.04
    steps:
      - name: Setup Cloud CLI
        uses: GlobeFishNG/setup-cloud-cli@v1
        with:
          profile: aws-cn
      - run: |
          aws s3 cp s3://example-bucket/example-file.json .
```
# Lambda secure access key

Function Lambda in Node.js that query old access key age (> 90 days), deactivate, and delete for security proposal. Some features:

- Function shield, see more [FS](https://www.puresec.io/function-shield-token-form)
- Ignore user setting environment variable `userToIgnore=whateveruser` if you prefer keep a user with old keys (no recommended).
- Ready to deploy with the terraform module [lambda](https://github.com/hendrixroa/terraform-aws-lambda-nodejs-yarn) or whatever you prefer.

## Requirements

- Minimum IAM Permissions.

```hcl
//Lambda deactivate keys
resource "aws_iam_role" "lambda_deactivate_keys_role" {
  name = "lambda_deactivate_keys_execution_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "lambda_deactivate_keys_policy" {
  name = "lambda_deactivate_keys_execution_policy"
  role = aws_iam_role.lambda_deactivate_keys_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListAccountAliases",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey"
      ],
      "Resource": ["*"]
    }
  ]
}
EOF
}
```

# terraform {
#   required_providers {
#     aws = {
#         source = "hashicorp/aws"
#         region = "us-east-2"
#         shared_credentials_file = "/home/leyner/Documentos/jane_weather/.aws/credentials"
#     }
#   }
# }

provider "aws" {
  region = "us-east-2"
  shared_credentials_files = ["/home/leyner/Documentos/jane_weather/.aws/credentials"]
}
data "aws_availability_zones" "available" {}

data "aws_region" "current" {}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket
resource "aws_s3_bucket" "poc_bucket" {
  bucket = "poc-jane-airflow"
  versioning {
        enabled = true
        mfa_delete = false
    }

  tags = {
    Name        = "poc-jane-airflow"
    Environment = "Dev"
    TerraformCreated = "Yes"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse_config" {
  bucket = aws_s3_bucket.poc_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.poc_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}



resource "aws_s3_object" "poc_s3_object" {
  bucket = aws_s3_bucket.poc_bucket.id
  key    = "dags_2/"
  source = "/dev/null"
  server_side_encryption = "AES256"
}


resource "aws_iam_policy" "cloud_watch_full_access_iam_policy" {
  name = "CloudWatchFullAccessIamPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
                "autoscaling:Describe*",
                "cloudwatch:*",
                "logs:*",
                "sns:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "oam:ListSinks"
            ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action   = ["iam:CreateServiceLinkedRole"]
        Effect   = "Allow"
        Resource = "arn:aws:iam::*:role/aws-service-role/events.amazonaws.com/AWSServiceRoleForCloudWatchEvents*"
         Condition = {
          "StringEquals" = {
            "iam:AWSServiceName" = "events.amazonaws.com"
            }
        }
      },
      {
        Action   = ["oam:ListAttachedLinks"]
        Effect   = "Allow"
        Resource = "arn:aws:oam:*:*:sink/*"
      }
    ]
  })
}

resource "aws_iam_policy" "s3_full_access_iam_policy" {
  name = "S3FullAccessIamPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
                "s3:*",
                "s3-object-lambda:*"
            ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "mwaa_executor_iam_policy" {
  name = "MwaaExecutorIamPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["airflow:PublishMetrics"]
        Effect   = "Allow"
        Resource = "arn:aws:airflow:us-east-2:382514615446:environment/AirflowEnvironmentJanePOC"
      },
      {
        Effect   = "Deny"
        Action   = ["s3:ListAllMyBuckets"]
        Resource = [
                "arn:aws:s3:::airflow-poc-jane",
                "arn:aws:s3:::airflow-poc-jane/*"
            ]
      },
      {
        Effect   = "Allow"
        Action   = [
                "s3:GetObject*",
                "s3:GetBucket*",
                "s3:List*"
            ]
        Resource = [
                "arn:aws:s3:::airflow-poc-jane",
                "arn:aws:s3:::airflow-poc-jane/*"
            ]
      },
      {
        Effect   = "Allow"
        Action   = [
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:GetLogRecord",
                "logs:GetLogGroupFields",
                "logs:GetQueryResults"
            ]
        Resource = [
                "arn:aws:logs:us-east-2:382514615446:log-group:airflow-AirflowEnvironmentJanePOC-*"
            ]
      },
      {
        Effect   = "Allow"
        Action   = [
                "logs:DescribeLogGroups"
            ]
        Resource = [
                "*"
            ]
      },
      {
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
                "sqs:ChangeMessageVisibility",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes",
                "sqs:GetQueueUrl",
                "sqs:ReceiveMessage",
                "sqs:SendMessage"
            ]
        Resource = "arn:aws:sqs:us-east-2:*:airflow-celery-*"
      },
      {
        Effect   = "Allow"
        Action   = [
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:GenerateDataKey*",
                "kms:Encrypt"
            ]
        NotResource = "arn:aws:kms:*:382514615446:key/*"
        Condition = {
          "StringEquals" = {
            "kms:ViaService" = ["sqs.us-east-2.amazonaws.com"]
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "role_poc_airflow" {
  name                = "role_poc_airflow"
  assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Sid    = ""
          Principal = {
            AWS = "*",
            Service = ["airflow.amazonaws.com","airflow-env.amazonaws.com"]
          }
        },
      ]
    })
}

resource "aws_iam_role_policy_attachment" "role_poc_policiy_role" {
  for_each = toset([
    aws_iam_policy.mwaa_executor_iam_policy.arn,
    aws_iam_policy.s3_full_access_iam_policy.arn,
    aws_iam_policy.cloud_watch_full_access_iam_policy.arn
    ])
    role = aws_iam_role.role_poc_airflow.name
    policy_arn = each.value
}

resource "aws_vpc" "test" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}

# resource "aws_security_group" "allow_tls" {
#   name        = "allow_tls"
#   description = "Allow TLS inbound traffic"
#   vpc_id      = aws_vpc.test.id

#   ingress {
#     description      = "TLS from VPC"
#     from_port        = 443
#     to_port          = 443
#     protocol         = "tcp"
#     cidr_blocks      = [aws_vpc.test.cidr_block]
#   }

#   egress {
#     from_port        = 0
#     to_port          = 0
#     protocol         = "-1"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   tags = {
#     Name = "allow_tls"
#   }
# }

resource "aws_subnet" "main" {
  count = 2
  vpc_id = aws_vpc.test.id
  cidr_block = "10.0.${count.index + 2}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "Main"
  }
}
##### Security group
resource "aws_security_group" "managed_airflow_sg" {
  name        = "managed_airflow-sg"
  vpc_id      = aws_vpc.test.id

  tags = {
    Name          = "managed-airflow-sg"
  }
}

##### Security group rules
resource "aws_security_group_rule" "allow_all_out_traffic_managed_airflow" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = -1
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.managed_airflow_sg.id
}

resource "aws_security_group_rule" "allow_inbound_internal_traffic" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.managed_airflow_sg.id
}

resource "aws_security_group_rule" "self_reference_sgr" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.managed_airflow_sg.id
}

resource "aws_mwaa_environment" "my_airflow_environment" {
  airflow_configuration_options = {
    "core.default_task_retries" = 16
    "core.parallelism"          = 1
  }
  execution_role_arn = aws_iam_role.role_poc_airflow.arn
  dag_s3_path        = aws_s3_object.poc_s3_object.key
  name               = "MyAirflowEnvironment2"
  airflow_version    = "2.5.1"
  webserver_access_mode = "PUBLIC_ONLY"
  network_configuration {
    security_group_ids = [aws_security_group.managed_airflow_sg.id]
    subnet_ids         = aws_subnet.main[*].id # 2 subnets required for high availability
  }

  source_bucket_arn = aws_s3_bucket.poc_bucket.arn
  logging_configuration {
    dag_processing_logs {
      enabled   = true
      log_level = "DEBUG"
    }

    scheduler_logs {
      enabled   = true
      log_level = "INFO"
    }

    task_logs {
      enabled   = true
      log_level = "INFO"
    }

    webserver_logs {
      enabled   = true
      log_level = "INFO"
    }

    worker_logs {
      enabled   = true
      log_level = "INFO"
    }
}
}

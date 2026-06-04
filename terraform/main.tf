# AegisGRC Sample Infrastructure Module
# This module describes specimen assets audited by our OPA & AI GRC pipeline.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VIOLATION: Unencrypted AWS S3 Bucket hosting active application logs
resource "aws_s3_bucket" "prod_logs" {
  bucket = "aegis-prod-application-logs"
  tags = {
    Environment = "Production"
    Owner       = "SecOps"
  }
}

# VIOLATION: AWS S3 Bucket with public access level
resource "aws_s3_bucket" "public_assets" {
  bucket = "aegis-raw-public-materials"
  
  # Crucial Public configuration
  # Checked by our OPA policy package soc2.cc6
}

resource "aws_s3_bucket_public_access_block" "public_block_assets" {
  bucket = aws_s3_bucket.public_assets.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VIOLATION: Insecure Security Group opening SSH to the public internet
resource "aws_security_group" "ssh_ingress_all" {
  name        = "allow-ssh-from-anywhere"
  description = "Insecure SSH configuration that permits global ingress"

  ingress {
    description      = "SSH Access"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"] # Violation: unrestricted gateway
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}

# VIOLATION: IAM Role with wildcard permissions
resource "aws_iam_role" "privileged_executor" {
  name = "aegis-unrestricted-executor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*" # Violation: broad access authority
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "wildcard_policy" {
  name = "unrestricted-permissions"
  role = aws_iam_role.privileged_executor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*" # Violation: full permissions granted
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# VIOLATION: Customer Managed Key with Automated Rotation Disabled
resource "aws_kms_key" "data_key" {
  description             = "Aegis customer asset encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = false # Violation: lacks regulatory rotation
}

# VIOLATION: AWS CloudTrail deployed without active log file validation
resource "aws_cloudtrail" "audit_trail" {
  name                          = "aegis-activity-monitor"
  s3_bucket_name                = aws_s3_bucket.prod_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = false # Violation: lacks integrity proof
}

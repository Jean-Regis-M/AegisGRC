provider "aws" {
  region = "us-east-1"
}

# ==================== WARNING: INSECURE RESOURCE ENTRIES ====================
# These resources contain deliberate security configuration drifts violating SOC2 boundaries.

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "aegis-sensitive-client-backups"
  acl    = "public-read" # Critical access vulnerability

  tags = {
    Environment = "production"
    Owner       = "finance-team"
  }
}

resource "aws_security_group" "allow_ssh_global" {
  name        = "administrative-ssh-access-sg"
  description = "Allows SSH access on administrative port 22 from anywhere"
  vpc_id      = "vpc-0a1b2c3d4e5f"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Flagged globally open ingress configuration
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted_ebs" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # Violates NIST encryption requirement

  tags = {
    Name = "critical-postgres-database"
  }
}

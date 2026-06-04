package soc2.cc6

# Deny Rules for S3 Public Access Block
deny[msg] {
  bucket := input.aws_s3_bucket[_]
  not has_public_access_block(bucket.id)
  msg := sprintf("SOC2 CC6.3 Violation: Bucket '%s' is missing a restricted public access block.", [bucket.id])
}

# Deny S3 Buckets which explicitly allow public traffic
deny[msg] {
  block := input.aws_s3_bucket_public_access_block[_]
  block.block_public_acls == false
  msg := sprintf("SOC2 CC6.3 Violation: S3 configuration explicitly disables block_public_acls for target '%s'.", [block.bucket])
}

# Deny S3 Buckets with no Server Side Encryption Block
deny[msg] {
  bucket := input.aws_s3_bucket[_]
  not is_encrypted(bucket.id)
  msg := sprintf("SOC2 CC6.1 Violation: S3 Bucket '%s' lacks default KMS or AES-256 server-side encryption.", [bucket.bucket])
}

# Deny AWS Security Group ingress allowing CIDR 0.0.0.0/0 on sensitive administrative port 22 (SSH)
deny[msg] {
  sg := input.aws_security_group[_]
  ingress := sg.ingress[_]
  ingress.from_port <= 22
  ingress.to_port >= 22
  is_globally_open(ingress.cidr_blocks)
  msg := sprintf("SOC2 CC6.4 Violation: Security Group '%s' permits global ingress (0.0.0.0/0) to SSH port 22.", [sg.name])
}

# Deny AWS Security Group ingress allowing CIDR 0.0.0.0/0 on sensitive administrative port 3389 (RDP)
deny[msg] {
  sg := input.aws_security_group[_]
  ingress := sg.ingress[_]
  ingress.from_port <= 3389
  ingress.to_port >= 3389
  is_globally_open(ingress.cidr_blocks)
  msg := sprintf("SOC2 CC6.4 Violation: Security Group '%s' permits global ingress (0.0.0.0/0) to RDP port 3389.", [sg.name])
}

# Deny raw customer managed keys which disable automatic annually rotation
deny[msg] {
  key := input.aws_kms_key[_]
  key.enable_key_rotation == false
  msg := sprintf("SOC2 CC6.2 Violation: Customer Managed KMS Key '%s' has disabled automated yearly key rotation.", [key.id])
}

# Deny IAM roles with wildcards in assume policies
deny[msg] {
  role := input.aws_iam_role[_]
  assume_doc := json_decode(role.assume_role_policy)
  statement := assume_doc.Statement[_]
  statement.Principal.AWS == "*"
  msg := sprintf("SOC2 CC6.1 Violation: IAM Role '%s' allows wildcard '*' credentials to assume its context.", [role.name])
}

# Helper functions
has_public_access_block(bucket_id) {
  block := input.aws_s3_bucket_public_access_block[_]
  block.bucket == bucket_id
  block.block_public_acls == true
  block.block_public_policy == true
}

is_encrypted(bucket_id) {
  conf := input.aws_s3_bucket_server_side_encryption_configuration[_]
  conf.bucket == bucket_id
}

is_globally_open(cidr_blocks) {
  cidr := cidr_blocks[_]
  cidr == "0.0.0.0/0"
}

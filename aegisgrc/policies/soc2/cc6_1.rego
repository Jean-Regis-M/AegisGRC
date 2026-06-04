package soc2.cc6

# Default values
default allow = false
default allow_ssh = false
default allow_s3_unencrypted = false

# Allow is true if there are zero flagged violations
allow {
    count(violation) == 0
}

# Flagged violations collection
violation[msg] {
    some resource
    is_unencrypted_s3_bucket(resource)
    msg := sprintf("SOC2 CC6.3 Violation: S3 bucket '%s' does not enforce AES256 server-side encryption.", [resource.name])
}

violation[msg] {
    some resource
    is_global_ingress_port_22(resource)
    msg := sprintf("SOC2 CC6.4 Violation: Security Group '%s' allows globally open ingress (0.0.0.0/0) to port 22.", [resource.name])
}

violation[msg] {
    some resource
    is_unencrypted_ebs_volume(resource)
    msg := sprintf("NIST CSF PR.DS-01 Violation: EBS Volume '%s' is not encrypted.", [resource.name])
}

# Helper check for S3 buckets
is_unencrypted_s3_bucket(resource) {
    resource.type == "aws_s3_bucket"
    not resource.attributes.server_side_encryption_configuration
}

# Helper check for Security Groups restricting global SSH boundary rules
is_global_ingress_port_22(resource) {
    resource.type == "aws_security_group"
    some ingress
    ingress := resource.attributes.ingress[_]
    ingress.from_port <= 22
    ingress.to_port >= 22
    ingress.cidr_blocks[_] == "0.0.0.0/0"
}

# Helper check for EBS volumes
is_unencrypted_ebs_volume(resource) {
    resource.type == "aws_ebs_volume"
    not resource.attributes.encrypted
}

###############################################################################
# Network
#
# One security group, deliberately wide open on the two remote-administration
# ports. Should produce FAIL for 3.1.12.
#
# Cost: a security group is free. It is attached to nothing -- no EC2 instance
# is created -- but the scanner reads security group configuration, not running
# instances, so an unattached group is enough to exercise the check.
###############################################################################

# Every AWS account comes with a default VPC per region, so this uses that
# rather than creating one.
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "open_ssh" {
  name        = "${local.name_prefix}-open-ssh"
  description = "Deliberately non-compliant for scanner testing."
  vpc_id      = data.aws_vpc.default.id

  # SSH open to the entire internet.
  ingress {
    description = "SSH from anywhere - deliberately non-compliant"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP open to the entire internet.
  ingress {
    description = "RDP from anywhere - deliberately non-compliant"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress is not what 3.1.12 is about; this is the AWS default and is here only
  # so Terraform does not manage an empty egress set.
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-open-ssh"
  }
}

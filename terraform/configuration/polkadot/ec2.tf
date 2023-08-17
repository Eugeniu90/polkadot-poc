data "template_file" "target_role" {
  template = file("${path.cwd}/iam_policies/ec2_role.json")
}


resource "aws_iam_instance_profile" "target_profile" {
  name          = "target-instance-poc"
  role          = aws_iam_role.target_ec2_role.name
}

resource "aws_iam_role" "target_ec2_role" {
  name               = "target-ec2-role"
  path               = "/"
  assume_role_policy = data.template_file.target_role.rendered
}

resource "aws_iam_role_policy_attachment" "target_attachment" {
  role       = aws_iam_role.target_ec2_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_security_group" "sg_target" {
  name        = "allow_sg_target"
  description = "Allow Target inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}


resource "aws_instance" "target" {
  count                       = var.servers_count
  ami                         = var.ubuntu_ami
  subnet_id                   = module.vpc.private_subnets[0]
  user_data                   = local.ec2_userdata
  instance_type               = "t2.micro"
  vpc_security_group_ids      = [aws_security_group.sg_target.id]
  disable_api_termination     = false
  key_name                    = "${local.aws_account}-${var.aws_region}-${terraform.workspace}"
  iam_instance_profile        = aws_iam_instance_profile.target_profile.name

  dynamic "root_block_device" {
    for_each = var.root_block_device_bastion
    content {
      volume_size              = lookup(root_block_device.value, "volume_size", null)
      volume_type              = lookup(root_block_device.value, "volume_type", null)
    }
  }
  associate_public_ip_address = false
  tags = merge(
  {
    Name = "${terraform.workspace}-poc-${count.index + 1}"
  },
  local.tags,
  )
}

resource "aws_route53_zone" "private_zone" {
  name     =  "poc.cloud"
  tags     = local.tags
  vpc {
    vpc_id = module.vpc.vpc_id
  }
  lifecycle {
    ignore_changes = [vpc]
  }
}
# Mapping IP's into Route53 #
resource "aws_route53_record" "servers_ssh" {
  count   = var.servers_count
  zone_id = aws_route53_zone.private_zone.zone_id
  name    = "${terraform.workspace}-poc-${count.index + 1}"
  type    = "A"
  records = [element(aws_instance.target.*.private_ip, count.index)]
  ttl     = "3600"
}



data "template_file" "bastion_role" {
  template = file("${path.cwd}/iam_policies/ec2_role.json")
}

data "template_file" "secrets_access_policy" {
  template = file("${path.cwd}/iam_policies/secret_manager_policy.json")
  vars = {
    aws_region         = var.aws_region
    aws_account_number = local.aws_account
  }
}

resource "aws_iam_instance_profile" "bastion_profile" {
  name          = "bastion-machine-profile_poc"
  role          = aws_iam_role.bastion_role.name
}

resource "aws_iam_role" "bastion_role" {
  name               = "bastion-machine-role-poc"
  path               = "/"
  assume_role_policy = data.template_file.bastion_role.rendered
}

resource "aws_iam_policy" "policy" {
  name        = "secrets_manager_access_poc"
  description = "Policy to access secrets manager"
  policy      = data.template_file.secrets_access_policy.rendered
}

resource "aws_iam_role_policy_attachment" "attachment" {
  role       = aws_iam_role.bastion_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_security_group" "sg_bastion"{
  name          = "bastion-sg"
  vpc_id        = module.vpc.vpc_id
  description   = "This SG will be responsible for Bastion network on instance level"


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }


  tags = merge(
  {
    "Name" = "bastion_security_group"
  },
  local.tags,
  )
}


resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazon-linux.id
  subnet_id                   = module.vpc.public_subnets[0]
  instance_type               = "t2.micro"
  vpc_security_group_ids      = [aws_security_group.sg_bastion.id]
  user_data                   = local.bastion_userdata
  disable_api_termination     = false
  key_name                    = aws_key_pair.generated_key.key_name
  iam_instance_profile         = aws_iam_instance_profile.bastion_profile.name

  tags = merge(
  {
    "Name" = "poc-bastion"
  },
  local.tags,
  )
}


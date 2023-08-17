locals {
  aws_account                = data.aws_caller_identity.current.account_id
  ansible_version            = "2.11.12"
  availability_zones         = var.availability_zones_map[var.aws_region]
  tags = merge(
  var.common_tags,
  {
    Name        = "poc"
    Environment = terraform.workspace
    Application = "MVP"
    TagVersion  = "1"
  }
  )
  bastion_userdata = <<USERDATA
    #!/bin/bash
    set -o xtrace
    printf "[`date +'%d-%m-%y %H:%M:%S'`] - Install all packages related to Bastion machine \n" | tee -a /tmp/user-data.log
    aws secretsmanager get-secret-value --secret-id /bastion/${terraform.workspace}-private-key --query 'SecretString' --output text --region ${var.aws_region}  > ~/.ssh/${local.aws_account}-${var.aws_region}-${terraform.workspace}.pem
    printf "\n\n[`date +'%d-%m-%y %H:%M:%S'`] - Installing Ansible, version ${local.ansible_version}!" | tee -a /tmp/user-data.log
    python3 -m pip install --user ansible
    python3 -m pip install --user ansible-core==${local.ansible_version}
    printf "\n\n[`date +'%d-%m-%y %H:%M:%S'`] - END User data!" | tee -a /tmp/user-data.log
    USERDATA
}
locals {
  ec2_userdata = <<USERDATA
    #!/bin/bash
    set -o xtrace
    printf "[`date +'%d-%m-%y %H:%M:%S'`] - Install all packages related to Bastion machine \n" | tee -a /tmp/user-data.log
    aws secretsmanager get-secret-value --secret-id /bastion/${terraform.workspace}-private-key --query 'SecretString' --output text --region ${var.aws_region}  > ~/.ssh/${local.aws_account}-${var.aws_region}-${terraform.workspace}.pem
    printf "\n\n[`date +'%d-%m-%y %H:%M:%S'`] - END User data!" | tee -a /tmp/user-data.log
    USERDATA
}

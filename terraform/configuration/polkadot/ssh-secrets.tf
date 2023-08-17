## Generating SSH key locally ##

resource "tls_private_key" "ssh-generator" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name   = "${local.aws_account}-${var.aws_region}-${terraform.workspace}"
  public_key = tls_private_key.ssh-generator.public_key_openssh
}

resource "local_file" "pem_file" {
  filename                              = pathexpand("~/.ssh/${local.aws_account}-${var.aws_region}-${terraform.workspace}.pem")
  file_permission                       = "600"
  sensitive_content                    = tls_private_key.ssh-generator.private_key_pem
}

## Once we have our key generate locally, and injected in our bastion , therefore we can create secret based on this key

resource "aws_secretsmanager_secret" "bastion_secret_key" {
  name        = "/bastion/${terraform.workspace}-private-key"
  description = "PrivateKey to enter Environment: ${terraform.workspace} for ${local.aws_account} account number, within region:${var.aws_region}"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "bastion_secret_key_version" {
  secret_id     = aws_secretsmanager_secret.bastion_secret_key.id
  secret_string = tls_private_key.ssh-generator.private_key_pem
}

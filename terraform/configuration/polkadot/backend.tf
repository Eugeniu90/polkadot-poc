terraform {
  backend "s3" {
    bucket       = "poc-bucket"
    key          = "mvp-test"
    region       = "eu-west-1"
    session_name = "dot-poc"
    profile       = "poc-profile"
  }
}

resource "aws_vpc" "my_vpc1" {
  cidr_block = "10.0.0.0/16"
  tags = {
    name = "my_vpc1"
  }
}
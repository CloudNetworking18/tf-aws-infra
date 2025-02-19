resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.my_vpc1.id # Ensure consistency with your VPC resource

  tags = {
    Name = "MainIGW"
  }
}

# Public Subnets
resource "aws_subnet" "public_subnets" {
  count = length(var.public_subnet_cidrs)

  vpc_id     = aws_vpc.my_vpc1.id
  cidr_block = var.public_subnet_cidrs[count.index]

    map_public_ip_on_launch = true

  tags = {
    Name = "PublicSubnet-${count.index + 1}"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnets" {
  count = length(var.private_subnet_cidrs)

  vpc_id     = aws_vpc.my_vpc1.id
  cidr_block = var.private_subnet_cidrs[count.index]


  tags = {
    Name = "PrivateSubnet-${count.index + 1}"
  }
}
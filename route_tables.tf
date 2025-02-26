# Public Route Table
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.my_vpc1.id

  tags = {
    Name = "PublicRouteTable"
  }
}

# Private Route Table
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.my_vpc1.id

  tags = {
    Name = "PrivateRouteTable"
  }
}

# Create a route in the public route table to route internet traffic via the IGW
resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main_igw.id

  depends_on = [aws_internet_gateway.main_igw] # Ensures IGW is created first
}

# Associate all public subnets with the public route table
resource "aws_route_table_association" "public_subnet_associations" {
  count = length(aws_subnet.public_subnets)

  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

# Associate all private subnets with the private route table
resource "aws_route_table_association" "private_subnet_associations" {
  count = length(aws_subnet.private_subnets)

  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}
# Private Route via NAT Gateway
resource "aws_route" "private_nat_gateway_route" {
  count = length(aws_subnet.private_subnets) > 0 ? 1 : 0

  route_table_id         = aws_route_table.private_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gw.id

  depends_on = [aws_nat_gateway.nat_gw]
}


resource "aws_eip" "nat_eip" {
  depends_on = [aws_internet_gateway.main_igw]
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnets[0].id # Attach NAT to first public subnet

  tags = {
    Name = "MainNATGateway"
  }
}

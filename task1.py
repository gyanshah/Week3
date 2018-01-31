class ip_address():
	def __init__(self,oct_a,oct_b,oct_c,oct_d,subnet):
		self.a=oct_a
		self.b=oct_b
		self.c=oct_c
		self.d=oct_d
		self.netmask=subnet
	def __str__(self):
		return (str(self.a)+"."+str(self.b)+"."+str(self.c)+"."+str(self.d)+"/"+str(self.netmask))


ipv4=ip_address(192,168,0,1,24)
print(ipv4)

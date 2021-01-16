# -*- coding: utf-8 -*-
"""
@author: iceland
"""

import bit
import time
import binascii
import random
import sys
import os
import hashlib
from eth_hash.auto import keccak
# from cashaddress import convert
from bitcoinlib.encoding import addr_bech32_to_pubkeyhash, change_base

from fastecdsa import curve
from fastecdsa.point import Point

from multiprocessing import Event, Process, Queue, Value, cpu_count

#==============================================================================
eth_address_filename = 'eth_address.txt'                # 0x type address with lowercase
all_coins_combined_hash160_filename = 'h160.txt'        # all the coins hash160 file

eth_address_list = [line.split()[0] for line in open(eth_address_filename,'r')]
h160_list = [line.split()[0] for line in open(all_coins_combined_hash160_filename,'r')]
eth_address_list = set(eth_address_list)
h160_list = set(h160_list)
#==============================================================================

################# Initialization Phase #########################
# print("\n-----------------------Starting------------------------------------\
#      \nThis program can check 12 Types of Address.\
#      \n[Legacy Compressed BTC, Legacy UnCompressed BTC, Segwit BTC, Bech32 BTC, \
#      \n Legacy LTC, Zcash t1, Zcash t3, DASH, DOGE, ETH, BCH, XRP]")

ripple_alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
################ Used Functions #############################
def HASH160(pubk_bytes):
    return hashlib.new('ripemd160', hashlib.sha256(pubk_bytes).digest() ).digest()  # 6% faster than bit.crypto

def bech32_to_hash160(address):
    return change_base(addr_bech32_to_pubkeyhash(address), 256, 16)

def ripple_address_to_hash160(address):
    n = 0
    for char in address:
        n = n * len(ripple_alphabet) + ripple_alphabet.index(char)
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h)
    return bytes.fromhex(s)[:-4].hex()
            
def ETH_Address(un_pubk_bytes):
    return '0x' + keccak(un_pubk_bytes[1:])[-20:].hex()

#==============================================================================
def hunt_allcoins_together(cores='all'):  # pragma: no cover

    available_cores = cpu_count()

    if cores == 'all':
        cores = available_cores
    elif 0 < int(cores) <= available_cores:
        cores = int(cores)
    else:
        cores = 1

    counter = Value('i')
    match = Event()
    queue = Queue()
    

    workers = []
    for r in range(cores):
        p = Process(target=generate_key_address_pairs, args=(counter, match, queue, r))
        workers.append(p)
        p.start()

    for worker in workers:
        worker.join()

    keys_generated = 0
    while True:
        time.sleep(1)
        current = counter.value
        if current == keys_generated:
            if current == 0:
                continue
            break
        keys_generated = current
        s = 'Keys generated: {}\r'.format(keys_generated)

        sys.stdout.write(s)
        sys.stdout.flush()

    private_key, cpub, upub, eth_address = queue.get()
    print('\n\nPrivate Key(hex): ', hex(private_key))
    print('PrivateKey(wif): {}'.format(bit.format.bytes_to_wif(binascii.unhexlify((hex(private_key)[2:]).zfill(64)))))
    print('Public Key(Compressed): ', cpub.hex())
    print('Public Key(UnCompressed): ', upub.hex())
    print('BTC Address(Compressed): ', bit.format.public_key_to_address(cpub))
    print('BTC Address(UnCompressed): ', bit.format.public_key_to_address(upub))
    print('ETH Address: ', eth_address)
    print('\nCongratulations for your achievement !!. \nAlso check yourself other altcoin address for this Private Key.')

#==============================================================================
def generate_key_address_pairs(counter, match, queue, r):  # pragma: no cover

    k = 0
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    key_int = random.randint(1,N)
    G = curve.secp256k1.G
    x1, y1 = bit.format.public_key_to_coords(bit.Key.from_int(key_int).public_key)
    P = Point(x1,y1, curve=curve.secp256k1)
    print('Starting thread:', r, 'base: ',hex(key_int))

    while True:
        if match.is_set():
            return

        with counter.get_lock():
            counter.value += 1

        
        current_pvk = key_int + k
        if k > 0:
            P += G
        
        cpub = bit.format.point_to_public_key(P, compressed=True)
        upub = bit.format.point_to_public_key(P, compressed=False)
        crmd = HASH160(cpub)
        urmd = HASH160(upub)
        segwit_rmd = HASH160(b'\x00\x14' + crmd)
        eth_addr = '0x' + keccak(upub[1:])[-20:].hex()

        if (k+1)%100000 == 0: print('checked ',k+1,' keys by Thread:',r, 'Current RipeMD:',crmd.hex())
        if crmd.hex() in h160_list or urmd.hex() in h160_list or segwit_rmd.hex() in h160_list or eth_addr in eth_address_list:
            match.set()
            queue.put_nowait((current_pvk, cpub, upub, eth_addr))
            return
        
        k += 1



#==============================================================================


if __name__ == '__main__':
    hunt_allcoins_together(cores=4)     # change this number to how much cpu you want to use
    
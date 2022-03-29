from bitcoinaddress import Wallet
from bit import Key
import hashlib
from cryptography.fernet import Fernet


wallet = Wallet('1CZTRXQ62q6tWppWxYshxd9MAQSpSZdqSR')
print(f'Public Address bc1 P2WPKH: bc1qulxze7f2mjvz8zxa86lmqn7ugzed6en9mtw3g6')
my_key = Key(wallet.testnet)
print(f'dsds - {wallet.testnet}')
print(my_key)
print(my_key.get_balance('usd'))
'''
print(my_key.get_balance('eur'))
print(my_key.get_balance('btc'))
print(my_key.balance)
print(my_key.address)'''
f = Fernet(b'8m8_UPHzMdA4w1SNC1Pn7Lsya7i8tnbE0gL9ezW79jY=')
encrypted_message = f.encrypt('211e8b5e3c19bac768be28b10a6fbe973a7422d9b8537ea25a2eabaa94a2d6ee'.encode())
print(encrypted_message.decode())
print(f.decrypt(encrypted_message).decode())
# b'gAAAAABiJ4O5OveCtx0OPMndmkk7AMOTe5VG9YcnkdcsXTQl5SvamNUSsK-Rqgxke_zsylcheLgkorkZKMCGk9rVRBcyB_qNxQ=='
# b'gAAAAABiJ4RD3JKcRV8o9yCJUZq3cQf7BaRD1o2vDwarV4ACpid9Jt2xsFJBFqQdC51iwgSlQyxf3_OWxNeq6jsQdu7dV2D3NA=='
# b'gAAAAABiJ4RKBJ0_xK5fp3JcvaSFBtCARKUich7tmrl0UNinEyJWhX819mqEzUQV9BkNuRrcUabqe3uOCpjXkdoLzWSkhDcUqg=='
print('------------------------')
'''print(b'gAAAAABiJ4RKBJ0_xK5fp3JcvaSFBtCARKUich7tmrl0UNinEyJWhX819mqEzUQV9BkNuRrcUabqe3uOCpjXkdoLzWSkhDcUqg==')
print((b'gAAAAABiJ4RKBJ0_xK5fp3JcvaSFBtCARKUich7tmrl0UNinEyJWhX819mqEzUQV9BkNuRrcUabqe3uOCpjXkdoLzWSkhDcUqg==').decode())
print(('gAAAAABiJ4RKBJ0_xK5fp3JcvaSFBtCARKUich7tmrl0UNinEyJWhX819mqEzUQV9BkNuRrcUabqe3uOCpjXkdoLzWSkhDcUqg==').encode())'''

# c3fef021f4544a80442cd2b994abe326d217a5c59c14b3e53d62f886fc4debb7
# 211e8b5e3c19bac768be28b10a6fbe973a7422d9b8537ea25a2eabaa94a2d6ee
# 8b3a736746c3b3da0f23380bc7744734cd7a9c605137e261652a89c35e5e11e7

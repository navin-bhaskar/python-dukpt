"""                                 Shree Krishnaya Namaha 
This is an implementation of DUKPT algorithm in Python.
The reference for this implementation is the excellent write up found here:
https://www.parthenonsoftware.com/blog/how-to-decrypt-magnetic-stripe-scanner-data-with-dukpt/
This module converts the steps mentioned in the above link to Python code.
"""
from Crypto.Cipher import DES3, DES
from Crypto.Random import get_random_bytes
from bitstring import BitArray

RESET_COUNTER_MASK = BitArray(hex="FFFFFFFFFFFFFFE00000")
COUNTER_MASK = BitArray(hex="000000000000001FFFFF")
PIN_MASK = BitArray(hex="00000000000000FF00000000000000FF")
C = BitArray(hex='0xC0C0C0C000000000C0C0C0C000000000')
DEK_MASK = BitArray(hex="0000000000FF00000000000000FF0000")


class Dukpt:
    """This class provides methods for generating the Future keys as well 
    as IPEK keys after setting the BDK and KSN """
    def __init__(self):
        self.bdk = None
        self.ipek = None
        self.ksn = None

    def set_bdk(self, bdk):
        """Sets the Base Derivation Key for the current DUKPT calculator instance"""
        if len(bdk) != 32:
            raise ValueError("The BDK should be 16 bytes wide")
        self.bdk = BitArray(hex=bdk)

    def set_ksn(self, ksn):
        """Sets the KSN (Key serial number) for the DUKPT calculator"""
        if len(ksn) != 20:
            raise ValueError("KSN has to be a 10 byte value")
        self.ksn = BitArray(hex=ksn)

    @staticmethod
    def get_complete_bdk(bdk):
        return bdk + bdk.bytes[0:8]

    def compute_ipek(self):
        """Computes the initial pin encryption key"""
        cleared_ksn = self.ksn & RESET_COUNTER_MASK
        ksn = cleared_ksn.bytes[0:8]

        bdk = Dukpt.get_complete_bdk(self.bdk)
        cipher = DES3.new(bdk.bytes, DES3.MODE_ECB)
        left_register = cipher.encrypt(ksn)

        c_masked_bdk = self.bdk ^ C
        bdk = Dukpt.get_complete_bdk(c_masked_bdk)
        cipher = DES3.new(bdk.bytes, DES3.MODE_ECB)
        right_register = cipher.encrypt(ksn)
        self.ipek = BitArray(bytes=left_register + right_register)
        return self.ipek



def main():
    dukpt = Dukpt()
    bdk = "0123456789ABCDEFFEDCBA9876543210"
    ksn = "FFFF9876543210E00008"
    dukpt.set_bdk(bdk)
    dukpt.set_ksn(ksn)
    ipek = dukpt.compute_ipek()
    print (str(ipek))

main()




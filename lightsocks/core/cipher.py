from Crypto.Cipher import AES


class Cipher:
    """
        Cipher class is for the encipherment of data flow.
        One octet is in the range 0 ~ 255 (2 ^ 8).
        To do encryption, it just maps one byte to another one.
        Example:
            encodePassword
            | index | 0x00 | 0x01 | 0x02 | 0x03 | ... | 0xff | || 0x02ff0a04
            | ----- | ---- | ---- | ---- | ---- | --- | ---- | ||
            | value | 0x01 | 0x02 | 0x03 | 0x04 | ... | 0x00 | \/ 0x03000b05
            decodePassword
            | index | 0x00 | 0x01 | 0x02 | 0x03 | 0x04 | ... | || 0x03000b05
            | ----- | ---- | ---- | ---- | ---- | ---- | --- | ||
            | value | 0xff | 0x00 | 0x01 | 0x02 | 0x03 | ... | \/ 0x02ff0a04
        It just shifts one step to make a simply encryption, encode and decode.
    """

    def __init__(self, encodePassword: bytearray) -> None:
        self.encodePassword = encodePassword.copy()
        self.e_aes = AES.new(encodePassword, AES.MODE_EAX)
        self.d_aes = AES.new(encodePassword, AES.MODE_EAX, self.e_aes.nonce)

    def encode(self, bs: bytearray):
        bs = bytearray(self.e_aes.encrypt(bs))

    def decode(self, bs: bytearray):
        # data = self.aes.decrypt(bs)
        bs = bytearray(self.d_aes.decrypt(bs))
        # bs = bytearray(self.aes.decrypt(bs))

    @staticmethod
    def pad(text):
        length = 16 - (len(text) % 16)
        text += bytes([length]) * length
        return text

    # @classmethod
    # def NewCipher(cls, encodePassword: bytearray):
    #     decodePassword = encodePassword.copy()
    #     for i, v in enumerate(encodePassword):
    #         decodePassword[v] = i
    #     return cls(encodePassword, decodePassword)

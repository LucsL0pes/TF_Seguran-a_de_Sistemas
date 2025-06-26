from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

# Dados recebidos
RSACipheredMsg_hex = "52EE766F15A54F351478A08ECFBF75763D07FE9314A743177CB3385DF11BF85CA4972EA751D8683B5D539A496BBE449D6B3AE81E4BAF8B31FB03D20BE24932AC84FFD9C45BCFBFC4204E62DEF3B2B857DAF7E880AE5D4AECE461D8B457BF05AF2163E1A46939284359FFE58DF1A2C3BCB8336EBB4B469BF87B84C5592F31BA0D5FB8C9E4F8057A34FDD918C45016A1DB83F9CC65700BC7EAFC23ED8E75E67E7FFE1C27AEAF224188D9539EE5188A56511F38AF542012C15D92F846C1C46FECA7209F08579FE2905C65835DD44A1B81F0E8BEF07AEB8CE4DC84B852DA9DDA40821E9070E222A2B679B43A1852B8C08D405CBCD9D5E075300AC8C45756FFCC76C2"
AESCipheredMsg_hex = "65F336967630FA8CE5E4A5226CD74DB59E74F24F11EDA0CD5281E566043E9E70"

Da_hex = "0x50333b4787fbec0548e812387007a41d0a370c25c1f5901a98502c942d7d7da03b541d3ab5f1d0aeb48edf6a8d54804dccb7950070f84d75188af57777e2976b962ed794fca3aa471a4671cce570935f9ea423dc79020c640de2dc11740d0aeaf3afe07fdb72ff983524eb7eb48276a0771cdad97f0d1e27e668b8d31e0e1db037657886ecb74727d3e37ce05a411b39c786d1065cd6bd62ac88070fbabd312ac21d26bfbf362cf68b0df8834b304e7be8fdff4407d2683ba87404664b71e647e43e2a71c82af74a8a43f7d39c6be7a6c98227089725a16c234574e5a189342ada304495865f995f87fa1ef16f815eba0723bb6c5d741b35721dd8125c6f34d1"  # Mantenha igual ao anterior
Na_hex = "0x68d038402d1adb7d7af5ec63a3f7b5d15790fd1c0d6ed07a7b281feb0f470d46d39014bd9d96b28b6c741123be6d397a87b53b19c1294e81afec62fceb1b070293746b0a63c915ceadab63e80b22eacccaba6a9b05c95f9f43073154c4dc7816fc5aaa649e7e721ce881ea42d3093da0890b8d6a47c246cfb9985ac413b628fd57eb061e00c510e3d582666e1183b8af156b5dd2b3ebe119ce12e7c3b4dbf9cf640cc95e5a98b76c2e182d5811c793c367ecef0c0975026ae9ed3adbe0fed0bf7a783c71930dbe63d8cba0f1b2413559bc6bce652f2a48f1ced0ce405b32bbf7d1d21523ac7c415055a2cafb4cca0fe683fb35816b2be161e98770f0fcc4dd71"  # Mantenha igual ao anterior
Sa_hex = "03e07ea16a1e952588495d2db2482718"

# Conversão
RSACiphered_int = int(RSACipheredMsg_hex, 16)
Da = int(Da_hex, 16)
Na = int(Na_hex, 16)
Sa = bytes.fromhex(Sa_hex)

# RSA
RSADecrypted = long_to_bytes(pow(RSACiphered_int, Da, Na))
print("Mensagem decifrada com RSA:")
print(RSADecrypted.hex())

# AES
ciphered = bytes.fromhex(AESCipheredMsg_hex)
iv = ciphered[:16]
ciphertext = ciphered[16:]

try:
    cipher = AES.new(Sa, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    print("\nMensagem decifrada com AES:")
    print(plaintext.hex())

    print("\n=== RESULTADO FINAL ===")
    if plaintext == RSADecrypted:
        print("Comunicação validada com sucesso!")
        print(RSADecrypted)
    else:
        print("As mensagens são diferentes. Algo deu errado.")
except Exception as e:
    print(f"\nErro ao decifrar AES: {e}")

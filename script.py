from Crypto.Util.number import getPrime, inverse, bytes_to_long
from Crypto.Random import get_random_bytes



# 1. Chave pública do professor
Ep_hex = "EEC2681EDAFB5FBF4249302A43764824B28F1D007C5D75955ECCD5CF630243F9"
Np_hex = "EB7ED592C4C4F9C5CF0D8DFA8921FA91DA89FAB0D31E74CE0451C54998B5CD6BED2F02D7BC5B5F1CF65023A4BD9C2A7B550BC89B8056B38F0AEC9302FDAFEDECFC3742D7D849DC2075CABE17806F1E03AA0E2E71439EDA9B69A703275C835AF82087085DC2325CE792B591EDE2DFD365096AFE9C3B607351C9A71984030638264BE2CD494F8E83B0112A875F31F73BF7CFF93BC17AB8023181872256AD4868AEE9516DCF058879B01CA893775DA16CDF268FC345DC682F7221F75D0E01C86C7DD67E47954596FC5D3F2CACA5546A737ECBFA09F36B5D328CBD6326980B10203979B7190457426F534D1BB6E4696BEC33D21DB581C3035F9F26B05C051A574EC9"


# Conversão para inteiros
Ep = int(Ep_hex, 16)
Np = int(Np_hex, 16)

# 2. Geração das chaves
Pa = getPrime(1024)
Qa = getPrime(1024)
Na = Pa * Qa
phi = (Pa - 1) * (Qa - 1)
Ea = 65537

while True:
    try:
        Da = inverse(Ea, phi)
        break
    except ValueError:
        print("Inverso não encontrado, gerando novos primos...")
        Pa = getPrime(1024)
        Qa = getPrime(1024)
        Na = Pa * Qa
        phi = (Pa - 1) * (Qa - 1)

# Validação da chave privada
if (Ea * Da) % phi != 1:
    print("Erro crítico: Ea * Da mod φ ≠ 1")
    exit()

print("Chaves RSA (Ea, Da) geradas com sucesso.")

# 3. Geração da chave AES (Sa) e cifragem com chave do professor (X)
while True:
    Sa = get_random_bytes(16)
    Sa_int = bytes_to_long(Sa)
    X = pow(Sa_int, Ep, Np)
    if X < Na:
        break
    print("X >= Na, gerando nova chave AES...")

print("Chave AES (Sa) cifrada com sucesso (X gerado).")

# 4. Assinatura digital de X com chave privada
SIGx = pow(X, Da, Na)
print("Assinatura digital (SIGx) gerada com sucesso.")

# 5. Verificação local da assinatura
X_check = pow(SIGx, Ea, Na)
if X_check == X:
    print("\nVerificação da assinatura interna OK. Pronto para envio!")
else:
    print("\nA verificação da assinatura falhou. Revise antes de enviar.")
    exit()

# 6. Impressão dos dados no formato pedido
print("=== DADOS PARA ENVIO ===\n")
print("PKa:")
print("{")
print(f"Ea = {Ea:x}")
print(f"Na = {Na:x}")
print("}")
print("\nX (AES cifrada):")
print(f"{X:x}")
print("\nSIGx (assinatura digital de X):")
print(f"{SIGx:x}")


# Salva dados privados
with open("dados_privados.txt", "w", encoding="utf-8") as f:
    f.write("=== DADOS ===\n\n")
    f.write(f"Pa = {hex(Pa)}\n")
    f.write(f"Qa = {hex(Qa)}\n")
    f.write(f"Na = {hex(Na)}\n")
    f.write(f"phi(Na) = {hex(phi)}\n")
    f.write(f"Ea = {hex(Ea)}\n")
    f.write(f"Da = {hex(Da)}\n")
    f.write(f"\nSa (chave AES em hex) = {Sa.hex()}\n")
    f.write(f"Sa (como inteiro) = {Sa_int}\n")
    f.write(f"\nX = {hex(X)}\n")
    f.write(f"SIGx = {hex(SIGx)}\n")
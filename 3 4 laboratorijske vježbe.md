# 3./4. laboratorijske vježbe

December 7, 2021 

### **Digital signatures using public-key cryptography**

U ovom izazovu ćemo odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Odgovarajući javni ključ dostupan je na serveru.

Slike i odgovarajući digitalni potpisi nalaze se u direktoriju `juric-marino\public_key_challenge`. Kao i u prethodnoj vježbi, za rješavanje ove koristimo Python biblioteku `[cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)` - konkretnije **RSA kriptosustav**.

- učitavanje javnog ključa iz datoteke

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
 
def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    return PUBLIC_KEY
 
 
print(load_public_key())
```

```bash
(marino_juric) C:\Users\A507\marino_juric\marino_juric>.\digital_signature.py
<cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object at 0x0000019251530CD0>
```

- provjera ispravnosti digitalnog potpisa

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
 
 
with open("image_2.png", "rb") as file:
    image = file.read()
 
 
with open("image_2.sig", "rb") as file:
    signature = file.read()
 
is_authentic = verify_signature_rsa(signature, image)
 
print(is_authentic)
```

```bash
(marino_juric) C:\Users\A507\marino_juric\marino_juric>.\digital_signature.py
True
 
(marino_juric) C:\Users\A507\marino_juric\marino_juric>.\digital_signature.py
False
 
(marino_juric) C:\Users\A507\marino_juric\marino_juric>.\digital_signature.py
False
```

- u terminalu dobivamo odgovor True ili False ovisno o tome je li se određena slika podudara sa digitalno potpisanom slikom

## Lab 4.

### **Password-hashing (iterative hashing, salt, memory-hard functions)**

Zaporke/lozinke su najzastupljeniji način autentikacije korisnika. U okviru vježbe upoznati ćemo se pobliže sa osnovnim konceptima relevantnim za sigurnu pohranu lozinki. Usporediti ćemo klasične (*brze*) kriptografske *hash* funkcije sa specijaliziranim (*sporim* i *memorijski zahtjevnim*) kriptografskim funkcijama za sigurnu pohranu zaporki i izvođenje enkripcijskih ključeva (*key derivation function (KDF)*).

Okviran popis aktivnosti; detaljne upute ćemo dati u realnom vremenu:

- Usporedba *brzih* i *sporih* kriptografskih *hash* funkcija.
- Razumijevanje suštine pojmova *spore/brze* funkcije.
- Demonstracija *memory-hard* funkcija.

```bash
(marino_juric) C:\Users\A507\marino_juric\marino_juric>.\password_hashing.py
```

- pokušavamo pokrenuti program ali za njega je potrebno instalirati dodatne pakete

```bash
(marino_juric) C:\Users\A507\marino_juric\marino_juric>pip install prettytable
Collecting prettytable
  Using cached prettytable-2.4.0-py3-none-any.whl (24 kB)
Collecting wcwidth
  Using cached wcwidth-0.2.5-py2.py3-none-any.whl (30 kB)
Installing collected packages: wcwidth, prettytable
Successfully installed prettytable-2.4.0 wcwidth-0.2.5
(marino_juric) C:\Users\A507\marino_juric\marino_juric>pip install passlib
Collecting passlib
  Using cached passlib-1.7.4-py2.py3-none-any.whl (525 kB)
Installing collected packages: passlib
Successfully installed passlib-1.7.4
```

- u terminalu pokrećemo slijedeći kod:

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2
 
 
def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
 
    return wrapper
 
 
@time_it
def aes(**kwargs):
    key = bytes(
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
        ]
    )
 
    plaintext = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )
 
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()
 
 
@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()
 
 
@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()
 
 
@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()
 
 
@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)
 
 
@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0" * 22
    rounds = kwargs.get("rounds", 12)  # time_cost
    memory_cost = kwargs.get("memory_cost", 2 ** 10)  # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt, rounds=rounds, memory_cost=memory_cost, parallelism=parallelism
    ).hash(input)
 
 
@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)
 
 
@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)
 
 
@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2 ** 14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    hash = kdf.derive(input)
    return {"hash": hash, "salt": salt}
 
 
if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"
 
    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []
 
    TESTS = [
        {"name": "AES", "service": lambda: aes(measure=True)},
        {"name": "HASH_MD5", "service": lambda: sha512(password, measure=True)},
        {"name": "HASH_SHA256", "service": lambda: sha512(password, measure=True)},
        {
            "name": "Linux CRYPT 5k",
            "service": lambda: linux_hash(password, measure=True),
        },
        {
            "name": "Linux CRYPT 1M",
            "service": lambda: linux_hash(password, rounds=10 ** 6, measure=True),
        },
    ]
 
    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2
 
    for test in TESTS:
        name = test.get("name")
        service = test.get("service")
 
        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time / ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

- funkcija `@time_it` kazuje koliko vremena treba pozvanoj funckiji da se izvrši
- sve ostale funkcije su kriptografske
- kreirali smo nova 2 testa da vidimo koliko prosječno vremena njima treba u 100 pokretanja:

```python
{"name": "Linux CRYPT 5k", "service": lambda: linux_hash(password, measure=True),},
{"name": "Linux CRYPT 1M", "service": lambda: linux_hash(password, rounds=10 ** 6, measure=True),},
```

```bash
Testing Linux CRYPT 1M 61/100
 
(marino_juric) C:\Users\A507\marino_juric\marino_juric>.\password_hashing.py
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| AES      |       0.000495       |
+----------+----------------------+
 
 
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| HASH_MD5 |       3.8e-05        |
| AES      |       0.000495       |
+----------+----------------------+
 
 
+-------------+----------------------+
| Function    | Avg. Time (100 runs) |
+-------------+----------------------+
| HASH_SHA256 |       3.2e-05        |
| HASH_MD5    |       3.8e-05        |
| AES         |       0.000495       |
+-------------+----------------------+
 
 
+----------------+----------------------+
| Function       | Avg. Time (100 runs) |
+----------------+----------------------+
| HASH_SHA256    |       3.2e-05        |
| HASH_MD5       |       3.8e-05        |
| AES            |       0.000495       |
| Linux CRYPT 5k |       0.006936       |
+----------------+----------------------+
 
 
+----------------+----------------------+
| Function       | Avg. Time (100 runs) |
+----------------+----------------------+
| HASH_SHA256    |       3.2e-05        |
| HASH_MD5       |       3.8e-05        |
| AES            |       0.000495       |
| Linux CRYPT 5k |       0.006936       |
| Linux CRYPT 1M |       1.376828       |
+----------------+----------------------+
```

- kao što vidimo brzina je različita kod svih kriptogtafskih hash funkcija
- ako je neka funkcija sporija to ne mora nužno značiti da je i lošija, mala brzina može uvelike povećati sigurnost
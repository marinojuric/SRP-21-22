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
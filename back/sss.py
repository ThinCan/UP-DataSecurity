import random
import galois

MAX = 2**32
G2 = galois.GF(MAX)
 
# letters should be: [(position in password, letter as bytes), ...]
def reconstruct_secret(letters, y):
    sums = G2([0])
    for j, letter_j in enumerate(letters):
        letter_j_value, share = G2([int.from_bytes(letter_j[1])]), G2([y[letter_j[0]]])
 
        numerator = G2([1])
        denominator = G2([1])
        for i, letter_i in enumerate(letters):
            xi = G2([int.from_bytes(letter_i[1])])
            if i != j and xi != letter_j_value:
                numerator *= xi
                denominator *= xi - letter_j_value
 
        prod = (share + letter_j_value) * (numerator / denominator)
        sums += prod
    return int(sums)

# password: bytes, letters: int, secret: int
def generate_shares(password, letters_to_guess, secret):
    coefficients = [G2(int.from_bytes(random.randbytes(4))) for _ in range(letters_to_guess - 1)]
    coefficients.append(G2([secret]))

    shares = []
    for i in range(1, len(password)+1):
        pletter = G2([password[i-1]])
        point = G2([0])
        for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
            point += pletter ** coefficient_index * coefficient_value
        shares.append(int(point - pletter))

    return shares
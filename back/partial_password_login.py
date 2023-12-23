import secrets
import bcrypt
plain = "abcdefghij"
#        0123456789
N = 4
k = len(plain)

R = []
for i in range(N-1):
    R.append(secrets.randbits(32))
y = []
K = secrets.randbits(32)
salt = bcrypt.gensalt(12)
hashh =bcrypt.hashpw(K.to_bytes(32), salt) 
K = int.from_bytes(hashh)
print(len(hashh))

for i in range(k):
    num = K
    for j in range(len(R)):
        num += R[j] * i
    y.append(num)

assert(len(y) == len(plain))

s = []
ycompare = []
for i in range(k):
    s.append(y[i] - ord(plain[i]))
s.append(K)


ip = [0, 2, 5, 7]
pp = "acfh"
yp = []
for i in range(N):
    idx = ip[i]
    yp.append(s[idx] + ord(pp[i]))
Kp = 0
for i in range(N):
    num = yp[i]
    numerator = 1
    denominator = 1
    for j in range(N):
        if j == i:
            continue
        numerator *= j
        denominator *= (i - j)
    num *= numerator/denominator
    Kp += num

print(K + Kp)
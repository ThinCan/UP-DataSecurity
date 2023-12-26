import secrets
import bcrypt
password_plain = "karol"
password_bytes = "karol".encode(encoding="utf-8")

enc = bcrypt.hashpw(password_plain.encode(), bcrypt.gensalt())
print(enc)


# for i in range(10):
#     print(bcrypt.gensalt())
#     print(bcrypt.checkpw(password_plain.encode(), enc))

# secret = 25 & 0xFFFFFFFF #bcrypt.hashpw(password=password_plain.encode(encoding="utf-8"), salt=bcrypt.gensalt())[:4]
# # print(secret)
# # secret = int.from_bytes(secret)
# N = 2
# randoms = [int.from_bytes(secrets.token_bytes(4)) for _ in range(N-1)]

# points = []
# for i in range(1, len(password_plain) + 1):
#     y = secret
#     for j in range(1, len(randoms) + 1):
#         y += (randoms[j-1] * pow(i, j)) & 0xFFFFFFFF
#     points.append(y & 0xFFFFFFFF )
# print("points: ", points)

# values = []
# for i in range(len(points)):
#     values.append((points[i] - password_bytes[i]) & 0xFFFFFFFF)
# assert(len(password_plain) == len(points) == len(values))
# print("values: ", values)

# pos = [1, 2]
# inp = "ka"
# inp_bytes = inp.encode(encoding="utf-8")
# recpoints = [(values[pos[i]] + inp_bytes[i]) & 0xFFFFFFFF for i in range(N)]
# print("recpoints: ", recpoints)


# calc_secret = 0
# for idx, i in enumerate(pos):
#     numerator = 1
#     denominator = 1
#     for j in pos:
#         if i == j:
#             continue
#         numerator *= j
#         denominator *= (i - j)
#     calc_secret += (points[idx] * numerator // denominator) 
# print(calc_secret )
# print(secret )
import bcrypt

password = input("Enter password: ")

print(password)

#passwords must be encoded before being hashed
p = password.encode('utf-8')

print(p)

hashed = bcrypt.hashpw(p, bcrypt.gensalt())

print(hashed)

_p = input("Confirm pasword: ").encode('utf-8')
#_hashed = bcrypt.hashpw(_p, bcrypt.gensalt())

if bcrypt.checkpw(hashed, _p):
    print("Access granted")

else:
    print("Access denied! Password mismatch!")


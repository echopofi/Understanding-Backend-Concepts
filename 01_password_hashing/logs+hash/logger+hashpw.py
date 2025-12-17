import bcrypt
import logging

'''
logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
        #filename="hashing_demo.log",
        #filemode="a"
        )'''
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(console)

file_handler = logging.FileHandler("hashing_demo.log")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(file_handler)

logger.info("\n" + "="*50)
logger.info("NEW RUN STARTED")
logger.info("="*50 + "\n")
logger.info("Password hashing demo started...")
logger.info("Logging to both consol and File")

#the password hashing logic
password = input("Enter password: ").encode('utf-8')
logger.info("Raw password received and encoded, the raw (string) passsword needs to first be encoded before hashing will be possible")
logger.debug(f"Password value: {password!r}")

salt = bcrypt.gensalt(rounds=12)
logger.info("Generated random salt")
logger.debug(f"Salt: {salt}")

hashed = bcrypt.hashpw(password, salt)
logger.info(f"Password Successfully hashed,\nHash length: {len(hashed)}, \nThis is what is stored in DB: {hashed}\n")
logger.debug(f"Full hash: {hashed.decode('utf-8')}")

logger.info("Next step is to confirm password")
_p = input("Confirm password: ").encode('utf-8')
logger.info("Confirmed password received successfully and encoded,  password matching....\n")

if bcrypt.checkpw(_p, hashed):
    logger.info("Password Verified,\nAccess Granted\n")
else:
    logger.warning("Password mismatch\n")

logger.info("demo ended")











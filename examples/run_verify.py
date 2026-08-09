from janeos.kernel.runtime import JaneOS
from jane_verify import JaneVerify

osys=JaneOS()
verify=JaneVerify(osys)
verify.authorize_project('.')
print(verify.validate('.'))

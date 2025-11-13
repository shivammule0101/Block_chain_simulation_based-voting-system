from werkzeug.security import check_password_hash
import json
D=json.load(open('storage.json'))
h=D.get('admins',[{}])[0].get('password_hash')
print('stored len', len(h))
print('prefix', h[:10])
print('check adminpass ->', check_password_hash(h,'adminpass'))
print('check wrong ->', check_password_hash(h,'x'))

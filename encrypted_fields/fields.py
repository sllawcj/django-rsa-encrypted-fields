import rsa
from django.db import models
import base64


class RSAFieldMixin(object):

    def loadKeys(self, keys=[]):
        if len(keys) == 0:
            (pubkey, privkey) = rsa.newkeys(512)
            keys.append(pubkey)
            keys.append(privkey)
        elif len(keys) == 2:
            pubkey = keys[0]
            privkey = keys[1]
        else:
            raise Exception("Invaild key array passed")

        keys[0] = pubkey
        keys[1] = privkey

        return keys

    def encrypt(self, value):
        cryptoText = value.encode('utf8')
        crypt = rsa.encrypt(cryptoText, self.loadKeys()[0])
        return crypt.hex()

    def decrypt(self, value):
        value = bytes.fromhex(value)

        text = rsa.decrypt(value, self.loadKeys()[1])
        return text

    def get_internal_type(self):
        """
        To treat everything as text
        """
        return 'CharField'

    def get_prep_value(self, value):
        if value:
            return self.encrypt(value)
        return None

    def get_db_prep_value(self, value, connection, prepared=False):
        if not prepared:
            value = self.get_prep_value(value)
        return value

    def from_db_value(self, value, expression, connection):
        return self.to_python(value)

    def to_python(self, value):
        if value is None:
            return value
        value = self.decrypt(value)
        return super(RSAFieldMixin, self).to_python(value.decode('utf8'))


class RSACharField(RSAFieldMixin, models.CharField):
    pass


class RSATextField(RSAFieldMixin, models.TextField):
    pass


class RSADateTimeField(RSAFieldMixin, models.DateTimeField):
    pass


class RSAIntegerField(RSAFieldMixin, models.IntegerField):
    pass


class RSADateField(RSAFieldMixin, models.DateField):
    pass


class RSAFloatField(RSAFieldMixin, models.FloatField):
    pass


class RSAEmailField(RSAFieldMixin, models.EmailField):
    pass


class RSABooleanField(RSAFieldMixin, models.BooleanField):
    pass


class RSABinaryField(RSAFieldMixin, models.BinaryField):
    pass

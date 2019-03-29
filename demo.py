#!/usr/bin/env python
#*******************************************************************************
#*   Ledger Blue
#*   (c) 2016 Ledger
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************
from ledgerblue.comm import getDongle
import base64
from ledgerblue.commException import CommException

from secp256k1 import PublicKey
from utils import serialize
import json
import codecs
import binascii

bipp44_path = ("80000000"
              +"00000000"
              +"00000000")

dongle = getDongle(True)
keys = dongle.exchange(codecs.decode("80010000FF"+ bipp44_path, 'hex'))
publicKey = keys[:65]
privateKey = keys[65:]

# create acc
_textToSign_create_acc = '["create_acc_tx","BNKQhfy4bRm3We9E+DXS7dhWp2avHSN2sIDuOlpJjWwl8Lo1FdKfNhk63yTFlXe685URVRDfbXPY16HlXDqYagg=",9,151168,"BFRPiXyi8DRZ/6u+MRFMQHUY339lVPHrkuF0u5ReA1fmFirF5d7+aioFOJQOcPTPJ3rpogolInseoudaOKIwgC8=",10000000]'

# spend 1
_textToSign_spend1 = '["spend","BB3G8DfYtkZurxIxAGw2Y8ELhVx8WyjjqAdoVptOB+tW5cQsj93XGflHJBrFKpgEFWTUKKYKDM8GYPu4eUM+DCg=",4,60707,"BNKQhfy4bRm3We9E+DXS7dhWp2avHSN2sIDuOlpJjWwl8Lo1FdKfNhk63yTFlXe685URVRDfbXPY16HlXDqYagg=",900000,0]'

# spend 2
_textToSign_spend2 = '["spend","BB3G8DfYtkZurxIxAGw2Y8ELhVx8WyjjqAdoVptOB+tW5cQsj93XGflHJBrFKpgEFWTUKKYKDM8GYPu4eUM+DCg=",36,61657,"BHVfQWRx7I1xmlWw5KJ7l9ijq4tcobFCub68jsmCGaEQXSr/hi0Vpz8+wa0v8ytcTEUu4wJwTfC+7q6r+CPYS20=",10000000,0]'

# oracle bet
_textToSign_bet = '["oracle_bet","BGJJ08FDDFCQ8w3G3AbrL/qjEQJXWZsLqIqrmyoH3Vhy709+UlkJLgA2KarZTfXQg5E46jd918Nl9AkexDUKNzI=",1137,152118,"OaQb/xyYNbqrT4p/P8i7wfvo7zWo7GkCUBFfI8RuRNE=",2,100000000]'

# oracle close
_textToSign_close = '["oracle_close","BF3rw/kC3c5UJ6Lfr/uKxGgDT4mbIHZmf+xffJldnqL0Hf8ilrI6OGdG+TAjJKL3rZPvDuqFUd6tg02CKnRGrr8=",12,152118,"POjbPIzIGg/7QHHdecpTnPZyGd0VGrbHSlZwA0EueMI="]'

# governance oracle
_textToSign_gov_oracle = '["oracle_new","BF3rw/kC3c5UJ6Lfr/uKxGgDT4mbIHZmf+xffJldnqL0Hf8ilrI6OGdG+TAjJKL3rZPvDuqFUd6tg02CKnRGrr8=",31,152118,"",0,"zItT81PP8MYrk+QDce2eUid8SQSsMzZKhWBy2Wb2WGY=",0,3,50]'

# question oracle
_textToSign_question_oracle = '["oracle_new","BF3rw/kC3c5UJ6Lfr/uKxGgDT4mbIHZmf+xffJldnqL0Hf8ilrI6OGdG+TAjJKL3rZPvDuqFUd6tg02CKnRGrr8=",38,152118,"UT12ZW8gaXMgd29ydGggbW9yZSB0aGFuICQxMDA7UD1vcmFjbGUgekl0VDgxUFA4TVlyaytRRGNlMmVVaWQ4U1FTc016WktoV0J5MldiMldHWT0gcmV0dXJucyB0cnVlOyAoUCBhbmQgUSkgb3IgKCFQIGFuZCAhUSku",39670,"koWAM1ANpoPGmd+o3AFVABVyc7EeEHanf8qqmxOLeE4=",0,0,0]'

# collect oracle winnings
_textToSign_winnings = '["oracle_winnings","BF3rw/kC3c5UJ6Lfr/uKxGgDT4mbIHZmf+xffJldnqL0Hf8ilrI6OGdG+TAjJKL3rZPvDuqFUd6tg02CKnRGrr8=",22,152118,"tgGxIve5FdNsAB0t4diP5p3cJjeax05KpWX7ltfJjyI="]'

# collect unmatched orders
_textToSign_unmatched = '["unmatched","BF3rw/kC3c5UJ6Lfr/uKxGgDT4mbIHZmf+xffJldnqL0Hf8ilrI6OGdG+TAjJKL3rZPvDuqFUd6tg02CKnRGrr8=",20,152118,"M16iB5Sd0BfXnFII3axzmbB924zBTgG3qDvwogYgyV4="]'

# CHANGE TO NEEDED TX
textToSign = _textToSign_close

print ("\nPublic key: %s, length: %d\n" % (base64.b64encode(publicKey), len(publicKey)))

try:
    offset = 0
    while offset != len(textToSign):
        if (len(textToSign) - offset) > 255:
            chunk = textToSign[offset : offset + 255]
        else:
            chunk = textToSign[offset:]
        if (offset + len(chunk)) == len(textToSign):
            p1 = 0x80
            bip = codecs.decode(bipp44_path, 'hex')
        else:
            p1 = 0x00
            bip = bytes('')

        apdu = codecs.decode("8002", "hex")
        apdu += bytes((p1, ))
        apdu += bytes((0x00, ))
        l = len(chunk) + len(bip)
        apdu += bytes((l, ))
        apdu += bytes(chunk, 'ascii')
        apdu += bip

        signature = dongle.exchange(apdu)
        offset += len(chunk)

        print ("\nSent chunk: " + binascii.hexlify(bytes(chunk, 'ascii')).decode())

    print ("\nGot signature: " + binascii.hexlify(signature).decode())
    publicKey = PublicKey(bytes(publicKey), raw=True)

    print ("base64-encoded: " + base64.b64encode(signature).decode())
    signature = publicKey.ecdsa_deserialize(bytes(signature))

    dataToSign = bytes(serialize(json.loads(textToSign)))
    print ("\nSource tx: " + textToSign)
    print ("\nIs signature verified? " + str(publicKey.ecdsa_verify(dataToSign, signature)))
    # fff = base64.b64decode("MEUCID3p7O1FIIWlN1kHAB3rSTK43HB8E9ZIN9h+sce1pDmcAiEA0P0DKOCEssJNqKsAEI+OuwBsU2AbYiCQfSxaveuxpWc=")
    # signature2 = publicKey.ecdsa_deserialize(bytes(fff))
    # print "verified " + str(publicKey.ecdsa_verify(bytes(_textToSign), signature2))

except CommException as comm:
    if comm.sw == 0x6985:
        print ("Aborted by user")
    else:
        print ("Invalid status " + comm.sw)

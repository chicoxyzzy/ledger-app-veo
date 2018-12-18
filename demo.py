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

bipp44_path = ("80000000"
              +"00000000"
              +"00000000")

dongle = getDongle(True)
keys = dongle.exchange(bytes(("80010000FF"+ bipp44_path).decode('hex')))
publicKey = keys[:65]
privateKey = keys[65:]

_textToSign = '["create_acc_tx","BNKQhfy4bRm3We9E+DXS7dhWp2avHSN2sIDuOlpJjWwl8Lo1FdKfNhk63yTFlXe685URVRDfbXPY16HlXDqYagg=",9,151168,"BFRPiXyi8DRZ/6u+MRFMQHUY339lVPHrkuF0u5ReA1fmFirF5d7+aioFOJQOcPTPJ3rpogolInseoudaOKIwgC8=",10000000]'

_textToSign = '["spend","BB3G8DfYtkZurxIxAGw2Y8ELhVx8WyjjqAdoVptOB+tW5cQsj93XGflHJBrFKpgEFWTUKKYKDM8GYPu4eUM+DCg=",4,60707,"BNKQhfy4bRm3We9E+DXS7dhWp2avHSN2sIDuOlpJjWwl8Lo1FdKfNhk63yTFlXe685URVRDfbXPY16HlXDqYagg=",900000,0]'





textToSign = _textToSign

print ("%s, %d, %s" % (base64.b64encode(publicKey), len(publicKey), str(privateKey).encode('hex')))

try:
    offset = 0
    while offset <> len(textToSign):
        if (len(textToSign) - offset) > 255:
            chunk = textToSign[offset : offset + 255]
        else:
            chunk = textToSign[offset:]
        if (offset + len(chunk)) == len(textToSign):
            p1 = 0x80
            bip = bytes(bipp44_path).decode('hex')
        else:
            p1 = 0x00
            bip = bytes('')
        apdu = bytes("8002".decode('hex')) + chr(p1) + chr(0x00) + chr(len(chunk + bip)) + bytes(chunk) + bip
        signature = dongle.exchange(apdu)
        offset += len(chunk)

    print "signature " + str(signature).encode('hex')
    publicKey = PublicKey(bytes(publicKey), raw=True)

    print "signature b64 " + base64.b64encode(signature)
    signature = publicKey.ecdsa_deserialize(bytes(signature))

    print "verified " + str(publicKey.ecdsa_verify(bytes(_textToSign), signature))
    # fff = base64.b64decode("MEUCID3p7O1FIIWlN1kHAB3rSTK43HB8E9ZIN9h+sce1pDmcAiEA0P0DKOCEssJNqKsAEI+OuwBsU2AbYiCQfSxaveuxpWc=")
    # signature2 = publicKey.ecdsa_deserialize(bytes(fff))
    # print "verified " + str(publicKey.ecdsa_verify(bytes(_textToSign), signature2))

except CommException as comm:
    if comm.sw == 0x6985:
        print "Aborted by user"
    else:
        print "Invalid status " + comm.sw

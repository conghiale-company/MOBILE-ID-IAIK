// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
// 
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
// 
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
// 
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
// 
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
// 
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.wrapper.CK_ECDSA_ECIES_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;


/**
 * Parameter class for the utimaco vendor defined ECIES encryption operation.
 * Possible values according to utimaco documentation: <br><br>
 *
 * hashAlg:<br>
 * CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384,
 * CKM_SHA512, CKM_RIPEMD160, CKM_MD5
 * <br>
 *
 * cryptAlg:<br>
 * CKM_AES_ECB, CKM_AES_CBC, CKM_ECDSA_ECIES_XOR
 * <br>
 *
 * cryptOpt:<br>
 * Key Length of cryptAlg . (0 for CKM_ECDSA_ECIES_XOR )
 *
 * macAlg: <br>
 * CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC,
 * CKM_SHA384_HMAC, CKM_SHA512_HMAC, CKM_MD5_HMAC,
 * CKM_RIPEMD160_HMAC
 * <br>
 * macOpt:<br>
 * currently ignored
 *
 */
public class EcdsaEciesParams implements Parameters {

    public long hashAlg;
    public long cryptAlg;
    public long cryptOpt;
    public long macAlg;
    public long macOpt;
    public byte[] sharedSecret1;
    public byte[] sharedSecret2;

    public EcdsaEciesParams(long hashAlg, long cryptAlg, long cryptOpt, long macAlg, long macOpt) {
        this(hashAlg, cryptAlg, cryptOpt, macAlg, macOpt, null, null);
    }

    public EcdsaEciesParams(long hashAlg, long cryptAlg, long cryptOpt, long macAlg, long macOpt, byte[] sharedSecret1, byte[] sharedSecret2) {
        this.hashAlg = hashAlg;
        this.cryptAlg = cryptAlg;
        this.cryptOpt = cryptOpt;
        this.macAlg = macAlg;
        this.macOpt = macOpt;
        this.sharedSecret1 = sharedSecret1 == null ? null : (byte[]) sharedSecret1.clone();
        this.sharedSecret2 = sharedSecret2 == null ? null : (byte[]) sharedSecret2.clone();
    }


    public Object getPKCS11ParamsObject() {
        CK_ECDSA_ECIES_PARAMS pkcs11Params = new CK_ECDSA_ECIES_PARAMS();
        pkcs11Params.hashAlg = hashAlg;
        pkcs11Params.cryptAlg = cryptAlg;
        pkcs11Params.cryptOpt = cryptOpt;
        pkcs11Params.macAlg = macAlg;
        pkcs11Params.macOpt = macOpt;
        pkcs11Params.pSharedSecret1 = sharedSecret1 == null ? null : (byte[]) sharedSecret1.clone();
        pkcs11Params.pSharedSecret2 = sharedSecret2 == null ? null : (byte[]) sharedSecret2.clone();

        return pkcs11Params;
    }

    public String toString() {
        StringBuffer buffer = new StringBuffer(256);

        buffer.append(Constants.INDENT);
        buffer.append(super.toString());
        buffer.append(": ");

        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);
        buffer.append(Constants.INDENT);
        buffer.append("hash algorithm:         ");
        buffer.append(Functions.mechanismCodeToString(hashAlg));

        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);
        buffer.append(Constants.INDENT);
        buffer.append("crypto algorithm:       ");
        buffer.append(Functions.mechanismCodeToString(cryptAlg));

        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);
        buffer.append(Constants.INDENT);
        buffer.append("crypto options:         ");
        buffer.append(cryptOpt);

        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);
        buffer.append(Constants.INDENT);
        buffer.append("mac algorithm:          ");
        buffer.append(Functions.mechanismCodeToString(macAlg));

        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);
        buffer.append(Constants.INDENT);
        buffer.append("mac    options:         ");
        buffer.append(macOpt);

        if (sharedSecret1 != null) {
            buffer.append(Constants.NEWLINE);
            buffer.append(Constants.INDENT);
            buffer.append(Constants.INDENT);
            buffer.append("shared secret1 (len):   ");
            buffer.append(sharedSecret1.length);
        }

        if (sharedSecret2 != null) {
            buffer.append(Constants.NEWLINE);
            buffer.append(Constants.INDENT);
            buffer.append(Constants.INDENT);
            buffer.append("shared secret2 (len):   ");
            buffer.append(sharedSecret2.length);
        }


        buffer.append(Constants.NEWLINE);
        return buffer.toString();
    }

}

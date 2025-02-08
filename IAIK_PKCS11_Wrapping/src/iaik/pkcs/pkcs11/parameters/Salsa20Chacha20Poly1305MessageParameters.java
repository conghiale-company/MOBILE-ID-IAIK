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

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;


/**
 * This class encapsulates parameters for the Salsa20Chacha20 en/decryption.
 *
 * @author Patrick Schuster
 * @version 1.0
 */
public class Salsa20Chacha20Poly1305MessageParameters implements MessageParameters {

    protected byte[] pNonce;
    protected byte[] pTag;

    /**
     * Create a new Salsa20Chacha20Poly1305MessageParameters object with the given attributes.
     *
     * @param pNonce The nonce.
     * @param pTag authentication tag which is returned on MessageEncrypt, and provided on MessageDecrypt.
     *
     *
     */
    public Salsa20Chacha20Poly1305MessageParameters(byte[] pNonce, byte[] pTag) {
        this.pNonce = pNonce;
        this.pTag = pTag;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @postconditions (result != null) and (result instanceof Salsa20Chacha20Poly1305MessageParameters) and
     * (result.equals(this))
     */
    public Object clone() {
        return new Salsa20Chacha20Poly1305Parameters((byte[]) this.pNonce.clone(), (byte[]) this.pTag.clone());
    }

    /**
     * Get this parameters object as an object of the CK_SALSA20_CHACHA20_MSG_POLY1305_PARAMS class.
     *
     * @return This object as a CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {

        CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS params = new CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS();
        params.pNonce = pNonce;
        params.pTag = pTag;

        return params;
    }

    /**
     * Read the parameters from the PKCS11Object and overwrite the values into this object.
     *
     * @param obj Object to read the parameters from
     */
    public void setValuesFromPKCS11Object(Object obj) {
        if(obj instanceof CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)
        {
            this.pNonce = ((CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) obj).pNonce;
            this.pTag = ((CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS) obj).pTag;
        }
    }

    /**
     * Returns the string representation of this object. Do not parse data from this string, it is for
     * debugging only.
     *
     * @return A string representation of this object.
     */
    public String toString() {
        StringBuffer buffer = new StringBuffer();

        buffer.append(super.toString());
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("pNonce: ");
        buffer.append(Functions.toHexString(pNonce));
        buffer.append(Constants.NEWLINE);
        buffer.append("pTag: ");
        buffer.append(Functions.toHexString(pTag));
        buffer.append(Constants.NEWLINE);

        return buffer.toString();
    }

    /**
     * Compares all member variables of this object with the other object. Returns only true, if all
     * are equal in both objects.
     *
     * @param otherObject The other object to compare to.
     * @return True, if other is an instance of this class and all member variables of both objects
     * are equal. False, otherwise.
     */
    public boolean equals(Object otherObject) {
        boolean equal = false;

        if (otherObject instanceof Salsa20Chacha20Poly1305MessageParameters) {
            Salsa20Chacha20Poly1305MessageParameters other = (Salsa20Chacha20Poly1305MessageParameters) otherObject;
            equal = (this == other) || (super.equals(other)
                    && Functions.equals(this.pNonce, other.pNonce)
                    && Functions.equals(this.pTag, other.pTag));
        }
        return equal;
    }

    /**
     * The overriding of this method should ensure that the objects of this class work correctly in a
     * hashtable.
     *
     * @return The hash code of this object.
     */
    public int hashCode() {
        return super.hashCode() ^ Functions.hashCode(pNonce) ^ Functions.hashCode(pTag);
    }
}

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

import iaik.pkcs.pkcs11.wrapper.CK_CCM_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the AES-CCM en/decryption
 *
 * @author Otto Touzil
 * @version 1.0
 */
public class CcmParameters implements Parameters {

    protected long ulDataLen;
    protected byte[] pNonce;
    protected byte[] pAad;
    protected long ulMacLen;

    /**
     * Create a new CCMParameters object with the given attributes.
     *
     * @param ulDataLen length of the data where 0 &le; ulDataLen &lt; 2^8L. This length should not include the length
     *                  of the MAC that is appended to the cipher text.
     *                  (where L is the size in bytes of the data length's length(2 &lt; L &lt; 8)
     * @param pNonce    the nonce
     * @param pAad      additional authentication data. This data is authenticated but not encrypted.
     * @param ulMacLen  length of the MAC (output following cipher text) in bytes. Valid values are (4, 6, 8, 10, 12, 14 and 16)
     */
    public CcmParameters(long ulDataLen, byte[] pNonce, byte[] pAad, long ulMacLen) {
        if (pNonce.length < 7 || pNonce.length > 13) {
            throw new IllegalArgumentException("Illegal nonce size! Must be between 7 and 13");
        }
        if (ulMacLen != 4 && ulMacLen != 6 && ulMacLen != 8 && ulMacLen != 10 && ulMacLen != 12 && ulMacLen != 14 && ulMacLen != 16) {
            throw new IllegalArgumentException("Invalid MAC length. Valid values are: 4, 6, 8, 10, 12, 14 or 16");
        }

        this.ulDataLen = ulDataLen;
        this.pNonce = pNonce;
        this.pAad = pAad;
        this.ulMacLen = ulMacLen;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @postconditions (result != null) and (result instanceof CK_CCM_PARAMS) and
     * (result.equals(this))
     */
    public Object clone() {
        if (pAad != null) {
            return new CcmParameters(this.ulDataLen, (byte[]) this.pNonce.clone(),
                    (byte[]) this.pAad.clone(), this.ulMacLen);
        }
        return new CcmParameters(this.ulDataLen, (byte[]) this.pNonce.clone(),
                null, this.ulMacLen);
    }

    /**
     * Get this parameters object as an object of the CK_CCM_PARAMS class.
     *
     * @return This object as a CK_CCM_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {

        CK_CCM_PARAMS params = new CK_CCM_PARAMS();
        params.pNonce = pNonce;
        params.pAAD = pAad;
        params.ulMacLen = ulMacLen;
        params.ulDataLen = ulDataLen;

        return params;
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
        // buffer.append(Constants.NEWLINE);

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

        if (otherObject instanceof CcmParameters) {
            CcmParameters other = (CcmParameters) otherObject;
            equal = (this == other) || (super.equals(other)
                    && Functions.equals(this.pNonce, other.pNonce)
                    && Functions.equals(this.pAad, other.pAad)
                    && this.ulMacLen == other.ulMacLen
                    && this.ulDataLen == other.ulDataLen);
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
        return super.hashCode() ^ Functions.hashCode(pNonce) ^ Functions.hashCode(pAad) ^
                new Long(ulDataLen).hashCode() ^ new Long(ulDataLen).hashCode();
    }

}

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

import iaik.pkcs.pkcs11.wrapper.CK_CCM_MESSAGE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.CK_GCM_MESSAGE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the AES-GCM message en/decryption.
 *
 * @author Patrick Schuster
 * @version 1.0
 */
public class CcmMessageParameters implements MessageParameters {


    protected long ulDataLen;
    protected byte[] pNonce;
    protected long ulNonceFixedBits;
    protected long nonceGenerator;
    protected byte[] pMAC;

    /**
     * Create a new CcmMessageParameters object with the given attributes.
     *
     * @param ulDataLen length of the data where 0 &le; ulDataLen &lt; 2^(8L).
     * @param pNonce the nonce. length: 7 &le; ulNonceLen &le; 13.
     * @param ulNonceFixedBits number of bits of the original nonce to preserve when generating a <br>
     *                     new nonce. These bits are counted from the Most significant bits (to the right).
     * @param nonceGenerator Function used to generate a new nonce. Each nonce must be
     *                          unique for a given session.
     * @param pMAC CCM MAC returned on MessageEncrypt, provided on MessageDecrypt
     */
    public CcmMessageParameters(long ulDataLen, byte[] pNonce, long ulNonceFixedBits, long nonceGenerator, byte[] pMAC) {
        this.ulDataLen = ulDataLen;
        this.pNonce = pNonce;
        this.ulNonceFixedBits = ulNonceFixedBits;
        this.nonceGenerator = nonceGenerator;
        this.pMAC = pMAC;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @postconditions (result != null) and (result instanceof CcmMessageParameters) and
     * (result.equals(this))
     */
    public Object clone() {
        return new CcmMessageParameters(this.ulDataLen,(byte[]) this.pNonce.clone(), this.ulNonceFixedBits,
                this.nonceGenerator, (byte[]) this.pMAC.clone());
    }

    /**
     * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
     *
     * @return This object as a CK_CCM_MESSAGE_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {

        CK_CCM_MESSAGE_PARAMS params = new CK_CCM_MESSAGE_PARAMS();
        params.ulDataLen = ulDataLen;
        params.pNonce = pNonce;
        params.ulNonceFixedBits = ulNonceFixedBits;
        params.nonceGenerator = nonceGenerator;
        params.pMAC = pMAC;

        return params;
    }

    /**
     * Read the parameters from the PKCS11Object and overwrite the values into this object.
     *
     * @param obj Object to read the parameters from
     */
    public void setValuesFromPKCS11Object(Object obj) {
        if(obj instanceof CK_CCM_MESSAGE_PARAMS)
        {
            this.ulDataLen = ((CK_CCM_MESSAGE_PARAMS) obj).ulDataLen;
            this.pNonce = ((CK_CCM_MESSAGE_PARAMS) obj).pNonce;
            this.ulNonceFixedBits = ((CK_CCM_MESSAGE_PARAMS) obj).ulNonceFixedBits;
            this.nonceGenerator = ((CK_CCM_MESSAGE_PARAMS) obj).nonceGenerator;
            this.pMAC = ((CK_CCM_MESSAGE_PARAMS) obj).pMAC;
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

        buffer.append("Class: ");
        buffer.append(getClass().getName());
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulDataLen: ");
        buffer.append(ulDataLen);
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("pNonce: ");
        buffer.append(Functions.toHexString(pNonce));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulNonceFixedBits: ");
        buffer.append(ulNonceFixedBits);
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("pMAC: ");
        buffer.append(Functions.toHexString(pMAC));
        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);

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

        if (otherObject instanceof CcmMessageParameters) {
            CcmMessageParameters other = (CcmMessageParameters) otherObject;
            equal = (this == other) || (super.equals(other)
                    && Functions.equals(this.pNonce, other.pNonce)
                    && Functions.equals(this.pMAC, other.pMAC)
                    && this.ulNonceFixedBits == other.ulNonceFixedBits
                    && this.nonceGenerator == other.nonceGenerator);
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
        return super.hashCode() ^ Functions.hashCode(pNonce) ^ Functions.hashCode(pMAC) ^ new Long(nonceGenerator).hashCode()
                ^ new Long(ulNonceFixedBits).hashCode();
    }

    public byte[] getpMAC() {
        return pMAC;
    }

    public long getUlDataLen() {
        return ulDataLen;
    }

    public byte[] getpNonce() {
        return pNonce;
    }

}




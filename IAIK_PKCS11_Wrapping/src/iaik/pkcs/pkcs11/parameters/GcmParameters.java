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

import iaik.pkcs.pkcs11.wrapper.CK_GCM_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the AES-GCM en/decryption.
 *
 * @author Otto Touzil
 * @version 1.0
 */
public class GcmParameters implements Parameters {

    protected byte[] pIv;
    protected byte[] pAad;
    protected long ulTagBits;

    /**
     * Create a new GCMParameters object with the given attributes.
     *
     * @param pIv       Initialization vector
     * @param pAad      additional authentication data. This data is authenticated but not encrypted.
     * @param ulTagBits length of authentication tag (output following ciphertext) in bits. (0 - 128)
     *                  depending on the algorithm implementation within the hsm, ulTagBits may be any
     *                  one of the following five values: 128, 120, 112, 104, or 96, may be 64 or 32;
     */
    public GcmParameters(byte[] pIv, byte[] pAad, long ulTagBits) {
        if (pIv == null) {
            throw new NullPointerException("Argument \"pIv\" must not be null.");
        }
        if (ulTagBits < 0 || ulTagBits > 128) {
            throw new IllegalArgumentException(
                    "Argument \"ulTagBits\" must must be '0 < ulTagBits < 128'.");
        }

        this.pIv = pIv;
        this.pAad = pAad;
        this.ulTagBits = ulTagBits;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @postconditions (result != null) and (result instanceof EcDH1KeyDerivationParameters) and
     * (result.equals(this))
     */
    public Object clone() {
        if (pAad != null) {
            return new GcmParameters((byte[]) this.pIv.clone(), (byte[]) this.pAad.clone(), this.ulTagBits);
        }
        return new GcmParameters((byte[]) this.pIv.clone(), null, this.ulTagBits);
    }

    /**
     * Get this parameters object as an object of the CK_GCM_PARAMS class.
     *
     * @return This object as a CK_GCM_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {

        CK_GCM_PARAMS params = new CK_GCM_PARAMS();
        params.pIv = pIv;
        params.pAAD = pAad;
        params.ulTagBits = ulTagBits;

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
        buffer.append("pIV: ");
        buffer.append(Functions.toHexString(pIv));
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

        if (otherObject instanceof GcmParameters) {
            GcmParameters other = (GcmParameters) otherObject;
            equal = (this == other) || (super.equals(other)
                    && Functions.equals(this.pIv, other.pIv)
                    && Functions.equals(this.pAad, other.pAad)
                    && this.ulTagBits == other.ulTagBits);
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
        return super.hashCode() ^ Functions.hashCode(pIv) ^ Functions.hashCode(pAad) ^ new Long(ulTagBits).hashCode();
    }

}


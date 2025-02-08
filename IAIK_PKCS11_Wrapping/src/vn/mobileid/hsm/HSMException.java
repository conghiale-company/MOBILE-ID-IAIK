/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.mobileid.hsm;

/**
 *
 * @author Tan_Hung
 */
public class HSMException extends Exception{
    
    //private static final long serialVersionUID = -6122994861628966528L;
    
    protected static String diagnostic = "HSM Exception";

    public HSMException() {
        super(diagnostic);
    }

    public HSMException(final String detail) {
        super(diagnostic + ": " + detail);
    }
}

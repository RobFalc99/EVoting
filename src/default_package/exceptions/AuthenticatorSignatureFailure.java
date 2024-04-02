/*
 * Copyright © 2022, Roberto Falcone, All rights reserved.
 */

package default_package.exceptions;

/**
 *
 * @author rf199
 */
public class AuthenticatorSignatureFailure extends Exception {

    /**
     * Creates a new instance of <code>AuthenticatorSignatureFailure</code> without detail message.
     */
    public AuthenticatorSignatureFailure() {
    }


    /**
     * Constructs an instance of <code>AuthenticatorSignatureFailure</code> with the specified detail message.
     * @param msg the detail message.
     */
    public AuthenticatorSignatureFailure(String msg) {
        super(msg);
    }
}

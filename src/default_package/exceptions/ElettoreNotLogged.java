package default_package.exceptions;


public class ElettoreNotLogged extends Exception {

    /**
     * Creates a new instance of <code>ElettoreNotLogged</code> without detail message.
     */
    public ElettoreNotLogged() {
    }


    /**
     * Constructs an instance of <code>ElettoreNotLogged</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ElettoreNotLogged(String msg) {
        super(msg);
    }
}

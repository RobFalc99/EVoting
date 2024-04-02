package default_package.exceptions;


public class ElettoreAlreadySigned extends Exception{

    /**
     * Creates a new instance of <code>ElettoreAlreadySigned</code> without detail message.
     */
    public ElettoreAlreadySigned() {
    }


    /**
     * Constructs an instance of <code>ElettoreAlreadySigned</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ElettoreAlreadySigned(String msg) {
        super(msg);
    }
}

package pl.marcinbialecki.learning.xades.signer;

/**
 * Type T provider interface.
 */
public interface IProvider<T> {

    /**
     * Provide element of type T.
     * @return Type T Object.
     */
    T provide();
}
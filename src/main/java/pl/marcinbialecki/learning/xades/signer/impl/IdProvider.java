package pl.marcinbialecki.learning.xades.signer.impl;

import pl.marcinbialecki.learning.xades.signer.IProvider;

import java.util.UUID;

/**
 * Identify number provider.
 */
public class IdProvider implements IProvider<String> {

    /**
     * Format of provided IDs.
     */
    private static final String ID_FORMAT = "ID-%s";

    @Override
    public String provide() {
        return String.format(ID_FORMAT, UUID.randomUUID());
    }

}

package pl.marcinbialecki.learning.xades.model;

/**
 * Created by Marcin Białecki on 2016-04-25.
 */
public class Attachement {

    /**
     * File content.
     */
    private byte[] content;

    /**
     * Name of file.
     */
    private String name;

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

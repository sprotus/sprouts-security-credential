package kr.sprouts.security.credential;

public class Credential<T> {
    private T value;

    private Credential() { }

    public Credential(T value) {
        this.value = value;
    }

    public T getValue() {
        return value;
    }
}

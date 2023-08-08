package kr.sprouts.security.credential;

public class Credential<T> {
    private final T value;

    public Credential(T value) {
        this.value = value;
    }

    public T getValue() {
        return value;
    }
}

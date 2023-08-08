package kr.sprouts.security.credential;

public class Credential<V> {
    private final String key;
    private final V value;

    public Credential(String key, V value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public V getValue() {
        return value;
    }
}
